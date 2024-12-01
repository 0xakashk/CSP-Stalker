import argparse
import requests
from urllib.parse import urlparse
import tldextract
import os
import json
import socket
import time

# Display the ASCII logo
def show_logo():
    logo = r"""
 ██████╗███████╗██████╗     ███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗    ██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
██║     ███████╗██████╔╝    ███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
██║     ╚════██║██╔═══╝     ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚██████╗███████║██║         ███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
 ╚═════╝╚══════╝╚═╝         ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
        CSPStalker - Extract Apex Domains and Subdomains
-----------------------------------------------------------------------------------------
           Created by: 0xakashk (Twitter: @0xakashk)
-----------------------------------------------------------------------------------------
"""
    print(logo)

# Sanitize filename to avoid OS errors
def sanitize_filename(name):
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    return name

# Extract the apex domain
def extract_apex_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

# Fetch CSP headers and extract domains
def get_csp_domains(url):
    try:
        response = requests.head(url, timeout=10)
        csp_header = response.headers.get("Content-Security-Policy", "")
        domains = set()
        if csp_header:
            for directive in csp_header.split(";"):
                for token in directive.split():
                    if token.startswith("http://") or token.startswith("https://"):
                        parsed_url = urlparse(token)
                        domains.add(extract_apex_domain(parsed_url.netloc))
        return domains
    except requests.RequestException as e:
        print(f"Failed to fetch headers for {url}: {e}")
        return set()

# Fetch subdomains using MerkleMap API with pagination
def fetch_subdomains(domain):
    api_url = "https://api.merklemap.com/search"
    all_subdomains = []
    page = 0

    try:
        while True:
            params = {"query": domain, "page": page}
            response = requests.get(api_url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                print(f"Page {page}: {len(results)} subdomains fetched.")

                if not results:
                    break

                subdomains = [item["domain"] for item in results]
                all_subdomains.extend(subdomains)
                page += 1

                # Avoid hitting API rate limits
                time.sleep(1)
            else:
                print(f"Failed to fetch subdomains for {domain} (Status code: {response.status_code})")
                break
    except requests.RequestException as e:
        print(f"Failed to fetch subdomains for {domain}: {e}")
    
    return sorted(set(all_subdomains))

# Save results to a file
def save_results(domain, subdomains):
    sanitized_domain = sanitize_filename(domain)
    if not os.path.exists("results"):
        os.makedirs("results")
    json_file_path = os.path.join("results", f"{sanitized_domain}_results.json")
    with open(json_file_path, "w") as json_file:
        json.dump({"apex_domain": domain, "subdomains": subdomains}, json_file, indent=4)
    print(f"Results saved to {json_file_path}")

# Process a single URL
def process_single_url(url):
    print(f"\nProcessing URL: {url}")
    apex_domains = get_csp_domains(url)
    if apex_domains:
        for apex_domain in apex_domains:
            print("-------------------------------------------------")
            print(f"Apex Domain: {apex_domain}")
            subdomains = fetch_subdomains(apex_domain)
            if subdomains:
                print("Subdomains:")
                for subdomain in subdomains:
                    print(f"  - {subdomain}")
                save_results(apex_domain, subdomains)
            else:
                print("No subdomains found.")
            print("-------------------------------------------------")
    else:
        print(f"No CSP domains found for {url}")

# Process URLs from a file
def process_url_list(file_path):
    try:
        with open(file_path, "r") as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                if url:
                    process_single_url(url)
    except FileNotFoundError:
        print(f"File not found: {file_path}")

# Main function
def main():
    show_logo()
    parser = argparse.ArgumentParser(description="Extract apex domains and subdomains from CSP headers.")
    parser.add_argument("-u", "--url", help="Single URL to process.")
    parser.add_argument("-f", "--file", help="File containing a list of URLs to process.")
    args = parser.parse_args()

    if args.url:
        process_single_url(args.url)
    elif args.file:
        process_url_list(args.file)
    else:
        print("Please specify either a URL (-u) or a file (-f).")

if __name__ == "__main__":
    main()

# CSP-Stalker

**CSP-Stalker** is a Python-based CLI tool designed for reconnaissance by leveraging Content-Security-Policy (CSP) headers to extract apex domains. The tool further queries the MerkleMap API to enumerate subdomains and resolve their respective IP addresses. It is particularly useful for penetration testers, security researchers, and OSINT enthusiasts.

About MerkleMap : MerkleMap offers a comprehensive solution for subdomain enumeration, certificate transparency monitoring, and infrastructure discovery. Uncover hidden assets, investigate suspicious domains, and gain valuable insights with ease.

---

## Features

- Extracts **apex domains** from CSP headers of target websites.
- Enumerates **all subdomains** for each apex domain using MerkleMap's paginated API.
- Resolves IP addresses for the discovered subdomains.
- Supports both single URL and batch processing (file input for multiple URLs).
- Saves results in a structured JSON format for further analysis.
- Logs subdomain extraction progress across API pagination.

---

## Getting Started

### Prerequisites

The tool requires **Python 3.6+** and the following Python libraries:
- `requests`
- `tldextract`
- `tabulate`
- `beautifulsoup4`

Install these dependencies using the included `requirements.txt` file.

---

### Installation and Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/0xakashk/CSP-Stalker.git
   cd CSP-Stalker
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
3. Run the tool:
   ```bash
   python cli_CSP_Stalker.py -u https://example.com
   
 - `To process a single URL:`
   
   ```bash
   python cli_CSP_Stalker.py -u https://example.com
 - `To process multiple URLs from a file:`
   
   ```bash
   python cli_CSP_Stalker.py -f urls.txt
4. View the output: Results are saved in the results directory as JSON files, with each domain's output saved as <domain>_results.json.

   

   

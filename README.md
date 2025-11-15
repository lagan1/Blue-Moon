# Blue-Moon

Blue Moon is an end-to-end recon automation toolkit designed for security researchers and bug bounty hunters.
It streamlines subdomain enumeration, URL harvesting, JS recon, vulnerability scanning, and takeover detection, all in one workflow.

🚀 Features
Phase 1 - Subdomain Enumeration
Step	Tool	Description
1	Subfinder	Recursive passive/active subdomain enumeration from domains.txt
2	Amass	Full active and passive enumeration
3	Merge	Consolidates Subfinder and Amass results into a unique list
4	AlterX + DNSX	Generates permutations, resolves them, outputs brute-subs.txt
5	PureDNS	Resolves brute subs to final-subs.txt
6	Merge	Combines initial and resolved subs into all-subs.txt
7	HTTPX	Probes common ports and generates alive_subs.txt
Phase 2 - URL Collection
Step	Tool	Description
1	GAU	Fetches historical URLs from archive sources
2	urlfinder	Extracts additional URLs from alive hosts
3	Katana	High-performance crawler with JS-awareness
4	Waymore	Fetches deep historical URLs from multiple archives
5	Merge	Deduplicates and produces urls.txt
6	JS Extract	Extracts JS file links into jsfiles.txt
7	HTTPX	Probes URLs to generate aliveEndpoints.txt
Phase 3 - Nuclei Scanning

Full Scan: Runs Nuclei on alive_subs.txt (fallback: aliveEndpoints.txt)
Excludes low and info templates for cleaner results.

DAST Scan: Performs fuzzing using Nuclei fuzz templates

Custom Templates: Runs user-supplied templates

JS Scan (Optional): Runs Nuclei on jsfiles.txt for JS exposures

Phase 4 - JavaScript Recon

SecretFinder: Extracts secrets from JS files

LinkFinder: Extracts endpoints and generates HTML reports

Phase 5 - Subdomain Takeover Detection

Runs Nuclei takeover templates on all discovered subdomains

⚙️ Configuration Options
Option	Description
domains_file	Path to domain list (default: domains.txt)
resolvers	DNS resolver list
resolvers_trusted	Trusted resolvers for PureDNS
nuclei_templates	Main Nuclei template directory
fuzz_templates	Fuzzing templates
custom_templates	User-provided templates
nuclei_list	Custom list for Nuclei scan targets
js_scan	Enable or disable JS scanning
secretfinder_path	Custom SecretFinder path
linkfinder_path	Custom LinkFinder path
🔥 Full Automation

You can run individual phases or execute the full pipeline using Run ALL.

📁 Output Structure
output/
 ├── subs/
 │   ├── all-subs.txt
 │   ├── alive_subs.txt
 │   └── final-subs.txt
 ├── urls/
 │   ├── urls.txt
 │   ├── aliveEndpoints.txt
 │   └── jsfiles.txt
 ├── reports/
 │   ├── nuclei/
 │   ├── secretfinder/
 │   └── linkfinder/
 └── logs/

🛠️ Requirements

Blue Moon integrates with the following tools:
Subfinder, Amass, AlterX, DNSX, PureDNS, HTTPX, GAU, Katana, urlfinder, Waymore, Nuclei, SecretFinder, LinkFinder.

Ensure all tools are installed and available in your PATH.

📦 Installation

Blue Moon includes automated setup scripts for installing all required dependencies on both Linux and Windows.

Linux Setup

Run the installation script:

chmod +x scripts/install_tools.sh
./scripts/install_tools.sh

This installs all required tools such as Subfinder, Amass, DNSX, PureDNS, HTTPX, GAU, Katana, Waymore, Nuclei, SecretFinder, LinkFinder, and others used throughout the pipeline.

Windows Setup

Run the PowerShell installation script:

Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install_tools.ps1

This installs all supported Windows versions of the required tools.

Manual Setup (Optional)

If you prefer to install tools manually, ensure that all dependencies are available in your system PATH.
🧪 Usage

Example:

python bluemoon.py menu

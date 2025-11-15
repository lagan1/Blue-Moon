# Blue-Moon

Blue Moon is an end-to-end recon automation toolkit designed for security researchers and bug bounty hunters.
It streamlines subdomain enumeration, URL harvesting, JS recon, vulnerability scanning, and takeover detection, all in one workflow.

![Preview](https://github.com/lagan1/Blue-Moon/blob/main/image.png)


## 🚀 Features

### Phase 1 - Subdomain Enumeration

| Step | Tool | Description |
|------|------|-------------|
| 1 | Subfinder | Recursive passive and active subdomain enumeration from `domains.txt` |
| 2 | Amass | Full active and passive subdomain enumeration |
| 3 | Merge | Combines Subfinder and Amass results into a unique list |
| 4 | AlterX + DNSX | Generates permutations and resolves them into `brute-subs.txt` |
| 5 | PureDNS | Resolves brute subs to create `final-subs.txt` |
| 6 | Merge | Combines initial results with resolved subs into `all-subs.txt` |
| 7 | HTTPX | Probes common ports to generate `alive_subs.txt` |

### Phase 2 - URL Collection

| Step | Tool | Description |
|------|------|-------------|
| 1 | GAU | Fetches historical URLs from archive sources |
| 2 | urlfinder | Extracts additional URLs from alive hosts |
| 3 | Katana | High-speed crawler with JS awareness |
| 4 | Waymore | Collects deeper archive and historical URLs |
| 5 | Merge | Deduplicates and merges URL lists into `urls.txt` |
| 6 | JS Extract | Extracts `.js` file links into `jsfiles.txt` |
| 7 | HTTPX | Probes URLs to identify alive endpoints in `aliveEndpoints.txt` |

### Phase 3 - Nuclei Scanning

| Step | Scan Type | Description |
|------|-----------|-------------|
| 1 | Full Scan | Runs Nuclei on `alive_subs.txt` or fallback `aliveEndpoints.txt` while excluding low and info templates |
| 2 | DAST Scan | Performs fuzzing using Nuclei fuzzing templates on `aliveEndpoints.txt` |
| 3 | Custom Templates | Runs user-provided Nuclei templates on `alive_subs.txt` |
| 4 | JS Scan (Optional) | Uses Nuclei templates to scan `jsfiles.txt` for exposures |

### Phase 4 - JavaScript Recon

| Step | Tool | Description |
|------|------|-------------|
| 1 | SecretFinder | Extracts secrets from each JS file in `jsfiles.txt` |
| 2 | LinkFinder | Extracts JS endpoints and creates HTML report |

### Phase 5 - Subdomain Takeover Detection

| Step | Tool | Description |
|------|------|-------------|
| 1 | Nuclei | Scans all discovered subdomains using takeover templates |

### Configuration Options

| Option | Description |
|--------|-------------|
| `domains_file` | Path to the domain list file (default: `domains.txt`) |
| `resolvers` | Path to the DNS resolvers file used for resolution |
| `resolvers_trusted` | Path to trusted resolvers file for PureDNS |
| `nuclei_templates` | Directory for Nuclei main templates |
| `fuzz_templates` | Directory for Nuclei fuzzing templates |
| `custom_templates` | Directory for user-supplied custom templates |
| `nuclei_list` | Custom Nuclei input list for scanning |
| `js_scan` | Enable or disable JS scanning for Phase 3 and 4 (True or False) |
| `secretfinder_path` | Path to the SecretFinder executable or script |
| `linkfinder_path` | Path to the LinkFinder script (Python or standalone) |


### 🔥 Full Automation
You can run individual phases or execute the full pipeline using Run ALL.

### 📁 Output Structure
 ```  output/
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
``` 

### 🛠️ Requirements

- Blue Moon integrates with the following tools:
Subfinder, Amass, AlterX, DNSX, PureDNS, HTTPX, GAU, Katana, urlfinder, Waymore, Nuclei, SecretFinder, LinkFinder.

- Ensure all tools are installed and available in your PATH.

### 📦 Installation

- Blue Moon includes automated setup scripts for installing all required dependencies on both Linux and Windows.

#### Linux Setup

- Run the installation script:

```
 chmod +x scripts/install_tools.sh
./scripts/install_tools.sh
```

This installs all required tools such as Subfinder, Amass, DNSX, PureDNS, HTTPX, GAU, Katana, Waymore, Nuclei, SecretFinder, LinkFinder, and others used throughout the pipeline.

#### Windows Setup

Run the PowerShell installation script:

```
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install_tools.ps1
```

This installs all supported Windows versions of the required tools.

#### Manual Setup (Optional)

- If you prefer to install tools manually, ensure that all dependencies are available in your system PATH.


### 🧪Example/Usage:

``` python3 bluemoon.py menu ```

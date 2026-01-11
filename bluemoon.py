#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def print_err(message: str) -> None:
    sys.stderr.write(f"[!] {message}\n")


def print_ok(message: str) -> None:
    sys.stdout.write(f"[+] {message}\n")


def ensure_file_exists(path: Path, description: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{description} not found: {path}")


def is_tool_available(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_command(
    args: List[str],
    *,
    cwd: Optional[Path] = None,
    stdin: Optional[object] = None,
    stdout: Optional[object] = None,
    env: Optional[dict] = None,
    silent: bool = False,
) -> int:
    if silent and stdout is None:
        stdout = subprocess.DEVNULL
    stderr = subprocess.DEVNULL if silent else subprocess.STDOUT
    process = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        text=True,
        check=False,
    )
    return process.returncode


def merge_unique_files(input_files: List[Path], output_file: Path) -> None:
    seen = set()
    for file_path in input_files:
        if not file_path.exists():
            continue
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                seen.add(line)
    unique_sorted = sorted(seen)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as out:
        for item in unique_sorted:
            out.write(item + "\n")


def filter_js_urls(input_file: Path, output_file: Path) -> None:
    pattern = re.compile(r"\.js(\?|$)")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with input_file.open("r", encoding="utf-8", errors="ignore") as src, output_file.open(
        "w", encoding="utf-8"
    ) as dst:
        for line in src:
            url = line.strip()
            if not url:
                continue
            if pattern.search(url):
                dst.write(url + "\n")


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def phase_subdomains(
    domains_file: Path,
    resolvers_file: Optional[Path],
    resolvers_trusted_file: Optional[Path],
) -> None:
    ensure_file_exists(domains_file, "Domains file")

    # 1) subfinder
    subfinder_out = Path("subfinder.txt")
    if not is_tool_available("subfinder"):
        print_err("subfinder not found in PATH. Skipping subfinder step.")
    else:
        print_ok("Running subfinder ...")
        rc = run_command([
            "subfinder",
            "-all",
            "-recursive",
            "-dL",
            str(domains_file),
            "-o",
            str(subfinder_out),
        ], silent=True)
        if rc != 0:
            print_err("subfinder failed")
        else:
            print_ok(f"subfinder done. Found ~{count_nonempty_lines(subfinder_out)} subdomains")

    # 2) amass
    amass_out = Path("subs-amass.txt")
    if not is_tool_available("amass"):
        print_err("amass not found in PATH. Skipping amass step.")
    else:
        print_ok("Running amass enum ...")
        # Prefer using -df and -o to avoid shell pipes
        rc = run_command([
            "amass",
            "enum",
            "-active",
            "-passive",
            "-df",
            str(domains_file),
            "-o",
            str(amass_out),
        ], silent=True)
        if rc != 0:
            print_err("amass failed")
        else:
            print_ok(f"amass done. Found ~{count_nonempty_lines(amass_out)} subdomains")

    # 3) merge subfinder + amass -> subs.txt
    subs_txt = Path("subs.txt")
    print_ok("Merging subdomains -> subs.txt ...")
    merge_unique_files([subfinder_out, amass_out], subs_txt)

    # 4) permutations: subs.txt | alterx | dnsx -t -> brute-subs.txt
    brute_out = Path("brute-subs.txt")
    if not is_tool_available("alterx") or not is_tool_available("dnsx"):
        print_err("alterx or dnsx not found. Skipping permutation step.")
    else:
        print_ok("Generating permutations with alterx | dnsx ...")
        with subs_txt.open("r", encoding="utf-8", errors="ignore") as fin, brute_out.open(
            "w", encoding="utf-8"
        ) as fout:
            p1 = subprocess.Popen(["alterx"], stdin=fin, stdout=subprocess.PIPE, text=True)
            p2 = subprocess.Popen(["dnsx", "-t", "1000"], stdin=p1.stdout, stdout=fout, text=True)
            p1.stdout.close()  # allow p1 to receive a SIGPIPE if p2 exits.
            p2.wait()
            p1.wait()
        print_ok(f"Permutations done. Generated ~{count_nonempty_lines(brute_out)} candidates")

    # 5) resolve permutations with puredns -> final-subs.txt
    final_subs = Path("final-subs.txt")
    if not is_tool_available("puredns"):
        print_err("puredns not found. Skipping resolution step.")
    else:
        print_ok("Resolving with puredns ...")
        # Prefer brute-subs.txt; if missing, fall back to subs.txt to avoid failure
        resolve_input = brute_out if brute_out.exists() else subs_txt
        if not brute_out.exists():
            print_err(f"{brute_out} not found. Falling back to {resolve_input} for resolution.")
        cmd = [
            "puredns",
            "resolve",
            str(resolve_input),
            "--threads",
            "250",
        ]
        # Always include resolvers flags if provided, without requiring pre-checks
        if resolvers_file:
            cmd.extend(["--resolvers", str(resolvers_file)])
        if resolvers_trusted_file:
            cmd.extend(["--resolvers-trusted", str(resolvers_trusted_file)])
        cmd.extend(["--rate-limit", "1000"])  # default
        with final_subs.open("w", encoding="utf-8") as fout:
            rc = run_command(cmd, stdout=fout, silent=True)
        if rc != 0:
            print_err("puredns resolve failed")
        else:
            print_ok(f"Resolution done. Valid ~{count_nonempty_lines(final_subs)} subdomains")

    # 6) merge subs + final-subs -> all-subs.txt
    all_subs = Path("all-subs.txt")
    print_ok("Merging all subdomains -> all-subs.txt ...")
    merge_unique_files([subs_txt, final_subs], all_subs)

    # 7) httpx for alive subs -> alive_subs.txt
    alive_subs = Path("alive_subs.txt")
    if not is_tool_available("httpx"):
        print_err("httpx not found. Skipping alive subdomains step.")
    else:
        print_ok("Probing with httpx ...")
        cmd = [
            "httpx",
            "-l",
            str(all_subs),
            "-ports",
            "80,443,8080,8000,8888",
            "-H",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "-random-agent",
            "-rate-limit",
            "50",
            "-retries",
            "2",
            "-timeout",
            "10",
            "-silent",
        ]
        with alive_subs.open("w", encoding="utf-8") as fout:
            rc = run_command(cmd, stdout=fout, silent=True)
        if rc != 0:
            print_err("httpx probing failed")
        else:
            print_ok(f"httpx done. Alive ~{count_nonempty_lines(alive_subs)} hosts")


def phase_urls(domains_file: Path) -> None:
    alive_subs = Path("alive_subs.txt")
    ensure_file_exists(alive_subs, "alive_subs.txt")

    # 1) gau
    gau_out = Path("gau.txt")
    if not is_tool_available("gau"):
        print_err("gau not found. Skipping gau step.")
    else:
        print_ok("Collecting URLs with gau ...")
        with alive_subs.open("r", encoding="utf-8", errors="ignore") as fin, gau_out.open(
            "w", encoding="utf-8"
        ) as fout:
            rc = run_command(["gau"], stdin=fin, stdout=fout, silent=True)
        if rc != 0:
            print_err("gau failed")
        else:
            print_ok(f"gau done. ~{count_nonempty_lines(gau_out)} URLs")

    # 2) urlfinder
    urlfinder_out = Path("urlfinder.txt")
    if not is_tool_available("urlfinder"):
        print_err("urlfinder not found. Skipping urlfinder step.")
    else:
        print_ok("Collecting URLs with urlfinder ...")
        with urlfinder_out.open("w", encoding="utf-8") as fout:
            rc = run_command([
                "urlfinder",
                "-all",
                "-d",
                str(alive_subs),  # path to file
            ], stdout=fout, silent=True)
        if rc != 0:
            print_err("urlfinder failed")
        else:
            print_ok(f"urlfinder done. ~{count_nonempty_lines(urlfinder_out)} URLs")

    # 3) katana
    katana_out = Path("katana.txt")
    if not is_tool_available("katana"):
        print_err("katana not found. Skipping katana step.")
    else:
        print_ok("Crawling with katana ...")
        # Use -list for file input; exclude extensions; jsonl disabled; depth 4
        with katana_out.open("a", encoding="utf-8") as fout:
            rc = run_command([
                "katana",
                "-u",
                str(alive_subs),
                "-d",
                "4",
                "-jc",
                "-ef",
                "css,png,svg,ico,woff,gif",
            ], stdout=fout, silent=True)
        if rc != 0:
            print_err("katana failed")
        else:
            print_ok(f"katana done. Appended results → katana.txt")

    # 4) waymore per domain
    waymore_out = Path("waymore_all.txt")
    if not is_tool_available("waymore"):
        print_err("waymore not found. Skipping waymore step.")
    else:
        print_ok("Collecting URLs with waymore ...")
        with waymore_out.open("w", encoding="utf-8") as fout:
            with domains_file.open("r", encoding="utf-8", errors="ignore") as dfin:
                for domain in dfin:
                    domain = domain.strip()
                    if not domain:
                        continue
                    rc = run_command(["waymore", "-i", domain, "-mode", "U"], stdout=fout, silent=True)
                    if rc != 0:
                        print_err(f"waymore failed for domain: {domain}")

    # 5) merge all -> pipe to uro -> urls.txt
    urls_txt = Path("urls.txt")
    merged_tmp = Path(".merged_urls.tmp")
    print_ok("Merging and normalizing URLs with uro -> urls.txt ...")
    merge_unique_files([gau_out, urlfinder_out, katana_out, waymore_out], merged_tmp)
    if not is_tool_available("uro"):
        # Fallback: if uro not available, just move merged_tmp to urls.txt
        print_err("uro not found. Writing merged URLs without uro normalization.")
        merged_tmp.replace(urls_txt)
    else:
        with merged_tmp.open("r", encoding="utf-8", errors="ignore") as fin, urls_txt.open(
            "w", encoding="utf-8"
        ) as fout:
            rc = run_command(["uro"], stdin=fin, stdout=fout, silent=True)
        if rc != 0:
            print_err("uro failed; writing unprocessed merged URLs.")
            merged_tmp.replace(urls_txt)
        if merged_tmp.exists():
            try:
                merged_tmp.unlink()
            except Exception:
                pass
    print_ok(f"URLs merged. ~{count_nonempty_lines(urls_txt)} unique URLs")

    # 6) separate js files -> jsfiles.txt
    js_files = Path("jsfiles.txt")
    print_ok("Extracting JS file URLs -> jsfiles.txt ...")
    filter_js_urls(urls_txt, js_files)

    # 7) httpx for alive URLs -> aliveEndpoints.txt
    alive_endpoints = Path("aliveEndpoints.txt")
    if not is_tool_available("httpx"):
        print_err("httpx not found. Skipping alive endpoints step.")
    else:
        print_ok("Probing URLs with httpx ...")
        rc = run_command([
            "httpx",
            "-l",
            str(urls_txt),
            "-threads",
            "250",
            "-mc",
            "200,302,403,405",
            "-o",
            str(alive_endpoints),
        ], silent=True)
        if rc != 0:
            print_err("httpx URL probing failed")
        else:
            print_ok(f"Alive endpoints: ~{count_nonempty_lines(alive_endpoints)}")


def phase_nuclei(
    nuclei_templates_dir: Optional[Path],
    fuzz_templates_dir: Optional[Path],
    custom_templates_dir: Optional[Path],
    nuclei_list_path: Optional[Path],
    run_js_scan: bool,
) -> None:
    if not is_tool_available("nuclei"):
        print_err("nuclei not found. Skipping nuclei phase.")
        return

    # Determine list file to scan
    list_file = nuclei_list_path or Path("alive_subs.txt")
    if not list_file.exists():
        # fallback to aliveEndpoints
        alt = Path("aliveEndpoints.txt")
        if alt.exists():
            list_file = alt
        else:
            print_err(f"Neither {list_file} nor {alt} found. Skipping nuclei scans.")
            return

    # 1) Full nuclei scan
    if nuclei_templates_dir and nuclei_templates_dir.exists():
        print_ok("Running nuclei full scan ...")
        rc = run_command([
            "nuclei",
            "-t",
            str(nuclei_templates_dir),
            "-es",
            "info,low",
            "-l",
            str(list_file),
            "-o",
            "nuclei.out",
        ])
        if rc != 0:
            print_err("nuclei full scan failed")
    else:
        print_err("nuclei templates directory not provided or not found. Skipping full scan.")

    # 2) Parameterized scanning (DAST)
    target_list = Path("aliveEndpoints.txt") if Path("aliveEndpoints.txt").exists() else list_file
    if fuzz_templates_dir and fuzz_templates_dir.exists():
        print_ok("Running nuclei DAST scan (fuzzing templates) ...")
        rc = run_command([
            "nuclei",
            "-l",
            str(target_list),
            "-dast",
            "-t",
            str(fuzz_templates_dir),
            "-o",
            "fuzzing.out",
        ])
        if rc != 0:
            print_err("nuclei DAST scan failed")
    else:
        # Try an alternative path if provided directory missing
        alt_path = Path("/root/nuclei-templates/http/vulnerabilties/dast")
        if alt_path.exists():
            print_ok("Running nuclei DAST scan (alternative templates path) ...")
            rc = run_command([
                "nuclei",
                "-l",
                str(target_list),
                "-dast",
                "-t",
                str(alt_path),
                "-o",
                "fuzzing.out",
            ])
            if rc != 0:
                print_err("nuclei DAST scan failed (alternative path)")
        else:
            print_err("No DAST templates directory provided/found. Skipping parameterized scan.")

    # 3) Custom templates scanning
    if custom_templates_dir and custom_templates_dir.exists():
        print_ok("Running nuclei custom templates scan ...")
        rc = run_command([
            "nuclei",
            "-l",
            str(Path("alive_subs.txt") if Path("alive_subs.txt").exists() else list_file),
            "-t",
            str(custom_templates_dir),
            "-o",
            "custom.out",
        ])
        if rc != 0:
            print_err("nuclei custom templates scan failed")
    else:
        print_err("Custom templates directory not provided or not found. Skipping custom scan.")

    # 4) JS scan (optional, not recommended)
    if run_js_scan:
        if Path("jsfiles.txt").exists():
            js_templates = Path("/root/nuclei-templates/http/exposure")
            if js_templates.exists():
                print_ok("Running nuclei JS exposure scan ...")
                rc = run_command([
                    "nuclei",
                    "-l",
                    "jsfiles.txt",
                    "-t",
                    str(js_templates),
                ])
                if rc != 0:
                    print_err("nuclei JS exposure scan failed")
            else:
                print_err("JS exposure templates path not found. Skipping JS nuclei scan.")
        else:
            print_err("jsfiles.txt not found. Skipping JS nuclei scan.")


def phase_js_recon(secretfinder_path: Optional[Path], linkfinder_path: Optional[Path]) -> None:
    js_files = Path("jsfiles.txt")
    ensure_file_exists(js_files, "jsfiles.txt")

    # 1) SecretFinder scraping
    if secretfinder_path and secretfinder_path.exists():
        print_ok("Extracting secrets with SecretFinder ...")
        with js_files.open("r", encoding="utf-8", errors="ignore") as fin, open(
            "secret.txt", "w", encoding="utf-8"
        ) as fout:
            for url in fin:
                url = url.strip()
                if not url:
                    continue
                rc = run_command([
                    sys.executable,
                    str(secretfinder_path),
                    "-i",
                    url,
                    "-o",
                    "cli",
                ], stdout=fout, silent=True)
                if rc != 0:
                    print_err(f"SecretFinder failed for: {url}")
        print_ok(f"SecretFinder complete. Wrote to secret.txt")
    else:
        print_err("SecretFinder path not provided or not found. Skipping secrets extraction.")

    # 2) LinkFinder endpoints to HTML
    html_out = Path("srf_endpoints.html")
    print_ok("Generating endpoints HTML with LinkFinder ...")
    with html_out.open("w", encoding="utf-8") as html:
        html.write("<html><body><pre>\n")
        with js_files.open("r", encoding="utf-8", errors="ignore") as fin:
            for url in fin:
                url = url.strip()
                if not url:
                    continue
                html.write(f"[*] {url}\n")
                if linkfinder_path and linkfinder_path.exists():
                    # LinkFinder outputs CLI text
                    proc = subprocess.run(
                        [sys.executable, str(linkfinder_path), "-i", url, "-o", "cli"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                        check=False,
                    )
                    html.write(proc.stdout)
                else:
                    html.write("(LinkFinder not configured)\n")
                html.write("\n\n")
        html.write("</pre></body></html>\n")
    print_ok("LinkFinder report generated: srf_endpoints.html")


def phase_takeover(takeover_templates: Optional[Path] = None) -> None:
    # Defaults to provided path; fallback to /root/nuclei-templates/http/takeovers
    if not is_tool_available("nuclei"):
        print_err("nuclei not found. Skipping takeover scan.")
        return
    alive_subs = Path("alive_subs.txt")
    ensure_file_exists(alive_subs, "alive_subs.txt")
    templates = takeover_templates or Path("/root/nuclei-templates/http/takeovers")
    if not templates.exists():
        print_err(f"Takeover templates directory not found: {templates}")
        return
    print_ok("Scanning for subdomain takeovers with nuclei ...")
    rc = run_command([
        "nuclei",
        "-l",
        str(alive_subs),
        "-t",
        str(templates),
        "-o",
        "takeovers.out",
    ])
    if rc != 0:
        print_err("nuclei takeover scan failed")
    else:
        print_ok("Takeover scan complete. Results: takeovers.out")


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bug bounty multi-tool CLI: subdomains -> urls -> nuclei -> js-recon",
    )
    parser.add_argument(
        "phase",
        choices=["subdomains", "urls", "nuclei", "jsrecon", "takeover", "all", "menu"],
        nargs="?",
        default="all",
        help="Which phase to run",
    )
    parser.add_argument("--domains-file", default=None, help="Path to domains.txt")

    # Config
    parser.add_argument("--config", default=None, help="Path to config.json (optional)")
    parser.add_argument(
        "--write-config",
        default=None,
        help="Write current options to config.json (path). Exits after writing.",
    )

    # Subdomains options
    parser.add_argument("--resolvers", default=None, help="Path to resolvers.txt for puredns")
    parser.add_argument(
        "--resolvers-trusted", default=None, help="Path to resolvers-trusted.txt for puredns"
    )

    # Nuclei options
    parser.add_argument(
        "--nuclei-templates",
        default=None,
        help="Path to nuclei templates directory (for full scan)",
    )
    parser.add_argument(
        "--fuzz-templates",
        default=None,
        help="Path to fuzzing/DAST templates directory",
    )
    parser.add_argument(
        "--custom-templates", default=None, help="Path to custom nuclei templates directory"
    )
    parser.add_argument(
        "--nuclei-list", default=None, help="Path to list file for nuclei scans (default auto)"
    )
    parser.add_argument(
        "--js-scan", action="store_true", help="Also run optional nuclei JS exposure scan"
    )

    # JS Recon options
    parser.add_argument(
        "--secretfinder-path",
        default=None,
        help="Path to SecretFinder.py (e.g., /home/user/SecretFinder/SecretFinder.py)",
    )
    parser.add_argument(
        "--linkfinder-path",
        default=None,
        help="Path to linkfinder.py (e.g., /path/to/LinkFinder/linkfinder.py)",
    )

    return parser.parse_args(argv)


def _prompt_text(default_value: str, prompt_label: str) -> str:
    shown_default = default_value or ""
    value = input(f"{prompt_label} [{shown_default}]: ").strip()
    if value.lower() == "none":
        return ""
    return value or shown_default


def _prompt_bool(default_value: bool, prompt_label: str) -> bool:
    default_str = "Y" if default_value else "n"
    value = input(f"{prompt_label} (Y/n) [{default_str}]: ").strip().lower()
    if value in ("y", "yes"):  # explicit yes
        return True
    if value in ("n", "no"):  # explicit no
        return False
    return default_value


def _load_config_from(path: Path) -> Dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print_err(f"Failed to load config from {path}: {e}")
        return {}


def _save_config_to(config: Dict, path: Path) -> None:
    try:
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        print_ok(f"Saved config to {path}")
    except Exception as e:
        print_err(f"Failed to save config to {path}: {e}")


def interactive_menu(initial_config: Dict) -> Tuple[Dict[str, bool], Dict]:
    # Start from initial_config, mutable copy
    cfg = dict(initial_config) if initial_config else {}

    def show_menu() -> None:
        print("\n" * 2)
        art = """
        ################################################################################
        ██████╗ ██╗     ██╗   ██╗███████╗    ███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗
        ██╔══██╗██║     ██║   ██║██╔════╝    ████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║
        ██████╔╝██║     ██║   ██║█████╗      ██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║
        ██╔══██╗██║     ██║   ██║██╔══╝      ██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║
        ██████╔╝███████╗╚██████╔╝███████╗    ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║
        m################################################################################

"""
        footer = f"""
Author      : Lagan Parihar             Blue Moon v1.0.0 (\033[92mupdated\033[0m)
Instagram   : @laganx.__                Status      : \033[93mWorking\033[0m
LinkedIn    : @laganparihar             GitHub      : @lagan1
                                        
"""
        print("\033[94m" + art + "\033[0m")
        print(footer)
        print("\n" + "-" * 100 + "\n")
        print("\033[96mChoose Feature:\033[0m\n")
        print("")
        print(f"\033[96m[0]     Feature Information\033[0m")
        print(f"\033[92m[1]     Phase 1: Subdomain Enumeration\033[0m")  # Green
        print(f"\033[93m[2]     Phase 2: URL Collection\033[0m")         # Yellow
        print(f"\033[95m[3]     Phase 3: Nuclei Scanning\033[0m")        # Magenta
        print(f"\033[94m[4]     Phase 4: JS Recon\033[0m")               # Blue
        print(f"\033[91m[5]     Phase 5: Subdomain Takeover\033[0m")     # Red
        print(f"\033[96m[6]     Configure Options\033[0m")               # Cyan
        print(f"\033[92m[7]     Run ALL Phases\033[0m")                   # Green
        print(f"\033[96m[8]     Load config.json\033[0m")                 # Cyan
        print(f"\033[96m[9]     Save config.json\033[0m")                 # Cyan
        print(f"\033[91m[999]   Quit\033[0m")                                   # Red
        print("-" * 80 + "\n" * 2)


    def configure_options() -> None:
        print("")
        print("--- Configure Options ---")
        cfg["domains_file"] = _prompt_text(cfg.get("domains_file", "domains.txt"), "Domains file path")
        cfg["resolvers"] = _prompt_text(cfg.get("resolvers", ""), "Resolvers file for puredns (or 'none')")
        cfg["resolvers_trusted"] = _prompt_text(
            cfg.get("resolvers_trusted", ""), "Trusted resolvers file for puredns (or 'none')"
        )
        cfg["nuclei_templates"] = _prompt_text(
            cfg.get("nuclei_templates", ""), "Nuclei templates directory (full scan) (or 'none')"
        )
        cfg["fuzz_templates"] = _prompt_text(
            cfg.get("fuzz_templates", ""), "DAST/Fuzz templates directory (or 'none')"
        )
        cfg["custom_templates"] = _prompt_text(
            cfg.get("custom_templates", ""), "Custom nuclei templates directory (or 'none')"
        )
        cfg["nuclei_list"] = _prompt_text(
            cfg.get("nuclei_list", ""), "Override list file for nuclei (or 'none')"
        )
        cfg["js_scan"] = _prompt_bool(bool(cfg.get("js_scan", False)), "Enable optional JS exposure scan")
        cfg["secretfinder_path"] = _prompt_text(
            cfg.get("secretfinder_path", ""), "Path to SecretFinder.py (or 'none')"
        )
        cfg["linkfinder_path"] = _prompt_text(
            cfg.get("linkfinder_path", ""), "Path to linkfinder.py (or 'none')"
        )

    def feature_info() -> None:
        print("")
        print(f"\033[96m[1] === Blue Moon — Feature Information === \033[0m")
        print("")
        print(f"\033[92m[2] Phase 1 -- Subdomain Enumeration\033[0m")
        print("  1) subfinder: Enumerates all subdomains recursively from domains.txt")
        print("  2) amass:    Active + passive subdomain enumeration from domains.txt")
        print("  3) merge:    Combines results from Subfinder + Amass into a unique, sorted list.")
        print("  4) perms:    Generates permutations with AlterX, resolves with DNSX, outputs brute-subs.txt.")
        print("  5) resolve:  Resolves brute-subs.txt with PureDNS to get final-subs.txt")
        print("  6) merge:    Merges initial subs with final resolved ones → all-subs.txt.")
        print("  7) probe:    Uses HTTPX on all-subs.txt (common ports) to get alive_subs.txt.")
        print("")
        print(f"\033[93m[3]  Phase 2 -- URL Collection\033[0m")
        print("  1) gau:        Fetches historical URLs from alive_subs.txt")
        print("  2) urlfinder:  Finds additional URLs from alive_subs.txt.")
        print("  3) katana:     Crawls alive subdomains for URLs and assets (excludes static files).")
        print("  4) waymore:    Collects URLs from archives and sources for each domain.")
        print("  5) merge:      Combines all URL lists and filters unique → urls.txt.")
        print("  6) js split:   Extracts all .js links from urls.txt → jsfiles.txt.")
        print("  7) probe:      HTTPX checks urls.txt for alive endpoints → aliveEndpoints.txt.")
        print("")
        print(f"\033[95m[4] Phase 3 -- Nuclei Scanning\033[0m")
        print("  1) Full scan:       Nuclei scan on alive_subs.txt (or fallback to aliveEndpoints.txt), excluding info/low severity.")
        print("     - default list: alive_subs.txt, fallback: aliveEndpoints.txt")
        print("  2) DAST scan:       Nuclei fuzzing on aliveEndpoints.txt.")
        print("  3) Custom templates: Runs user-provided Nuclei templates on alive_subs.txt")
        print("  4) Optional JS scan: Scans jsfiles.txt for exposures using Nuclei templates")
        print("")
        print(f"\033[94m[5] Phase 4 -- JS Recon\033[0m")
        print("  1) SecretFinder: Extracts secrets from each .js in jsfiles.txt")
        print("  2) LinkFinder:   Finds endpoints from .js files and outputs HTML report.")
        print("")
        print(f"\033[91m[6] Phase 5 -- Subdomain Takeover\033[0m")
        print("  1) Uses Nuclei Templates to scan for takeovers ")
        print("")
        print("Current Options (from config/CLI):")
        print(f"  domains_file       : {cfg.get('domains_file', 'domains.txt')}")
        print(f"  resolvers          : {cfg.get('resolvers', '')}")
        print(f"  resolvers_trusted  : {cfg.get('resolvers_trusted', '')}")
        print(f"  nuclei_templates   : {cfg.get('nuclei_templates', '')}")
        print(f"  fuzz_templates     : {cfg.get('fuzz_templates', '')}")
        print(f"  custom_templates   : {cfg.get('custom_templates', '')}")
        print(f"  nuclei_list        : {cfg.get('nuclei_list', '')}")
        print(f"  js_scan            : {bool(cfg.get('js_scan', False))}")
        print(f"  secretfinder_path  : {cfg.get('secretfinder_path', '')}")
        print(f"  linkfinder_path    : {cfg.get('linkfinder_path', '')}")
        print("")
        print("Tip: Use [6] Configure Options to change any of the above, then choose a phase or [7] Run ALL.")

    while True:
        show_menu()
        choice = input("Select an option [0-9 or 999]: ").strip()
        if choice == "0":
            feature_info()
            print_ok("Closing Blue Moon. Goodbye.")
            sys.exit(0)
        elif choice == "1":
            return {"subdomains": True}, cfg
        elif choice == "2":
            return {"urls": True}, cfg
        elif choice == "3":
            return {"nuclei": True}, cfg
        elif choice == "4":
            return {"jsrecon": True}, cfg
        elif choice == "5":
            return {"takeover": True}, cfg
        elif choice == "6":
            configure_options()
        elif choice == "7":
            return {
                "subdomains": True,
                "urls": True,
                "nuclei": True,
                "jsrecon": True,
                "takeover": True,
            }, cfg
        elif choice == "8":
            path_str = _prompt_text("config.json", "Path to config.json to load")
            loaded = _load_config_from(Path(path_str))
            if loaded:
                cfg.update(loaded)
        elif choice == "9":
            out_path_str = _prompt_text("config.json", "Path to write config.json")
            _save_config_to(cfg, Path(out_path_str))
        elif choice == "999":
            print_ok("Exiting.")
            sys.exit(0)
        else:
            print_err("Invalid choice. Please select 0-9 or 999.")


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)

    # Load config if present
    config_path = Path(args.config) if args.config else Path("config.json")
    config: dict = {}
    if config_path.exists() and (not args.write_config):
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            print_ok(f"Loaded config: {config_path}")
        except Exception as e:
            print_err(f"Failed to read config {config_path}: {e}")

    def coalesce(*values):
        for v in values:
            if v is not None and v != "":
                return v
        return None

    # Defaults based on requested paths
    DEFAULTS = {
        "domains_file": "domains.txt",
        "resolvers": "/home/lagan/resolvers/resolvers.txt",
        "resolvers_trusted": "/home/lagan/resolvers/resolvers-trusted.txt",
        "nuclei_templates": "/root/nuclei-templates",
        "fuzz_templates": "/home/lagan/fuzzing-templates",
        "custom_templates": "/home/lagan/coffintemps/nuclei-templates/my",
        "nuclei_list": "",
        "js_scan": False,
        "secretfinder_path": "/home/lagan/SecretFinder/SecretFinder.py",
        "linkfinder_path": "/home/lagan/LinkFinder/linkfinder.py",
    }

    # Resolve effective options with precedence: CLI > config > default
    domains_file = Path(
        coalesce(args.domains_file, config.get("domains_file"), DEFAULTS["domains_file"]) or "domains.txt"
    )
    resolvers_file = Path(coalesce(args.resolvers, config.get("resolvers"), DEFAULTS["resolvers"])) if coalesce(args.resolvers, config.get("resolvers"), DEFAULTS["resolvers"]) else None
    resolvers_trusted_file = Path(coalesce(args.resolvers_trusted, config.get("resolvers_trusted"), DEFAULTS["resolvers_trusted"])) if coalesce(args.resolvers_trusted, config.get("resolvers_trusted"), DEFAULTS["resolvers_trusted"]) else None

    nuclei_templates_dir = Path(coalesce(args.nuclei_templates, config.get("nuclei_templates"), DEFAULTS["nuclei_templates"])) if coalesce(args.nuclei_templates, config.get("nuclei_templates"), DEFAULTS["nuclei_templates"]) else None
    fuzz_templates_dir = Path(coalesce(args.fuzz_templates, config.get("fuzz_templates"), DEFAULTS["fuzz_templates"])) if coalesce(args.fuzz_templates, config.get("fuzz_templates"), DEFAULTS["fuzz_templates"]) else None
    custom_templates_dir = Path(coalesce(args.custom_templates, config.get("custom_templates"), DEFAULTS["custom_templates"])) if coalesce(args.custom_templates, config.get("custom_templates"), DEFAULTS["custom_templates"]) else None
    nuclei_list_path = Path(coalesce(args.nuclei_list, config.get("nuclei_list"), DEFAULTS["nuclei_list"])) if coalesce(args.nuclei_list, config.get("nuclei_list"), DEFAULTS["nuclei_list"]) else None

    js_scan = bool(coalesce(args.js_scan, config.get("js_scan"), DEFAULTS["js_scan"]))

    secretfinder_path = Path(coalesce(args.secretfinder_path, config.get("secretfinder_path"), DEFAULTS["secretfinder_path"])) if coalesce(args.secretfinder_path, config.get("secretfinder_path"), DEFAULTS["secretfinder_path"]) else None
    linkfinder_path = Path(coalesce(args.linkfinder_path, config.get("linkfinder_path"), DEFAULTS["linkfinder_path"])) if coalesce(args.linkfinder_path, config.get("linkfinder_path"), DEFAULTS["linkfinder_path"]) else None

    # Handle write-config request
    if args.write_config:
        out_path = Path(args.write_config)
        cfg = {
            "domains_file": str(domains_file) if domains_file else DEFAULTS["domains_file"],
            "resolvers": str(resolvers_file) if resolvers_file else DEFAULTS["resolvers"],
            "resolvers_trusted": str(resolvers_trusted_file) if resolvers_trusted_file else DEFAULTS["resolvers_trusted"],
            "nuclei_templates": str(nuclei_templates_dir) if nuclei_templates_dir else DEFAULTS["nuclei_templates"],
            "fuzz_templates": str(fuzz_templates_dir) if fuzz_templates_dir else DEFAULTS["fuzz_templates"],
            "custom_templates": str(custom_templates_dir) if custom_templates_dir else DEFAULTS["custom_templates"],
            "nuclei_list": str(nuclei_list_path) if nuclei_list_path else DEFAULTS["nuclei_list"],
            "js_scan": js_scan,
            "secretfinder_path": str(secretfinder_path) if secretfinder_path else DEFAULTS["secretfinder_path"],
            "linkfinder_path": str(linkfinder_path) if linkfinder_path else DEFAULTS["linkfinder_path"],
        }
        out_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        print_ok(f"Wrote config to {out_path}")
        return 0

    try:
        if args.phase == "menu":
            selected, cfg = interactive_menu(config)
            # Merge menu cfg into runtime values
            domains_file = Path(cfg.get("domains_file") or "domains.txt")
            resolvers_file = Path(cfg["resolvers"]) if cfg.get("resolvers") else None
            resolvers_trusted_file = Path(cfg["resolvers_trusted"]) if cfg.get("resolvers_trusted") else None
            nuclei_templates_dir = Path(cfg["nuclei_templates"]) if cfg.get("nuclei_templates") else None
            fuzz_templates_dir = Path(cfg["fuzz_templates"]) if cfg.get("fuzz_templates") else None
            custom_templates_dir = Path(cfg["custom_templates"]) if cfg.get("custom_templates") else None
            nuclei_list_path = Path(cfg["nuclei_list"]) if cfg.get("nuclei_list") else None
            js_scan = bool(cfg.get("js_scan", False))
            secretfinder_path = Path(cfg["secretfinder_path"]) if cfg.get("secretfinder_path") else None
            linkfinder_path = Path(cfg["linkfinder_path"]) if cfg.get("linkfinder_path") else None
            if selected.get("subdomains"):
                phase_subdomains(domains_file, resolvers_file, resolvers_trusted_file)
            if selected.get("urls"):
                phase_urls(domains_file)
            if selected.get("nuclei"):
                phase_nuclei(
                    nuclei_templates_dir,
                    fuzz_templates_dir,
                    custom_templates_dir,
                    nuclei_list_path,
                    js_scan,
                )
            if selected.get("jsrecon"):
                phase_js_recon(secretfinder_path, linkfinder_path)
            if selected.get("takeover"):
                phase_takeover(Path("/root/nuclei-templates/http/takeovers"))
            print_ok("Done.")
            return 0

        if args.phase in ("subdomains", "all"):
            phase_subdomains(domains_file, resolvers_file, resolvers_trusted_file)

        if args.phase in ("urls", "all"):
            phase_urls(domains_file)

        if args.phase in ("nuclei", "all"):
            phase_nuclei(
                nuclei_templates_dir,
                fuzz_templates_dir,
                custom_templates_dir,
                nuclei_list_path,
                js_scan,
            )

        if args.phase in ("jsrecon", "all"):
            phase_js_recon(secretfinder_path, linkfinder_path)

        if args.phase in ("takeover", "all"):
            phase_takeover(Path("/root/nuclei-templates/http/takeovers"))

        print_ok("Done.")
        return 0
    except FileNotFoundError as e:
        print_err(str(e))
        return 2
    except KeyboardInterrupt:
        print_err("Interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())



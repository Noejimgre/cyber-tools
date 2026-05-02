#!/usr/bin/env python3
"""
recon.py — Automated Reconnaissance Tool
Author: Noé Jimenez-Greverent
Description: Full recon on a target domain: WHOIS, DNS, headers, subdomains, ports
Usage: python3 recon.py <domain>
Educational purposes only. Use on systems you own or have permission to test.
"""

import socket
import subprocess
import json
import argparse
import sys
import os
from datetime import datetime

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("[!] Missing: pip install requests")
    sys.exit(1)

BANNER = r"""
 ____  _____ ____ ___  _   _
|  _ \| ____/ ___/ _ \| \ | |
| |_) |  _|| |  | | | |  \| |
|  _ <| |__| |__| |_| | |\  |
|_| \_\_____\____\___/|_| \_|
  Automated Recon Tool v1.0
  Educational use only
"""

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "portal", "vpn", "dev", "staging", "api",
    "app", "blog", "shop", "cdn", "static", "m", "mobile",
    "ns1", "ns2", "mx", "remote", "server", "test",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443,
                445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]


class Colors:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    B = "\033[94m"; C = "\033[96m"; W = "\033[0m"; BOLD = "\033[1m"


def c(text, color): print(f"{color}{text}{Colors.W}")
def section(title): c(f"\n{'─'*55}\n  {title}\n{'─'*55}", Colors.B)


# ── DNS LOOKUP ────────────────────────────────────────────

def dns_lookup(domain):
    section("🌐 DNS LOOKUP")
    results = {}

    # A record (IPv4)
    try:
        ip = socket.gethostbyname(domain)
        c(f"  [A    ] {domain} → {ip}", Colors.G)
        results["A"] = ip
    except socket.gaierror:
        c(f"  [!] Could not resolve {domain}", Colors.R)
        results["A"] = None

    # Reverse DNS
    if results.get("A"):
        try:
            hostname = socket.gethostbyaddr(results["A"])[0]
            c(f"  [PTR  ] {results['A']} → {hostname}", Colors.G)
            results["PTR"] = hostname
        except socket.herror:
            c(f"  [PTR  ] No reverse DNS", Colors.Y)

    # MX records via nslookup
    try:
        out = subprocess.run(
            ["nslookup", "-type=MX", domain],
            capture_output=True, text=True, timeout=5
        ).stdout
        mx_lines = [l for l in out.splitlines() if "mail exchanger" in l.lower()]
        for mx in mx_lines:
            c(f"  [MX   ] {mx.strip()}", Colors.C)
        results["MX"] = mx_lines
    except Exception:
        pass

    # TXT records (SPF, DMARC, etc.)
    try:
        out = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True, text=True, timeout=5
        ).stdout
        txt_lines = [l for l in out.splitlines() if '"' in l]
        for txt in txt_lines[:5]:
            c(f"  [TXT  ] {txt.strip()[:80]}", Colors.C)
        results["TXT"] = txt_lines
    except Exception:
        pass

    return results


# ── WHOIS ─────────────────────────────────────────────────

def whois_lookup(domain):
    section("📋 WHOIS INFORMATION")
    results = {}

    try:
        out = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        ).stdout

        interesting_fields = [
            "Registrar:", "Creation Date:", "Updated Date:",
            "Registry Expiry Date:", "Registrant Organization:",
            "Name Server:", "DNSSEC:", "Registrant Country:"
        ]

        for line in out.splitlines():
            for field in interesting_fields:
                if line.strip().startswith(field):
                    key = field.rstrip(":")
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    c(f"  {field:<35} {val}", Colors.G)
                    results[key] = val
                    break

    except FileNotFoundError:
        c("  [!] whois not installed: sudo apt install whois", Colors.Y)
    except Exception as e:
        c(f"  [!] WHOIS error: {e}", Colors.R)

    return results


# ── HTTP HEADERS ──────────────────────────────────────────

def check_headers(domain):
    section("🔒 HTTP HEADERS & SECURITY")
    results = {"security": [], "info_leak": []}

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=8, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            c(f"\n  [{scheme.upper()}] {url} → {r.status_code} ({len(r.content)} bytes)", Colors.G)

            # Security headers
            sec_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
            ]
            for h in sec_headers:
                if h in r.headers:
                    c(f"  [✓] {h}: {r.headers[h][:60]}", Colors.G)
                else:
                    c(f"  [✗] MISSING: {h}", Colors.Y)
                    results["security"].append(h)

            # Info-leaking headers
            for h in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                if h in r.headers:
                    c(f"  [!] {h}: {r.headers[h]}", Colors.R)
                    results["info_leak"].append(f"{h}: {r.headers[h]}")

            break  # Stop after first successful scheme
        except Exception:
            continue

    return results


# ── SUBDOMAIN ENUMERATION ─────────────────────────────────

def enum_subdomains(domain, wordlist=None):
    section("🔍 SUBDOMAIN ENUMERATION")
    found = []

    subdomains = wordlist if wordlist else COMMON_SUBDOMAINS

    c(f"  [*] Testing {len(subdomains)} subdomains...\n", Colors.C)

    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            c(f"  [FOUND] {fqdn:<40} → {ip}", Colors.G)
            found.append({"subdomain": fqdn, "ip": ip})
        except socket.gaierror:
            pass

    if not found:
        c("  [-] No subdomains found.", Colors.Y)
    else:
        c(f"\n  [+] {len(found)} subdomains discovered.", Colors.G)

    return found


# ── PORT SCAN ─────────────────────────────────────────────

def port_scan(target_ip, ports=None):
    section("🚪 PORT SCAN")
    open_ports = []
    ports = ports or COMMON_PORTS

    c(f"  [*] Scanning {len(ports)} ports on {target_ip}...\n", Colors.C)

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                c(f"  [OPEN ] {port:<6} {service}", Colors.G)
                open_ports.append({"port": port, "service": service})
            sock.close()
        except Exception:
            pass

    if not open_ports:
        c("  [-] No open ports found in common list.", Colors.Y)

    return open_ports


# ── ROBOTS & SITEMAP ─────────────────────────────────────

def check_robots(domain):
    section("🤖 ROBOTS.TXT & SITEMAP")
    results = {}

    for path in ["/robots.txt", "/sitemap.xml"]:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}{path}"
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code == 200:
                    c(f"  [200] {url}", Colors.G)
                    preview = r.text[:400].replace("\n", "\n       ")
                    c(f"       {preview}", Colors.C)
                    results[path] = r.text
                    break
                else:
                    c(f"  [{r.status_code}] {url}", Colors.Y)
            except Exception:
                pass

    return results


# ── REPORT ────────────────────────────────────────────────

def save_report(domain, data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recon_{domain.replace('.', '_')}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    c(f"\n[+] Report saved → {filename}", Colors.G)
    return filename


# ── MAIN ──────────────────────────────────────────────────

def main():
    print(Colors.C + BANNER + Colors.W)

    parser = argparse.ArgumentParser(description="Automated Recon Tool")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--skip-whois",      action="store_true")
    parser.add_argument("--skip-subdomains", action="store_true")
    parser.add_argument("--skip-ports",      action="store_true")
    parser.add_argument("--skip-robots",     action="store_true")
    parser.add_argument("--no-save",         action="store_true")
    args = parser.parse_args()

    domain = args.domain.replace("https://", "").replace("http://", "").strip("/")

    c(f"[*] Target  : {domain}", Colors.BOLD)
    c(f"[*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.BOLD)

    report = {"domain": domain, "date": datetime.now().isoformat()}

    # DNS (always run — needed for IP)
    dns = dns_lookup(domain)
    report["dns"] = dns

    if not args.skip_whois:
        report["whois"] = whois_lookup(domain)

    report["headers"] = check_headers(domain)

    if not args.skip_subdomains:
        report["subdomains"] = enum_subdomains(domain)

    if not args.skip_ports and dns.get("A"):
        report["open_ports"] = port_scan(dns["A"])

    if not args.skip_robots:
        report["robots"] = check_robots(domain)

    # Summary
    c(f"\n{'='*55}", Colors.BOLD)
    c("  RECON SUMMARY", Colors.BOLD)
    c(f"{'='*55}", Colors.BOLD)
    c(f"  Domain        : {domain}", Colors.W)
    c(f"  IP            : {dns.get('A', 'N/A')}", Colors.W)
    c(f"  Subdomains    : {len(report.get('subdomains', []))}", Colors.W)
    c(f"  Open ports    : {len(report.get('open_ports', []))}", Colors.W)
    c(f"  Missing hdrs  : {len(report.get('headers', {}).get('security', []))}", Colors.W)
    c(f"  Info leaks    : {len(report.get('headers', {}).get('info_leak', []))}", Colors.W)

    if not args.no_save:
        save_report(domain, report)

    c(f"\n[✓] Recon complete — {datetime.now().strftime('%H:%M:%S')}\n", Colors.G)


if __name__ == "__main__":
    main()

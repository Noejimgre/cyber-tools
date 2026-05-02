#!/usr/bin/env python3
"""
log_analyzer.py — Web Server Log Analyzer for Security
Author: Noé Jimenez-Greverent
Description: Parse Apache/Nginx access logs to detect attacks, scans, brute-force
Usage: python3 log_analyzer.py <logfile>
"""

import re
import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════╗
║        WEB LOG SECURITY ANALYZER v1.0            ║
║  Detect attacks, scans, brute-force in logs      ║
╚══════════════════════════════════════════════════╝
"""

class Colors:
    R="\033[91m";G="\033[92m";Y="\033[93m";C="\033[96m";W="\033[0m";BOLD="\033[1m"

def c(t, col=Colors.W): print(f"{col}{t}{Colors.W}")

# Apache/Nginx log pattern
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<date>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>[^\s"]+)[^"]*"\s+(?P<status>\d+)\s+(?P<size>\d+|-)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

# Attack signatures
ATTACK_SIGNATURES = {
    "SQL Injection":   [r"'", r"union\s+select", r"drop\s+table", r"1=1", r"or\s+1", r"--\s", r"xp_", r"exec\("],
    "XSS":             [r"<script", r"javascript:", r"onerror=", r"onload=", r"alert\(", r"<img\s+src"],
    "Path Traversal":  [r"\.\./", r"\.\.\\", r"%2e%2e", r"etc/passwd", r"etc/shadow", r"win/system32"],
    "Command Inject":  [r"\|", r";id;", r";ls", r";cat\s", r"`", r"\$\(", r"&&", r"\|\|"],
    "Scanner":         [r"nikto", r"nmap", r"masscan", r"sqlmap", r"burpsuite", r"dirbuster", r"gobuster", r"wfuzz"],
    "Wordlist Scan":   [r"\.php$", r"\.asp$", r"\.bak$", r"\.old$", r"\.env$", r"\.git/", r"/admin", r"/phpmyadmin"],
    "Shell Upload":    [r"\.php\?", r"cmd=", r"shell\.php", r"c99", r"r57", r"webshell"],
}

SUSPICIOUS_UAS = [
    "sqlmap", "nikto", "nmap", "masscan", "burp", "dirbuster",
    "gobuster", "wfuzz", "python-requests", "curl", "wget",
    "libwww-perl", "go-http-client", "zgrab",
]


def parse_log(filepath):
    """Parse log file and return list of entries."""
    entries = []
    errors = 0

    try:
        with open(filepath, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                m = LOG_PATTERN.match(line)
                if m:
                    entry = m.groupdict()
                    entry["line"] = line_num
                    entry["raw"] = line
                    entries.append(entry)
                else:
                    errors += 1
    except FileNotFoundError:
        c(f"[!] File not found: {filepath}", Colors.R)
        return []

    c(f"  [+] Parsed {len(entries):,} entries ({errors} skipped)", Colors.G)
    return entries


def detect_attacks(entries):
    """Detect attack patterns in log entries."""
    findings = defaultdict(list)

    for entry in entries:
        path = entry.get("path", "").lower()
        ua   = entry.get("ua", "").lower() if entry.get("ua") else ""

        for attack_type, patterns in ATTACK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, path, re.I) or re.search(pattern, ua, re.I):
                    findings[attack_type].append({
                        "ip":     entry["ip"],
                        "path":   entry["path"][:100],
                        "status": entry["status"],
                        "line":   entry["line"]
                    })
                    break

    return findings


def detect_brute_force(entries, threshold=20):
    """Detect brute-force: many 401/403 from same IP."""
    ip_failures = defaultdict(list)

    for entry in entries:
        if entry["status"] in ["401", "403"]:
            ip_failures[entry["ip"]].append(entry["path"])

    suspects = {ip: paths for ip, paths in ip_failures.items()
                if len(paths) >= threshold}
    return suspects


def detect_scanners(entries):
    """Detect IPs doing sequential scans (many 404s)."""
    ip_404 = Counter(e["ip"] for e in entries if e["status"] == "404")
    return {ip: count for ip, count in ip_404.items() if count >= 15}


def detect_suspicious_uas(entries):
    """Find requests with scanner/tool user-agents."""
    suspicious = []
    for entry in entries:
        ua = (entry.get("ua") or "").lower()
        for tool in SUSPICIOUS_UAS:
            if tool in ua:
                suspicious.append({
                    "ip": entry["ip"],
                    "ua": entry.get("ua", "")[:80],
                    "path": entry["path"][:60],
                    "tool": tool
                })
                break
    return suspicious


def top_stats(entries):
    """Compute top IPs, paths, user-agents, status codes."""
    stats = {
        "top_ips":     Counter(e["ip"]     for e in entries).most_common(10),
        "top_paths":   Counter(e["path"]   for e in entries).most_common(10),
        "status_codes":Counter(e["status"] for e in entries).most_common(),
        "top_4xx_ips": Counter(e["ip"] for e in entries
                               if e["status"].startswith("4")).most_common(5),
    }
    return stats


def print_section(title):
    c(f"\n{'─'*55}", Colors.C)
    c(f"  {title}", Colors.BOLD)
    c(f"{'─'*55}", Colors.C)


def print_results(entries, attacks, brute, scanners, sus_uas, stats):

    print_section("📊 GENERAL STATISTICS")
    total = len(entries)
    status_dist = dict(stats["status_codes"])
    c(f"  Total requests : {total:,}", Colors.W)
    c(f"  200 OK         : {status_dist.get('200', 0):,}", Colors.G)
    c(f"  404 Not Found  : {status_dist.get('404', 0):,}", Colors.Y)
    c(f"  401/403        : {int(status_dist.get('401',0))+int(status_dist.get('403',0)):,}", Colors.Y)
    c(f"  500 Errors     : {status_dist.get('500', 0):,}", Colors.R)

    print_section("🔝 TOP 5 IP ADDRESSES")
    for ip, count in stats["top_ips"][:5]:
        bar = "█" * min(count // 10, 30)
        print(f"  {ip:<18} {count:>6} reqs  {bar}")

    print_section("🔐 ATTACK SIGNATURES DETECTED")
    if attacks:
        for attack_type, hits in attacks.items():
            unique_ips = len(set(h["ip"] for h in hits))
            c(f"  [{len(hits):>4}x] {attack_type:<20} from {unique_ips} unique IP(s)", Colors.R)
            for hit in hits[:3]:
                c(f"         IP={hit['ip']}  [{hit['status']}]  {hit['path'][:60]}", Colors.Y)
    else:
        c("  No known attack patterns detected.", Colors.G)

    print_section("🔨 BRUTE-FORCE SUSPECTS")
    if brute:
        for ip, paths in brute.items():
            c(f"  {ip:<18} → {len(paths)} failed auth attempts", Colors.R)
    else:
        c("  No brute-force detected.", Colors.G)

    print_section("🔍 SCANNER ACTIVITY (15+ 404s)")
    if scanners:
        for ip, count in sorted(scanners.items(), key=lambda x: x[1], reverse=True):
            c(f"  {ip:<18} → {count} × 404", Colors.R)
    else:
        c("  No scanners detected.", Colors.G)

    print_section("🤖 SUSPICIOUS USER-AGENTS")
    if sus_uas:
        seen = set()
        for s in sus_uas:
            key = (s["ip"], s["tool"])
            if key not in seen:
                c(f"  [{s['tool']:<15}] {s['ip']}  {s['ua'][:50]}", Colors.R)
                seen.add(key)
    else:
        c("  No suspicious user-agents detected.", Colors.G)


def generate_sample_log(path="sample_access.log"):
    """Generate a sample log file for testing."""
    import random
    lines = [
        '192.168.1.10 - - [01/May/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.1 - - [01/May/2026:10:00:02 +0000] "GET /admin HTTP/1.1" 403 512 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [01/May/2026:10:00:03 +0000] "GET /index.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 0 "-" "sqlmap/1.6"',
        '45.55.44.33 - - [01/May/2026:10:00:04 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 0 "-" "nikto/2.1.6"',
        '10.0.0.2 - - [01/May/2026:10:00:05 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "curl/7.64"',
    ]
    # Add 404 spam for scanner detection
    for i in range(30):
        lines.append(f'1.2.3.4 - - [01/May/2026:10:00:{i:02}] "GET /{random.choice(["admin","backup","test","shell"])}.php HTTP/1.1" 404 0 "-" "python-requests/2.28"')

    with open(path, "w") as f:
        f.write("\n".join(lines))
    c(f"[+] Sample log created: {path}", Colors.G)
    return path


def main():
    print(Colors.C + BANNER + Colors.W)

    parser = argparse.ArgumentParser(description="Web Log Security Analyzer")
    parser.add_argument("logfile", nargs="?", help="Path to access log file")
    parser.add_argument("--brute-threshold", type=int, default=20,
                        help="Auth failures to flag as brute-force (default: 20)")
    parser.add_argument("--sample", action="store_true",
                        help="Generate and analyze a sample log")
    parser.add_argument("--save", action="store_true", help="Save report as JSON")
    args = parser.parse_args()

    if args.sample:
        logfile = generate_sample_log()
    elif args.logfile:
        logfile = args.logfile
    else:
        parser.print_help()
        c("\nTip: use --sample to generate and test with a demo log", Colors.Y)
        return

    c(f"[*] File     : {logfile}", Colors.BOLD)
    c(f"[*] Started  : {datetime.now().strftime('%H:%M:%S')}", Colors.BOLD)

    entries = parse_log(logfile)
    if not entries:
        return

    attacks  = detect_attacks(entries)
    brute    = detect_brute_force(entries, args.brute_threshold)
    scanners = detect_scanners(entries)
    sus_uas  = detect_suspicious_uas(entries)
    stats    = top_stats(entries)

    print_results(entries, attacks, brute, scanners, sus_uas, stats)

    total_alerts = sum(len(v) for v in attacks.values()) + len(brute) + len(scanners) + len(sus_uas)

    c(f"\n{'='*55}", Colors.BOLD)
    c(f"  SUMMARY — {total_alerts} alerts generated", Colors.BOLD)
    c(f"{'='*55}\n", Colors.BOLD)

    if args.save:
        report = {
            "file": logfile, "date": datetime.now().isoformat(),
            "total_requests": len(entries), "attacks": {k: len(v) for k,v in attacks.items()},
            "brute_force_ips": list(brute.keys()),
            "scanner_ips": list(scanners.keys()),
            "suspicious_uas": len(sus_uas)
        }
        out = f"log_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        c(f"[+] Report saved → {out}", Colors.G)


if __name__ == "__main__":
    main()

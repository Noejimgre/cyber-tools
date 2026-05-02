#!/usr/bin/env python3
"""
osint_username.py — OSINT Username Finder
Author: Noé Jimenez-Greverent
Description: Check if a username exists across 40+ platforms
Usage: python3 osint_username.py <username>
Educational purposes only.
"""

import requests
import argparse
import json
import threading
from datetime import datetime
from queue import Queue

try:
    import requests
except ImportError:
    print("[!] pip install requests")
    import sys; sys.exit(1)

BANNER = """
╔══════════════════════════════════════════╗
║         OSINT USERNAME FINDER v1.0       ║
║   Check username across 40+ platforms    ║
║         Educational use only             ║
╚══════════════════════════════════════════╝
"""

# Platform definitions: name → URL template + detection method
PLATFORMS = {
    # Social media
    "GitHub":        {"url": "https://github.com/{}", "check": "status"},
    "GitLab":        {"url": "https://gitlab.com/{}", "check": "status"},
    "Twitter/X":     {"url": "https://twitter.com/{}", "check": "status"},
    "Instagram":     {"url": "https://www.instagram.com/{}/", "check": "status"},
    "TikTok":        {"url": "https://www.tiktok.com/@{}", "check": "status"},
    "Reddit":        {"url": "https://www.reddit.com/user/{}", "check": "status"},
    "Pinterest":     {"url": "https://www.pinterest.com/{}/", "check": "status"},
    "Tumblr":        {"url": "https://{}.tumblr.com", "check": "status"},
    "LinkedIn":      {"url": "https://www.linkedin.com/in/{}", "check": "status"},
    "Facebook":      {"url": "https://www.facebook.com/{}", "check": "status"},

    # Dev / tech
    "HackTheBox":    {"url": "https://app.hackthebox.com/users/profile/{}", "check": "status"},
    "TryHackMe":     {"url": "https://tryhackme.com/p/{}", "check": "status"},
    "StackOverflow": {"url": "https://stackoverflow.com/users/{}", "check": "status"},
    "Dev.to":        {"url": "https://dev.to/{}", "check": "status"},
    "Medium":        {"url": "https://medium.com/@{}", "check": "status"},
    "Pastebin":      {"url": "https://pastebin.com/u/{}", "check": "status"},
    "Keybase":       {"url": "https://keybase.io/{}", "check": "status"},
    "Replit":        {"url": "https://replit.com/@{}", "check": "status"},
    "Codepen":       {"url": "https://codepen.io/{}", "check": "status"},
    "HackerOne":     {"url": "https://hackerone.com/{}", "check": "status"},
    "Bugcrowd":      {"url": "https://bugcrowd.com/{}", "check": "status"},

    # Gaming
    "Steam":         {"url": "https://steamcommunity.com/id/{}", "check": "not_found_text", "text": "The specified profile could not be found"},
    "Twitch":        {"url": "https://www.twitch.tv/{}", "check": "status"},
    "Chess.com":     {"url": "https://www.chess.com/member/{}", "check": "status"},

    # Creative / content
    "Dribbble":      {"url": "https://dribbble.com/{}", "check": "status"},
    "Behance":       {"url": "https://www.behance.net/{}", "check": "status"},
    "Flickr":        {"url": "https://www.flickr.com/people/{}", "check": "status"},
    "SoundCloud":    {"url": "https://soundcloud.com/{}", "check": "status"},
    "Spotify":       {"url": "https://open.spotify.com/user/{}", "check": "status"},
    "Vimeo":         {"url": "https://vimeo.com/{}", "check": "status"},

    # Forums / communities
    "Hackernews":    {"url": "https://news.ycombinator.com/user?id={}", "check": "not_found_text", "text": "No such user"},
    "ProductHunt":   {"url": "https://www.producthunt.com/@{}", "check": "status"},
    "Mastodon.social":{"url": "https://mastodon.social/@{}", "check": "status"},
    "Gravatar":      {"url": "https://en.gravatar.com/{}", "check": "status"},
    "About.me":      {"url": "https://about.me/{}", "check": "status"},
    "Linktree":      {"url": "https://linktr.ee/{}", "check": "status"},
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


class Colors:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    C = "\033[96m"; W = "\033[0m";  BOLD = "\033[1m"


def check_platform(name, config, username, results, lock):
    """Check a single platform for the username."""
    url = config["url"].format(username)
    try:
        r = requests.get(url, headers=HEADERS, timeout=8,
                         allow_redirects=True, verify=False)

        found = False
        if config["check"] == "status":
            found = r.status_code == 200
        elif config["check"] == "not_found_text":
            found = config.get("text", "") not in r.text and r.status_code == 200

        with lock:
            if found:
                print(f"  \033[92m[✓] FOUND   {name:<20} → {url}\033[0m")
                results["found"].append({"platform": name, "url": url})
            else:
                print(f"  \033[90m[✗] NOT FOUND {name}\033[0m")
                results["not_found"].append(name)

    except requests.exceptions.Timeout:
        with lock:
            print(f"  \033[93m[T] TIMEOUT  {name}\033[0m")
            results["errors"].append({"platform": name, "error": "timeout"})
    except Exception as e:
        with lock:
            results["errors"].append({"platform": name, "error": str(e)})


def run_search(username, threads=10):
    """Run username search across all platforms using threading."""
    results = {"username": username, "found": [], "not_found": [], "errors": []}
    lock = threading.Lock()
    q = Queue()

    for name, config in PLATFORMS.items():
        q.put((name, config))

    def worker():
        while not q.empty():
            try:
                name, config = q.get_nowait()
                check_platform(name, config, username, results, lock)
                q.task_done()
            except Exception:
                break

    thread_list = []
    for _ in range(min(threads, len(PLATFORMS))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    return results


def print_summary(results):
    username = results["username"]
    found    = results["found"]
    errors   = results["errors"]

    print(f"\n{Colors.BOLD}{'='*55}{Colors.W}")
    print(f"{Colors.BOLD}  RESULTS FOR: @{username}{Colors.W}")
    print(f"{Colors.BOLD}{'='*55}{Colors.W}")
    print(f"  Platforms scanned : {len(PLATFORMS)}")
    print(f"  {Colors.G}Found             : {len(found)}{Colors.W}")
    print(f"  Errors/Timeouts   : {len(errors)}")

    if found:
        print(f"\n{Colors.G}  ✓ CONFIRMED PROFILES:{Colors.W}")
        for p in found:
            print(f"    → {p['platform']:<20} {p['url']}")

    print()


def save_report(results):
    username = results["username"]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"osint_{username}_{ts}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"{Colors.G}[+] Report saved → {filename}{Colors.W}")


def main():
    import urllib3
    urllib3.disable_warnings()

    print(Colors.C + BANNER + Colors.W)

    parser = argparse.ArgumentParser(description="OSINT Username Finder")
    parser.add_argument("username", help="Username to search (e.g. john_doe)")
    parser.add_argument("--threads", type=int, default=10, help="Parallel threads (default: 10)")
    parser.add_argument("--no-save", action="store_true", help="Don't save report")
    args = parser.parse_args()

    username = args.username.strip()
    print(f"{Colors.BOLD}[*] Username : {username}{Colors.W}")
    print(f"{Colors.BOLD}[*] Platforms: {len(PLATFORMS)}{Colors.W}")
    print(f"{Colors.BOLD}[*] Threads  : {args.threads}{Colors.W}")
    print(f"{Colors.BOLD}[*] Started  : {datetime.now().strftime('%H:%M:%S')}{Colors.W}\n")
    print("─" * 55)

    results = run_search(username, args.threads)
    results["date"] = datetime.now().isoformat()

    print_summary(results)

    if not args.no_save:
        save_report(results)


if __name__ == "__main__":
    main()

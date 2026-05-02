#!/usr/bin/env python3
"""
password_auditor.py — Password Strength & Security Auditor
Author: Noé Jimenez-Greverent
Description: Analyze password strength, check against common lists, estimate crack time
Usage: python3 password_auditor.py [password] or --file passwords.txt
"""

import argparse
import hashlib
import math
import re
import string
import sys
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════╗
║       PASSWORD STRENGTH AUDITOR v1.0             ║
║  Strength · Entropy · Crack time · Policy check  ║
╚══════════════════════════════════════════════════╝
"""

class Colors:
    R="\033[91m";G="\033[92m";Y="\033[93m";C="\033[96m";W="\033[0m";BOLD="\033[1m"

def c(t, col=Colors.W): print(f"{col}{t}{Colors.W}")

# Top 100 most common passwords
TOP_PASSWORDS = {
    "123456","password","123456789","12345678","12345","1234567","1234567890",
    "qwerty","abc123","111111","123123","admin","letmein","welcome","monkey",
    "1234","dragon","master","login","password1","iloveyou","sunshine","princess",
    "admin123","passw0rd","password123","123321","654321","superman","batman",
    "qwerty123","hello","test","azerty","000000","P@ssw0rd","P@ssword","qwertyuiop",
    "1q2w3e4r","1qaz2wsx","zxcvbnm","987654321","pass","mypassword","trustno1",
    "michael","jessica","shadow","football","baseball","soccer","hockey","killer",
    "hunter","george","andrew","charlie","thomas","andrew","jordan",
}

# Common patterns to penalize
PATTERNS = [
    (r"^(.)\1+$",           "Repeated characters"),
    (r"^(012|123|234|345|456|567|678|789|890|abc|qwe|asd|zxc)+$", "Sequential pattern"),
    (r"(19|20)\d{2}",       "Contains year"),
    (r"^[a-zA-Z]+\d{1,4}$","Word + short number"),
    (r"^[A-Z][a-z]+\d+[!@#$%]?$", "Common capitalization pattern"),
]

# Password policies
POLICIES = {
    "Minimum": {
        "min_length": 8, "require_upper": False,
        "require_lower": False, "require_digit": False,
        "require_special": False
    },
    "Standard": {
        "min_length": 10, "require_upper": True,
        "require_lower": True, "require_digit": True,
        "require_special": False
    },
    "Strong": {
        "min_length": 12, "require_upper": True,
        "require_lower": True, "require_digit": True,
        "require_special": True
    },
    "NIST SP 800-63B": {
        "min_length": 8, "require_upper": False,
        "require_lower": False, "require_digit": False,
        "require_special": False,
        "note": "NIST focuses on length and breach check, not complexity rules"
    },
}

# Crack speeds (hashes per second) for different attack scenarios
CRACK_SPEEDS = {
    "Online (throttled)":    100,
    "Online (no limit)":     10_000,
    "MD5 (GPU)":             80_000_000_000,
    "SHA-256 (GPU)":         4_000_000_000,
    "bcrypt (GPU)":          20_000,
}


def compute_entropy(password):
    """Calculate password entropy in bits."""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d',    password): charset += 10
    if re.search(r'[ !"#$%&\'()*+,\-./:;<=>?@\[\\\]^_`{|}~]', password): charset += 32

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)


def crack_time_str(combinations, speed):
    """Return human-readable crack time estimate."""
    if combinations <= 0 or speed <= 0:
        return "instant"

    seconds = combinations / (2 * speed)  # Average case = half keyspace

    if seconds < 1:          return f"< 1 second"
    if seconds < 60:         return f"{int(seconds)} seconds"
    if seconds < 3600:       return f"{int(seconds/60)} minutes"
    if seconds < 86400:      return f"{int(seconds/3600)} hours"
    if seconds < 2592000:    return f"{int(seconds/86400)} days"
    if seconds < 31536000:   return f"{int(seconds/2592000)} months"
    if seconds < 3153600000: return f"{int(seconds/31536000)} years"
    return f"{int(seconds/31536000):,} years"


def analyze_password(password):
    """Full password analysis."""
    results = {
        "password":      password,
        "length":        len(password),
        "entropy":       compute_entropy(password),
        "score":         0,
        "strength":      "",
        "issues":        [],
        "suggestions":   [],
        "patterns":      [],
        "policy":        {},
        "crack_times":   {},
    }

    # Character variety
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d',    password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    # Scoring (0-100)
    score = 0

    # Length scoring
    l = len(password)
    if l >= 20:   score += 30
    elif l >= 16: score += 25
    elif l >= 12: score += 20
    elif l >= 10: score += 15
    elif l >= 8:  score += 10
    else:         score += 0

    # Variety scoring
    if has_lower:   score += 10
    if has_upper:   score += 10
    if has_digit:   score += 10
    if has_special: score += 15

    # Entropy bonus
    if results["entropy"] >= 80: score += 25
    elif results["entropy"] >= 60: score += 15
    elif results["entropy"] >= 40: score += 10

    # Penalties
    if password.lower() in TOP_PASSWORDS:
        score -= 50
        results["issues"].append("🚨 CRITICAL: Found in top common passwords list!")

    for pattern_re, label in PATTERNS:
        if re.search(pattern_re, password, re.I):
            score -= 10
            results["patterns"].append(label)

    score = max(0, min(100, score))
    results["score"] = score

    # Strength label
    if score >= 80:   results["strength"] = "💪 VERY STRONG"
    elif score >= 60: results["strength"] = "✅ STRONG"
    elif score >= 40: results["strength"] = "⚠️  MODERATE"
    elif score >= 20: results["strength"] = "❌ WEAK"
    else:             results["strength"] = "🚨 VERY WEAK"

    # Issues & suggestions
    if l < 12:
        results["issues"].append(f"Too short ({l} chars) — aim for 12+")
        results["suggestions"].append("Increase length to at least 12 characters")
    if not has_upper:
        results["issues"].append("No uppercase letters")
        results["suggestions"].append("Add uppercase letters")
    if not has_lower:
        results["issues"].append("No lowercase letters")
    if not has_digit:
        results["issues"].append("No digits")
        results["suggestions"].append("Add numbers")
    if not has_special:
        results["issues"].append("No special characters")
        results["suggestions"].append("Add special chars (!@#$%...)")
    if results["patterns"]:
        results["suggestions"].append("Avoid predictable patterns")

    # Policy check
    for policy_name, policy in POLICIES.items():
        meets = True
        reasons = []
        if l < policy["min_length"]:
            meets = False; reasons.append(f"length < {policy['min_length']}")
        if policy.get("require_upper") and not has_upper:
            meets = False; reasons.append("no uppercase")
        if policy.get("require_lower") and not has_lower:
            meets = False; reasons.append("no lowercase")
        if policy.get("require_digit") and not has_digit:
            meets = False; reasons.append("no digit")
        if policy.get("require_special") and not has_special:
            meets = False; reasons.append("no special char")
        results["policy"][policy_name] = {"meets": meets, "reasons": reasons}

    # Crack times
    charset = 0
    if has_lower:   charset += 26
    if has_upper:   charset += 26
    if has_digit:   charset += 10
    if has_special: charset += 32
    keyspace = charset ** l if charset > 0 else 1

    for scenario, speed in CRACK_SPEEDS.items():
        results["crack_times"][scenario] = crack_time_str(keyspace, speed)

    # Check HaveIBeenPwned API (SHA-1 k-anonymity)
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    results["sha1_prefix"] = sha1[:5]

    return results


def print_analysis(r, show_password=True):
    """Pretty-print analysis results."""
    pwd_display = r["password"] if show_password else "*" * len(r["password"])

    c(f"\n{'═'*55}", Colors.BOLD)
    if show_password:
        c(f"  Password    : {pwd_display}", Colors.BOLD)
    c(f"  Length      : {r['length']} characters", Colors.W)
    c(f"  Entropy     : {r['entropy']} bits", Colors.W)

    # Score bar
    score = r["score"]
    bar_len = 30
    filled = int(score / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    color = Colors.G if score >= 60 else Colors.Y if score >= 40 else Colors.R
    c(f"  Score       : {score}/100  [{bar}]", color)
    c(f"  Strength    : {r['strength']}", color)

    if r["issues"]:
        c(f"\n  ⚠ Issues:", Colors.Y)
        for issue in r["issues"]:
            c(f"    → {issue}", Colors.R)

    if r["patterns"]:
        c(f"\n  🔍 Patterns detected:", Colors.Y)
        for p in r["patterns"]:
            c(f"    → {p}", Colors.Y)

    if r["suggestions"]:
        c(f"\n  💡 Suggestions:", Colors.C)
        for s in r["suggestions"]:
            c(f"    → {s}", Colors.C)

    c(f"\n  ⏱ Crack time estimates:", Colors.BOLD)
    for scenario, time in r["crack_times"].items():
        color = Colors.G if "year" in time and int(time.split()[0].replace(",","")) > 1000 else \
                Colors.Y if "year" in time or "month" in time else Colors.R
        c(f"    {scenario:<25} {time}", color)

    c(f"\n  📋 Policy compliance:", Colors.BOLD)
    for policy, result in r["policy"].items():
        if result["meets"]:
            c(f"    [✓] {policy}", Colors.G)
        else:
            reasons = ", ".join(result["reasons"])
            c(f"    [✗] {policy:<20} ({reasons})", Colors.R)

    c(f"\n  🔑 SHA-1 prefix (HaveIBeenPwned): {r['sha1_prefix']}...", Colors.C)
    c(f"     Check manually: https://api.pwnedpasswords.com/range/{r['sha1_prefix']}", Colors.C)

    c(f"\n{'═'*55}\n", Colors.BOLD)


def audit_file(filepath, show_passwords=False):
    """Audit all passwords in a file."""
    c(f"\n[*] Auditing file: {filepath}", Colors.BOLD)

    results = []
    try:
        with open(filepath) as f:
            passwords = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        c(f"[!] File not found: {filepath}", Colors.R)
        return

    c(f"[*] {len(passwords)} passwords to analyze\n", Colors.C)

    scores = {"very_weak": 0, "weak": 0, "moderate": 0, "strong": 0, "very_strong": 0}
    for pwd in passwords:
        r = analyze_password(pwd)
        results.append(r)
        if r["score"] < 20:   scores["very_weak"]   += 1
        elif r["score"] < 40: scores["weak"]         += 1
        elif r["score"] < 60: scores["moderate"]     += 1
        elif r["score"] < 80: scores["strong"]       += 1
        else:                 scores["very_strong"]  += 1

    c("\n📊 AUDIT SUMMARY", Colors.BOLD)
    c("─" * 40, Colors.C)
    c(f"  Total analyzed : {len(passwords)}", Colors.W)
    c(f"  🚨 Very weak   : {scores['very_weak']}", Colors.R)
    c(f"  ❌ Weak        : {scores['weak']}", Colors.R)
    c(f"  ⚠️  Moderate    : {scores['moderate']}", Colors.Y)
    c(f"  ✅ Strong      : {scores['strong']}", Colors.G)
    c(f"  💪 Very strong : {scores['very_strong']}", Colors.G)

    avg = sum(r["score"] for r in results) / len(results)
    c(f"\n  Average score  : {avg:.1f}/100", Colors.BOLD)

    pwned_check = [r for r in results if r["password"].lower() in TOP_PASSWORDS]
    if pwned_check:
        c(f"\n  🚨 {len(pwned_check)} password(s) found in common list!", Colors.R)
        for r in pwned_check:
            pwd = r["password"] if show_passwords else "*" * len(r["password"])
            c(f"     → {pwd}", Colors.R)


def main():
    print(Colors.C + BANNER + Colors.W)

    parser = argparse.ArgumentParser(description="Password Strength Auditor")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("password", nargs="?", help="Password to analyze")
    group.add_argument("--file", help="File with one password per line")
    parser.add_argument("--hide", action="store_true", help="Hide password in output")
    parser.add_argument("--show-passwords", action="store_true",
                        help="Show passwords when auditing a file")
    args = parser.parse_args()

    if args.file:
        audit_file(args.file, show_passwords=args.show_passwords)

    elif args.password:
        r = analyze_password(args.password)
        print_analysis(r, show_password=not args.hide)

    else:
        # Interactive mode
        c("Enter password to analyze (input hidden in terminal):", Colors.C)
        try:
            import getpass
            pwd = getpass.getpass("  Password: ")
            if pwd:
                r = analyze_password(pwd)
                print_analysis(r, show_password=False)
            else:
                parser.print_help()
        except (KeyboardInterrupt, EOFError):
            c("\n[!] Cancelled.", Colors.Y)


if __name__ == "__main__":
    main()

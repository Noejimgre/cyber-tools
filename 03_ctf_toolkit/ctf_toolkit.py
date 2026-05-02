#!/usr/bin/env python3
"""
ctf_toolkit.py — CTF Swiss Army Knife
Author: Noé Jimenez-Greverent
Description: All-in-one encoding/decoding/crypto tool for CTF challenges
Usage: python3 ctf_toolkit.py <command> <input>
"""

import base64
import binascii
import argparse
import string
import sys
import re
import hashlib
import urllib.parse
from itertools import cycle

BANNER = """
╔══════════════════════════════════════════════════╗
║            CTF TOOLKIT v1.0                      ║
║   Encoding · Decoding · Crypto · Analysis        ║
╚══════════════════════════════════════════════════╝
"""

class Colors:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    C = "\033[96m"; W = "\033[0m";  BOLD = "\033[1m"


def c(text, col=Colors.W): print(f"{col}{text}{Colors.W}")


# ── ENCODING / DECODING ───────────────────────────────────

def b64_encode(text):
    return base64.b64encode(text.encode()).decode()

def b64_decode(text):
    try:
        # Handle padding
        padded = text + "=" * (4 - len(text) % 4) if len(text) % 4 else text
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[!] Error: {e}"

def b32_encode(text):
    return base64.b32encode(text.encode()).decode()

def b32_decode(text):
    try:
        padded = text + "=" * (8 - len(text) % 8) if len(text) % 8 else text
        return base64.b32decode(padded.upper()).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[!] Error: {e}"

def hex_encode(text):
    return binascii.hexlify(text.encode()).decode()

def hex_decode(text):
    try:
        clean = text.replace(" ", "").replace("0x", "").replace("\\x", "")
        return binascii.unhexlify(clean).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[!] Error: {e}"

def binary_encode(text):
    return " ".join(format(ord(c), "08b") for c in text)

def binary_decode(text):
    try:
        bits = text.replace(" ", "")
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
        return "".join(chars)
    except Exception as e:
        return f"[!] Error: {e}"

def url_encode(text):
    return urllib.parse.quote(text)

def url_decode(text):
    return urllib.parse.unquote(text)

def morse_encode(text):
    MORSE = {
        'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
        'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
        'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
        '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...',
        '8':'---..','9':'----.',' ':'/'
    }
    return " ".join(MORSE.get(c.upper(), "?") for c in text)

def morse_decode(text):
    MORSE_REV = {
        '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J',
        '-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T',
        '..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y':'Y','--..':'Z',
        '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
        '---..':'8','----.':'9','/':' '
    }
    return "".join(MORSE_REV.get(code, "?") for code in text.split())


# ── CIPHERS ───────────────────────────────────────────────

def rot13(text):
    return text.translate(str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
    ))

def caesar(text, shift=13):
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)

def caesar_bruteforce(text):
    c("\n[*] Caesar brute-force (all 25 shifts):\n", Colors.C)
    for shift in range(1, 26):
        decoded = caesar(text, shift)
        print(f"  Shift {shift:>2}: {decoded}")

def vigenere_decode(text, key):
    key = key.upper()
    result = []
    key_cycle = cycle(key)
    for char in text:
        if char.isalpha():
            k = ord(next(key_cycle)) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - k) % 26 + base))
        else:
            result.append(char)
    return "".join(result)

def xor_decode(text, key):
    """XOR decode — input as hex string, key as integer or string."""
    try:
        if all(c in "0123456789abcdefABCDEF " for c in text):
            data = bytes.fromhex(text.replace(" ", ""))
        else:
            data = text.encode()

        if isinstance(key, str) and key.isdigit():
            key_bytes = [int(key)]
        elif isinstance(key, str):
            key_bytes = [ord(c) for c in key]
        else:
            key_bytes = [key]

        result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        return result.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[!] Error: {e}"


# ── ANALYSIS ──────────────────────────────────────────────

def analyze(text):
    """Auto-detect encoding and useful properties."""
    c("\n[*] AUTO ANALYSIS", Colors.BOLD)
    c("─" * 50, Colors.C)

    print(f"  Length        : {len(text)}")
    print(f"  Entropy chars : {len(set(text))}")

    # Base64 check
    b64_re = r'^[A-Za-z0-9+/]*={0,2}$'
    if re.match(b64_re, text) and len(text) % 4 == 0 and len(text) > 4:
        c("  [!] Looks like Base64", Colors.Y)
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="replace")
            c(f"      Decoded: {decoded[:80]}", Colors.G)
        except Exception:
            pass

    # Hex check
    if re.match(r'^[0-9a-fA-F\s]+$', text) and len(text.replace(" ","")) % 2 == 0:
        c("  [!] Looks like Hex", Colors.Y)
        try:
            decoded = binascii.unhexlify(text.replace(" ","")).decode("utf-8", errors="replace")
            c(f"      Decoded: {decoded[:80]}", Colors.G)
        except Exception:
            pass

    # Binary check
    if re.match(r'^[01\s]+$', text) and len(text.replace(" ","")) % 8 == 0:
        c("  [!] Looks like Binary", Colors.Y)
        decoded = binary_decode(text)
        c(f"      Decoded: {decoded[:80]}", Colors.G)

    # Hash identification
    hash_sizes = {32:"MD5", 40:"SHA-1", 64:"SHA-256", 96:"SHA-384", 128:"SHA-512"}
    stripped = text.strip()
    if re.match(r'^[a-f0-9]+$', stripped, re.I) and len(stripped) in hash_sizes:
        c(f"  [!] Looks like {hash_sizes[len(stripped)]} hash", Colors.Y)

    # Morse check
    if re.match(r'^[\.\-\s\/]+$', text):
        c("  [!] Looks like Morse code", Colors.Y)

    # ROT13 attempt
    rot = rot13(text)
    if rot != text:
        c(f"  [?] ROT13: {rot[:80]}", Colors.C)

    # URL encoded check
    if "%" in text:
        decoded = url_decode(text)
        c(f"  [!] URL decoded: {decoded[:80]}", Colors.Y)


def compute_hashes(text):
    c("\n[*] HASH DIGEST", Colors.BOLD)
    c("─" * 50, Colors.C)
    algos = [("MD5", hashlib.md5), ("SHA-1", hashlib.sha1),
             ("SHA-256", hashlib.sha256), ("SHA-512", hashlib.sha512)]
    for name, func in algos:
        h = func(text.encode()).hexdigest()
        print(f"  {name:<10}: {h}")


# ── MAIN ──────────────────────────────────────────────────

def main():
    print(Colors.C + BANNER + Colors.W)

    parser = argparse.ArgumentParser(description="CTF Toolkit — encoding, decoding, ciphers")
    sub = parser.add_subparsers(dest="cmd")

    # Encode/Decode commands
    for cmd in ["b64e","b64d","b32e","b32d","hexe","hexd","bine","bind","urle","urld","rot13","morse-e","morse-d"]:
        p = sub.add_parser(cmd); p.add_argument("input", nargs="+")

    # Cipher commands
    p = sub.add_parser("caesar");    p.add_argument("input", nargs="+"); p.add_argument("--shift", type=int, default=13)
    p = sub.add_parser("caesar-bf"); p.add_argument("input", nargs="+")
    p = sub.add_parser("vigenere");  p.add_argument("input", nargs="+"); p.add_argument("--key", required=True)
    p = sub.add_parser("xor");       p.add_argument("input", nargs="+"); p.add_argument("--key", required=True)

    # Analysis
    p = sub.add_parser("analyze");   p.add_argument("input", nargs="+")
    p = sub.add_parser("hash");      p.add_argument("input", nargs="+")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        c("\nCommands:", Colors.C)
        c("  Encoding : b64e b64d b32e b32d hexe hexd bine bind urle urld", Colors.W)
        c("  Ciphers  : rot13 caesar caesar-bf vigenere --key <k> xor --key <k>", Colors.W)
        c("  Misc     : morse-e morse-d analyze hash", Colors.W)
        c("\nExample:", Colors.Y)
        c("  python3 ctf_toolkit.py b64d SGVsbG8gV29ybGQ=", Colors.W)
        c("  python3 ctf_toolkit.py analyze U0dWc2JHOD0=", Colors.W)
        c("  python3 ctf_toolkit.py caesar-bf 'Khoor Zruog'", Colors.W)
        return

    text = " ".join(args.input)

    ops = {
        "b64e": lambda: c(f"\n[+] Base64: {b64_encode(text)}", Colors.G),
        "b64d": lambda: c(f"\n[+] Decoded: {b64_decode(text)}", Colors.G),
        "b32e": lambda: c(f"\n[+] Base32: {b32_encode(text)}", Colors.G),
        "b32d": lambda: c(f"\n[+] Decoded: {b32_decode(text)}", Colors.G),
        "hexe": lambda: c(f"\n[+] Hex: {hex_encode(text)}", Colors.G),
        "hexd": lambda: c(f"\n[+] Decoded: {hex_decode(text)}", Colors.G),
        "bine": lambda: c(f"\n[+] Binary: {binary_encode(text)}", Colors.G),
        "bind": lambda: c(f"\n[+] Decoded: {binary_decode(text)}", Colors.G),
        "urle": lambda: c(f"\n[+] URL encoded: {url_encode(text)}", Colors.G),
        "urld": lambda: c(f"\n[+] URL decoded: {url_decode(text)}", Colors.G),
        "rot13": lambda: c(f"\n[+] ROT13: {rot13(text)}", Colors.G),
        "morse-e": lambda: c(f"\n[+] Morse: {morse_encode(text)}", Colors.G),
        "caesar": lambda: c(f"\n[+] Caesar (shift {args.shift}): {caesar(text, args.shift)}", Colors.G),
        "caesar-bf": lambda: caesar_bruteforce(text),
        "vigenere": lambda: c(f"\n[+] Vigenere decoded (key={args.key}): {vigenere_decode(text, args.key)}", Colors.G),
        "xor": lambda: c(f"\n[+] XOR decoded: {xor_decode(text, args.key)}", Colors.G),
        "analyze": lambda: analyze(text),
        "hash": lambda: compute_hashes(text),
    }

    op = ops.get(args.cmd)
    if op:
        c(f"[*] Input : {text[:80]}{'...' if len(text)>80 else ''}", Colors.C)
        op()
    print()


if __name__ == "__main__":
    main()

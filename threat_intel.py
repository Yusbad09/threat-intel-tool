#!/usr/bin/env python3
"""
threat_intel.py
───────────────────────────────────────────────────────────────────
Threat Intelligence Lookup Tool
Checks IPs, domains, and file hashes against:
  - VirusTotal (IPs, domains, file hashes)
  - AbuseIPDB  (IPs only)

Usage:
  python threat_intel.py --ip 8.8.8.8
  python threat_intel.py --domain google.com
  python threat_intel.py --hash 44d88612fea8a8f36de82e1278abb02f
  python threat_intel.py --ip 1.2.3.4 --domain evil.com --hash abc123
"""

import argparse
import json
import os
import sys
import hashlib
from datetime import datetime

import requests
from dotenv import load_dotenv
from colorama import Fore, Style, init

# Initialise colorama for Windows terminal colour support
init(autoreset=True)

# Load API keys from .env file
load_dotenv()
VT_API_KEY      = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY")

VT_BASE_URL     = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL   = "https://api.abuseipdb.com/api/v2/check"


# ── HELPERS ───────────────────────────────────────────────────────

def print_banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════════════════════════╗
║         Threat Intelligence Lookup Tool v1.0             ║
║         VirusTotal + AbuseIPDB                           ║
╚══════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)


def print_header(title):
    print(Fore.CYAN + f"\n{'═' * 55}")
    print(f"  {title}")
    print(f"{'═' * 55}" + Style.RESET_ALL)


def verdict_color(malicious, suspicious, total):
    """Return colour based on detection ratio."""
    if malicious == 0 and suspicious == 0:
        return Fore.GREEN
    elif malicious <= 2:
        return Fore.YELLOW
    else:
        return Fore.RED


def format_verdict(malicious, suspicious, total):
    color = verdict_color(malicious, suspicious, total)
    if malicious == 0 and suspicious == 0:
        verdict = "CLEAN"
    elif malicious <= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"
    return color + f"  Verdict     : {verdict} ({malicious} malicious, {suspicious} suspicious / {total} engines)" + Style.RESET_ALL


def check_api_keys():
    missing = []
    if not VT_API_KEY:
        missing.append("VIRUSTOTAL_API_KEY")
    if not ABUSEIPDB_KEY:
        missing.append("ABUSEIPDB_API_KEY")
    if missing:
        print(Fore.RED + f"\n[ERROR] Missing API keys in .env file: {', '.join(missing)}")
        print("        Copy .env.example to .env and add your keys.\n" + Style.RESET_ALL)
        sys.exit(1)


# ── VIRUSTOTAL ────────────────────────────────────────────────────

def vt_lookup(endpoint, label):
    """Generic VirusTotal lookup."""
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(
            f"{VT_BASE_URL}/{endpoint}",
            headers=headers,
            timeout=15
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(Fore.YELLOW + f"  [VirusTotal] {label} not found in database." + Style.RESET_ALL)
        elif response.status_code == 401:
            print(Fore.RED + "  [VirusTotal] Invalid API key." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"  [VirusTotal] Error {response.status_code}: {response.text}" + Style.RESET_ALL)
    except requests.exceptions.Timeout:
        print(Fore.RED + "  [VirusTotal] Request timed out." + Style.RESET_ALL)
    except requests.exceptions.ConnectionError:
        print(Fore.RED + "  [VirusTotal] Connection error — check your internet." + Style.RESET_ALL)
    return None


def check_ip_virustotal(ip):
    print(Fore.BLUE + "\n  [VirusTotal] Checking IP..." + Style.RESET_ALL)
    data = vt_lookup(f"ip_addresses/{ip}", ip)
    if not data:
        return

    attr        = data.get("data", {}).get("attributes", {})
    stats       = attr.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    total       = sum(stats.values())
    country     = attr.get("country", "Unknown")
    owner       = attr.get("as_owner", "Unknown")
    reputation  = attr.get("reputation", "N/A")

    print(f"  Country     : {country}")
    print(f"  ASN Owner   : {owner}")
    print(f"  Reputation  : {reputation}")
    print(format_verdict(malicious, suspicious, total))


def check_domain_virustotal(domain):
    print(Fore.BLUE + "\n  [VirusTotal] Checking domain..." + Style.RESET_ALL)
    data = vt_lookup(f"domains/{domain}", domain)
    if not data:
        return

    attr        = data.get("data", {}).get("attributes", {})
    stats       = attr.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    total       = sum(stats.values())
    registrar   = attr.get("registrar", "Unknown")
    creation    = attr.get("creation_date", "Unknown")
    reputation  = attr.get("reputation", "N/A")
    categories  = attr.get("categories", {})
    cat_values  = list(set(categories.values()))[:3] if categories else ["None"]

    print(f"  Registrar   : {registrar}")
    print(f"  Created     : {creation}")
    print(f"  Reputation  : {reputation}")
    print(f"  Categories  : {', '.join(cat_values)}")
    print(format_verdict(malicious, suspicious, total))


def check_hash_virustotal(file_hash):
    print(Fore.BLUE + "\n  [VirusTotal] Checking file hash..." + Style.RESET_ALL)
    data = vt_lookup(f"files/{file_hash}", file_hash)
    if not data:
        return

    attr        = data.get("data", {}).get("attributes", {})
    stats       = attr.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    total       = sum(stats.values())
    file_type   = attr.get("type_description", "Unknown")
    file_name   = attr.get("meaningful_name", "Unknown")
    file_size   = attr.get("size", "Unknown")
    first_seen  = attr.get("first_submission_date", None)

    if first_seen:
        first_seen = datetime.utcfromtimestamp(first_seen).strftime("%Y-%m-%d %H:%M UTC")

    print(f"  File Name   : {file_name}")
    print(f"  File Type   : {file_type}")
    print(f"  File Size   : {file_size} bytes" if isinstance(file_size, int) else f"  File Size   : {file_size}")
    print(f"  First Seen  : {first_seen or 'Unknown'}")
    print(format_verdict(malicious, suspicious, total))


# ── ABUSEIPDB ─────────────────────────────────────────────────────

def check_ip_abuseipdb(ip):
    print(Fore.BLUE + "\n  [AbuseIPDB] Checking IP reputation..." + Style.RESET_ALL)
    headers = {
        "Key"    : ABUSEIPDB_KEY,
        "Accept" : "application/json"
    }
    params = {
        "ipAddress"    : ip,
        "maxAgeInDays" : 90,          # Reports from last 90 days
        "verbose"      : True
    }
    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=15
        )
        if response.status_code == 200:
            data        = response.json().get("data", {})
            score       = data.get("abuseConfidenceScore", 0)
            total_rpts  = data.get("totalReports", 0)
            country     = data.get("countryCode", "Unknown")
            isp         = data.get("isp", "Unknown")
            domain      = data.get("domain", "Unknown")
            last_rpt    = data.get("lastReportedAt", "Never")
            is_tor      = data.get("isTor", False)
            is_public   = data.get("isPublic", True)

            # Score colour
            if score == 0:
                score_color = Fore.GREEN
                score_label = "CLEAN"
            elif score < 50:
                score_color = Fore.YELLOW
                score_label = "LOW RISK"
            elif score < 80:
                score_color = Fore.YELLOW
                score_label = "MEDIUM RISK"
            else:
                score_color = Fore.RED
                score_label = "HIGH RISK"

            print(f"  ISP         : {isp}")
            print(f"  Domain      : {domain}")
            print(f"  Country     : {country}")
            print(f"  TOR Node    : {'Yes' if is_tor else 'No'}")
            print(f"  Reports     : {total_rpts} (last 90 days)")
            print(f"  Last Report : {last_rpt}")
            print(score_color + f"  Abuse Score : {score}% — {score_label}" + Style.RESET_ALL)

        elif response.status_code == 401:
            print(Fore.RED + "  [AbuseIPDB] Invalid API key." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"  [AbuseIPDB] Error {response.status_code}" + Style.RESET_ALL)

    except requests.exceptions.Timeout:
        print(Fore.RED + "  [AbuseIPDB] Request timed out." + Style.RESET_ALL)
    except requests.exceptions.ConnectionError:
        print(Fore.RED + "  [AbuseIPDB] Connection error — check your internet." + Style.RESET_ALL)


# ── MAIN ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Lookup — VirusTotal + AbuseIPDB",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ip",     help="IP address to investigate")
    parser.add_argument("--domain", help="Domain name to investigate")
    parser.add_argument("--hash",   help="File hash (MD5/SHA1/SHA256) to investigate")
    parser.add_argument("--output", help="Save results to a JSON file", metavar="FILE")

    args = parser.parse_args()

    if not any([args.ip, args.domain, args.hash]):
        parser.print_help()
        sys.exit(0)

    print_banner()
    check_api_keys()

    results = {
        "timestamp" : datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "results"   : {}
    }

    # ── IP lookup ──
    if args.ip:
        print_header(f"IP Address: {args.ip}")
        check_ip_virustotal(args.ip)
        check_ip_abuseipdb(args.ip)
        results["results"]["ip"] = args.ip

    # ── Domain lookup ──
    if args.domain:
        print_header(f"Domain: {args.domain}")
        check_domain_virustotal(args.domain)
        results["results"]["domain"] = args.domain

    # ── Hash lookup ──
    if args.hash:
        print_header(f"File Hash: {args.hash}")
        check_hash_virustotal(args.hash)
        results["results"]["hash"] = args.hash

    print(Fore.CYAN + f"\n{'═' * 55}")
    print(f"  Scan complete — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'═' * 55}\n" + Style.RESET_ALL)

    # ── Optional JSON output ──
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(Fore.GREEN + f"  Results saved to {args.output}\n" + Style.RESET_ALL)


if __name__ == "__main__":
    main()

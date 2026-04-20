# 🔍 Threat Intelligence Lookup Tool

A command-line threat intelligence tool that investigates IP addresses, domains, and file hashes against multiple threat intelligence sources simultaneously — giving SOC analysts and security engineers instant, consolidated verdicts without manually querying each platform.

Built from real-world SOC experience where manual lookups across multiple platforms slow down incident triage.

---

## 🔎 What It Does

| Input | Sources Queried | Output |
|---|---|---|
| IP Address | VirusTotal + AbuseIPDB | Detection ratio, abuse score, ASN, country, TOR status, report history |
| Domain | VirusTotal | Detection ratio, registrar, creation date, categories, reputation |
| File Hash | VirusTotal | Detection ratio, file type, file name, first seen date |

All results are **colour-coded by severity** — green (clean), yellow (suspicious), red (malicious) — for fast visual triage.

---

## 🏗️ Architecture

```
threat_intel.py
│
├── VirusTotal API v3
│   ├── /ip_addresses/{ip}
│   ├── /domains/{domain}
│   └── /files/{hash}
│
└── AbuseIPDB API v2
    └── /check (IP reputation + report history)
```

---

## ⚙️ Setup

### 1. Clone the repository
```bash
git clone https://github.com/yusbad09/threat-intel-tool.git
cd threat-intel-tool
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API keys
```bash
cp .env.example .env
```

Edit `.env` and add your keys:
```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

Get your free API keys:
- **VirusTotal**: https://virustotal.com → Profile → API Key
- **AbuseIPDB**: https://abuseipdb.com → Account → API → Create Key

---

## 🚀 Usage

### Check an IP address
```bash
python threat_intel.py --ip 1.2.3.4
```

### Check a domain
```bash
python threat_intel.py --domain suspicious-domain.com
```

### Check a file hash (MD5, SHA1, or SHA256)
```bash
python threat_intel.py --hash 44d88612fea8a8f36de82e1278abb02f
```

### Check multiple indicators at once
```bash
python threat_intel.py --ip 1.2.3.4 --domain evil.com --hash abc123def456
```

### Save results to JSON (for reporting or SIEM ingestion)
```bash
python threat_intel.py --ip 1.2.3.4 --output report.json
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════╗
║         Threat Intelligence Lookup Tool v1.0             ║
║         VirusTotal + AbuseIPDB                           ║
╚══════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════
  IP Address: 185.220.101.1
═══════════════════════════════════════════════════════

  [VirusTotal] Checking IP...
  Country     : DE
  ASN Owner   : Tor Exit Node
  Reputation  : -100
  Verdict     : MALICIOUS (14 malicious, 3 suspicious / 89 engines)

  [AbuseIPDB] Checking IP reputation...
  ISP         : Frantech Solutions
  Domain      : frantech.ca
  Country     : DE
  TOR Node    : Yes
  Reports     : 2,847 (last 90 days)
  Last Report : 2024-03-18T04:12:00+00:00
  Abuse Score : 100% — HIGH RISK

═══════════════════════════════════════════════════════
  Scan complete — 2024-03-18 08:45 UTC
═══════════════════════════════════════════════════════
```

---

## 🔐 Security Design

- API keys stored in `.env` file — never hardcoded
- `.env` is git-ignored — keys never reach version control
- Timeout handling on all API calls — prevents script hanging
- Graceful error handling — invalid keys, network errors, and 404s all handled cleanly

---

## 🔧 Extending the Tool

The script is designed to be modular. To add a new threat intel source:
1. Add the API key to `.env.example` and `.env`
2. Write a new `check_*` function following the same pattern
3. Call it from `main()` under the appropriate argument block

Potential additions:
- **Shodan** — open port and service fingerprinting for IPs
- **URLScan.io** — screenshot and full analysis of URLs
- **GreyNoise** — distinguish scanners from targeted attackers
- **AlienVault OTX** — community threat intelligence feeds

---

## 📌 Real-World Context

Built to replicate and automate the manual threat intelligence lookups performed daily during SOC operations — checking indicators from firewall logs, email headers, and endpoint alerts against multiple reputation sources. The `--output` flag enables integration with ticketing systems and SIEM workflows by producing structured JSON reports.

---

## 🛡️ Related Skills

`Python` · `Threat Intelligence` · `SOC Operations` · `VirusTotal API` · `AbuseIPDB` · `Incident Response` · `Security Automation` · `REST APIs` · `CLI Tools`

---

## 📄 License

MIT License — free to use and adapt with attribution.

---

## 👤 Author

**Yusuf Akinkunmi Badrudeen**
Cybersecurity & Cloud Security Engineer
[LinkedIn](https://www.linkedin.com/in/badrudeen-yusuf-akinkunmi-6692b819b/) · [Portfolio](https://yusbad09.github.io/)

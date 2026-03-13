<div align="center">

```
██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔══██╗   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

# RAPTOR — Advanced Automated Web Application Security Testing Tool

**Reconnaissance · Exploitation · Reporting**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/Version-3.0-red?style=flat-square)

*A zero-dependency, async Python security framework for bug bounty hunters and penetration testers.*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Output & Reports](#output--reports)
- [Configuration](#configuration)
- [Neo4j Setup](#neo4j-setup)
- [Legal & Ethics](#legal--ethics)

---

## Overview

RAPTOR is a comprehensive, **Kali Linux-native** offensive security framework designed for professional bug bounty hunting and authorized penetration testing. It implements **intelligent attack chaining** — automatically correlating reconnaissance findings with multi-vector vulnerability testing to discover complex vulnerability chains that single-purpose tools miss.

Unlike tools that rely on heavy dependency stacks, RAPTOR runs on **zero external packages** — pure Python stdlib only (`asyncio`, `urllib`, `sqlite3`, `html.parser`). Drop it on any Kali box and run immediately.

```
Target → Recon → Server → XSS → SQLi → IDOR → Brute → Correlated Report
```

---

## Features

| Feature | Details |
|---|---|
| **Zero Dependencies** | No pip install. Pure Python stdlib — runs on any Kali Linux out of the box |
| **Async Architecture** | All modules execute concurrently via `asyncio.gather()` with semaphore control |
| **Attack Correlation** | Graph-based engine chains findings across modules (e.g. info-disclosure → IDOR → privilege escalation) |
| **Stealth Mode** | Request jitter, randomized User-Agents, adaptive rate control, proxy support |
| **WAF Evasion** | Encoding chains, case variation, chunked payloads — max evasion by default |
| **CVSS 3.1 Scoring** | Every finding gets a CVSS score and estimated bug bounty reward |
| **Markdown Reports** | Reports compatible with HackerOne, Bugcrowd, and Synack submission formats |
| **Optional Neo4j** | Visual attack path mapping (falls back to SQLite gracefully if unavailable) |

---

## Architecture

```
raptor/
├── raptor.py                    ← Single entry point
├── config/
│   └── config.yaml              ← Scan configuration
├── core/
│   ├── _yaml_lite.py            ← Zero-dep YAML parser
│   ├── _console.py              ← Zero-dep terminal renderer
│   ├── base_module.py           ← Async HTTP engine (urllib-backed)
│   ├── database_manager.py      ← SQLite persistence layer
│   ├── correlator.py            ← Attack path correlation engine
│   ├── report_manager.py        ← Markdown report generator
│   └── graph_manager.py         ← Neo4j integration (optional)
├── modules/
│   ├── recon/
│   │   ├── subdomain_enum.py    ← CT logs, DNS brute, tool wrappers
│   │   └── tech_fingerprint.py  ← Header/HTML/JS technology detection
│   ├── server_misconfig/
│   │   ├── header_audit.py      ← HTTP security header analysis
│   │   └── sensitive_files.py   ← Exposed file scanner (50+ paths)
│   ├── xss/
│   │   └── xss_tester.py        ← Reflected, DOM, Blind XSS
│   ├── sqli/
│   │   └── sqli_tester.py       ← Error, Boolean, Time, UNION injection
│   ├── idor/
│   │   └── idor_tester.py       ← ID fuzzing, REST manipulation
│   └── brute_force/
│       └── credential_tester.py ← Login discovery & brute force
├── wordlists/
│   ├── usernames.txt
│   ├── passwords.txt
│   └── sensitive_paths.txt
└── reports/output/              ← Generated reports land here
```

---

## Installation

**Requirements:** Python 3.10+, Kali Linux (or any Debian-based OS)

```bash
# Clone the repository
git clone https://github.com/AbasMustafa-Crypto/raptor.git
cd raptor

# That's it. No pip install needed.
python3 raptor.py --help
```

**Optional — install external recon tools for enhanced subdomain enumeration:**

```bash
# Subfinder (recommended)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
sudo apt install amass

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest
```

> RAPTOR works without these tools — it falls back to Certificate Transparency logs and DNS brute-forcing automatically.

---

## Usage

### Basic Scan (Full Power by Default)

```bash
python3 raptor.py -t https://target.com
```

Runs all modules (`recon`, `server`, `xss`, `sqli`, `idor`) at max aggressiveness automatically.

### Targeted Module Testing

```bash
# Server misconfiguration only
python3 raptor.py -t https://target.com --modules server

# Web vulnerability testing
python3 raptor.py -t https://target.com --modules xss,sqli,idor

# Reconnaissance only
python3 raptor.py -t https://target.com --modules recon
```

### Authenticated Scanning

```bash
# With session cookie
python3 raptor.py -t https://target.com --cookie "session=abc123; auth=token"

# With Authorization header
python3 raptor.py -t https://target.com --auth-header "Bearer eyJhbGci..."
```

### Stealth Mode

```bash
# Adds request jitter and rate control to avoid detection
python3 raptor.py -t https://target.com --stealth
```

### Brute Force

```bash
# Requires explicit flag — discovers login forms and tests credentials
python3 raptor.py -t https://target.com --modules brute --enable-brute-force
```

### Through a Proxy (e.g. Burp Suite)

```bash
python3 raptor.py -t https://target.com --proxy http://127.0.0.1:8080
```

### Full Command Reference

```
Required:
  -t, --target          Target URL or domain

Modules:
  --modules LIST        Comma-separated: recon,server,xss,sqli,idor,brute
                        Default: recon,server,xss,sqli,idor (all non-brute)
  --full-scan           Explicit alias for all non-brute modules
  --enable-brute-force  Enable brute force module (explicit permission required)

Scanning:
  --stealth             Enable stealth mode (jitter, rate control)

Auth & Proxy:
  --cookie STR          Cookie string for authenticated scanning
  --auth-header STR     Authorization header value
  --proxy URL           Proxy URL (http://host:port)

Output:
  -o, --output PATH     Custom report output path
  --config PATH         Config file (default: config/config.yaml)
  -v, --verbose         Verbose output
```

---

## Modules

### `recon` — Reconnaissance & Discovery

Discovers the attack surface before active testing begins.

- **Subdomain enumeration** via amass, subfinder, assetfinder (with automatic fallback to CT logs)
- **Technology fingerprinting** — detects CMS, frameworks, CDN, hosting provider from headers and HTML
- **Endpoint discovery** — crawls target and extracts API endpoints from JavaScript
- **Certificate Transparency** — queries crt.sh for historical subdomain data

```bash
python3 raptor.py -t https://target.com --modules recon
```

---

### `server` — Server Misconfiguration

Audits server configuration for common security failures.

- **Security header audit** — checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more
- **Sensitive file exposure** — probes 50+ paths including `.git/config`, `.env`, `backup.zip`, `phpinfo.php`
- **Information disclosure** — detects server version banners and debug output

```bash
python3 raptor.py -t https://target.com --modules server
```

---

### `xss` — Cross-Site Scripting

Tests all XSS injection contexts with WAF evasion.

- **Reflected XSS** — parameter-based injection with context-aware payloads
- **DOM-based XSS** — source/sink analysis in JavaScript
- **Blind XSS** — out-of-band callback payloads for stored/delayed execution
- **WAF bypass** — encoding chains, case variation, event handler obfuscation

```bash
python3 raptor.py -t https://target.com --modules xss
```

---

### `sqli` — SQL Injection

Detects injection across all major database engines.

- **Error-based** — MySQL, PostgreSQL, MSSQL, Oracle, SQLite error signature detection
- **Boolean-blind** — true/false response differential analysis
- **Time-blind** — sleep-based injection with timing measurement
- **UNION-based** — column enumeration and data extraction

```bash
python3 raptor.py -t https://target.com --modules sqli
```

---

### `idor` — Insecure Direct Object Reference

Discovers broken object-level authorization.

- **Sequential ID fuzzing** — tests ±5 IDs around any discovered numeric reference
- **RESTful manipulation** — detects and tests `/api/v1/users/{id}` patterns
- **Parameter pollution** — HPP bypass testing
- **Mass assignment** — probes for privileged field injection (`role`, `isAdmin`)

```bash
python3 raptor.py -t https://target.com --modules idor
```

---

### `brute` — Brute Force & Authentication

Tests authentication strength. **Requires explicit permission.**

- **Login form discovery** — automatically finds login endpoints across the target
- **Credential testing** — tests username/password combinations from wordlists
- **Rate limit detection** — identifies missing account lockout mechanisms
- **Credential reporting** — prints found credentials loudly in terminal and report

```bash
python3 raptor.py -t https://target.com --modules brute --enable-brute-force
```

---

## Output & Reports

Reports are automatically saved to `reports/output/` after every scan.

### Terminal Output

```
Security Findings Summary
╭──────────┬───────╮
│ Severity │ Count │
├──────────┼───────┤
│ Critical │     3 │
│ High     │     1 │
│ Medium   │     2 │
╰──────────┴───────╯

▶ Exposed Sensitive File: .git/config (Critical)
  PoC: curl https://target.com/.git/config

▶ Missing Security Header: Content-Security-Policy (High)
  PoC: curl -I https://target.com | grep -i Content-Security-Policy
```

### Markdown Report Structure

```markdown
# RAPTOR Security Assessment Report

**Target:** https://target.com
**Total Findings:** 6

## Executive Summary
⚠️ 4 Critical/High severity issues found

## Findings

### Exposed Sensitive File: .git/config
- **Severity:** Critical
- **CVSS Score:** 9.1
- **Bounty Score:** $3000
- **PoC:** curl https://target.com/.git/config
- **Remediation:** Remove .git directory from web root...
```

---

## Configuration

Edit `config/config.yaml` to customize scan behaviour:

```yaml
scan:
  timeout: 30
  rate_limit: 50
  max_depth: 5
  scope: aggressive

stealth:
  min_delay: 0.5
  max_delay: 2.0
  rotate_user_agents: true

database:
  path: data/raptor.db

modules:
  brute_force:
    max_attempts: 200
    wordlist_path: wordlists/
```

---

## Neo4j Setup

Neo4j is **optional** — RAPTOR falls back to SQLite-based correlation automatically if it is not installed. The warning `[!] Neo4j driver not installed. Graph features disabled.` is harmless if graph mapping is not needed.

To enable visual attack path mapping, follow these three steps:

### Step 1 — Install the Python driver

```bash
pip install neo4j
```

### Step 2 — Install the Neo4j database server

On Kali Linux / Debian:

```bash
# Add the Neo4j repository
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list

# Install
sudo apt update
sudo apt install neo4j -y

# Start and enable on boot
sudo systemctl start neo4j
sudo systemctl enable neo4j
```

On first start, open **http://localhost:7474** in a browser. Default login is `neo4j / neo4j` — you will be forced to change the password immediately.

### Step 3 — Configure RAPTOR

You have two ways to connect RAPTOR to Neo4j:

#### Option A: Interactive Sync (Easiest)
Simply run your scan. At the end, RAPTOR will detect if Neo4j is available and ask if you'd like to sync the results:
```text
Would you like to sync results to Neo4j for visual representation? (y/n)
 > y
 Neo4j URI [bolt://localhost:7687]: 
 Neo4j User [neo4j]: 
 Neo4j Password: 
```
This is perfect for one-off syncs or when using different Neo4j instances.

#### Option B: Persistent Configuration
Add to `config/config.yaml` or use Environment Variables:

```yaml
graph:
  enabled:  true
  neo4j_uri: "bolt://localhost:7687"
  neo4j_user: "neo4j"
  neo4j_password: "your_password"
```

**Environment Variables:**
```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your_password"
```

---

## Legal & Ethics

> **RAPTOR is for authorized security testing only.**
>
> Using this tool against systems without **explicit written permission** is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent legislation worldwide.
>
> - Only test systems you own or have written authorization to test
> - Brute force module (`--enable-brute-force`) can lock user accounts — use with extreme caution
> - The `--stealth` flag does not make testing legal — only authorization does
> - The developers assume zero liability for unauthorized or malicious use

---

<div align="center">

**RAPTOR v2.0** — Built for Authorized Security Research

*Reconnaissance · Attack · Penetration · Testing · Orchestration · Resource*

</div>

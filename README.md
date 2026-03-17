<div align="center">

```
██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔══██╗   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

# RAPTOR — Enterprise Automated Web Security Testing Framework

**Reconnaissance · Exploitation · Authorization · Intelligence**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/Version-4.0--Enterprise-red?style=flat-square)

*A zero-dependency, professional-grade Python security framework for elite bug bounty hunters and red teams.*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Enterprise Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Professional Modules](#modules)
- [Reporting](#output--reports)
- [Neo4j Visualization](#neo4j-setup)
- [Legal & Ethics](#legal--ethics)

---

## Overview

RAPTOR v4.0 is a comprehensive, **Kali Linux-native** offensive security framework designed for enterprise-scale infrastructure auditing. It implements an **Intelligent Workflow Engine** — automatically chaining reconnaissance findings with multi-vector vulnerability testing to discover complex high-impact security flaws that standard scanners miss.

Unlike tools that rely on heavy dependency stacks, RAPTOR runs on **zero external packages** — pure Python stdlib only.

```
Target → Recon → Endpoint Discovery → Parameter Discovery → Multi-Vector Fuzz → SQLi → IDOR → Server Audit → Brute Audit → Final Report
```

---

## Enterprise Features

| Feature | Details |
|---|---|
| **Workflow Engine** | Stateful pipeline that passes intelligence automatically between scan phases. |
| **Zero Dependencies** | Pure Python stdlib — runs on any Kali/Debian box out of the box. |
| **Async Performance** | Massive concurrency via `asyncio.gather()` with optimized semaphore flow control. |
| **Endpoint Discovery** | Recursive directory discovery with wildcard/soft-404 anomaly detection. |
| **Param Discovery** | Identifies hidden GET/POST/JSON parameters via behavioral analysis & JS extraction. |
| **Identity Fingerprinting** | (IDOR) Detects authorization flaws via behavioral response similarity mapping. |
| **WAF Evasion Engine** | (SQLi) Dynamic payload mutation (Case, Comments, Hex, Scientific notation). |
| **Password Spraying** | (Brute) Horizontal spraying to circumvent enterprise account lockout policies. |
| **SSL/TLS Auditing** | Pro-grade audit of protocols (TLS 1.0-1.3), certificate chains, and weak ciphers. |
| **CVSS 3.1 Scoring** | Every finding includes high-fidelity CVSS scores and bounty estimates. |

---

## Architecture

```
raptor/
├── raptor.py                    ← Core Workflow Engine / CLI Entry
├── config/
│   └── config.yaml              ← Global Scan Configuration
├── core/
│   ├── base_module.py           ← Async HTTP Engine (urllib-backed + URL Encoding)
│   ├── database_manager.py      ← SQLite Persistence Layer
│   ├── correlator.py            ← Attack Path Correlation Engine
│   └── graph_manager.py         ← Neo4j Intelligence Integration
├── modules/
│   ├── recon/
│   │   ├── subdomain_enum.py    ← Subdomain Discovery Suite
│   │   ├── tech_fingerprint.py  ← Technology Stack Analysis
│   │   ├── port_scanner.py      ← High-speed Async TCP Scanner
│   │   ├── dns_analyzer.py      ← Takeover & DNS Config Audit
│   │   └── endpoint_fuzzer.py   ← Recursive Directory & API Discovery
│   ├── server_misconfig/
│   │   ├── header_audit.py      ← Enterprise Security Header Audit
│   │   ├── sensitive_files.py   ← 150+ Sensitive Path Probes
│   │   └── ssl_tester.py        ← Professional SSL/TLS Assessment
│   ├── fuzzing/
│   │   ├── param_discovery.py   ← Hidden Parameter Discovery (JS/HTML Analysis)
│   │   └── param_fuzzer.py      ← Advanced Anomaly Detection Fuzzer
│   ├── sqli/
│   │   └── sqli_tester.py       ← Multi-Vector SQLi & Data Extraction
│   ├── idor/
│   │   └── idor_tester.py       ← Behavioral Authorization Audit
│   └── brute_force/
│       └── credential_tester.py ← Auth Auditing & Password Spraying
└── wordlists/
    ├── dirs.txt                 ← Directory Wordlist (Optimized)
    ├── params.txt               ← Parameter Wordlist (Optimized)
    ├── sensitive_paths.txt      ← Server Path Wordlist
    └── usernames.txt/passwords.txt
```

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/AbasSec/raptor.git
cd raptor

# No pip install needed. Pure Stdlib.
python3 raptor.py --help
```

---

## Usage

### Professional Standard Scan

```bash
# Aggressive audit of all non-brute modules
python3 raptor.py -t https://target.com
```

### Full Enterprise Audit

```bash
# Includes password spraying and hidden portal discovery
python3 raptor.py -t https://target.com --full-scan --enable-brute-force
```

### Stealth Mode

```bash
# Adds request jitter and randomized headers to avoid WAF/IDS triggers
python3 raptor.py -t https://target.com --stealth
```

---

## Professional Modules

### `recon` — Infrastructure Intelligence
- **Subdomain Discovery** — Multi-tool aggregation with CT Log fallbacks.
- **Port Scanning** — Async TCP scanning of top 100+ services with banner grabbing.
- **Endpoint Fuzzing** — Recursive directory discovery with optimized wordlists and soft-404 detection.
- **DNS Audit** — Subdomain takeover detection, AXFR checks, and DMARC/SPF analysis.

### `fuzz` — Hidden Discovery & Anomaly Detection
- **Parameter Discovery** — Identifies hidden GET/POST/JSON parameters via JS analysis and behavioral differential.
- **Anomaly Detection** — Detects valid discovery via status changes, size deltas, and timing side-channels.
- **Optimization** — Automatically filters static assets and redundant patterns for high-speed operation.

### `server` — Configuration Audit
- **Header Audit** — Deep audit of CSP, HSTS, XFO, CORS, and Cookie flags.
- **Path Probing** — Probes 150+ paths (VCS, CI/CD, Cloud Config, Backup Archives).
- **SSL/TLS Assessment** — Native audit of protocols, ciphers, and certificate validity.

### `sqli` — Advanced Injection Engine
- **Multi-Vector** — Error-based, Boolean-blind, Time-blind, and UNION extraction.
- **WAF Evasion** — Intelligent payload mutation when security filters are detected.
- **Data Extraction** — Automatically extracts DB version and identifies privileged users.

### `idor` — Authorization Audit
- **Behavioral Mapping** — Detects IDOR via structural and content similarity analysis.
- **Multi-Vector** — ID Shifting, Verb Tampering, and HPP bypass techniques.
- **Mass Assignment** — Aggressively probes for privileged field injection in API bodies.

### `brute` — Authentication Audit
- **Password Spraying** — Horizontal testing to bypass standard lockout policies.
- **Discovery** — Dynamically locates login portals and API authentication endpoints.
- **Anomaly Detection** — Uses failure baselines to detect success via response differentials.

---

## Legal & Ethics

> **RAPTOR is for authorized security testing only.**
>
> Using this tool against systems without **explicit written permission** is illegal. The developers assume zero liability for unauthorized or malicious use.

---

<div align="center">

**RAPTOR v4.0** — Built for Elite Security Research

*AbasSec · student of cyber Security*

</div>

# RAPTOR - Advanced Web Application Security Testing Framework

## ⚠️ LEGAL DISCLAIMER

&gt; **WARNING: This tool is for authorized security testing only!**
&gt; 
&gt; **Use only on systems you own or have explicit written permission to test.**
&gt; 
&gt; **Unauthorized access to computer systems is illegal under CFAA, Computer Misuse Act, and similar international laws.**
&gt; 
&gt; The authors assume no liability for misuse or damage caused by this program.

---

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Module Documentation](#module-documentation)
- [Configuration](#configuration)
- [Wordlists](#wordlists)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Description

RAPTOR is a comprehensive, Kali Linux-native offensive security framework designed specifically for bug bounty hunters and penetration testers. It implements intelligent attack chaining — correlating reconnaissance data with multi-vector vulnerability testing to identify exploitable attack paths.

**Core Philosophy:** *"One confirmed vulnerability is worth a thousand theoretical findings"*

### Key Capabilities

| Capability | Description |
|-----------|-------------|
| **Intelligent Correlation** | Links findings across modules to discover complex attack chains |
| **Stealth Operations** | Built-in evasion techniques, rate limiting, and randomization |
| **Zero External Dependencies** | Works out-of-the-box without pip install hassles on Kali |
| **Database Persistence** | SQLite/Neo4j backend for large-scale assessments |
| **Professional Reporting** | Markdown reports with CVSS scoring and bounty estimates |

---

## Features

### 🔍 Reconnaissance Module
- **Subdomain Enumeration**: Passive discovery via Certificate Transparency logs, DNS brute force
- **Technology Fingerprinting**: Detects 100+ technologies with version detection
- **Cloud Asset Discovery**: Identifies AWS S3 buckets, Azure blobs, GCP storage
- **Service Detection**: Identifies open ports and running services

### ⚙️ Server Misconfiguration
- **Security Header Audit**: Checks HSTS, CSP, X-Frame-Options, and 15+ headers
- **SSL/TLS Analysis**: Certificate validation, cipher suite assessment
- **Sensitive File Detection**: Discovers backup files, config leaks, .env exposures
- **Method Enumeration**: HTTP verb tampering tests

### 🔓 IDOR Testing
- **Object Reference Manipulation**: Automated IDOR vulnerability detection
- **Parameter Fuzzing**: Tests for insecure direct object references
- **Access Control Bypass**: Horizontal and vertical privilege escalation tests

### 🔐 Authentication Testing
- **JWT Analysis**: Token validation, algorithm confusion, secret brute force
- **Session Management**: Cookie security, fixation, predictable tokens
- **Brute Force Protection**: Rate limiting detection, account lockout testing
- **Credential Stuffing**: Custom wordlist support with intelligent detection

### 🛡️ Stealth & Evasion
- **Request Randomization**: Rotating user agents, headers, and timing
- **Proxy Support**: HTTP/HTTPS/SOCKS proxy rotation
- **Rate Limit Adaptation**: Auto-adjusts delays based on 429/503 responses
- **Header Spoofing**: X-Forwarded-For, X-Real-IP bypass attempts

---

## Installation

### Prerequisites

- Kali Linux (recommended) or any Debian-based system
- Python 3.8+
- No external tool dependencies required

### Direct Clon:

```bash
# Clone the repository
git clone https://github.com/AbasMustafa-Crypto/raptor.git

# Navigate to directory
cd raptor

# The tool works immediately - no pip install needed!
python3 raptor.py --help

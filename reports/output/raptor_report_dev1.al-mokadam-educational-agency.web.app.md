# RAPTOR Security Assessment Report

**Target:** dev1.al-mokadam-educational-agency.web.app

**Total Findings:** 421

## Executive Summary

## Findings

### Staging/Dev Environment Exposed: dev1.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'dev' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://dev1.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: preprod.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'preprod' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://preprod.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: test1.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'test' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://test1.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: testing.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'test' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://testing.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: dev2.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'dev' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://dev2.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: speedtest.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'test' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://speedtest.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: preview.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'preview' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://preview.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: devel.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'dev' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://devel.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: qa.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'qa' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://qa.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: development.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'dev' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://development.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Staging/Dev Environment Exposed: test3.al-mokadam-educational-agency.web.app

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 500
- **Description:** Discovered a 'test' environment that may have weaker security controls than production.
- **Proof of Concept:**
```
https://test3.al-mokadam-educational-agency.web.app
```
- **Remediation:** Apply the same security controls (auth, headers, TLS) to non-production environments as production.

### Hidden Parameter Discovered: admin (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `admin` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter admin=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: debug (HEADER)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `debug` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `HEADER` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X HEADER 'https://al-mokadam-educational-agency.web.app/' (with parameter debug=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: secret (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `secret` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter secret=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: client_secret (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `client_secret` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter client_secret=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: admin (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `admin` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter admin=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: debug (HEADER)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `debug` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `HEADER` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X HEADER 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter debug=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: secret (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `secret` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter secret=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: client_secret (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `client_secret` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter client_secret=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: admin (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `admin` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter admin=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: debug (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `debug` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter debug=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: secret (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `secret` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter secret=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: client_secret (POST_JSON)

- **Severity:** Medium
- **CVSS Score:** 5.3
- **Bounty Score:** 300
- **Description:** ## Hidden Parameter Discovery

The parameter `client_secret` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter client_secret=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Missing SPF Record (Email Spoofing)

- **Severity:** Medium
- **CVSS Score:** 4.3
- **Bounty Score:** 200
- **Description:** The domain web.app is missing an SPF record, making it vulnerable to email spoofing.
- **Proof of Concept:**
```
host -t TXT web.app
```
- **Remediation:** Add an SPF TXT record (e.g., v=spf1 -all) to DNS.

### Missing DMARC Record

- **Severity:** Medium
- **CVSS Score:** 4.3
- **Bounty Score:** 250
- **Description:** The domain web.app is missing a DMARC record, severely weakening email spoofing protections.
- **Proof of Concept:**
```
host -t TXT _dmarc.web.app
```
- **Remediation:** Add a DMARC record with p=reject or p=quarantine.

### Hidden Parameter Discovered: token (HEADER)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `token` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `HEADER` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X HEADER 'https://al-mokadam-educational-agency.web.app/' (with parameter token=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dry_run (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dry_run` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter dry_run=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pin (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pin` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter pin=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: preview (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `preview` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter preview=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: log (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `log` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter log=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: limit (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `limit` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter limit=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pretty (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pretty` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter pretty=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: password (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `password` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter password=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: type (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `type` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter type=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: ref (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `ref` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter ref=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: cat (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `cat` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter cat=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: settings (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `settings` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter settings=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: db (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `db` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter db=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: zip (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `zip` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter zip=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: uuid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `uuid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter uuid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: id_token (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `id_token` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter id_token=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: address (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `address` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter address=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: path (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `path` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter path=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: root (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `root` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter root=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: auth (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `auth` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter auth=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: callback (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `callback` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter callback=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: public (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `public` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter public=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: database (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `database` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter database=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: api_key (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `api_key` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter api_key=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: addr (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `addr` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter addr=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: file (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `file` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter file=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: setup (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `setup` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter setup=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sort (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sort` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter sort=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: system (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `system` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter system=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: hidden (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `hidden` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter hidden=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: download (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `download` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter download=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: superuser (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `superuser` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter superuser=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: page (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `page` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter page=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: xml (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `xml` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter xml=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: format (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `format` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter format=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: s (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `s` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter s=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: q (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `q` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter q=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: output (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `output` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter output=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: uid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `uid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter uid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: search (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `search` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter search=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: username (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `username` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter username=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dest (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dest` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter dest=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: verbose (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `verbose` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter verbose=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: name (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `name` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter name=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: user (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `user` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter user=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mobile (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mobile` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter mobile=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: key (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `key` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter key=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dev (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dev` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter dev=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: script (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `script` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter script=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: next (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `next` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter next=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: active (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `active` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter active=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: csrf (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `csrf` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter csrf=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter sid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: destination (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `destination` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter destination=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: filter (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `filter` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter filter=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: visible (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `visible` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter visible=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: target (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `target` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter target=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: command (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `command` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter command=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: proxy (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `proxy` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter proxy=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: environment (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `environment` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter environment=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: feature (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `feature` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter feature=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: code (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `code` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter code=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: enabled (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `enabled` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter enabled=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: state (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `state` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter state=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: email (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `email` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter email=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: config (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `config` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter config=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pass (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pass` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter pass=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: cmd (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `cmd` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter cmd=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: forward (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `forward` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter forward=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: role (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `role` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter role=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: session (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `session` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter session=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: enable (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `enable` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter enable=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: privilege (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `privilege` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter privilege=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: test (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `test` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter test=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: client_id (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `client_id` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter client_id=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: upload (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `upload` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter upload=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: exec (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `exec` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter exec=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: folder (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `folder` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter folder=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: keyword (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `keyword` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter keyword=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: id (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `id` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter id=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: phone (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `phone` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter phone=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: include (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `include` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter include=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: back (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `back` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter back=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: source (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `source` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter source=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sql (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sql` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter sql=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: expand (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `expand` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter expand=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: tag (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `tag` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter tag=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: action (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `action` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter action=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: port (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `port` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter port=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: query (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `query` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter query=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: method (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `method` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter method=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: captcha (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `captcha` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter captcha=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: internal (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `internal` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter internal=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: redirect (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `redirect` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter redirect=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: fields (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `fields` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter fields=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: wrap (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `wrap` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter wrap=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: host (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `host` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter host=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: url (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `url` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter url=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: trace (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `trace` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter trace=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: referrer (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `referrer` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter referrer=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: offset (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `offset` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter offset=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: status (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `status` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter status=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: level (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `level` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter level=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: src (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `src` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter src=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: prev (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `prev` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter prev=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: category (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `category` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter category=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: profile (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `profile` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter profile=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mode (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mode` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter mode=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: shell (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `shell` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter shell=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: ip (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `ip` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter ip=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: oauth (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `oauth` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter oauth=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: info (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `info` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter info=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: staging (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `staging` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter staging=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mock (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mock` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter mock=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: env (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `env` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter env=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: otp (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `otp` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter otp=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: access (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `access` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter access=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: version (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `version` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter version=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: private (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `private` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter private=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: json (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `json` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter json=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dir (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dir` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter dir=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: socket (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `socket` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter socket=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: disabled (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `disabled` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/' (with parameter disabled=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: token (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `token` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter token=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dry_run (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dry_run` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter dry_run=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: log (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `log` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter log=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pin (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pin` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter pin=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: preview (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `preview` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter preview=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: cat (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `cat` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter cat=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: zip (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `zip` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter zip=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: limit (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `limit` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter limit=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pretty (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pretty` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter pretty=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: ref (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `ref` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter ref=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: auth (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `auth` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter auth=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: settings (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `settings` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter settings=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: db (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `db` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter db=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: password (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `password` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter password=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: type (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `type` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter type=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: uuid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `uuid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter uuid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: id_token (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `id_token` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter id_token=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: page (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `page` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter page=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: address (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `address` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter address=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: path (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `path` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter path=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: uid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `uid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter uid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: root (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `root` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter root=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: callback (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `callback` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter callback=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: public (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `public` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter public=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: database (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `database` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter database=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: addr (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `addr` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter addr=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: api_key (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `api_key` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter api_key=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: hidden (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `hidden` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter hidden=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: setup (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `setup` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter setup=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: system (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `system` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter system=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sort (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sort` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter sort=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: file (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `file` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter file=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: superuser (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `superuser` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter superuser=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: download (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `download` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter download=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: xml (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `xml` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter xml=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: format (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `format` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter format=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: active (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `active` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter active=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: q (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `q` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter q=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: s (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `s` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter s=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: output (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `output` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter output=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: search (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `search` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter search=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dest (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dest` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter dest=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: username (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `username` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter username=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: name (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `name` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter name=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: verbose (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `verbose` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter verbose=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: user (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `user` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter user=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mobile (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mobile` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter mobile=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dev (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dev` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter dev=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: key (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `key` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter key=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: csrf (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `csrf` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter csrf=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: script (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `script` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter script=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: filter (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `filter` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter filter=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter sid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: next (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `next` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter next=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: destination (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `destination` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter destination=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: visible (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `visible` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter visible=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: command (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `command` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter command=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: target (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `target` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter target=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: feature (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `feature` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter feature=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: environment (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `environment` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter environment=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: proxy (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `proxy` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter proxy=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: enabled (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `enabled` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter enabled=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: config (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `config` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter config=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: email (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `email` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter email=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: state (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `state` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter state=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: code (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `code` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter code=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: keyword (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `keyword` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter keyword=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pass (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pass` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter pass=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: cmd (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `cmd` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter cmd=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: forward (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `forward` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter forward=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: session (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `session` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter session=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: role (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `role` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter role=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: enable (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `enable` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter enable=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: privilege (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `privilege` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter privilege=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: test (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `test` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter test=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: client_id (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `client_id` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter client_id=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: upload (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `upload` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter upload=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: folder (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `folder` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter folder=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: id (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `id` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter id=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: phone (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `phone` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter phone=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: source (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `source` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter source=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: back (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `back` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter back=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: include (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `include` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter include=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sql (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sql` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter sql=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: expand (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `expand` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter expand=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: tag (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `tag` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter tag=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: action (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `action` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter action=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: port (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `port` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter port=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: query (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `query` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter query=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: method (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `method` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter method=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: captcha (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `captcha` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter captcha=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: exec (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `exec` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter exec=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: redirect (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `redirect` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter redirect=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: internal (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `internal` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter internal=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: wrap (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `wrap` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter wrap=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: host (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `host` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter host=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: referrer (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `referrer` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter referrer=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: url (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `url` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter url=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: trace (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `trace` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter trace=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: offset (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `offset` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter offset=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: status (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `status` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter status=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: level (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `level` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter level=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: prev (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `prev` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter prev=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: src (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `src` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter src=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: fields (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `fields` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter fields=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mode (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mode` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter mode=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: disabled (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `disabled` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter disabled=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: profile (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `profile` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter profile=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: category (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `category` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter category=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: shell (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `shell` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter shell=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: ip (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `ip` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter ip=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: staging (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `staging` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter staging=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: info (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `info` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter info=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: oauth (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `oauth` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter oauth=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mock (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mock` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter mock=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: otp (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `otp` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter otp=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: env (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `env` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter env=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: private (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `private` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter private=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: version (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `version` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter version=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: access (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `access` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter access=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: json (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `json` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter json=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dir (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dir` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter dir=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: socket (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `socket` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/index.html` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 17891 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/index.html' (with parameter socket=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: token (HEADER)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `token` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `HEADER` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X HEADER 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter token=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dry_run (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dry_run` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter dry_run=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: log (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `log` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter log=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pin (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pin` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter pin=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: preview (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `preview` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter preview=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: limit (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `limit` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter limit=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pretty (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pretty` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter pretty=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: zip (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `zip` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter zip=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: cat (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `cat` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter cat=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: ref (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `ref` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter ref=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: auth (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `auth` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter auth=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: settings (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `settings` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter settings=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: password (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `password` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter password=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: db (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `db` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter db=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: type (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `type` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter type=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: uuid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `uuid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter uuid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: page (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `page` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter page=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: id_token (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `id_token` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter id_token=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: path (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `path` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter path=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: uid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `uid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter uid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: callback (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `callback` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter callback=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: public (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `public` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter public=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: database (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `database` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter database=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: addr (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `addr` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter addr=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: setup (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `setup` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter setup=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: file (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `file` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter file=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: api_key (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `api_key` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter api_key=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: hidden (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `hidden` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter hidden=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: system (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `system` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter system=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: address (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `address` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter address=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sort (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sort` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter sort=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: download (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `download` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter download=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: root (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `root` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter root=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: superuser (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `superuser` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter superuser=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: xml (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `xml` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter xml=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: active (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `active` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter active=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: format (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `format` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter format=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: s (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `s` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter s=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: q (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `q` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter q=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: search (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `search` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter search=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: username (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `username` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter username=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: name (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `name` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter name=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: verbose (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `verbose` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter verbose=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: key (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `key` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter key=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dev (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dev` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter dev=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: script (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `script` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter script=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mobile (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mobile` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter mobile=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: user (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `user` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter user=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: next (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `next` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter next=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: csrf (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `csrf` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter csrf=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sid (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sid` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter sid=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: filter (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `filter` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter filter=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: output (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `output` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter output=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: destination (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `destination` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter destination=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: visible (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `visible` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter visible=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: command (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `command` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter command=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dest (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dest` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter dest=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: target (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `target` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter target=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: feature (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `feature` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter feature=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: proxy (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `proxy` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter proxy=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: environment (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `environment` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter environment=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: enabled (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `enabled` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter enabled=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: config (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `config` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter config=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: email (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `email` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter email=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: state (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `state` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter state=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: keyword (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `keyword` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter keyword=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: cmd (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `cmd` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter cmd=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: code (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `code` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter code=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: pass (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `pass` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter pass=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: forward (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `forward` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter forward=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: role (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `role` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter role=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: session (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `session` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter session=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: enable (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `enable` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter enable=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: privilege (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `privilege` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter privilege=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: test (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `test` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter test=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: client_id (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `client_id` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter client_id=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: upload (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `upload` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter upload=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: folder (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `folder` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter folder=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: exec (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `exec` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter exec=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: id (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `id` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter id=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: phone (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `phone` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter phone=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: source (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `source` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter source=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: back (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `back` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter back=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: include (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `include` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter include=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: expand (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `expand` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter expand=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: sql (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `sql` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter sql=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: port (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `port` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter port=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: tag (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `tag` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter tag=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: action (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `action` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter action=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: query (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `query` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter query=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: captcha (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `captcha` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter captcha=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: method (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `method` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter method=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: internal (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `internal` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter internal=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: redirect (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `redirect` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter redirect=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: fields (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `fields` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter fields=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: wrap (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `wrap` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter wrap=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: host (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `host` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter host=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: referrer (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `referrer` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter referrer=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: status (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `status` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter status=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: url (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `url` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter url=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: trace (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `trace` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter trace=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: level (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `level` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter level=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: offset (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `offset` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter offset=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: src (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `src` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter src=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: prev (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `prev` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter prev=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: profile (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `profile` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter profile=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: category (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `category` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter category=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: disabled (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `disabled` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter disabled=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mode (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mode` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter mode=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: ip (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `ip` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter ip=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: shell (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `shell` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter shell=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: oauth (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `oauth` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter oauth=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: info (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `info` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter info=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: mock (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `mock` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter mock=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: env (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `env` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter env=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: private (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `private` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter private=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: otp (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `otp` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter otp=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: access (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `access` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter access=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: version (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `version` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter version=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: json (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `json` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter json=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: dir (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `dir` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter dir=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: socket (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `socket` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter socket=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Hidden Parameter Discovered: staging (POST_JSON)

- **Severity:** Low
- **CVSS Score:** 3.1
- **Bounty Score:** 100
- **Description:** ## Hidden Parameter Discovery

The parameter `staging` was discovered on endpoint `https://al-mokadam-educational-agency.web.app/README.md` via `POST_JSON` requests.

**Detection Reason:** Response size changed by 2507 bytes
**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations.
- **Proof of Concept:**
```
curl -i -X POST 'https://al-mokadam-educational-agency.web.app/README.md' (with parameter staging=...)
```
- **Remediation:** Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.

### Technology Detected: Firebase Hosting

- **Severity:** Info
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** Detected Firebase Hosting on the target (version unknown).
- **Proof of Concept:**
```
Technology identified at https://al-mokadam-educational-agency.web.app/
```
- **Remediation:** Verify this technology is intentional and up to date.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=node/add/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=node/add/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=node/add/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=admin/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=admin/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=admin/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=search/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=search/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=search/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=user/register/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=user/register/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=user/register/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=comment/reply/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=comment/reply/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=comment/reply/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=user/logout/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=user/logout/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=user/logout/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=user/login/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=user/login/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=user/login/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=filter/tips/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=filter/tips/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=filter/tips/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=user/password/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=user/password/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=user/password/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=logout/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=logout/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=logout/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/index.html (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/index.html
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/index.html
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?s= (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?s=
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?s=
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/apple-app-site-association (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/apple-app-site-association
**Status:** 200
**Size:** 37B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/apple-app-site-association
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=contact/ (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=contact/
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=contact/
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?refresh (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?refresh
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?refresh
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?show_error=true (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?show_error=true
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?show_error=true
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/.well-known/assetlinks.json (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/.well-known/assetlinks.json
**Status:** 200
**Size:** 2B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/.well-known/assetlinks.json
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?feed= (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?feed=
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?feed=
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/index.html (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/index.html
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/index.html
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=user/register (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=user/register
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=user/register
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=user/login (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=user/login
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=user/login
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=user/password (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=user/password
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=user/password
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?q=node/add (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?q=node/add
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?q=node/add
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/README.md (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/README.md
**Status:** 200
**Size:** 1805B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/README.md
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?action=search (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?action=search
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?action=search
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.

### Discovered Endpoint: https://al-mokadam-educational-agency.web.app/?blackhole (HTTP 200)

- **Severity:** Low
- **CVSS Score:** 0.0
- **Bounty Score:** 0
- **Description:** A hidden or undocumented endpoint was discovered via fuzzing.

**URL:** https://al-mokadam-educational-agency.web.app/?blackhole
**Status:** 200
**Size:** 4741B
- **Proof of Concept:**
```
curl -i https://al-mokadam-educational-agency.web.app/?blackhole
```
- **Remediation:** Ensure this endpoint is intentional and properly protected by authentication/authorization.


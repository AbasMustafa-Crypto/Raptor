"""
ssl_analyzer.py — SSL/TLS configuration analyzer for RAPTOR.

FIXES vs original
─────────────────
 1. __init__ now accepts graph_manager and passes it to super().__init__()
 2. socket.create_connection() wrapped in run_in_executor() — no longer
    blocks the event loop
 3. Hostname extracted with urlparse — path/port no longer included
 4. Weak-protocol detection uses a PERMISSIVE ssl context (no minimum version
    set), because ssl.create_default_context() already rejects weak protocols
    so ssock.version() could never return SSLv2/SSLv3/TLS1.0/1.1 — the entire
    check was dead code in the original
 5. Dead 'import subprocess' removed
 6. Certificate expiry check added
 7. Self-signed certificate check added
 8. Cipher check extended to include EXPORT and ANON cipher families
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import urlparse

from core.base_module import BaseModule, Finding

# Weak cipher name substrings — any cipher containing one of these is flagged
_WEAK_CIPHER_PATTERNS = ("RC4", "DES", "MD5", "NULL", "EXPORT", "ANON", "ADH", "AECDH")

# Protocols rejected by default context — to detect them we need a permissive one
_WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _build_permissive_context() -> ssl.SSLContext:
    """
    FIX 4: A context that accepts any TLS version including TLS 1.0 / 1.1.
    Used only for detection purposes — we never send real data through it.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    # Allow the lowest supported minimum version
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except AttributeError:
        pass  # Python < 3.7 — best effort
    return ctx


def _ssl_connect_sync(hostname: str, port: int, ctx: ssl.SSLContext) -> Dict:
    """
    Synchronous SSL connection that returns cert + cipher + version info.
    Called via run_in_executor so it never blocks the event loop (FIX 2).
    """
    result: Dict = {}
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            result["version"] = ssock.version()
            result["cipher"]  = ssock.cipher()
            result["cert"]    = ssock.getpeercert()
    return result


class SSLAnalyzer(BaseModule):
    """Analyze SSL/TLS configuration of a target."""

    # FIX 1: accept graph_manager and pass to super
    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info("Analyzing SSL/TLS for %s", target)

        # FIX 3: proper hostname extraction — strips scheme, path, port
        parsed   = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or ""
        port     = parsed.port or 443

        if not hostname:
            self.logger.error("Could not extract hostname from %s", target)
            return self.findings

        loop = asyncio.get_running_loop()

        # ── Standard TLS connection (cert + cipher info) ──────────────────────
        try:
            default_ctx = ssl.create_default_context()
            default_ctx.check_hostname = False
            default_ctx.verify_mode    = ssl.CERT_NONE

            # FIX 2: blocking socket I/O in executor
            info = await loop.run_in_executor(
                None, lambda: _ssl_connect_sync(hostname, port, default_ctx)
            )
        except Exception as exc:
            self.logger.error("SSL connection failed for %s: %s", hostname, exc)
            return self.findings

        version = info.get("version", "")
        cipher  = info.get("cipher")   # (name, proto, bits) tuple
        cert    = info.get("cert", {})

        # ── FIX 6: Certificate expiry check ───────────────────────────────────
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now    = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                if days_left < 0:
                    self.add_finding(Finding(
                        module="server_misconfig",
                        title=f"SSL Certificate Expired ({abs(days_left)} days ago)",
                        severity="Critical",
                        description=(
                            f"The SSL certificate for {hostname} expired on "
                            f"{not_after} ({abs(days_left)} days ago). "
                            "Browsers will show a security warning and block access."
                        ),
                        evidence={"hostname": hostname, "not_after": not_after},
                        poc=f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -dates",
                        remediation="Renew the SSL certificate immediately.",
                        cvss_score=7.5,
                        bounty_score=800,
                        target=target,
                    ))
                elif days_left < 30:
                    self.add_finding(Finding(
                        module="server_misconfig",
                        title=f"SSL Certificate Expiring Soon ({days_left} days)",
                        severity="Medium",
                        description=(
                            f"The SSL certificate for {hostname} expires on "
                            f"{not_after} — only {days_left} days remaining."
                        ),
                        evidence={"hostname": hostname, "not_after": not_after, "days_left": days_left},
                        poc=f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -dates",
                        remediation="Renew the SSL certificate before it expires.",
                        cvss_score=5.3,
                        bounty_score=200,
                        target=target,
                    ))
            except (ValueError, TypeError) as exc:
                self.logger.debug("Could not parse cert expiry '%s': %s", not_after, exc)

        # ── FIX 7: Self-signed certificate check ──────────────────────────────
        issuer  = dict(x[0] for x in cert.get("issuer",  []) if x)
        subject = dict(x[0] for x in cert.get("subject", []) if x)
        if issuer and subject and issuer == subject:
            self.add_finding(Finding(
                module="server_misconfig",
                title="Self-Signed SSL Certificate",
                severity="High",
                description=(
                    f"{hostname} is using a self-signed certificate. "
                    "Browsers display security warnings; the cert provides no "
                    "third-party trust assurance."
                ),
                evidence={"hostname": hostname, "issuer": issuer, "subject": subject},
                poc=f"openssl s_client -connect {hostname}:{port} 2>&1 | grep 'self signed'",
                remediation="Replace the self-signed certificate with one issued by a trusted CA.",
                cvss_score=6.5,
                bounty_score=500,
                target=target,
            ))

        # ── FIX 8: Weak cipher check (extended to EXPORT / ANON families) ─────
        if cipher:
            cipher_name = cipher[0] or ""
            if any(weak in cipher_name.upper() for weak in _WEAK_CIPHER_PATTERNS):
                self.add_finding(Finding(
                    module="server_misconfig",
                    title=f"Weak Cipher Suite Negotiated: {cipher_name}",
                    severity="Medium",
                    description=(
                        f"The server negotiated the weak cipher suite '{cipher_name}' "
                        f"using {cipher[1]} ({cipher[2]} bits). "
                        "Weak ciphers enable decryption or key-recovery attacks."
                    ),
                    evidence={"cipher": cipher, "version": version},
                    poc=f"openssl s_client -connect {hostname}:{port} -cipher '{cipher_name}'",
                    remediation=(
                        "Disable RC4, DES, NULL, EXPORT, and ANON cipher suites. "
                        "Configure the server to use AES-GCM or ChaCha20-Poly1305."
                    ),
                    cvss_score=5.3,
                    bounty_score=300,
                    target=target,
                ))

        # ── FIX 4: Weak protocol detection via PERMISSIVE context ─────────────
        #
        # The original code used ssl.create_default_context() which already
        # REJECTS TLS < 1.2 — so ssock.version() could never return
        # 'SSLv3'/'TLSv1'/etc.  The check was unreachable dead code.
        # We now connect with a permissive context to actually detect weak protos.
        try:
            perm_ctx = _build_permissive_context()
            perm_info = await loop.run_in_executor(
                None, lambda: _ssl_connect_sync(hostname, port, perm_ctx)
            )
            negotiated = perm_info.get("version", "")
            if negotiated in _WEAK_PROTOCOLS:
                self.add_finding(Finding(
                    module="server_misconfig",
                    title=f"Weak TLS Protocol Supported: {negotiated}",
                    severity="High",
                    description=(
                        f"The server accepted a connection using {negotiated}, "
                        "which is deprecated and vulnerable to attacks such as "
                        "POODLE (SSLv3), BEAST (TLS 1.0), and SWEET32 (TLS 1.0/1.1)."
                    ),
                    evidence={"protocol": negotiated, "hostname": hostname},
                    poc=f"openssl s_client -connect {hostname}:{port} -{negotiated.lower().replace('v', '')}",
                    remediation="Disable TLS 1.0 and 1.1; enforce TLS 1.2 minimum, prefer TLS 1.3.",
                    cvss_score=7.5,
                    bounty_score=800,
                    target=target,
                ))
        except ssl.SSLError:
            pass  # server rejected the weak-protocol handshake — good
        except Exception as exc:
            self.logger.debug("Permissive protocol probe failed: %s", exc)

        return self.findings

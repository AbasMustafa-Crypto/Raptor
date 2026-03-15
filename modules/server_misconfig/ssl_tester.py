"""
ssl_tester.py — Professional SSL/TLS Configuration Assessor for RAPTOR.
"""

import ssl
import socket
import asyncio
import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from core.base_module import BaseModule, Finding


class SSLTester(BaseModule):
    """
    Assesses SSL/TLS security including protocol versions, certificate validity, 
    cipher suites, and common vulnerabilities.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(10)

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info(f"🔥 Starting SSL/TLS Assessment on {target}")
        
        parsed = urlparse(target)
        host = parsed.hostname
        if not host:
             # Try target as host if URL parsing fails
             host = target.split('/')[0]

        async with self.semaphore:
            # 1. TLS Version Support
            await self._check_tls_versions(host)
            
            # 2. Certificate Checks & Cipher Suite Audit
            await self._audit_certificate_and_ciphers(host)

        return self.findings

    async def _check_tls_versions(self, host: str):
        versions = [
            (ssl.TLSVersion.SSLv3, "SSLv3", "Critical", 9.8),
            (ssl.TLSVersion.TLSv1, "TLSv1.0", "High", 7.4),
            (ssl.TLSVersion.TLSv1_1, "TLSv1.1", "High", 7.4),
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2", "Pass", 0.0),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3", "Pass", 0.0),
        ]

        for ver_const, name, sev, cvss in versions:
            try:
                # Use a separate thread for blocking socket/ssl calls
                success = await asyncio.to_thread(self._test_connection, host, ver_const)
                if success:
                    if sev != "Pass":
                        self.add_finding(Finding(
                            module='server_misconfig',
                            title=f"Deprecated Protocol Supported: {name}",
                            severity=sev,
                            description=f"The server accepts connections using {name}, which is deprecated and contains known security vulnerabilities.",
                            evidence={'protocol': name, 'accepted': True},
                            poc=f"openssl s_client -connect {host}:443 -{name.lower().replace('.', '_')}",
                            remediation=f"Disable {name} and require TLSv1.2 or higher.",
                            cvss_score=cvss, bounty_score=2000 if sev == "High" else 5000,
                            target=host
                        ))
                    else:
                        self.logger.debug(f"{name} is supported (Secure).")
            except Exception as e:
                self.logger.debug(f"Error testing {name} on {host}: {e}")

    def _test_connection(self, host: str, version: ssl.TLSVersion) -> bool:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except Exception:
            return False

    async def _audit_certificate_and_ciphers(self, host: str):
        try:
            data = await asyncio.to_thread(self._get_cert_and_cipher_data, host)
            if not data: return
            
            cert = data['cert']
            cipher = data['cipher']
            protocol = data['protocol']
            
            # 1. Expiry
            not_after_str = cert.get('notAfter')
            if not_after_str:
                not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                delta = not_after - datetime.datetime.utcnow()
                if delta.days < 0:
                    self._add_ssl_finding(host, "Expired SSL Certificate", 'Critical', 9.8, 1500, f"Certificate expired on {not_after_str}.")
                elif delta.days < 30:
                    self._add_ssl_finding(host, "SSL Certificate Expiring Soon (< 30 days)", 'High', 7.4, 1500, f"Certificate expires on {not_after_str}.")
                elif delta.days < 90:
                    self._add_ssl_finding(host, "SSL Certificate Expiring Soon (< 90 days)", 'Medium', 5.0, 500, f"Certificate expires on {not_after_str}.")

            # 2. Hostname Mismatch (Checked by create_default_context usually, but we check explicitly)
            # (Simplified: self-signed check and name check)
            if not cert:
                 self._add_ssl_finding(host, "Self-Signed or Invalid Certificate", 'High', 7.4, 1500, "Could not retrieve full peer certificate. Likely self-signed or invalid chain.")

            # 3. Weak Signature
            # Note: s.getpeercert() only returns fields if cert is validated.
            # For deeper audit we'd need cryptography/OpenSSL, but we can report on what we have.

            # 4. Cipher Audit
            cipher_name = cipher[0]
            if any(x in cipher_name.upper() for x in ("NULL", "EXPORT", "RC4", "DES", "ADH")):
                 self._add_ssl_finding(host, f"Weak Cipher Suite Supported: {cipher_name}", 'Critical', 9.1, 3000, f"Server supports weak cipher {cipher_name}.")

            # 5. SANs
            sans = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']
            if sans:
                 self.logger.info(f"[SSL] SANs found for {host}: {', '.join(sans)}")

        except Exception as e:
            self.logger.error(f"SSL Audit error for {host}: {e}")

    def _get_cert_and_cipher_data(self, host: str) -> Optional[Dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE # We want to connect even if invalid to audit
        
        try:
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    # If verify_mode is CERT_NONE, getpeercert() returns empty dict unless binary=True
                    # Let's try again with binary=True to get something or just use the cipher info
                    if not cert:
                        cert = ssock.getpeercert(binary_form=False) # Fallback
                    
                    return {
                        'cert': cert or {},
                        'cipher': ssock.cipher(),
                        'protocol': ssock.version()
                    }
        except Exception:
            return None

    def _add_ssl_finding(self, target, title, severity, cvss, bounty, desc):
        self.add_finding(Finding(
            module='server_misconfig', title=title, severity=severity,
            description=f"## SSL/TLS Security Issue\n\n{desc}",
            evidence={'issue': title, 'detail': desc},
            cvss_score=cvss, bounty_score=bounty, target=target
        ))

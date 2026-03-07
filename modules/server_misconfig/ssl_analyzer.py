from typing import List, Dict
from core.base_module import BaseModule, Finding
import ssl
import socket
import subprocess

class SSLAnalyzer(BaseModule):
    """Analyze SSL/TLS configuration"""
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run SSL/TLS analysis"""
        self.logger.info(f"Analyzing SSL/TLS for {target}")
        
        # Remove protocol for SSL check
        hostname = target.replace('https://', '').replace('http://', '').split(':')[0]
        
        try:
            # Basic SSL connection test
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak SSL/TLS versions
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        finding = Finding(
                            module='server_misconfig',
                            title=f'Weak SSL/TLS Version: {version}',
                            severity='High',
                            description=f'Server supports outdated protocol: {version}',
                            evidence={'version': version, 'cipher': cipher},
                            poc=f"openssl s_client -connect {hostname}:443 -{version.lower()}",
                            remediation='Disable weak protocols, enable TLS 1.2+ only',
                            cvss_score=7.5,
                            bounty_score=800,
                            target=target
                        )
                        self.add_finding(finding)
                        
                    # Check cipher strength
                    if cipher and any(weak in cipher[0] for weak in ['RC4', 'DES', 'MD5', 'NULL']):
                        finding = Finding(
                            module='server_misconfig',
                            title=f'Weak Cipher Suite: {cipher[0]}',
                            severity='Medium',
                            description=f'Server supports weak cipher: {cipher[0]}',
                            evidence={'cipher': cipher, 'version': version},
                            poc=f"openssl s_client -connect {hostname}:443",
                            remediation='Disable weak ciphers',
                            cvss_score=5.3,
                            bounty_score=300,
                            target=target
                        )
                        self.add_finding(finding)
                        
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            
        return self.findings

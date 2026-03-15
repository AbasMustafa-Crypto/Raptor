"""
port_scanner.py — High-speed async TCP Port Scanner for RAPTOR.
"""

import asyncio
import urllib.parse
from typing import Dict, List, Optional, Tuple

from core.base_module import BaseModule, Finding


class PortScanner(BaseModule):
    """
    Enterprise-grade asynchronous TCP port scanner.
    Scans the top 100 most common ports, grabs banners, and reports exposed services.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(100)
        
        # Top 100 common ports
        self.top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
            1723, 3306, 3389, 5900, 8080, 8443, 1433, 1521, 2049, 2121, 2222, 2601,
            3128, 3306, 4848, 5000, 5432, 5984, 6379, 6666, 6667, 7001, 7070, 7100,
            8000, 8008, 8081, 8888, 9000, 9090, 9200, 10000, 11211, 27017, 27018, 
            50000, 50030, 50060, 61616, 111, 512, 513, 514, 1099, 1524, 2049, 2100, 
            3306, 4333, 5000, 5432, 5555, 6667, 7000, 8000, 8080, 8443, 8888, 9000, 
            9090, 9200, 11211, 27017, 33060, 6379, 22, 23, 80, 443, 445, 139, 135, 
            110, 25, 21, 143, 993, 995, 3389, 5900, 8080, 1433, 1521, 3306, 5432
        ]
        # Remove duplicates
        self.top_ports = sorted(list(set(self.top_ports)))

        # Port risk definitions
        self.port_risks = {
            21:   ('FTP', 'High', 7.5, 'Cleartext file transfer, potential anonymous access.'),
            22:   ('SSH', 'Low', 2.0, 'Secure shell, usually safe if properly configured.'),
            23:   ('Telnet', 'Critical', 9.0, 'Cleartext remote administration.'),
            25:   ('SMTP', 'Low', 2.0, 'Mail routing.'),
            53:   ('DNS', 'Low', 2.0, 'Domain name system.'),
            111:  ('RPCBind', 'Medium', 5.3, 'Can leak information about RPC services.'),
            135:  ('MSRPC', 'Medium', 5.3, 'Exposes Windows RPC endpoints.'),
            139:  ('NetBIOS', 'Medium', 5.3, 'Windows file/printer sharing.'),
            445:  ('SMB', 'Medium', 5.3, 'Windows file/printer sharing.'),
            1433: ('MSSQL', 'High', 7.5, 'Exposed database port.'),
            1521: ('Oracle DB', 'High', 7.5, 'Exposed database port.'),
            2049: ('NFS', 'High', 7.5, 'Network File System.'),
            3306: ('MySQL', 'High', 7.5, 'Exposed database port.'),
            3389: ('RDP', 'Medium', 5.3, 'Remote Desktop Protocol.'),
            5432: ('PostgreSQL', 'High', 7.5, 'Exposed database port.'),
            5900: ('VNC', 'Medium', 5.3, 'Virtual Network Computing.'),
            5984: ('CouchDB', 'High', 7.5, 'Exposed database port.'),
            6379: ('Redis', 'Critical', 9.0, 'Exposed in-memory database, often unauthenticated.'),
            9200: ('Elasticsearch', 'Critical', 9.0, 'Exposed database, often unauthenticated.'),
            11211:('Memcached', 'Critical', 9.0, 'Exposed in-memory cache, often unauthenticated.'),
            27017:('MongoDB', 'Critical', 9.0, 'Exposed database, often unauthenticated.')
        }

    def _extract_domain(self, target: str) -> str:
        if "://" not in target:
            target = "https://" + target
        host = urllib.parse.urlparse(target).hostname or ""
        return host.split(":")[0].strip()

    async def run(self, target: str, **kwargs) -> List[Finding]:
        domain = self._extract_domain(target)
        self.logger.info(f"🔥 Starting Port Scan on {domain} ({len(self.top_ports)} ports)")

        tasks = [self._scan_port(domain, port) for port in self.top_ports]
        if tasks:
            await asyncio.gather(*tasks)

        return self.findings

    async def _scan_port(self, host: str, port: int):
        async with self.semaphore:
            try:
                # 3 second timeout for port scans
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=3.0)
                
                # Port is open
                banner = await self._grab_banner(reader, writer, port)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                self._report_open_port(host, port, banner)

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is closed or filtered
                pass
            except Exception as exc:
                self.logger.debug(f"Port {port} scan error: {exc}")

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        banner = ""
        try:
            # Send a generic payload that works for HTTP and some other protocols
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()

            # Read response
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        
        return banner[:200]  # Return first 200 chars

    def _report_open_port(self, host: str, port: int, banner: str):
        # Determine risk
        service, severity, cvss, desc = self.port_risks.get(
            port, 
            ('Unknown', 'Info', 0.0, 'An open port was detected.')
        )

        # Skip reporting 80 and 443 as they are expected
        if port in [80, 443] and severity == 'Info':
            return

        self.add_finding(Finding(
            module='recon',
            title=f"Exposed Service: {service} (Port {port})",
            severity=severity,
            description=f"## Exposed Port Detected\n\n**Port:** {port}\n**Service:** {service}\n\n{desc}",
            evidence={'port': port, 'service': service, 'banner': banner},
            poc=f"nc -vn {host} {port}",
            remediation="Restrict access to this port using a firewall or security group. Ensure the service is securely configured and authenticated.",
            cvss_score=cvss,
            bounty_score=500 if cvss >= 7.0 else 0,
            target=host
        ))

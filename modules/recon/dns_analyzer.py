"""
dns_analyzer.py — Professional DNS & Subdomain Takeover Analyzer for RAPTOR.
"""

import asyncio
import re
import urllib.parse
from typing import Dict, List, Optional, Set

from core.base_module import BaseModule, Finding


class DNSAnalyzer(BaseModule):
    """
    Enterprise-grade DNS analyzer:
    - SPF and DMARC misconfiguration detection (Email Spoofing)
    - Subdomain Takeover detection via CNAME analysis
    - Zone Transfer (AXFR) vulnerability checks
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(10)
        
        # Signatures for subdomain takeover
        self.takeover_signatures = {
            'AWS S3': ['The specified bucket does not exist', 'NoSuchBucket'],
            'GitHub Pages': ["There isn't a GitHub Pages site here"],
            'Heroku': ['No such app'],
            'Pantheon': ['The page you are looking for is not here'],
            'Surge.sh': ['project not found'],
            'Azure': ['404 Web Site not found'],
            'Vercel': ['DEPLOYMENT_NOT_FOUND'],
            'Zendesk': ['404 Help Center not found'],
            'Bitbucket': ['Repository not found'],
            'DigitalOcean': ['Site not found'],
            'Wordpress': ['Do you want to register']
        }

    def _extract_domain(self, target: str) -> str:
        if "://" not in target:
            target = "https://" + target
        host = urllib.parse.urlparse(target).hostname or ""
        return host.split(":")[0].strip()

    async def run(self, target: str, **kwargs) -> List[Finding]:
        domain = self._extract_domain(target)
        self.logger.info(f"🔥 Starting Enterprise DNS Analysis on {domain}")

        # 1. SPF and DMARC Analysis
        await self._analyze_spf_dmarc(domain)

        # 2. Zone Transfer Check
        await self._check_zone_transfer(domain)

        # 3. Subdomain Takeover Check (uses gathered subdomains if available)
        subdomains = set(kwargs.get('discovered_urls', []))
        subdomains.add(domain)
        
        # Clean subdomains to just hostnames
        clean_subs = set()
        for sub in subdomains:
            clean_subs.add(self._extract_domain(sub))

        self.logger.info(f"Checking {len(clean_subs)} subdomains for takeover vulnerabilities...")
        
        tasks = [self._check_takeover(sub) for sub in clean_subs if sub]
        if tasks:
            await asyncio.gather(*tasks)

        return self.findings

    async def _run_cmd(self, *args) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return stdout.decode('utf-8', errors='ignore')
        except Exception:
            return ""

    async def _analyze_spf_dmarc(self, domain: str):
        # Base domain is needed for email config, not subdomains usually
        parts = domain.split('.')
        if len(parts) > 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain

        # Check SPF
        spf_out = await self._run_cmd('host', '-t', 'TXT', base_domain)
        spf_record = None
        for line in spf_out.splitlines():
            if 'v=spf1' in line:
                spf_record = line.strip()
                break
        
        if not spf_record:
            self.add_finding(Finding(
                module='recon', title="Missing SPF Record (Email Spoofing)",
                severity='Medium', cvss_score=4.3, bounty_score=200,
                description=f"The domain {base_domain} is missing an SPF record, making it vulnerable to email spoofing.",
                evidence={'domain': base_domain}, poc=f"host -t TXT {base_domain}",
                remediation="Add an SPF TXT record (e.g., v=spf1 -all) to DNS.", target=base_domain
            ))
        elif '~all' in spf_record or '?all' in spf_record:
            self.add_finding(Finding(
                module='recon', title="Weak SPF Record (~all or ?all)",
                severity='Low', cvss_score=3.1, bounty_score=50,
                description=f"The SPF record for {base_domain} uses a soft fail (~all) or neutral (?all) mechanism.",
                evidence={'domain': base_domain, 'record': spf_record}, poc=f"host -t TXT {base_domain}",
                remediation="Change the SPF mechanism to hard fail (-all).", target=base_domain
            ))

        # Check DMARC
        dmarc_out = await self._run_cmd('host', '-t', 'TXT', f'_dmarc.{base_domain}')
        dmarc_record = None
        for line in dmarc_out.splitlines():
            if 'v=DMARC1' in line:
                dmarc_record = line.strip()
                break
        
        if not dmarc_record:
            self.add_finding(Finding(
                module='recon', title="Missing DMARC Record",
                severity='Medium', cvss_score=4.3, bounty_score=250,
                description=f"The domain {base_domain} is missing a DMARC record, severely weakening email spoofing protections.",
                evidence={'domain': base_domain}, poc=f"host -t TXT _dmarc.{base_domain}",
                remediation="Add a DMARC record with p=reject or p=quarantine.", target=base_domain
            ))
        elif 'p=none' in dmarc_record:
            self.add_finding(Finding(
                module='recon', title="DMARC Policy is None (Monitoring Only)",
                severity='Low', cvss_score=3.1, bounty_score=100,
                description=f"The DMARC record for {base_domain} is set to p=none, meaning it does not block spoofed emails.",
                evidence={'domain': base_domain, 'record': dmarc_record}, poc=f"host -t TXT _dmarc.{base_domain}",
                remediation="Upgrade DMARC policy to p=quarantine or p=reject.", target=base_domain
            ))

    async def _check_zone_transfer(self, domain: str):
        # Get nameservers
        ns_out = await self._run_cmd('host', '-t', 'NS', domain)
        nameservers = []
        for line in ns_out.splitlines():
            if 'name server' in line:
                parts = line.split('name server')
                if len(parts) > 1:
                    nameservers.append(parts[1].strip())
        
        for ns in nameservers:
            axfr_out = await self._run_cmd('host', '-l', domain, ns)
            if 'Transfer failed' not in axfr_out and 'failed' not in axfr_out.lower() and domain in axfr_out:
                # Count records to confirm it's actually a zone transfer
                if len(axfr_out.splitlines()) > 5:
                    self.add_finding(Finding(
                        module='recon', title="DNS Zone Transfer (AXFR) Allowed",
                        severity='High', cvss_score=7.5, bounty_score=2000,
                        description=f"The nameserver {ns} allows anonymous zone transfers, leaking all DNS records for {domain}.",
                        evidence={'nameserver': ns, 'domain': domain, 'records_dumped': len(axfr_out.splitlines())},
                        poc=f"host -l {domain} {ns}",
                        remediation="Configure the DNS server to disallow AXFR requests from unauthorized IP addresses.",
                        target=domain
                    ))
                    break # One successful AXFR is enough

    async def _check_takeover(self, sub: str):
        async with self.semaphore:
            # Get CNAME
            cname_out = await self._run_cmd('host', '-t', 'CNAME', sub)
            cname = None
            for line in cname_out.splitlines():
                if 'alias for' in line:
                    parts = line.split('alias for')
                    if len(parts) > 1:
                        cname = parts[1].strip()
                        break
            
            if not cname:
                return # No CNAME, generally no third-party takeover
            
            # Request the subdomain via HTTP/HTTPS to check for "Not Found" signatures
            for proto in ['http', 'https']:
                try:
                    resp = await self._make_request(f"{proto}://{sub}", timeout=5)
                    if not resp: continue
                    body = await resp.text()
                    
                    for provider, sigs in self.takeover_signatures.items():
                        for sig in sigs:
                            if sig in body:
                                self.add_finding(Finding(
                                    module='recon', title=f"Subdomain Takeover Vulnerability ({provider})",
                                    severity='Critical', cvss_score=9.1, bounty_score=4000,
                                    description=f"The subdomain `{sub}` has a dangling CNAME pointing to `{cname}`. "
                                                f"The provider ({provider}) returned a response indicating the target is unclaimed, "
                                                f"allowing an attacker to register it and hijack the subdomain.",
                                    evidence={'subdomain': sub, 'cname': cname, 'provider': provider, 'signature': sig},
                                    poc=f"curl -s {proto}://{sub} | grep '{sig}'",
                                    remediation="Remove the dangling CNAME record from DNS immediately, or claim the resource on the third-party provider.",
                                    target=sub
                                ))
                                return # Move to next subdomain
                except Exception:
                    pass

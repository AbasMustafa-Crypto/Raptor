"""
RAPTOR Parameter Fuzzer Module v1.0
===================================
Discovers hidden parameters, debug flags, and undocumented API endpoints.
"""

import asyncio
import logging
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Set, Any

from core.base_module import BaseModule, Finding

class ParamFuzzer(BaseModule):
    """
    Parameter Fuzzer: Discover hidden parameters and anomaly detection.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.wordlist: List[str] = self._load_wordlist()
        self.semaphore = asyncio.Semaphore(20)
        self.max_pages = config.get('max_pages', 30)
        
        # Anomaly keywords
        self.critical_keywords = ['admin', 'root', 'password', 'secret', 'token', 'api_key']
        self.debug_keywords = ['debug', 'trace', 'stack', 'exception', 'error', 'internal', 'config']

    def _load_wordlist(self) -> List[str]:
        """Load parameter wordlist from wordlists/params.txt."""
        try:
            with open('wordlists/params.txt', 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.error("Wordlist wordlists/params.txt not found.")
            return []

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Main module entry point."""
        self.logger.info(f"🔥 Starting Parameter Fuzzing on {target}")
        
        # Phase 1: URL Collection
        raw_urls = await self._collect_urls(target, **kwargs)
        
        # FIX: Filter out static assets and duplicates
        urls = []
        seen_patterns = set()
        for url in raw_urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.ttf', '.svg', '.ico', '.pdf', '.js']):
                continue
            pattern = re.sub(r'/\d+', '/*', path)
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                urls.append(url)

        self.logger.info(f"[FUZZ] Filtered to {len(urls)} interesting endpoints")
        
        for url in urls:
            # Phase 2: Baseline Capture
            baseline = await self._capture_baseline(url)
            if not baseline:
                continue
                
            self.logger.info(f"[FUZZ] Testing {url} (baseline: {baseline['status']}, {baseline['length']}B)")
            
            # Phase 3: Fuzzing
            await self._fuzz_endpoint(url, baseline)
            
        return self.findings

    async def _collect_urls(self, target: str, **kwargs) -> List[str]:
        """Gather candidate URLs from various sources."""
        urls = set()
        
        # Source 1: Discovered URLs from other modules
        for url in kwargs.get('discovered_urls', []):
            urls.add(url)
            
        # Source 2: Crawl target
        crawled = await self.crawl_pages(target, max_pages=self.max_pages)
        for url in crawled:
            urls.add(url)
            
        # Source 3: Target itself
        urls.add(target)
        
        return list(urls)

    async def _capture_baseline(self, url: str) -> Optional[Dict]:
        """Establish baseline response for comparison."""
        try:
            resp = await self._make_request(url)
            if not resp:
                return None
            
            body = await resp.text()
            return {
                'status': resp.status,
                'length': len(body),
                'body_sample': body[:500].lower(),
                'full_body': body.lower()
            }
        except Exception as e:
            self.logger.error(f"Failed to capture baseline for {url}: {e}")
            return None

    async def _fuzz_endpoint(self, url: str, baseline: Dict):
        """Fuzz an endpoint with parameters from the wordlist."""
        tasks = []
        for param in self.wordlist:
            # Variants for each parameter - limit to top 3 as per requirements
            for value in ['true', '1', 'admin']:
                tasks.append(self._test_param(url, param, value, baseline))
        
        if tasks:
            # Chunking to prevent memory issues with massive wordlists
            chunk_size = 1000
            for i in range(0, len(tasks), chunk_size):
                await asyncio.gather(*tasks[i:i+chunk_size], return_exceptions=True)

    async def _test_param(self, url: str, param: str, value: str, baseline: Dict):
        """Test a single parameter variation with rate limiting."""
        async with self.semaphore:
            # Build fuzzed URL
            fuzzed_url = self._inject_param(url, param, value)
            
            start_time = time.monotonic()
            try:
                resp = await self._make_request(fuzzed_url)
                if not resp:
                    return
                
                body = await resp.text()
                elapsed = time.monotonic() - start_time
                fuzzed_status = resp.status
                fuzzed_length = len(body)
                
                # Phase 4: Anomaly Detection
                anomaly = self._detect_anomaly(baseline, fuzzed_status, fuzzed_length, body, elapsed)
                
                if anomaly:
                    severity, cvss, bounty = self._calc_severity(anomaly, baseline, fuzzed_status, fuzzed_length, body)
                    
                    finding = Finding(
                        module='fuzzing',
                        title=f'Hidden Parameter Discovered: {param}={value} on {url}',
                        severity=severity,
                        description=(
                            f"## Hidden Parameter Discovery\n\n"
                            f"An anomaly was detected when fuzzing parameter `{param}` with value `{value}`.\n\n"
                            f"**Baseline Status:** {baseline['status']} | **Fuzzed Status:** {fuzzed_status}\n"
                            f"**Baseline Length:** {baseline['length']}B | **Fuzzed Length:** {fuzzed_length}B\n"
                            f"**Anomaly:** {anomaly}\n"
                            f"**Response Time:** {elapsed:.2f}s"
                        ),
                        evidence={
                            'endpoint': url,
                            'parameter': param,
                            'value': value,
                            'baseline_status': baseline['status'],
                            'fuzzed_status': fuzzed_status,
                            'baseline_length': baseline['length'],
                            'fuzzed_length': fuzzed_length,
                            'anomaly': anomaly,
                            'response_snippet': body[:300]
                        },
                        poc=f"curl '{fuzzed_url}'",
                        remediation='Remove or restrict undocumented parameters. Apply server-side parameter allowlisting.',
                        cvss_score=cvss,
                        bounty_score=bounty,
                        target=url
                    )
                    self.add_finding(finding)
                    self.logger.info(f"[FUZZ] FINDING: Hidden parameter '{param}' on {url} [{severity}]")
                    
            except Exception as e:
                self.logger.debug(f"Error fuzzing {fuzzed_url}: {e}")

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Add or update a parameter in the URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _detect_anomaly(self, baseline: Dict, status: int, length: int, body: str, elapsed: float) -> Optional[str]:
        """Detect differences between baseline and fuzzed response."""
        body_lower = body.lower()
        
        # 1. Status change
        if status != baseline['status']:
            return f"Status code changed from {baseline['status']} to {status}"
        
        # 2. Significant length change
        length_delta = abs(length - baseline['length'])
        if length_delta > 50 and length_delta > (baseline['length'] * 0.1):
            return f"Response length changed by {length_delta}B (>{baseline['length'] * 0.1:.0f}B)"
            
        # 3. New keywords in body
        new_keywords = []
        for kw in self.critical_keywords + self.debug_keywords:
            if kw in body_lower and kw not in baseline['full_body']:
                new_keywords.append(kw)
        
        if new_keywords:
            return f"New keywords found: {', '.join(new_keywords)}"
            
        # 4. Response time (time-based disclosure)
        if elapsed > 5:
            return f"Slow response time detected: {elapsed:.2f}s"
            
        return None

    def _calc_severity(self, anomaly: str, baseline: Dict, status: int, length: int, body: str) -> tuple:
        """Determine severity, CVSS, and bounty based on anomaly."""
        body_lower = body.lower()
        
        # Critical - auth/access keywords
        if any(kw in body_lower and kw not in baseline['full_body'] for kw in self.critical_keywords):
            return 'Critical', 9.1, 3000
            
        # High - status 200 from non-200, or internal error
        if status == 200 and baseline['status'] >= 400:
            return 'High', 7.5, 2000
        if 'internal' in anomaly.lower() or 'stack' in body_lower or 'exception' in body_lower:
            return 'High', 7.5, 2000
            
        # Medium - size change or debug info
        if 'length' in anomaly.lower() or any(kw in body_lower and kw not in baseline['full_body'] for kw in self.debug_keywords):
            return 'Medium', 5.0, 800
            
        # Low - minor keyword or small size delta
        return 'Low', 3.1, 200

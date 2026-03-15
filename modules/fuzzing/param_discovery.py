"""
param_discovery.py — Enterprise Parameter Discovery Module for RAPTOR.
======================================================================
Identifies hidden HTTP parameters via GET, POST, JSON, and Headers.
Implements behavioral anomaly detection and JavaScript parameter extraction.
"""

import asyncio
import json
import re
import urllib.parse
import hashlib
import time
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass

from core.base_module import BaseModule, Finding

# ── Configuration & Signatures ───────────────────────────────────────────────

# Keywords that indicate a parameter might have changed the application state
INTERESTING_KEYWORDS = [
    'admin', 'debug', 'test', 'error', 'exception', 'stack', 'token', 
    'auth', 'secret', 'config', 'internal', 'root', 'api_key', 'dev'
]

JS_PARAM_REGEX = r'(?:[\?&]|(?:obj|params|query|data)\s*[:=]\s*\{?\s*["\'])([a-zA-Z0-9_\-]+)(?=["\']|[\?&=])'

@dataclass
class DiscoveryBaseline:
    status: int
    length: int
    body_hash: str
    keywords: Set[str]
    response_time: float

# ── ParameterDiscovery Class ─────────────────────────────────────────────────

class ParameterDiscovery(BaseModule):
    """
    Advanced Parameter Discovery Engine.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(config.get('concurrency', 10))
        self.wordlist_path = config.get('wordlist', 'wordlists/params.txt')
        self.params = self._load_params()
        self.discovered_params = {} # {endpoint: [params]}

    def _load_params(self) -> List[str]:
        try:
            with open(self.wordlist_path, 'r') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except Exception:
            return ['debug', 'admin', 'test', 'v', 'id', 'mode', 'source', 'config']

    async def discover_parameters(self, endpoints: List[str]) -> Dict[str, List[str]]:
        """
        Public API required by the framework requirements.
        """
        await self.run_discovery(endpoints)
        return self.discovered_params

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Standard RAPTOR module entry point.
        """
        endpoints = kwargs.get('discovered_urls', [target])
        await self.run_discovery(endpoints)
        return self.findings

    async def run_discovery(self, endpoints: List[str]):
        self.logger.info(f"🔥 Starting Parameter Discovery on {len(endpoints)} endpoints")
        
        # 1. Filter out static assets and duplicates
        interesting_endpoints = []
        seen_patterns = set()
        
        for url in endpoints:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.ttf', '.svg', '.ico', '.pdf']):
                continue
            
            # Simple pattern deduplication (e.g. /user/1 and /user/2 -> /user/*)
            pattern = re.sub(r'/\d+', '/*', path)
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                interesting_endpoints.append(url)

        self.logger.info(f"[PARAM] Filtered to {len(interesting_endpoints)} interesting endpoints")

        # Process endpoints in chunks to avoid overwhelming the loop
        endpoint_chunk_size = 5
        for i in range(0, len(interesting_endpoints), endpoint_chunk_size):
            chunk = interesting_endpoints[i:i + endpoint_chunk_size]
            for url in chunk:
                # 1. Advanced Feature: Extraction from JS/HTML
                extracted = await self._extract_from_source(url)
                if extracted:
                    self.logger.info(f"[PARAM] Extracted {len(extracted)} potential params from source: {url}")
                
                # 2. Capture Baseline
                baseline = await self._capture_baseline(url)
                if not baseline: continue

                # 3. Discover hidden parameters
                await self._discover_hidden(url, baseline, extracted)
            
            # Brief cooldown between chunks
            await asyncio.sleep(0.5)

    # ── Phase 1: Source Extraction ───────────────────────────────────────────

    async def _extract_from_source(self, url: str) -> Set[str]:
        """Extract params from HTML forms and linked JS files."""
        found = set()
        try:
            resp = await self._make_request(url)
            if not resp: return found
            body = await resp.text()

            # HTML Forms
            forms = await self.get_forms(url)
            for f in forms:
                found.update(f['inputs'].keys())

            # JS regex scan
            if url.endswith('.js') or 'javascript' in resp.headers.get('Content-Type', '').lower():
                matches = re.findall(JS_PARAM_REGEX, body)
                found.update(matches)
            
            # Scan for linked JS files if HTML
            if 'text/html' in resp.headers.get('Content-Type', '').lower():
                scripts = re.findall(r'src=["\']([^"\']+\.js)["\']', body)
                for s in scripts:
                    js_url = urllib.parse.urljoin(url, s)
                    js_resp = await self._make_request(js_url)
                    if js_resp:
                        js_body = await js_resp.text()
                        found.update(re.findall(JS_PARAM_REGEX, js_body))

        except Exception: pass
        return found

    # ── Phase 2: Baseline Capture ────────────────────────────────────────────

    async def _capture_baseline(self, url: str) -> Optional[DiscoveryBaseline]:
        try:
            start = time.monotonic()
            resp = await self._make_request(url)
            elapsed = time.monotonic() - start
            if not resp: return None

            body = await resp.text()
            body_l = body.lower()
            
            return DiscoveryBaseline(
                status=resp.status,
                length=len(body),
                body_hash=hashlib.md5(body.encode('utf-8', errors='ignore')).hexdigest(),
                keywords={k for k in INTERESTING_KEYWORDS if k in body_l},
                response_time=elapsed
            )
        except Exception: return None

    # ── Phase 3: Hidden Discovery ────────────────────────────────────────────

    async def _discover_hidden(self, url: str, baseline: DiscoveryBaseline, extracted: Set[str]):
        """Test all parameters in wordlist + extracted."""
        all_to_test = list(set(self.params) | extracted)
        
        # We split into GET, POST, and Header tasks
        tasks = []
        for param in all_to_test:
            # 1. Test GET
            tasks.append(self._test_param(url, 'GET', param, 'true', baseline))
            # 2. Test POST JSON
            tasks.append(self._test_param(url, 'POST_JSON', param, 'true', baseline))
            # 3. Test Headers
            if param.lower() in ['debug', 'admin', 'api-key', 'token', 'x-forwarded-for']:
                tasks.append(self._test_param(url, 'HEADER', param, 'true', baseline))

        if tasks:
            # Execute in batches to respect semaphore
            await asyncio.gather(*tasks)

    async def _test_param(self, url: str, method: str, param: str, value: str, baseline: DiscoveryBaseline):
        async with self.semaphore:
            try:
                start = time.monotonic()
                resp = await self._execute_request(url, method, param, value)
                elapsed = time.monotonic() - start
                if not resp: return

                body = await resp.text()
                is_valid, reason = self._analyze_response(resp, body, elapsed, baseline)

                if is_valid:
                    self._record_found(url, param, method, reason, baseline, resp, body)
            except Exception: pass

    async def _execute_request(self, url: str, method: str, param: str, value: str):
        if method == 'GET':
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param] = [value]
            new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
            return await self._make_request(new_url, method='GET')

        if method == 'POST_JSON':
            data = {param: value}
            return await self._make_request(url, method='POST', data=json.dumps(data), headers={'Content-Type': 'application/json'})

        if method == 'HEADER':
            headers = {param: value}
            return await self._make_request(url, method='GET', headers=headers)

        return None

    def _analyze_response(self, resp, body: str, elapsed: float, baseline: DiscoveryBaseline) -> Tuple[bool, str]:
        # 1. Status Code Change
        if resp.status != baseline.status:
            return True, f"Status code changed from {baseline.status} to {resp.status}"

        # 2. Significant Size Change (>5% and >50 bytes)
        length = len(body)
        delta = abs(length - baseline.length)
        if delta > 50 and delta > (baseline.length * 0.05):
            return True, f"Response size changed by {delta} bytes"

        # 3. Content difference (New keywords)
        body_l = body.lower()
        current_keywords = {k for k in INTERESTING_KEYWORDS if k in body_l}
        new_keywords = current_keywords - baseline.keywords
        if new_keywords:
            return True, f"New interesting keywords appeared: {', '.join(new_keywords)}"

        # 4. Timing Anomaly (>3s and >2x baseline)
        if elapsed > 3.0 and elapsed > (baseline.response_time * 2):
            return True, f"Response time increased significantly: {elapsed:.2f}s"

        return False, ""

    def _record_found(self, url: str, param: str, method: str, reason: str, baseline: DiscoveryBaseline, resp, body: str):
        if url not in self.discovered_params:
            self.discovered_params[url] = []
        
        if param not in self.discovered_params[url]:
            self.discovered_params[url].append(param)
            
            severity = 'Low'
            if 'admin' in param or 'debug' in param or 'secret' in param: severity = 'Medium'
            if resp.status == 200 and baseline.status >= 400: severity = 'High'

            self.add_finding(Finding(
                module='fuzzing',
                title=f"Hidden Parameter Discovered: {param} ({method})",
                severity=severity,
                description=(
                    f"## Hidden Parameter Discovery\n\n"
                    f"The parameter `{param}` was discovered on endpoint `{url}` via `{method}` requests.\n\n"
                    f"**Detection Reason:** {reason}\n"
                    f"**Impact:** Discovered parameters may expose debug interfaces, administrative functions, or internal configurations."
                ),
                evidence={
                    'url': url, 'parameter': param, 'method': method, 'reason': reason,
                    'baseline_length': baseline.length, 'fuzzed_length': len(body)
                },
                poc=f"curl -i -X {method.split('_')[0]} '{url}' (with parameter {param}={ '...' })",
                remediation="Ensure all active parameters are documented, authenticated, and sanitized. Remove debug parameters in production.",
                cvss_score=5.3 if severity == 'Medium' else 3.1,
                bounty_score=300 if severity == 'Medium' else 100,
                target=url
            ))
            self.logger.info(f"[PARAM] Found {param} on {url} [{severity}]")

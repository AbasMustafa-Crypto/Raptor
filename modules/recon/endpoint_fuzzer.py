"""
endpoint_fuzzer.py — Enterprise-grade Directory & API Endpoint Fuzzer for RAPTOR.
"""

import asyncio
import urllib.parse
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from core.base_module import BaseModule, Finding


class EndpointFuzzer(BaseModule):
    """
    Professional-grade directory and endpoint fuzzer.
    Features:
    - Recursive discovery (detects directories and explores them)
    - Wildcard/Soft-404 detection via baseline failure analysis
    - Content-length and Hash-based anomaly detection
    - High-concurrency async probing
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(config.get('concurrency', 50))
        self.wordlist_path = config.get('wordlist', 'wordlists/dirs.txt')
        self.max_depth = config.get('max_depth', 2)
        self.visited: Set[str] = set()
        self.baselines: Dict[str, Dict] = {} # Base URL -> Baseline info

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info(f"🔥 Starting Enterprise Endpoint Fuzzing on {target}")
        
        # Load wordlist
        wordlist = self._load_wordlist()
        if not wordlist:
            return self.findings

        # Initial depth 0
        await self._fuzz_recursive(target, wordlist, depth=0)

        return self.findings

    def _load_wordlist(self) -> List[str]:
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                # Filter comments and empty lines, ensure leading slash
                paths = []
                for line in f:
                    p = line.strip()
                    if not p or p.startswith('#') or ' ' in p or '*' in p:
                        continue
                    if not p.startswith('/'):
                        p = '/' + p
                    paths.append(p)
                
                # Deduplicate and limit to top 2000 for efficiency
                unique_paths = list(dict.fromkeys(paths))
                self.logger.info(f"[FUZZ] Loaded {len(unique_paths)} paths, limiting to top 2000")
                return unique_paths[:2000]
        except Exception as e:
            self.logger.error(f"Failed to load wordlist {self.wordlist_path}: {e}")
            return []

    async def _fuzz_recursive(self, base_url: str, wordlist: List[str], depth: int):
        if depth > self.max_depth or base_url in self.visited:
            return
        
        self.visited.add(base_url)
        self.logger.info(f"[FUZZ] Probing {base_url} (Depth {depth})")

        # 1. Establish Baseline for this directory (to catch wildcards/soft-404s)
        baseline = await self._capture_baseline(base_url)
        if not baseline:
            return

        # 2. Run Fuzzing Tasks
        tasks = []
        # Limit to top 500 entries for depth > 0 to avoid explosion
        current_wordlist = wordlist if depth == 0 else wordlist[:500]
        
        for path in current_wordlist:
            url = urllib.parse.urljoin(base_url, path.lstrip('/'))
            tasks.append(self._probe_endpoint(url, base_url, baseline, wordlist, depth))
        
        if tasks:
            await asyncio.gather(*tasks)

    async def _capture_baseline(self, base_url: str) -> Optional[Dict]:
        """Establish baseline for a non-existent path to detect soft-404s."""
        fake_path = f"/raptor_probe_{hashlib.md5(base_url.encode()).hexdigest()[:8]}"
        url = urllib.parse.urljoin(base_url, fake_path)
        
        try:
            resp = await self._make_request(url, allow_redirects=False)
            if not resp: return None
            
            body = await resp.text()
            return {
                'status': resp.status,
                'length': len(body),
                'hash': hashlib.md5(body.encode('utf-8', errors='ignore')).hexdigest()
            }
        except Exception:
            return None

    async def _probe_endpoint(self, url: str, base_url: str, baseline: Dict, wordlist: List[str], depth: int):
        if url in self.visited:
            return

        async with self.semaphore:
            try:
                resp = await self._make_request(url, allow_redirects=False)
                if not resp: return
                
                # Check against baseline
                body = await resp.text()
                current_len = len(body)
                current_hash = hashlib.md5(body.encode('utf-8', errors='ignore')).hexdigest()

                # Anomaly Detection:
                # 1. Different status than baseline
                # 2. Different length than baseline (significant delta)
                # 3. Different hash
                is_real = False
                if resp.status != baseline['status']:
                    if resp.status in (200, 204, 301, 302, 307, 401, 403, 405):
                        is_real = True
                elif abs(current_len - baseline['length']) > 100 and current_hash != baseline['hash']:
                    is_real = True

                if is_real:
                    self.visited.add(url)
                    severity = 'Info'
                    if resp.status == 200: severity = 'Low'
                    if resp.status in (401, 403): severity = 'Medium'
                    
                    self.add_finding(Finding(
                        module='recon',
                        title=f"Discovered Endpoint: {url} (HTTP {resp.status})",
                        severity=severity,
                        description=f"A hidden or undocumented endpoint was discovered via fuzzing.\n\n**URL:** {url}\n**Status:** {resp.status}\n**Size:** {current_len}B",
                        evidence={'url': url, 'status': resp.status, 'length': current_len},
                        poc=f"curl -i {url}",
                        remediation="Ensure this endpoint is intentional and properly protected by authentication/authorization.",
                        cvss_score=3.1 if severity == 'Medium' else 0.0,
                        bounty_score=100 if severity == 'Medium' else 0,
                        target=url
                    ))

                    # If it looks like a directory (301 redirect or ends in /), recurse
                    if resp.status in (301, 302) or url.endswith('/'):
                        # Avoid recursing too deep or into external redirects
                        new_target = url if url.endswith('/') else url + '/'
                        if urllib.parse.urlparse(new_target).netloc == urllib.parse.urlparse(base_url).netloc:
                            await self._fuzz_recursive(new_target, wordlist, depth + 1)

            except Exception:
                pass

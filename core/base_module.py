"""
base_module.py  –  Zero-dependency base class for all RAPTOR modules.

FIXES
─────
1. request_timeout default → 10 s (was 30) — prevents hangs
2. retry_attempts default  → 1  (was 3) — avoids triple-timeout on dead params
3. retry_delay default     → 1  (was 2)
4. Connection refused / ECONNREFUSED → skip immediately, no retry
5. crawl_pages() helper — finds real injectable pages on the target
6. get_forms()    helper — extracts all HTML forms from a URL
"""

import asyncio
import logging
import ssl
import urllib.request
import urllib.error
import urllib.parse
import re
import random
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime


# ── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class Finding:
    module:       str
    title:        str
    severity:     str
    description:  str
    evidence:     Dict[str, Any] = field(default_factory=dict)
    poc:          str = ""
    remediation:  str = ""
    cvss_score:   float = 0.0
    bounty_score: int = 0
    timestamp:    datetime = field(default_factory=datetime.now)
    target:       str = ""

    def to_dict(self) -> Dict:
        return {
            'module':       self.module,
            'title':        self.title,
            'severity':     self.severity,
            'description':  self.description,
            'evidence':     self.evidence,
            'poc':          self.poc,
            'remediation':  self.remediation,
            'cvss_score':   self.cvss_score,
            'bounty_score': self.bounty_score,
            'timestamp':    self.timestamp.isoformat(),
            'target':       self.target,
        }


# ── Response wrapper ─────────────────────────────────────────────────────────

class _Response:
    def __init__(self, status: int, headers: dict, body: bytes, url: str):
        self.status  = status
        self.headers = headers
        self._body   = body
        self.url     = url

    async def read(self) -> bytes:
        return self._body

    async def text(self, encoding: str = 'utf-8', errors: str = 'replace') -> str:
        return self._body.decode(encoding, errors=errors)

    async def json(self):
        import json
        return json.loads(self._body)


# ── User-Agents ───────────────────────────────────────────────────────────────

_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

# These mean "no server listening" — no point retrying at all
_FATAL_ERRORS = (
    'connection refused',
    'no route to host',
    'network is unreachable',
    'name or service not known',
    'nodename nor servname provided',
    '[errno 111]',
    '[errno 113]',
)


# ── BaseModule ────────────────────────────────────────────────────────────────

class BaseModule(ABC):

    def __init__(self, config: Dict, stealth_manager=None, db_manager=None,
                 graph_manager=None):
        self.config  = config
        self.stealth = stealth_manager
        self.db      = db_manager
        self.graph   = graph_manager
        self.findings: List[Finding] = []
        self.logger  = logging.getLogger(self.__class__.__name__)
        self.session = self

        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    # ── Headers ───────────────────────────────────────────────────────────────

    async def _get_headers(self) -> Dict[str, str]:
        if self.stealth:
            try:
                return await self.stealth.get_headers()
            except Exception:
                pass
        return {
            'User-Agent':                random.choice(_USER_AGENTS),
            'Accept':                    'text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language':           'en-US,en;q=0.5',
            'Accept-Encoding':           'gzip, deflate',
            'Connection':                'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

    # ── HTTP ──────────────────────────────────────────────────────────────────

    async def _make_request(
        self,
        url:             str,
        method:          str = 'GET',
        data:            Any = None,
        headers:         Dict = None,
        allow_redirects: bool = True,
        timeout:         int  = None,
    ) -> Optional[_Response]:

        timeout_val = timeout or self.config.get('request_timeout', 10)
        max_retries = self.config.get('retry_attempts', 1)
        retry_delay = self.config.get('retry_delay', 1)

        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        for attempt in range(max_retries):
            try:
                if self.stealth:
                    await self.stealth.delay()

                req_headers = headers or await self._get_headers()

                encoded_data = None
                if data is not None:
                    if isinstance(data, str):
                        encoded_data = data.encode()
                    elif isinstance(data, bytes):
                        encoded_data = data
                    elif isinstance(data, dict):
                        encoded_data = urllib.parse.urlencode(data).encode()

                req = urllib.request.Request(
                    url,
                    data=encoded_data,
                    headers=req_headers,
                    method=method.upper(),
                )

                loop = asyncio.get_event_loop()
                response = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: self._do_urllib(req, timeout_val, allow_redirects),
                    ),
                    timeout=timeout_val + 3,
                )
                return response

            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout attempt {attempt+1} for {url}")

            except urllib.error.URLError as e:
                err_str = str(e).lower()
                self.logger.warning(f"URLError {url}: {e}")
                if any(s in err_str for s in _FATAL_ERRORS):
                    return None   # no retry

            except OSError as e:
                err_str = str(e).lower()
                self.logger.warning(f"OSError {url}: {e}")
                if any(s in err_str for s in _FATAL_ERRORS):
                    return None

            except Exception as e:
                self.logger.error(f"Request error {url}: {e}")

            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)

        return None

    def _do_urllib(self, req: urllib.request.Request,
                   timeout: int, allow_redirects: bool) -> _Response:
        opener = urllib.request.OpenerDirector()
        opener.addheaders = []
        if allow_redirects:
            opener.add_handler(urllib.request.HTTPRedirectHandler())
        opener.add_handler(urllib.request.HTTPHandler())
        opener.add_handler(urllib.request.HTTPSHandler(context=self._ssl_ctx))
        opener.add_handler(urllib.request.UnknownHandler())

        try:
            with opener.open(req, timeout=timeout) as resp:
                body      = resp.read()
                status    = resp.status
                hdrs      = dict(resp.headers)
                final_url = resp.url
        except urllib.error.HTTPError as e:
            body      = e.read() if hasattr(e, 'read') else b''
            status    = e.code
            hdrs      = dict(e.headers) if e.headers else {}
            final_url = req.full_url

        return _Response(status, hdrs, body, final_url)

    # ── Crawl helper ──────────────────────────────────────────────────────────

    async def crawl_pages(self, target: str, max_pages: int = 60,
                          same_host_only: bool = True) -> List[str]:
        """
        Crawl target and return a list of discovered page URLs including
        parameterised ones (the ones worth scanning for vulns).
        """
        from urllib.parse import urlparse, urljoin

        parsed   = urlparse(target)
        visited: Set[str]  = set()
        queue:   List[str] = [target]
        pages:   List[str] = []

        while queue and len(pages) < max_pages:
            url = queue.pop(0)
            # Normalise (drop fragment)
            url = url.split('#')[0]
            if url in visited:
                continue
            visited.add(url)

            resp = await self._make_request(url, timeout=8)
            if not resp or resp.status >= 400:
                continue

            pages.append(url)
            ct = resp.headers.get('Content-Type', '')
            if 'text/html' not in ct:
                continue

            body = await resp.text()

            for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
                raw  = m.group(1)
                link = urljoin(url, raw).split('#')[0]
                if not link.startswith('http'):
                    continue
                if same_host_only and urllib.parse.urlparse(link).netloc != parsed.netloc:
                    continue
                if link not in visited:
                    queue.append(link)

        return pages or [target]

    async def get_forms(self, url: str) -> List[Dict]:
        """Return list of {action, method, inputs} from all HTML forms at url."""
        from urllib.parse import urljoin
        resp = await self._make_request(url, timeout=8)
        if not resp:
            return []
        body = await resp.text()
        forms = []
        for m in re.finditer(r'<form(?P<a>[^>]*)>(?P<i>.*?)</form>',
                             body, re.DOTALL | re.I):
            action_m = re.search(r'action=["\']([^"\']*)["\']', m.group('a'), re.I)
            method_m = re.search(r'method=["\'](\w+)["\']',    m.group('a'), re.I)
            action   = action_m.group(1) if action_m else url
            method   = (method_m.group(1) if method_m else 'GET').upper()
            if not action.startswith('http'):
                action = urljoin(url, action)
            inputs = {}
            for inp in re.finditer(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                m.group('i'), re.I
            ):
                inputs[inp.group(1)] = inp.group(2) or 'test'
            for ta in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']',
                                  m.group('i'), re.I):
                inputs[ta.group(1)] = 'test'
            if inputs:
                forms.append({'action': action, 'method': method, 'inputs': inputs})
        return forms

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.logger.info(f"Finding: {finding.title} ({finding.severity})")
        if self.db:
            self.db.save_finding(finding)

    @abstractmethod
    async def run(self, target: str, **kwargs) -> List[Finding]:
        pass

    async def test_endpoint(self, url: str, method: str = 'GET',
                            params: Dict = None, data: Any = None) -> Dict:
        if params:
            url += '?' + urllib.parse.urlencode(params)
        response = await self._make_request(url, method, data)
        if not response:
            return {'error': 'No response'}
        return {
            'status':  response.status,
            'headers': response.headers,
            'url':     response.url,
            'method':  method,
        }

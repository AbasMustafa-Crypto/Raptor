"""
base_module.py  –  Zero-dependency base class for all RAPTOR modules.
Replaces aiohttp with Python's built-in urllib + asyncio.
All public API (Finding, BaseModule, _make_request, add_finding) is unchanged.
"""

import asyncio
import logging
import ssl
import urllib.request
import urllib.error
import urllib.parse
import random
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


# ── Finding dataclass (unchanged public API) ────────────────────────────────

@dataclass
class Finding:
    """Represents a security finding."""
    module:      str
    title:       str
    severity:    str           # Critical, High, Medium, Low, Info
    description: str
    evidence:    Dict[str, Any] = field(default_factory=dict)
    poc:         str = ""
    remediation: str = ""
    cvss_score:  float = 0.0
    bounty_score: int = 0
    timestamp:   datetime = field(default_factory=datetime.now)
    target:      str = ""

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


# ── Lightweight response wrapper ────────────────────────────────────────────

class _Response:
    """Mimics the parts of aiohttp.ClientResponse used by modules."""

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


# ── Default User-Agents pool ────────────────────────────────────────────────

_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
]


# ── BaseModule ───────────────────────────────────────────────────────────────

class BaseModule(ABC):
    """Base class for all RAPTOR modules (zero external deps)."""

    def __init__(self, config: Dict, stealth_manager=None, db_manager=None,
                 graph_manager=None):
        self.config  = config
        self.stealth = stealth_manager
        self.db      = db_manager
        self.graph   = graph_manager
        self.findings: List[Finding] = []
        self.logger  = logging.getLogger(self.__class__.__name__)
        # kept for API compat – not an aiohttp session, but modules call self.session
        self.session = self          # acts as a pass-through

        # SSL context that skips verification (same behaviour as before)
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    # ── Context manager ──────────────────────────────────────────────────────

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass   # nothing to close

    # ── Headers ─────────────────────────────────────────────────────────────

    async def _get_headers(self) -> Dict[str, str]:
        if self.stealth:
            try:
                return await self.stealth.get_headers()
            except Exception:
                pass
        return {
            'User-Agent':               random.choice(_USER_AGENTS),
            'Accept':                   'text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language':          'en-US,en;q=0.5',
            'Accept-Encoding':          'gzip, deflate',
            'Connection':               'keep-alive',
            'Upgrade-Insecure-Requests':'1',
        }

    # ── Core HTTP (runs urllib in a thread so callers stay async) ────────────

    async def _make_request(
        self,
        url:             str,
        method:          str = 'GET',
        data:            Any = None,
        headers:         Dict = None,
        allow_redirects: bool = True,
    ) -> Optional[_Response]:

        max_retries = self.config.get('retry_attempts', 3)
        retry_delay = self.config.get('retry_delay', 2)

        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        for attempt in range(max_retries):
            try:
                if self.stealth:
                    await self.stealth.delay()

                req_headers = headers or await self._get_headers()
                timeout_val = self.config.get('request_timeout', 30)

                # Build urllib Request
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

                # Run blocking urllib call in a thread pool
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: self._do_urllib(req, timeout_val, allow_redirects),
                )
                return response

            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout attempt {attempt+1} for {url}")
            except urllib.error.URLError as e:
                self.logger.warning(f"URLError {url}: {e}")
            except OSError as e:
                self.logger.warning(f"OSError {url}: {e}")
            except Exception as e:
                self.logger.error(f"Request error {url}: {e}")

            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay * (attempt + 1))

        return None

    def _do_urllib(self, req: urllib.request.Request,
                   timeout: int, allow_redirects: bool) -> _Response:
        """Blocking urllib call executed in a thread."""
        opener = urllib.request.OpenerDirector()
        opener.addheaders = []

        if allow_redirects:
            opener.add_handler(urllib.request.HTTPRedirectHandler())
        else:
            # No redirect handler → stops at first 3xx
            pass

        opener.add_handler(urllib.request.HTTPHandler())
        opener.add_handler(urllib.request.HTTPSHandler(context=self._ssl_ctx))
        opener.add_handler(urllib.request.UnknownHandler())

        try:
            with opener.open(req, timeout=timeout) as resp:
                body    = resp.read()
                status  = resp.status
                hdrs    = dict(resp.headers)
                final_url = resp.url
        except urllib.error.HTTPError as e:
            body      = e.read() if hasattr(e, 'read') else b''
            status    = e.code
            hdrs      = dict(e.headers) if e.headers else {}
            final_url = req.full_url

        return _Response(status, hdrs, body, final_url)

    # ── Findings ─────────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.logger.info(f"Finding: {finding.title} ({finding.severity})")
        if self.db:
            self.db.save_finding(finding)

    # ── Subclass interface ────────────────────────────────────────────────────

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

"""
base_module.py — Zero-dependency base class for all RAPTOR modules.

FIXES vs original
─────────────────
 1. asyncio.get_event_loop() → get_running_loop()  (deprecated in 3.10+)
 2. lambda req capture made safe with default-arg binding
 3. timeout_val cast to int so YAML strings don't cause TypeError
 4. _do_urllib: e.read() wrapped in try/except (can raise if body consumed)
 5. crawl_pages: separate 'queued' set so URLs are not enqueued multiple times
 6. crawl_pages: Content-Type lookup is now case-insensitive
 7. get_forms: input value regex fixed — value group properly optional & anchored
 8. get_forms: select elements now captured as form inputs
 9. Connection refused / fatal errors → return None immediately, no retry
10. request_timeout=10, retry_attempts=1, retry_delay=1 (sane defaults)
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
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    module:       str
    title:        str
    severity:     str          # Critical | High | Medium | Low | Info
    description:  str
    evidence:     Dict[str, Any] = field(default_factory=dict)
    poc:          str  = ""
    remediation:  str  = ""
    cvss_score:   float = 0.0
    bounty_score: int   = 0
    timestamp:    datetime = field(default_factory=datetime.now)
    target:       str  = ""

    def to_dict(self) -> Dict:
        return {
            "module":       self.module,
            "title":        self.title,
            "severity":     self.severity,
            "description":  self.description,
            "evidence":     self.evidence,
            "poc":          self.poc,
            "remediation":  self.remediation,
            "cvss_score":   self.cvss_score,
            "bounty_score": self.bounty_score,
            "timestamp":    self.timestamp.isoformat(),
            "target":       self.target,
        }


# ── Internal HTTP response wrapper ────────────────────────────────────────────

class HeaderProxy(dict):
    """A dictionary-like object that supports get_all for multi-value headers."""
    def __init__(self, headers_obj):
        # Initialise dict with single-value mapping
        super().__init__(dict(headers_obj))
        self._headers_obj = headers_obj

    def get_all(self, name, default=None):
        """Return all values for a given header name."""
        if hasattr(self._headers_obj, 'get_all'):
            return self._headers_obj.get_all(name, default)
        return [self.get(name)] if name in self else default

class _Response:
    def __init__(self, status: int, headers: Any, body: bytes, url: str):
        self.status  = status
        self.headers = HeaderProxy(headers)
        self._body   = body
        self.url     = url

    async def read(self) -> bytes:
        return self._body

    async def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        return self._body.decode(encoding, errors=errors)

    async def json(self) -> Any:
        import json
        return json.loads(self._body)


# ── Constants ─────────────────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Network errors where retrying is pointless
_FATAL_ERROR_SUBSTRINGS = (
    "connection refused",
    "no route to host",
    "network is unreachable",
    "name or service not known",
    "nodename nor servname provided",
    "[errno 111]",
    "[errno 113]",
)


# ── BaseModule ────────────────────────────────────────────────────────────────

class BaseModule(ABC):

    def __init__(
        self,
        config: Dict,
        stealth_manager=None,
        db_manager=None,
        graph_manager=None,
    ):
        self.config  = config
        self.stealth = stealth_manager
        self.db      = db_manager
        self.graph   = graph_manager
        self.findings: List[Finding] = []
        self.logger  = logging.getLogger(self.__class__.__name__)
        self.session = self  # legacy compat alias

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
            "User-Agent":                random.choice(_USER_AGENTS),
            "Accept":                    "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language":           "en-US,en;q=0.5",
            "Accept-Encoding":           "gzip, deflate",
            "Connection":                "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    # ── HTTP ──────────────────────────────────────────────────────────────────

    async def _make_request(
        self,
        url:             str,
        method:          str  = "GET",
        data:            Any  = None,
        headers:         Dict = None,
        allow_redirects: bool = True,
        timeout:         int  = None,
    ) -> Optional[_Response]:
        # FIX 3: cast to int so YAML-sourced strings don't cause TypeError
        timeout_val = int(timeout or self.config.get("request_timeout", 10))
        max_retries = int(self.config.get("retry_attempts", 1))
        retry_delay = float(self.config.get("retry_delay", 1))

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        for attempt in range(max_retries):
            try:
                if self.stealth:
                    await self.stealth.delay()

                req_headers = headers or await self._get_headers()

                encoded_data: Optional[bytes] = None
                if data is not None:
                    if isinstance(data, bytes):
                        encoded_data = data
                    elif isinstance(data, str):
                        encoded_data = data.encode()
                    elif isinstance(data, dict):
                        encoded_data = urllib.parse.urlencode(data).encode()

                req = urllib.request.Request(
                    url,
                    data=encoded_data,
                    headers=req_headers,
                    method=method.upper(),
                )

                # FIX 1: get_running_loop() instead of deprecated get_event_loop()
                loop = asyncio.get_running_loop()

                # FIX 2: bind req as default arg to avoid late-binding closure bug
                response = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda r=req: self._do_urllib(r, timeout_val, allow_redirects),
                    ),
                    timeout=timeout_val + 3,
                )
                return response

            except asyncio.TimeoutError:
                self.logger.warning("Timeout (attempt %d) for %s", attempt + 1, url)

            except urllib.error.URLError as exc:
                msg = str(exc).lower()
                self.logger.warning("URLError %s: %s", url, exc)
                if any(s in msg for s in _FATAL_ERROR_SUBSTRINGS):
                    return None  # no point retrying

            except OSError as exc:
                msg = str(exc).lower()
                self.logger.warning("OSError %s: %s", url, exc)
                if any(s in msg for s in _FATAL_ERROR_SUBSTRINGS):
                    return None

            except Exception as exc:
                self.logger.error("Request error %s: %s", url, exc)

            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)

        return None

    def _do_urllib(
        self,
        req: urllib.request.Request,
        timeout: int,
        allow_redirects: bool,
    ) -> _Response:
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
                hdrs      = resp.headers
                final_url = resp.url
        except urllib.error.HTTPError as exc:
            # FIX 7: e.read() can raise if body already consumed — guard it
            try:
                body = exc.read() if hasattr(exc, "read") else b""
            except Exception:
                body = b""
            status    = exc.code
            hdrs      = exc.headers if exc.headers else {}
            final_url = req.full_url

        return _Response(status, hdrs, body, final_url)

    # ── Crawl helper ──────────────────────────────────────────────────────────

    async def crawl_pages(
        self,
        target: str,
        max_pages: int = 60,
        same_host_only: bool = True,
    ) -> List[str]:
        """
        BFS crawl of target; returns discovered page URLs (including
        parameterised ones that are worth scanning for vulns).
        """
        from urllib.parse import urlparse, urljoin

        parsed    = urlparse(target)
        base_host = parsed.netloc

        visited: Set[str] = set()
        # FIX 5: track queued URLs separately so we never enqueue the same
        # URL twice, even before it has been processed.
        queued:  Set[str] = {target}
        queue:   List[str] = [target]
        pages:   List[str] = []

        while queue and len(pages) < max_pages:
            url = queue.pop(0).split("#")[0]  # drop fragment
            if url in visited:
                continue
            visited.add(url)

            resp = await self._make_request(url, timeout=8)
            if not resp or resp.status >= 400:
                continue

            pages.append(url)

            # FIX 4: case-insensitive Content-Type lookup
            ct = next(
                (v for k, v in resp.headers.items() if k.lower() == "content-type"),
                "",
            )
            if "text/html" not in ct.lower():
                continue

            body = await resp.text()

            for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
                raw  = m.group(1).strip()
                link = urljoin(url, raw).split("#")[0]
                if not link.startswith("http"):
                    continue
                if same_host_only and urlparse(link).netloc != base_host:
                    continue
                if link not in visited and link not in queued:
                    queued.add(link)
                    queue.append(link)

        return pages or [target]

    # ── Form extraction helper ─────────────────────────────────────────────────

    async def get_forms(self, url: str) -> List[Dict]:
        """Return list of {action, method, inputs} dicts for every HTML form."""
        from urllib.parse import urljoin

        resp = await self._make_request(url, timeout=8)
        if not resp:
            return []
        body = await resp.text()
        forms = []

        for form_m in re.finditer(
            r"<form(?P<attrs>[^>]*)>(?P<inner>.*?)</form>",
            body,
            re.DOTALL | re.I,
        ):
            attrs_str = form_m.group("attrs")
            inner     = form_m.group("inner")

            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs_str, re.I)
            method_m = re.search(r'method=["\'](\w+)["\']',     attrs_str, re.I)

            action = action_m.group(1) if action_m else url
            method = (method_m.group(1) if method_m else "GET").upper()
            if not action.startswith("http"):
                action = urljoin(url, action)

            inputs: Dict[str, str] = {}

            # FIX 5: Corrected input regex — name and optional value are
            # matched as independent attributes anywhere in the tag, not
            # positionally chained, so we find name first then search for
            # value separately per input element.
            for inp_m in re.finditer(r"<input([^>]*)>", inner, re.I):
                tag_body = inp_m.group(1)
                name_m   = re.search(r'name=["\']([^"\']+)["\']', tag_body, re.I)
                if not name_m:
                    continue
                name    = name_m.group(1)
                value_m = re.search(r'value=["\']([^"\']*)["\']', tag_body, re.I)
                inputs[name] = value_m.group(1) if value_m else "test"

            # Textarea elements
            for ta_m in re.finditer(
                r'<textarea[^>]+name=["\']([^"\']+)["\']', inner, re.I
            ):
                inputs[ta_m.group(1)] = "test"

            # FIX 8: Select elements (common form inputs missed by original)
            for sel_m in re.finditer(
                r'<select[^>]+name=["\']([^"\']+)["\']', inner, re.I
            ):
                inputs[sel_m.group(1)] = "1"

            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs})

        return forms

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.logger.info("Finding: %s (%s)", finding.title, finding.severity)
        if self.db:
            self.db.save_finding(finding)

    @abstractmethod
    async def run(self, target: str, **kwargs) -> List[Finding]:
        pass

    async def test_endpoint(
        self,
        url:    str,
        method: str  = "GET",
        params: Dict = None,
        data:   Any  = None,
    ) -> Dict:
        if params:
            url += "?" + urllib.parse.urlencode(params)
        response = await self._make_request(url, method, data)
        if not response:
            return {"error": "No response"}
        return {
            "status":  response.status,
            "headers": response.headers,
            "url":     response.url,
            "method":  method,
        }

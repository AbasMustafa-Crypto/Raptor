"""
RAPTOR IDOR Testing Module v4.0 - Autonomous Detection
========================================================
Advanced Insecure Direct Object Reference detection without credentials.
Features:
- Passive IDOR detection via response analysis
- Active ID parameter fuzzing with smart inference
- Session-aware testing (single session manipulation)
- Predictable ID pattern analysis
- Graph-based vulnerability mapping
"""

import asyncio
import re
import json
import hashlib
import random
from typing import List, Dict, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, urlencode, quote
from core.base_module import BaseModule, Finding


@dataclass
class IDORPattern:
    """IDOR detection pattern configuration"""
    name: str
    pattern: str
    id_extractor: str
    test_strategy: str
    severity: str
    bounty_score: int
    confidence: float


@dataclass
class ResourceEndpoint:
    """Discovered resource endpoint"""
    url: str
    method: str
    param_name: Optional[str]
    param_value: str
    resource_type: str
    response_sample: str
    content_type: str
    auth_required: bool = False


class IDORTester(BaseModule):
    """
    Autonomous IDOR detection module for RAPTOR Framework.
    
    No credentials required. Uses:
    1. Response analysis to identify IDOR patterns
    2. Parameter fuzzing with ID manipulation
    3. Predictable ID sequence detection
    4. Access control bypass testing
    """
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.findings: List[Finding] = []
        self.discovered_endpoints: List[ResourceEndpoint] = []
        self.tested_combinations: Set[str] = set()
        self.session_cookies: Dict[str, str] = {}
        
        # Configuration
        self.fuzz_range = config.get('idor_fuzz_range', 50)
        self.max_depth = config.get('max_depth', 3)
        self.rate_limit = config.get('rate_limit', 10)
        self.id_patterns = self._load_id_patterns()
        self.high_value_indicators = config.get('high_value_indicators', [
            'account', 'user', 'order', 'invoice', 'payment', 'document',
            'file', 'download', 'admin', 'api_key', 'token', 'password'
        ])
        
    def _load_id_patterns(self) -> List[IDORPattern]:
        """Load comprehensive IDOR detection patterns"""
        return [
            IDORPattern(
                name='Sequential Numeric ID',
                pattern=r'[?&/](id|user_id|account_id|order_id|doc_id|file_id|invoice_id|payment_id|product_id)[=/](\d+)',
                id_extractor=r'(\d+)$',
                test_strategy='sequential',
                severity='Critical',
                bounty_score=2500,
                confidence=0.9
            ),
            IDORPattern(
                name='RESTful Object Reference',
                pattern=r'/api/v?\d*/(users|orders|documents|files|accounts|invoices|payments|products|items)/(\d+|[a-f0-9-]{36})',
                id_extractor=r'/([^/]+)$',
                test_strategy='rest_manipulation',
                severity='Critical',
                bounty_score=3000,
                confidence=0.95
            ),
            IDORPattern(
                name='UUID in Path',
                pattern=r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
                id_extractor=r'/([a-f0-9-]{36})$',
                test_strategy='uuid_swap',
                severity='Medium',
                bounty_score=1000,
                confidence=0.6
            ),
            IDORPattern(
                name='Predictable Token',
                pattern=r'[?&/](token|access_token|auth_token|api_key|session_id)[=/]([a-zA-Z0-9]{8,64})',
                id_extractor=r'[=/]([a-zA-Z0-9]{8,64})$',
                test_strategy='token_manipulation',
                severity='High',
                bounty_score=2000,
                confidence=0.8
            ),
            IDORPattern(
                name='GraphQL ID Argument',
                pattern=r'["\']id["\']\s*:\s*["\']?(\d+)["\']?',
                id_extractor=r'(\d+)',
                test_strategy='graphql_id',
                severity='High',
                bounty_score=1800,
                confidence=0.85
            ),
            IDORPattern(
                name='Hash-based ID',
                pattern=r'[?&/](hash|checksum|md5|sha)[=/]([a-f0-9]{8,64})',
                id_extractor=r'[=/]([a-f0-9]{8,64})$',
                test_strategy='hash_prediction',
                severity='Medium',
                bounty_score=1200,
                confidence=0.5
            ),
            IDORPattern(
                name='Email-based Reference',
                pattern=r'[?&/](email|user|username)[=/]([^&]+@[^&]+)',
                id_extractor=r'[=/]([^&]+@[^&]+)',
                test_strategy='email_manipulation',
                severity='High',
                bounty_score=2200,
                confidence=0.75
            ),
            IDORPattern(
                name='Bulk ID Array',
                pattern=r'[?&/]ids[=/]?([^&]+)',
                id_extractor=r'[=/]([^&]+)',
                test_strategy='bulk_access',
                severity='Critical',
                bounty_score=3500,
                confidence=0.9
            ),
        ]
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.logger.info("🔥 Initializing IDOR Testing Module")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.findings and self.db:
            await self._store_findings()
        return False
    
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Execute autonomous IDOR testing.
        
        Args:
            target: Target URL
            scope: 'quick', 'standard', 'comprehensive', 'aggressive'
            
        Returns:
            List of Finding objects
        """
        scope = kwargs.get('scope', 'standard')
        self.logger.info(f"🚀 Starting IDOR scan against {target} [Scope: {scope}]")
        
        # Phase 1: Crawl and discover endpoints
        self.logger.info("🔍 Phase 1: Discovering resource endpoints")
        await self._discover_endpoints(target, scope)
        
        # Phase 2: Analyze responses for ID patterns
        self.logger.info("📊 Phase 2: Analyzing ID patterns")
        await self._analyze_id_patterns()
        
        # Phase 3: Test ID manipulation (sequential)
        self.logger.info("🎯 Phase 3: Testing sequential ID manipulation")
        await self._test_sequential_ids()
        
        # Phase 4: Test parameter pollution
        if scope in ['comprehensive', 'aggressive']:
            self.logger.info("💉 Phase 4: Testing parameter pollution")
            await self._test_parameter_pollution()
        
        # Phase 5: Test HTTP method bypass
        if scope in ['standard', 'comprehensive', 'aggressive']:
            self.logger.info("🔄 Phase 5: Testing HTTP method bypass")
            await self._test_method_bypass()
        
        # Phase 6: Test for mass assignment
        if scope in ['comprehensive', 'aggressive']:
            self.logger.info("📦 Phase 6: Testing mass assignment")
            await self._test_mass_assignment()
        
        # Phase 7: Graph analysis
        if self.graph:
            self.logger.info("🕸️ Phase 7: Analyzing attack paths")
            await self._analyze_graph_paths(target)
        
        self.logger.info(f"✅ IDOR module complete. Findings: {len(self.findings)}")
        return self.findings
    
    async def _discover_endpoints(self, target: str, scope: str):
        """Crawl target and discover potential IDOR endpoints"""
        to_visit = {target}
        visited = set()
        max_pages = 10 if scope == 'quick' else 30 if scope == 'standard' else 80
        
        # Common API paths to test
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/graphql', '/json', '/ajax',
            '/user', '/users', '/account', '/accounts',
            '/order', '/orders', '/document', '/documents',
            '/file', '/files', '/download', '/downloads',
            '/invoice', '/invoices', '/payment', '/payments',
            '/product', '/products', '/item', '/items',
            '/admin', '/manage', '/internal', '/private',
            '/config', '/settings', '/profile', '/me'
        ]
        
        # Add API paths to visit list
        base_parsed = urlparse(target)
        for path in api_paths:
            to_visit.add(f"{base_parsed.scheme}://{base_parsed.netloc}{path}")
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop()
            if url in visited:
                continue
            
            visited.add(url)
            
            try:
                response = await self._make_request(url)
                if not response:
                    continue
                
                # Store session cookies if any
                if response.cookies:
                    self.session_cookies.update(response.cookies)
                
                content_type = response.headers.get('Content-Type', '')
                body = await response.text()
                
                # Check if this looks like a resource endpoint
                endpoint = self._analyze_endpoint(url, response.status, content_type, body)
                if endpoint:
                    self.discovered_endpoints.append(endpoint)
                    self.logger.info(f"  Found endpoint: {endpoint.url} ({endpoint.resource_type})")
                
                # Extract links for further crawling
                if 'text/html' in content_type:
                    links = self._extract_links(body, url)
                    to_visit.update(links - visited)
                
                # Extract API endpoints from JS
                if 'javascript' in content_type or '<script' in body:
                    api_links = self._extract_api_endpoints(body, url)
                    to_visit.update(api_links - visited)
                
                # Rate limiting
                if self.stealth:
                    await asyncio.sleep(1 / self.rate_limit)
                    
            except Exception as e:
                self.logger.debug(f"Crawl error for {url}: {e}")
        
        self.logger.info(f"Discovered {len(self.discovered_endpoints)} resource endpoints")
    
    def _analyze_endpoint(self, url: str, status: int, content_type: str, body: str) -> Optional[ResourceEndpoint]:
        """Analyze if URL is a potential IDOR endpoint"""
        
        # Skip error pages
        if status >= 400:
            return None
        
        # Check for ID patterns in URL
        for pattern in self.id_patterns:
            matches = list(re.finditer(pattern.pattern, url, re.IGNORECASE))
            if matches:
                match = matches[0]
                id_value = match.group(2) if len(match.groups()) > 1 else match.group(1)
                
                return ResourceEndpoint(
                    url=url,
                    method='GET',
                    param_name=self._extract_param_name(url, pattern.name),
                    param_value=id_value,
                    resource_type=self._classify_resource_type(url, body),
                    response_sample=body[:500],
                    content_type=content_type,
                    auth_required=self._detect_auth_required(status, body)
                )
        
        # Check for REST patterns without ID (collection endpoints)
        rest_pattern = r'/api/v?\d*/(users|orders|documents|files|accounts|invoices|payments|products)'
        if re.search(rest_pattern, url, re.IGNORECASE):
            # This might be a list endpoint - check if it returns array
            try:
                data = json.loads(body)
                if isinstance(data, list) and len(data) > 0:
                    return ResourceEndpoint(
                        url=url,
                        method='GET',
                        param_name=None,
                        param_value='',
                        resource_type='collection',
                        response_sample=body[:500],
                        content_type=content_type,
                        auth_required=self._detect_auth_required(status, body)
                    )
            except:
                pass
        
        return None
    
    def _extract_param_name(self, url: str, pattern_name: str) -> Optional[str]:
        """Extract parameter name from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in ['id', 'user_id', 'account_id', 'order_id', 'doc_id', 'file_id']:
            if param in params:
                return param
        
        # Extract from path
        match = re.search(r'/(\w+)_id/', url)
        if match:
            return match.group(1) + '_id'
        
        return 'id'
    
    def _classify_resource_type(self, url: str, body: str) -> str:
        """Classify the type of resource"""
        url_lower = url.lower()
        
        # High-value indicators
        for indicator in self.high_value_indicators:
            if indicator in url_lower:
                return indicator
        
        # Check body for type hints
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                if any(k in data for k in ['username', 'email', 'password', 'role']):
                    return 'user_account'
                if any(k in data for k in ['credit_card', 'payment_method', 'billing']):
                    return 'payment'
                if any(k in data for k in ['ssn', 'dob', 'address', 'phone']):
                    return 'pii'
        except:
            pass
        
        return 'generic'
    
    def _detect_auth_required(self, status: int, body: str) -> bool:
        """Detect if endpoint requires authentication"""
        auth_indicators = ['login', 'unauthorized', 'authentication required', 'sign in', '401', '403']
        body_lower = body.lower()
        
        if status in [401, 403]:
            return True
        
        return any(ind in body_lower for ind in auth_indicators)
    
    def _extract_links(self, body: str, base_url: str) -> Set[str]:
        """Extract links from HTML body"""
        links = set()
        
        # href links
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, body):
            href = match.group(1)
            full_url = urljoin(base_url, href)
            links.add(full_url)
        
        # API endpoints in JS
        js_pattern = r'["\'](/api/[^"\']+)["\']'
        for match in re.finditer(js_pattern, body):
            endpoint = match.group(1)
            full_url = urljoin(base_url, endpoint)
            links.add(full_url)
        
        return links
    
    def _extract_api_endpoints(self, body: str, base_url: str) -> Set[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = set()
        
        # Common patterns
        patterns = [
            r'["\'](/api/v?\d+/[^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, body):
                endpoint = match.group(1) if len(match.groups()) == 1 else match.group(2)
                if endpoint.startswith('/'):
                    full_url = urljoin(base_url, endpoint)
                    endpoints.add(full_url)
        
        return endpoints
    
    async def _analyze_id_patterns(self):
        """Analyze discovered endpoints for ID predictability"""
        numeric_ids = []
        
        for endpoint in self.discovered_endpoints:
            value = endpoint.param_value
            if value.isdigit():
                numeric_ids.append(int(value))
        
        if len(numeric_ids) >= 2:
            # Check for sequential patterns
            numeric_ids.sort()
            gaps = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
            
            if all(g == 1 for g in gaps):
                self.logger.warning("🚨 CRITICAL: Sequential ID pattern detected (1, 2, 3...)")
                self._create_pattern_finding(
                    "Sequential ID Pattern",
                    "IDs are sequential integers (1, 2, 3...)",
                    "Critical",
                    4000,
                    {"ids": numeric_ids[:10], "pattern": "sequential"}
                )
            elif all(g == gaps[0] for g in gaps):
                self.logger.warning(f"🚨 Predictable ID pattern detected (step: {gaps[0]})")
                self._create_pattern_finding(
                    "Predictable ID Pattern",
                    f"IDs follow predictable arithmetic sequence (step: {gaps[0]})",
                    "High",
                    2500,
                    {"ids": numeric_ids[:10], "step": gaps[0]}
                )
    
    def _create_pattern_finding(self, title: str, description: str, severity: str, bounty: int, evidence: Dict):
        """Create finding for ID pattern vulnerability"""
        finding = Finding(
            module='idor',
            title=f"[PATTERN] {title}",
            severity=severity,
            description=f"""
## IDOR Pattern Vulnerability

**Type:** {title}
**Description:** {description}

### Impact
Predictable ID patterns make it trivial for attackers to enumerate all resources
by simply incrementing or decrementing the ID value.

### Evidence
```json
{json.dumps(evidence, indent=2)}
```
""",
            evidence=evidence,
            poc=f"Enumerate IDs: curl 'https://target.com/api/resource/[1-100]'",
            remediation='Implement proper authorization checks. Use UUIDs instead of sequential IDs. Validate that the authenticated user owns the requested resource.',
            cvss_score=9.1 if severity == 'Critical' else 7.5,
            bounty_score=bounty,
            target=''
        )
        self.findings.append(finding)
        if self.db:
            self.db.save_finding(finding)

    async def _test_sequential_ids(self):
        """Test sequential ID manipulation on discovered endpoints"""
        for endpoint in self.discovered_endpoints:
            if not endpoint.param_value.isdigit():
                continue

            base_id = int(endpoint.param_value)
            test_ids = list(range(max(1, base_id - 5), base_id)) + list(range(base_id + 1, base_id + 6))

            for test_id in test_ids:
                combo = f"{endpoint.url}:{test_id}"
                if combo in self.tested_combinations:
                    continue
                self.tested_combinations.add(combo)

                try:
                    parsed = urlparse(endpoint.url)
                    params = parse_qs(parsed.query)

                    if endpoint.param_name and endpoint.param_name in params:
                        new_params = {k: v for k, v in params.items()}
                        new_params[endpoint.param_name] = [str(test_id)]
                        new_query = urlencode(new_params, doseq=True)
                        test_url = parsed._replace(query=new_query).geturl()
                    else:
                        # Replace last numeric segment in path
                        test_url = re.sub(r'/\d+(/|$)', f'/{test_id}\\1', endpoint.url)

                    response = await self._make_request(test_url)
                    if not response or response.status in [401, 403, 404]:
                        continue

                    body = await response.text()
                    if len(body) > 50 and not self._is_error_response(body):
                        finding = Finding(
                            module='idor',
                            title=f'IDOR: Sequential ID Access on {endpoint.resource_type}',
                            severity='Critical',
                            description=f'Successfully accessed resource with ID {test_id} (original: {base_id}) without authorization check.',
                            evidence={
                                'original_id': base_id,
                                'tested_id': test_id,
                                'url': test_url,
                                'resource_type': endpoint.resource_type,
                                'response_size': len(body)
                            },
                            poc=f"curl '{test_url}'",
                            remediation='Implement object-level authorization. Verify the authenticated user owns the requested resource ID before returning data.',
                            cvss_score=9.1,
                            bounty_score=3000,
                            target=endpoint.url
                        )
                        self.add_finding(finding)
                        return  # one confirmed finding is enough per endpoint

                except Exception as e:
                    self.logger.debug(f"Sequential ID test error: {e}")

    async def _test_parameter_pollution(self):
        """Test HTTP parameter pollution for IDOR bypass"""
        for endpoint in self.discovered_endpoints:
            if not endpoint.param_name:
                continue
            try:
                polluted_url = f"{endpoint.url}&{endpoint.param_name}=1"
                response = await self._make_request(polluted_url)
                if response and response.status == 200:
                    body = await response.text()
                    if not self._is_error_response(body):
                        finding = Finding(
                            module='idor',
                            title=f'Parameter Pollution IDOR on {endpoint.param_name}',
                            severity='High',
                            description=f'Parameter pollution may bypass authorization on {endpoint.url}',
                            evidence={'url': polluted_url, 'param': endpoint.param_name},
                            poc=f"curl '{polluted_url}'",
                            remediation='Use only the last or first occurrence of each parameter; validate ownership server-side.',
                            cvss_score=7.5,
                            bounty_score=2000,
                            target=endpoint.url
                        )
                        self.add_finding(finding)
            except Exception as e:
                self.logger.debug(f"Parameter pollution error: {e}")

    async def _test_method_bypass(self):
        """Test HTTP method override for IDOR bypass"""
        override_headers = [
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-HTTP-Method-Override': 'DELETE'},
            {'X-Method-Override': 'PATCH'},
        ]
        for endpoint in self.discovered_endpoints:
            for hdrs in override_headers:
                try:
                    response = await self._make_request(endpoint.url, headers=hdrs)
                    if response and response.status not in [401, 403, 404, 405]:
                        finding = Finding(
                            module='idor',
                            title=f'HTTP Method Override Bypass on {endpoint.resource_type}',
                            severity='High',
                            description=f'HTTP method override accepted on {endpoint.url}',
                            evidence={'url': endpoint.url, 'header': hdrs},
                            poc=f"curl -H '{list(hdrs.keys())[0]}: {list(hdrs.values())[0]}' '{endpoint.url}'",
                            remediation='Ignore X-HTTP-Method-Override unless explicitly required; enforce authorization per method.',
                            cvss_score=7.5,
                            bounty_score=1500,
                            target=endpoint.url
                        )
                        self.add_finding(finding)
                        break
                except Exception as e:
                    self.logger.debug(f"Method bypass error: {e}")

    async def _test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        privileged_fields = ['role', 'isAdmin', 'admin', 'is_staff', 'permissions', 'account_type']
        for endpoint in self.discovered_endpoints:
            for field in privileged_fields:
                try:
                    payload = {field: 'admin'}
                    response = await self._make_request(endpoint.url, method='POST', data=payload)
                    if response and response.status in [200, 201]:
                        body = await response.text()
                        if field in body:
                            finding = Finding(
                                module='idor',
                                title=f'Mass Assignment: {field} field accepted',
                                severity='Critical',
                                description=f'Server accepted privileged field "{field}" in POST body at {endpoint.url}',
                                evidence={'url': endpoint.url, 'field': field},
                                poc=f"curl -X POST '{endpoint.url}' -d '{field}=admin'",
                                remediation='Use allowlists for accepted fields; never bind user input directly to model attributes.',
                                cvss_score=9.1,
                                bounty_score=3500,
                                target=endpoint.url
                            )
                            self.add_finding(finding)
                except Exception as e:
                    self.logger.debug(f"Mass assignment error: {e}")

    async def _analyze_graph_paths(self, target: str):
        """Use graph manager to find attack paths if available"""
        try:
            if self.graph and getattr(self.graph, 'enabled', False):
                paths = self.graph.find_attack_paths()
                for path in paths:
                    self.logger.info(f"Graph attack path: {path}")
        except Exception as e:
            self.logger.debug(f"Graph analysis error: {e}")

    async def _store_findings(self):
        """Persist findings to database"""
        if self.db:
            for finding in self.findings:
                try:
                    self.db.save_finding(finding)
                except Exception:
                    pass

    def _is_error_response(self, body: str) -> bool:
        """Check if response body looks like an error page"""
        error_indicators = ['404', 'not found', 'error', 'forbidden', 'unauthorized', 'invalid']
        body_lower = body.lower()[:300]
        return any(ind in body_lower for ind in error_indicators)

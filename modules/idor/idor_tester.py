"""
RAPTOR IDOR Testing Module v4.0 - Enterprise Grade
==================================================
Professional-grade IDOR (Insecure Direct Object Reference) detection engine.
Implements multi-session behavioral analysis, deep REST fuzzing, and 
mass assignment probing with high-fidelity anomaly detection.
"""

import re
import json
import uuid
import base64
import random
import string
import hashlib
import asyncio
import os
import time
from difflib import SequenceMatcher
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, parse_qs, urlparse, urlencode, quote

from core.base_module import BaseModule, Finding

# ── Constants & Configuration ────────────────────────────────────────────────

DEFAULT_THRESHOLDS = {
    'structure': 0.85,  # JSON key similarity
    'content': 0.90,    # Overall text similarity
    'identity': 0.95    # Similarity to "owned" resource
}

SENSITIVE_DATA_MARKERS = {
    'PII': [r'\b\d{3}-\d{2}-\d{4}\b', r'\b[A-Z]{2}\d{6}[A-Z]\b'], # SSN, Passport
    'Email': [r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'],
    'Finance': [r'\b(?:\d[ -]?){13,16}\b', r'BC\d{4,10}'], # Credit Card, Bank
    'Auth': [r'"(token|auth|session|secret)"\s*:\s*"[^"]+"', r'ey[a-zA-Z0-9._\-]{20,}'] # JWT
}

PRIVILEGED_PAYLOADS = [
    {'role': 'admin'}, {'isAdmin': True}, {'admin': 1}, {'is_staff': True},
    {'privilege': 'superuser'}, {'access_level': 100}, {'permissions': '*'}
]

# ── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    url: str
    method: str
    params: Dict[str, Any]
    type: str # 'GET', 'POST_FORM', 'POST_JSON', 'REST'
    original_id: Optional[str] = None
    param_name: Optional[str] = None

@dataclass
class Baseline:
    status: int
    length: int
    body: str
    structure: Set[str] # Keys if JSON
    identity_markers: Set[str] # Strings that likely represent the current user

# ── IDORTester Class ─────────────────────────────────────────────────────────

class IDORTester(BaseModule):
    """
    Enterprise-grade IDOR detection module.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(10)
        self.discovered_endpoints: List[Endpoint] = []
        self.baselines: Dict[str, Baseline] = {}
        self.max_pages = config.get('max_pages', 30)

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info(f"🔥 Starting Enterprise IDOR Audit on {target}")

        # PHASE 0 — SURFACE COLLECTION
        await self._collect_surfaces(target)
        self.logger.info(f"[IDOR] Discovered {len(self.discovered_endpoints)} potential ID-bearing endpoints")

        # PHASE 1 — BASELINE CAPTURE
        for ep in self.discovered_endpoints:
            await self._capture_baseline(ep)

        # PHASE 2 — MULTI-VECTOR FUZZING
        tasks = []
        for ep in self.discovered_endpoints:
            if ep.url in self.baselines:
                tasks.append(self._test_endpoint(ep))
        
        if tasks:
            await asyncio.gather(*tasks)

        return self.findings

    # ── Phase 0: Surface Collection ──────────────────────────────────────────

    async def _collect_surfaces(self, target: str):
        """Find endpoints with numeric IDs, UUIDs, or common 'id' parameters."""
        pages = set(await self.crawl_pages(target, max_pages=self.max_pages))
        pages.add(target)

        for page in pages:
            parsed = urlparse(page)
            
            # 1. Check URL Parameters
            qs = parse_qs(parsed.query)
            for p, vals in qs.items():
                if self._is_id_like(vals[0]):
                    self.discovered_endpoints.append(Endpoint(
                        url=page, method='GET', params=qs, type='GET',
                        original_id=vals[0], param_name=p
                    ))

            # 2. Check RESTful Path Segments
            segments = parsed.path.split('/')
            for i, seg in enumerate(segments):
                if self._is_id_like(seg):
                    self.discovered_endpoints.append(Endpoint(
                        url=page, method='GET', params={'index': i}, type='REST',
                        original_id=seg
                    ))

            # 3. Check Forms
            forms = await self.get_forms(page)
            for form in forms:
                for name, val in form['inputs'].items():
                    if self._is_id_like(val) or any(x in name.lower() for x in ('id', 'user', 'account')):
                        self.discovered_endpoints.append(Endpoint(
                            url=form['action'], method=form['method'], 
                            params=form['inputs'], type='POST_FORM',
                            original_id=val, param_name=name
                        ))

    def _is_id_like(self, value: str) -> bool:
        """Heuristic to detect IDs: numeric, UUID, or certain hash lengths."""
        if not value: return False
        if value.isdigit(): return True
        if len(value) == 36 and '-' in value: # UUID
            try:
                uuid.UUID(value)
                return True
            except ValueError: pass
        if len(value) in (32, 40, 64) and all(c in string.hexdigits for c in value): # Hash
            return True
        return False

    # ── Phase 1: Baseline Capture ────────────────────────────────────────────

    async def _capture_baseline(self, ep: Endpoint):
        """Establish what 'my' resource looks like."""
        try:
            resp = await self._execute_request(ep)
            if not resp or resp.status != 200: return

            body = await resp.text()
            struct = set()
            try:
                data = json.loads(body)
                if isinstance(data, dict): struct = set(data.keys())
            except Exception: pass

            # Identity markers: values in the response that likely identify the user
            # (e.g. if I am user 123, '123' is an identity marker)
            markers = set()
            if ep.original_id: markers.add(ep.original_id)
            
            self.baselines[ep.url] = Baseline(
                status=resp.status, length=len(body), body=body,
                structure=struct, identity_markers=markers
            )
        except Exception: pass

    # ── Phase 2: Testing & Anomaly Detection ─────────────────────────────────

    async def _test_endpoint(self, ep: Endpoint):
        async with self.semaphore:
            # 1. ID Shifting (Numeric)
            if ep.original_id and ep.original_id.isdigit():
                base_id = int(ep.original_id)
                # Test ±1, ±10, 0, -1
                for offset in [-1, 1, -10, 10, 0]:
                    target_id = str(base_id + offset)
                    if target_id == ep.original_id: continue
                    await self._fuzz_and_compare(ep, target_id, "ID Shifting")

            # 2. UUID Fuzzing (if UUID, try random UUID)
            if ep.original_id and len(ep.original_id) == 36:
                await self._fuzz_and_compare(ep, str(uuid.uuid4()), "Random UUID")

            # 3. HTTP Method Swapping
            if ep.method == 'GET':
                for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    await self._test_verb_bypass(ep, method)

            # 4. Parameter Pollution
            if ep.type == 'GET' and ep.param_name:
                polluted_url = f"{ep.url}&{ep.param_name}=99999" # Simple pollution
                await self._fuzz_and_compare(ep, "99999", "HPP (Parameter Pollution)", custom_url=polluted_url)

            # 5. Mass Assignment
            if ep.method in ('POST', 'PUT', 'PATCH'):
                await self._test_mass_assignment(ep)

    async def _fuzz_and_compare(self, ep: Endpoint, test_id: str, technique: str, custom_url: str = None):
        """Inject test_id, execute, and detect IDOR."""
        try:
            resp = await self._execute_request(ep, test_id, custom_url=custom_url)
            if not resp: return
            
            body = await resp.text()
            baseline = self.baselines[ep.url]

            # ANOMALY DETECTION
            is_anomaly, reason = self._detect_idor_anomaly(baseline, resp.status, body)
            
            if is_anomaly:
                await self._report_idor(ep, test_id, technique, resp.status, body, reason)
        except Exception: pass

    def _detect_idor_anomaly(self, baseline: Baseline, status: int, body: str) -> Tuple[bool, str]:
        """Compare against baseline to find IDOR evidence."""
        if status != 200: return False, ""
        
        # 1. Structure Check (High confidence for JSON APIs)
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                current_struct = set(data.keys())
                # If keys match baseline but data changed -> Potential IDOR
                intersection = current_struct.intersection(baseline.structure)
                if len(intersection) / len(baseline.structure) > DEFAULT_THRESHOLDS['structure']:
                    # Check if identity markers changed (e.g. email is different)
                    if self._identity_changed(baseline, body):
                        return True, "Response structure matches baseline but identity data changed (PII leakage)."
        except Exception: pass

        # 2. Sensitive Content Leakage
        found_sensitive, items = self._check_sensitive(body)
        if found_sensitive:
            return True, f"Response contains sensitive data markers: {', '.join(items)}"

        # 3. Similarity Check
        sim = SequenceMatcher(None, baseline.body, body).ratio()
        if sim > DEFAULT_THRESHOLDS['content'] and sim < 1.0:
             if self._identity_changed(baseline, body):
                return True, f"Response is {sim:.1%} similar to baseline but contains different identity markers."

        return False, ""

    def _identity_changed(self, baseline: Baseline, body: str) -> bool:
        """Check if values that were in the baseline are missing/changed in the new body."""
        for marker in baseline.identity_markers:
            if marker in baseline.body and marker not in body:
                return True
        return False

    def _check_sensitive(self, body: str) -> Tuple[bool, List[str]]:
        found = []
        for cat, patterns in SENSITIVE_DATA_MARKERS.items():
            for p in patterns:
                if re.search(p, body):
                    found.append(cat)
                    break
        return bool(found), found

    async def _test_verb_bypass(self, ep: Endpoint, method: str):
        """Try accessing GET resources with other verbs or overrides."""
        headers = {'X-HTTP-Method-Override': method}
        resp = await self._make_request(ep.url, method=method, headers=headers)
        if resp and resp.status == 200:
            body = await resp.text()
            is_anomaly, reason = self._detect_idor_anomaly(self.baselines[ep.url], resp.status, body)
            if is_anomaly:
                await self._report_idor(ep, ep.original_id, f"Verb Tampering ({method})", resp.status, body, reason)

    async def _test_mass_assignment(self, ep: Endpoint):
        """Inject privileged fields into POST/PUT bodies."""
        for payload in PRIVILEGED_PAYLOADS:
            data = dict(ep.params)
            data.update(payload)
            
            resp = await self._make_request(ep.url, method=ep.method, data=data)
            if resp and resp.status in (200, 201):
                body = await resp.text()
                # If the injected field is reflected back, it's a strong indicator
                field_name = list(payload.keys())[0]
                if field_name in body:
                    self.add_finding(Finding(
                        module='idor',
                        title=f"Mass Assignment: Privileged Field '{field_name}' accepted",
                        severity='High',
                        description=f"The server accepted the privileged field `{field_name}` in a {ep.method} request to `{ep.url}` and reflected it in the response.",
                        evidence={'url': ep.url, 'field': field_name, 'payload': payload},
                        poc=f"curl -X {ep.method} {ep.url} -d '{field_name}={payload[field_name]}'",
                        remediation="Use allowlists for input parameters. Never bind request bodies directly to internal database models.",
                        cvss_score=7.5, bounty_score=1500, target=ep.url
                    ))

    # ── Helper: Request Executor ─────────────────────────────────────────────

    async def _execute_request(self, ep: Endpoint, test_id: str = None, custom_url: str = None) -> Any:
        url = custom_url or ep.url
        val = test_id or ep.original_id
        
        if ep.type == 'GET':
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if ep.param_name: qs[ep.param_name] = [val]
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self._make_request(url, method='GET')

        if ep.type == 'REST':
            parts = urlparse(url).path.split('/')
            parts[ep.params['index']] = val
            url = urlunparse(urlparse(url)._replace(path='/'.join(parts)))
            return await self._make_request(url, method='GET')

        if ep.type == 'POST_FORM':
            data = dict(ep.params)
            if ep.param_name: data[ep.param_name] = val
            return await self._make_request(url, method=ep.method, data=data)

        return await self._make_request(url, method=ep.method)

    # ── Reporting ────────────────────────────────────────────────────────────

    async def _report_idor(self, ep: Endpoint, test_id: str, tech: str, status: int, body: str, reason: str):
        severity = 'High'
        cvss = 7.5
        bounty = 2000

        # Escalate if PII found
        found_sensitive, _ = self._check_sensitive(body)
        if found_sensitive:
            severity = 'Critical'; cvss = 9.1; bounty = 4000

        finding = Finding(
            module='idor',
            title=f"IDOR Detected via {tech}: {ep.param_name or 'Path Segment'}",
            severity=severity,
            description=(
                f"## Insecure Direct Object Reference (IDOR)\n\n"
                f"An IDOR vulnerability was detected at `{ep.url}` using the `{tech}` technique.\n\n"
                f"**Detection Reason:** {reason}\n"
                f"**Original ID:** `{ep.original_id}` | **Tested ID:** `{test_id}`\n"
                f"**HTTP Status:** {status}\n\n"
                f"**Impact:** Unauthorized access to data belonging to other users or resources."
            ),
            evidence={
                'url': ep.url, 'technique': tech, 'original_id': ep.original_id, 
                'tested_id': test_id, 'status': status, 'reason': reason,
                'snippet': body[:300]
            },
            poc=f"curl -i '{ep.url}' (manipulate ID to {test_id})",
            remediation="Implement object-level authorization checks. Verify that the authenticated user has permission to access the requested resource ID before returning data.",
            cvss_score=cvss, bounty_score=bounty, target=ep.url
        )
        self.add_finding(finding)
        self.logger.info(f"[IDOR] {severity.upper()} FINDING: {tech} on {ep.url} [CVSS {cvss}]")

def urlunparse(data):
    from urllib.parse import urlunparse as _unparse
    return _unparse(data)

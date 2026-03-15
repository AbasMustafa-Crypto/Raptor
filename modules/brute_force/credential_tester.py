"""
RAPTOR Credential Tester Module v4.0 - Enterprise Grade
======================================================
Professional-grade authentication auditing suite.
Implements password spraying, baseline failure modeling, lockout detection,
and automatic authentication endpoint discovery. Uses BaseModule's async engine.
"""

import asyncio
import base64
import json
import re
import urllib.parse
import hashlib
from difflib import SequenceMatcher
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
import os
import time

from core.base_module import BaseModule, Finding

@dataclass
class AuthEndpoint:
    url: str
    auth_type: str
    method: str
    username_field: str
    password_field: str
    extra_fields: Dict[str, str]

@dataclass
class AuthBaseline:
    failed_status: int
    failed_length: int
    failed_body: str
    failed_hash: str

class CredentialTester(BaseModule):
    """
    Enterprise authentication auditing: Password Spraying and Brute Forcing.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.max_attempts    = config.get('max_attempts', 1000)
        self.concurrency     = config.get('concurrency', 5) # Keep low to avoid immediate lockouts
        self.wordlist_path   = config.get('wordlist_path', 'wordlists')
        self.custom_userlist = config.get('userlist', None)
        self.custom_passlist = config.get('passlist', None)
        self._max_usernames  = config.get('max_usernames', 100)
        self._max_passwords  = config.get('max_passwords', 50)
        self.max_pages       = config.get('max_pages', 20)
        
        self.semaphore = asyncio.Semaphore(self.concurrency)
        
        self.endpoints: List[AuthEndpoint] = []
        self.baselines: Dict[str, AuthBaseline] = {}
        
        self.locked_users: Set[str] = set()
        self.rate_limited = False

    async def run(self, target: str, **kwargs) -> List[Finding]:
        if not kwargs.get('enable_brute_force', False):
            self.logger.info("Brute force module disabled. Pass --enable-brute-force to run.")
            return self.findings

        # Override lists if provided via CLI args
        if kwargs.get('userlist'): self.custom_userlist = kwargs['userlist']
        if kwargs.get('passlist'): self.custom_passlist = kwargs['passlist']

        self.logger.info(f"🔥 Starting Enterprise Authentication Audit on {target}")

        # PHASE 0: Discovery
        await self._discover_endpoints(target)
        if not self.endpoints:
            # Fallback to universal JSON root if nothing found
            self.logger.info("[AUTH] No login forms found, adding root universal endpoint.")
            self.endpoints.append(AuthEndpoint(
                url=target, auth_type='universal_json', method='POST',
                username_field='email', password_field='password', extra_fields={}
            ))
            self.endpoints.append(AuthEndpoint(
                url=target, auth_type='basic_auth', method='GET',
                username_field='', password_field='', extra_fields={}
            ))

        self.logger.info(f"[AUTH] Testing {len(self.endpoints)} authentication endpoint(s)")

        # Load lists
        usernames, passwords = self._load_wordlists()
        if not usernames or not passwords:
            self.logger.error("Wordlists are empty. Aborting.")
            return self.findings

        # PHASE 1: Baseline Capture
        for ep in self.endpoints:
            await self._capture_baseline(ep)

        # PHASE 2: Password Spraying / Brute Forcing
        # We use password spraying (1 pass, all users) to minimize lockouts per user
        for ep in self.endpoints:
            if self.rate_limited:
                break
                
            self.logger.info(f"[AUTH] Auditing endpoint: {ep.url} ({ep.auth_type})")
            baseline = self.baselines.get(ep.url)
            
            # Tasks list
            tasks = []
            
            # Spraying approach
            for password in passwords:
                for username in usernames:
                    tasks.append(self._test_credential(ep, baseline, username, password))
            
            # Execute in controlled batches
            chunk_size = 50
            for i in range(0, len(tasks), chunk_size):
                if self.rate_limited: break
                await asyncio.gather(*tasks[i:i+chunk_size])
                await asyncio.sleep(0.5) # Gentle cooldown

        return self.findings

    # ── Phase 0: Discovery ───────────────────────────────────────────────────

    async def _discover_endpoints(self, target: str):
        """Crawl to find login forms and API auth endpoints."""
        pages = set(await self.crawl_pages(target, max_pages=self.max_pages))
        pages.add(target)
        
        # Add common API endpoints
        parsed = urllib.parse.urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        for path in ['/login', '/api/login', '/auth', '/api/auth/token', '/wp-login.php']:
            pages.add(f"{base_url}{path}")

        for page in pages:
            try:
                forms = await self.get_forms(page)
                for form in forms:
                    inputs = form['inputs']
                    
                    # Detect if it's a login form (has password field)
                    pass_field = None
                    user_field = None
                    
                    for name, _ in inputs.items():
                        nl = name.lower()
                        if 'pass' in nl or 'pwd' in nl:
                            pass_field = name
                        elif 'user' in nl or 'email' in nl or 'login' in nl:
                            user_field = name

                    # We found a login form
                    if pass_field and user_field:
                        # Remove them from extra fields
                        extra = dict(inputs)
                        if user_field in extra: del extra[user_field]
                        if pass_field in extra: del extra[pass_field]
                        
                        ep = AuthEndpoint(
                            url=form['action'] if form['action'].startswith('http') else urllib.parse.urljoin(page, form['action']),
                            auth_type='form_urlencoded',
                            method=form['method'].upper() if form['method'] else 'POST',
                            username_field=user_field,
                            password_field=pass_field,
                            extra_fields=extra
                        )
                        # Add if unique
                        if not any(e.url == ep.url for e in self.endpoints):
                            self.endpoints.append(ep)
                            self.logger.info(f"[AUTH] Discovered form login: {ep.url}")

            except Exception: pass

    # ── Phase 1: Baseline ────────────────────────────────────────────────────

    async def _capture_baseline(self, ep: AuthEndpoint):
        """Send a completely fake credential to establish what a failure looks like."""
        fake_u = f"fakeuser_{int(time.time())}@example.com"
        fake_p = "ThisPasswordIsFakeAndWillFail123!"
        
        resp = await self._send_auth_request(ep, fake_u, fake_p)
        if resp:
            body = await resp.text()
            self.baselines[ep.url] = AuthBaseline(
                failed_status=resp.status,
                failed_length=len(body),
                failed_body=body.lower()[:1000],
                failed_hash=hashlib.md5(body.encode('utf-8', errors='ignore')).hexdigest()
            )
            self.logger.info(f"[AUTH] Baseline set for {ep.url} -> Status {resp.status}, {len(body)}B")

    # ── Phase 2: Testing ─────────────────────────────────────────────────────

    async def _test_credential(self, ep: AuthEndpoint, baseline: Optional[AuthBaseline], username: str, password: str):
        if username in self.locked_users:
            return
            
        async with self.semaphore:
            if self.rate_limited: return
            
            resp = await self._send_auth_request(ep, username, password)
            if not resp: return
            
            body = await resp.text()
            body_l = body.lower()
            
            # WAF / Rate Limiting Check
            if resp.status in (429, 403) or 'too many requests' in body_l or 'cloudflare' in body_l:
                if resp.status == 429:
                    self.logger.warning("[AUTH] Rate limit hit (429). Halting auth audit.")
                    self.rate_limited = True
                    self._report_rate_limit(ep.url)
                return

            # Lockout Detection
            if any(x in body_l for x in ['account locked', 'too many attempts', 'temporarily banned']):
                self.logger.warning(f"[AUTH] Account {username} locked out. Skipping further tests for this user.")
                self.locked_users.add(username)
                return

            # Success Detection
            is_success = False
            
            # 1. HTTP Status Success
            if resp.status in (200, 201) and baseline and resp.status != baseline.failed_status:
                is_success = True
                
            # 2. Redirect to internal page
            if resp.status in (301, 302, 303):
                loc = resp.headers.get('Location', '').lower()
                if loc and not any(x in loc for x in ['login', 'error', 'fail']):
                    is_success = True
            
            # 3. JWT / Token in body (Very common in APIs)
            if any(k in body_l for k in ['access_token', 'id_token', 'sessionid', 'bearer']):
                if not any(err in body_l for err in ['invalid', 'error', 'failed']):
                    is_success = True

            # 4. Anomaly from baseline (Differential analysis)
            if baseline and not is_success:
                if abs(len(body) - baseline.failed_length) > (baseline.failed_length * 0.1) and resp.status != 401:
                    # If length changed by >10% and it's not a generic 401
                    if 'invalid' not in body_l and 'incorrect' not in body_l:
                        is_success = True

            if is_success:
                self._report_success(ep, username, password, resp.status)

    async def _send_auth_request(self, ep: AuthEndpoint, u: str, p: str):
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        try:
            if ep.auth_type == 'basic_auth':
                auth_str = base64.b64encode(f"{u}:{p}".encode()).decode()
                headers['Authorization'] = f"Basic {auth_str}"
                return await self._make_request(ep.url, method='GET', headers=headers, allow_redirects=False)

            elif ep.auth_type == 'universal_json':
                data = {ep.username_field: u, ep.password_field: p}
                data.update(ep.extra_fields)
                headers['Content-Type'] = 'application/json'
                return await self._make_request(ep.url, method='POST', headers=headers, data=json.dumps(data), allow_redirects=False)

            elif ep.auth_type == 'form_urlencoded':
                data = {ep.username_field: u, ep.password_field: p}
                data.update(ep.extra_fields)
                return await self._make_request(ep.url, method=ep.method, data=data, allow_redirects=False)
                
        except Exception:
            return None

    # ── Wordlist Management ──────────────────────────────────────────────────

    def _load_wordlists(self) -> Tuple[List[str], List[str]]:
        usernames = []
        passwords = []

        def _resolve(raw_path: str) -> Optional[Path]:
            cwd = Path(os.getcwd())
            candidates = [Path(raw_path), cwd / raw_path, Path(raw_path).expanduser()]
            for c in candidates:
                if c.exists(): return c.resolve()
            return None

        def _load_capped(path, cap):
            lines = []
            try:
                with open(path, 'r', errors='ignore') as fh:
                    for line in fh:
                        s = line.strip()
                        if s: lines.append(s)
                        if len(lines) >= cap: break
            except Exception: pass
            return lines

        # Users
        upath = _resolve(self.custom_userlist) if self.custom_userlist else _resolve(f"{self.wordlist_path}/usernames.txt")
        if upath:
            usernames = _load_capped(upath, self._max_usernames)
        else:
            usernames = ['admin', 'administrator', 'user', 'test', 'root']

        # Passwords
        ppath = _resolve(self.custom_passlist) if self.custom_passlist else _resolve(f"{self.wordlist_path}/passwords.txt")
        if ppath:
            passwords = _load_capped(ppath, self._max_passwords)
        else:
            passwords = ['admin', 'password', '123456', 'Password123!']

        return list(set(usernames)), list(set(passwords))

    # ── Reporting ────────────────────────────────────────────────────────────

    def _report_success(self, ep: AuthEndpoint, username: str, password: str, status: int):
        # Determine if it's default or weak
        is_default = username == password or password in ['admin', 'password', '123456']
        severity = 'Critical'
        bounty = 5000 if not is_default else 3000
        
        self.add_finding(Finding(
            module='brute_force',
            title=f"Valid Credentials Found: {username}:{password} at {ep.url}",
            severity=severity,
            description=(
                f"## Authentication Compromised\n\n"
                f"Successfully authenticated against `{ep.url}`.\n"
                f"**Username:** `{username}`\n"
                f"**Password:** `{password}`\n"
                f"**Auth Type:** {ep.auth_type}\n"
                f"**Status Code:** {status}\n\n"
                f"**Impact:** Total compromise of user account privileges."
            ),
            evidence={'url': ep.url, 'username': username, 'password': password, 'auth_type': ep.auth_type},
            poc=f"Authenticate at {ep.url} using {username}:{password}",
            remediation="Enforce strong password policies. Implement MFA/2FA. Ensure account lockout mechanisms and rate limiting are properly configured.",
            cvss_score=9.8, bounty_score=bounty, target=ep.url
        ))

    def _report_rate_limit(self, url: str):
        self.add_finding(Finding(
            module='brute_force',
            title='Rate Limiting / WAF Block Detected',
            severity='Info',
            description=f"Authentication audit halted for {url} due to Rate Limiting (HTTP 429) or WAF intervention (HTTP 403).",
            evidence={'url': url},
            cvss_score=0.0, bounty_score=0, target=url
        ))

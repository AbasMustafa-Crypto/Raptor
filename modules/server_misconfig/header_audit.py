"""
header_audit.py — Professional HTTP Security Header & Cookie Auditor for RAPTOR.
"""

import re
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.base_module import BaseModule, Finding


class HeaderAuditor(BaseModule):
    """
    Enterprise-grade HTTP security response header and cookie auditor.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(10)

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info(f"🔥 Starting Enterprise Header Audit on {target}")

        async with self.semaphore:
            # 1. Capture main response
            resp = await self._make_request(target)
            if not resp:
                self.logger.error(f"Failed to get response from {target}")
                return self.findings

            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            # 2. Audit specific headers
            await self._audit_hsts(target, headers)
            await self._audit_csp(target, headers)
            await self._audit_xfo(target, headers)
            await self._audit_xcto(target, headers)
            await self._audit_referrer_policy(target, headers)
            await self._audit_permissions_policy(target, headers)
            await self._audit_cross_origin_policies(target, headers)
            await self._audit_cache_control(target, headers, resp.url)
            await self._audit_info_disclosure(target, headers)
            
            # 3. Audit Cookies (Set-Cookie headers)
            # urllib.request response.headers is an HTTPMessage; get_all returns multiple values
            cookie_headers = resp.headers.get_all('Set-Cookie', [])
            await self._audit_cookies(target, cookie_headers)

            # 4. CORS Active Test
            await self._test_cors(target)

            # 5. HTTP -> HTTPS Redirect check
            await self._check_http_redirect(target)

        return self.findings

    # ── Header Audits ─────────────────────────────────────────────────────────

    async def _audit_hsts(self, target: str, headers: Dict[str, str]):
        hsts = headers.get('strict-transport-security')
        if not hsts:
            self._add_header_finding(target, 'Strict-Transport-Security', 'MISSING', 'Critical', 7.4, 1500,
                                     "HSTS forces HTTPS and prevents SSL-stripping. It is missing from the response.",
                                     "max-age=63072000; includeSubDomains; preload")
            return

        if 'max-age' in hsts.lower():
            try:
                age_match = re.search(r'max-age=(\d+)', hsts, re.I)
                if age_match:
                    age = int(age_match.group(1))
                    if age < 31536000:
                        self._add_header_finding(target, 'Strict-Transport-Security', hsts, 'High', 5.0, 500,
                                                 f"HSTS max-age is {age}, which is less than 1 year (31536000 seconds).",
                                                 "max-age=31536000")
            except Exception: pass

        if 'includesubdomains' not in hsts.lower():
            self._add_header_finding(target, 'Strict-Transport-Security', hsts, 'Medium', 4.0, 200,
                                     "HSTS 'includeSubDomains' directive is missing, leaving subdomains vulnerable.",
                                     "includeSubDomains")
        if 'preload' not in hsts.lower():
            self._add_header_finding(target, 'Strict-Transport-Security', hsts, 'Info', 0.0, 0,
                                     "HSTS 'preload' directive is missing. Preloading is recommended for maximum security.",
                                     "preload")

    async def _audit_csp(self, target: str, headers: Dict[str, str]):
        csp = headers.get('content-security-policy')
        if not csp:
            self._add_header_finding(target, 'Content-Security-Policy', 'MISSING', 'High', 6.1, 1000,
                                     "CSP mitigates XSS and data injection attacks. It is missing.",
                                     "Strictly defined default-src and script-src")
            return

        if "'unsafe-inline'" in csp.lower():
            self._add_header_finding(target, 'Content-Security-Policy', csp, 'High', 6.1, 500,
                                     "CSP allows 'unsafe-inline', which significantly weakens XSS protection.",
                                     "Use nonces or hashes instead.")
        if "'unsafe-eval'" in csp.lower():
            self._add_header_finding(target, 'Content-Security-Policy', csp, 'High', 6.1, 500,
                                     "CSP allows 'unsafe-eval', allowing potentially dangerous JavaScript execution.",
                                     "Avoid eval() and use strict CSP.")
        if re.search(r"script-src\s+[^;]*\*", csp, re.I):
            self._add_header_finding(target, 'Content-Security-Policy', csp, 'Critical', 8.6, 1500,
                                     "CSP script-src contains a wildcard '*', allowing scripts to be loaded from any origin.",
                                     "Restrict script-src to trusted origins.")
        if 'default-src' not in csp.lower():
            self._add_header_finding(target, 'Content-Security-Policy', csp, 'Medium', 5.0, 300,
                                     "CSP missing 'default-src' directive.", "Add default-src 'none' or 'self'.")
        if 'report-uri' not in csp.lower() and 'report-to' not in csp.lower():
            self._add_header_finding(target, 'Content-Security-Policy', csp, 'Low', 3.0, 100,
                                     "CSP missing reporting directives (report-uri/report-to).", "Add a reporting endpoint.")

    async def _audit_xfo(self, target: str, headers: Dict[str, str]):
        xfo = headers.get('x-frame-options', '').upper()
        csp = headers.get('content-security-policy', '')
        
        if not xfo:
            if 'frame-ancestors' in csp.lower():
                 self._add_header_finding(target, 'X-Frame-Options', 'MISSING', 'Info', 0.0, 0,
                                          "X-Frame-Options is missing, but CSP 'frame-ancestors' is present (modern replacement).", "")
            else:
                 self._add_header_finding(target, 'X-Frame-Options', 'MISSING', 'High', 6.1, 500,
                                          "Missing X-Frame-Options header (vulnerable to clickjacking).", "DENY or SAMEORIGIN")
        elif xfo not in ('DENY', 'SAMEORIGIN'):
            self._add_header_finding(target, 'X-Frame-Options', xfo, 'High', 6.1, 400,
                                     "Invalid X-Frame-Options value. Must be DENY or SAMEORIGIN.", "DENY")

    async def _audit_xcto(self, target: str, headers: Dict[str, str]):
        xcto = headers.get('x-content-type-options', '').lower()
        if not xcto:
            self._add_header_finding(target, 'X-Content-Type-Options', 'MISSING', 'Medium', 4.3, 300,
                                     "Missing X-Content-Type-Options header (vulnerable to MIME-sniffing).", "nosniff")
        elif xcto != 'nosniff':
            self._add_header_finding(target, 'X-Content-Type-Options', xcto, 'Medium', 4.3, 100,
                                     "Invalid X-Content-Type-Options value. Must be 'nosniff'.", "nosniff")

    async def _audit_referrer_policy(self, target: str, headers: Dict[str, str]):
        rp = headers.get('referrer-policy', '').lower()
        if not rp:
            self._add_header_finding(target, 'Referrer-Policy', 'MISSING', 'Low', 3.1, 50,
                                     "Missing Referrer-Policy header.", "strict-origin-when-cross-origin")
        elif rp in ('unsafe-url', 'no-referrer-when-downgrade'):
            self._add_header_finding(target, 'Referrer-Policy', rp, 'Medium', 5.0, 150,
                                     f"Weak Referrer-Policy '{rp}' leaks sensitive URL data.", "strict-origin-when-cross-origin")

    async def _audit_permissions_policy(self, target: str, headers: Dict[str, str]):
        pp = headers.get('permissions-policy', '').lower()
        if not pp:
            self._add_header_finding(target, 'Permissions-Policy', 'MISSING', 'Low', 2.0, 50,
                                     "Missing Permissions-Policy header (modern Feature-Policy).", "camera=(), microphone=()")
        else:
            dangerous = ['camera=*', 'microphone=*', 'geolocation=*']
            found = [d for d in dangerous if d in pp]
            if found:
                self._add_header_finding(target, 'Permissions-Policy', pp, 'Medium', 5.0, 200,
                                         f"Permissions-Policy allows dangerous wildcard access: {', '.join(found)}", "camera=()")

    async def _audit_cross_origin_policies(self, target: str, headers: Dict[str, str]):
        for hdr in ['cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy']:
            if not headers.get(hdr):
                self._add_header_finding(target, hdr.title(), 'MISSING', 'Low', 2.0, 50,
                                         f"Missing {hdr.title()} header.", "same-origin")

    async def _audit_cache_control(self, target: str, headers: Dict[str, str], url: str):
        cc = headers.get('cache-control', '').lower()
        # simplified check for 'auth' or 'api' in URL as "sensitive" endpoints
        is_sensitive = any(x in url.lower() for x in ('auth', 'api', 'login', 'account'))
        
        if is_sensitive:
            if 'no-store' not in cc:
                self._add_header_finding(target, 'Cache-Control', cc or 'MISSING', 'Medium', 4.0, 200,
                                         "Sensitive endpoint missing 'no-store' in Cache-Control.", "no-store, no-cache, must-revalidate")
            if 'public' in cc:
                self._add_header_finding(target, 'Cache-Control', cc, 'High', 6.0, 500,
                                         "Sensitive authenticated response marked as 'public' in Cache-Control.", "private")

    async def _audit_info_disclosure(self, target: str, headers: Dict[str, str]):
        info_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
        for hdr in info_headers:
            val = headers.get(hdr)
            if val:
                self._add_header_finding(target, hdr.title(), val, 'Medium', 5.3, 300,
                                         f"Technology version disclosure via '{hdr}' header.", "Remove or redact header")

    # ── Cookie Audits ─────────────────────────────────────────────────────────

    async def _audit_cookies(self, target: str, cookie_headers: List[str]):
        is_https = target.startswith('https://')
        for cookie in cookie_headers:
            name_match = re.match(r'^([^=;]+)', cookie)
            cname = name_match.group(1) if name_match else "Unknown"
            
            issues = []
            if 'secure' not in cookie.lower() and is_https:
                issues.append("Missing Secure flag (on HTTPS)")
            if 'httponly' not in cookie.lower():
                issues.append("Missing HttpOnly flag")
            if 'samesite' not in cookie.lower():
                issues.append("Missing SameSite flag")
            elif 'samesite=none' in cookie.lower() and 'secure' not in cookie.lower():
                issues.append("SameSite=None without Secure (Critical)")

            for issue in issues:
                severity = 'High'
                cvss = 7.5
                bounty = 1000
                if 'Critical' in issue:
                    severity = 'Critical'; cvss = 9.8; bounty = 2000
                elif 'SameSite' in issue and 'Secure' not in issue:
                    severity = 'Medium'; cvss = 5.0; bounty = 300

                self.add_finding(Finding(
                    module='server_misconfig',
                    title=f"Cookie Security: {issue} on '{cname}'",
                    severity=severity,
                    description=f"Cookie '{cname}' is misconfigured: {issue}.\nEvidence: `{cookie}`",
                    evidence={'cookie': cname, 'value': cookie, 'issue': issue},
                    poc=f"curl -I {target}",
                    remediation="Add Secure, HttpOnly, and SameSite=Strict/Lax flags to the cookie.",
                    cvss_score=cvss, bounty_score=bounty, target=target
                ))

    # ── Active Tests ──────────────────────────────────────────────────────────

    async def _test_cors(self, target: str):
        evil_origin = "https://evil-attacker.com"
        resp = await self._make_request(target, headers={'Origin': evil_origin})
        if not resp: return

        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        allow_origin = hdrs.get('access-control-allow-origin')
        allow_creds  = hdrs.get('access-control-allow-credentials', '').lower() == 'true'

        if allow_origin == '*':
            if allow_creds:
                self._add_custom_finding(target, "CORS Misconfiguration: Wildcard with Credentials",
                                         'Critical', 9.8, 5000,
                                         f"CORS allows wildcard '*' origin with credentials enabled. Total compromise of session data.",
                                         {'origin': allow_origin, 'credentials': 'true'})
            else:
                self._add_custom_finding(target, "CORS Misconfiguration: Permissive Wildcard",
                                         'Medium', 5.3, 500,
                                         "CORS allows wildcard '*' origin. Public data may be leaked.",
                                         {'origin': allow_origin})
        elif allow_origin == evil_origin:
            severity = 'High' if allow_creds else 'Medium'
            cvss = 8.8 if allow_creds else 5.3
            self._add_custom_finding(target, f"CORS Misconfiguration: Origin Reflection ({severity})",
                                     severity, cvss, 2000 if allow_creds else 500,
                                     f"Server reflects arbitrary Origin '{evil_origin}'. " +
                                     ("Credentials allowed — CRITICAL." if allow_creds else "Permissive CORS."),
                                     {'origin': allow_origin, 'credentials': str(allow_creds)})

    async def _check_http_redirect(self, target: str):
        parsed = urlparse(target)
        if parsed.scheme == 'https':
            http_url = f"http://{parsed.netloc}{parsed.path}"
            if parsed.query: http_url += f"?{parsed.query}"
            
            resp = await self._make_request(http_url, allow_redirects=False)
            if resp and resp.status not in (301, 302, 307, 308):
                 self._add_custom_finding(target, "Missing HTTP to HTTPS Redirect",
                                          'High', 7.4, 1500,
                                          "The site is accessible over plain HTTP and does not redirect to HTTPS.",
                                          {'url': http_url, 'status': resp.status})

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add_header_finding(self, target, header, value, severity, cvss, bounty, desc, expected):
        self.add_finding(Finding(
            module='server_misconfig',
            title=f"Security Header: {header} ({'Missing' if value == 'MISSING' else 'Misconfigured'})",
            severity=severity,
            description=f"## {header} Audit\n\n{desc}\n\n**Current Value:** `{value}`\n**Expected:** `{expected}`",
            evidence={'header': header, 'value': value, 'expected': expected},
            poc=f"curl -I {target}",
            remediation=f"Configure the {header} header properly in your server/CDN settings.",
            cvss_score=cvss, bounty_score=bounty, target=target
        ))

    def _add_custom_finding(self, target, title, severity, cvss, bounty, desc, evidence):
        self.add_finding(Finding(
            module='server_misconfig', title=title, severity=severity,
            description=desc, evidence=evidence, cvss_score=cvss,
            bounty_score=bounty, target=target
        ))

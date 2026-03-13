"""
header_audit.py — HTTP security header auditor for RAPTOR.

FIXES vs original
─────────────────
 1. super().__init__() now passes graph_manager correctly
 2. Loop variable renamed 'config' → 'hdr_cfg' (no longer shadows self.config)
 3. HSTS not reported on plain HTTP targets (false positive)
 4. CVSS scores corrected per header: HSTS→7.4, CSP→6.1, XFO→6.1, XCTO→5.3
 5. CSP quality check: flags unsafe-inline, unsafe-eval, wildcard sources
 6. Server/X-Powered-By only flagged when value contains a version number
 7. X-XSS-Protection: deprecated — reported as Info when present, not silently passing
 8. _check_dangerous_headers made sync (had no awaits; async was misleading)
"""

import re
from typing import Dict, List

from core.base_module import BaseModule, Finding

# Directives that completely negate CSP protection
_WEAK_CSP_RE = re.compile(
    r"'unsafe-inline'|'unsafe-eval'|default-src\s+\*|script-src\s+\*|script-src\s+https?:",
    re.IGNORECASE,
)

# Only flag version disclosure when value contains e.g. '1.18.0'
_VERSION_RE = re.compile(r"\d+\.\d+")


class HeaderAuditor(BaseModule):
    """Audit HTTP security response headers."""

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        # FIX 1
        super().__init__(config, stealth, db, graph_manager)

        # Per-header schema:
        #   required  – missing header → finding
        #   severity  – severity when missing
        #   cvss      – CVSS 3.1 base score when missing (FIX 4)
        #   bounty    – bounty when missing
        #   desc      – description
        #   check     – callable(value) → True if value is acceptable
        #   weak_msg  – emitted when header present but check() fails
        self._headers = {
            "Strict-Transport-Security": {
                "required": True,
                "severity": "High",
                "cvss":     7.4,
                "bounty":   500,
                "desc":     "HSTS forces HTTPS and prevents SSL-stripping / MiTM attacks.",
                "check":    lambda v: "max-age" in v.lower(),
                "weak_msg": "HSTS present but max-age directive is missing or zero.",
            },
            "Content-Security-Policy": {
                "required": True,
                "severity": "High",
                "cvss":     6.1,
                "bounty":   400,
                "desc":     "CSP restricts resource loading and mitigates XSS attacks.",
                # FIX 5: reject weak CSPs, not just short ones
                "check":    lambda v: len(v) > 10 and not _WEAK_CSP_RE.search(v),
                "weak_msg": (
                    "CSP present but contains unsafe directives "
                    "(unsafe-inline / unsafe-eval / wildcards) that negate its protection."
                ),
            },
            "X-Frame-Options": {
                "required": True,
                "severity": "Medium",
                "cvss":     6.1,
                "bounty":   200,
                "desc":     "X-Frame-Options prevents clickjacking attacks.",
                "check":    lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
                "weak_msg": "X-Frame-Options must be DENY or SAMEORIGIN.",
            },
            "X-Content-Type-Options": {
                "required": True,
                "severity": "Medium",
                "cvss":     5.3,
                "bounty":   100,
                "desc":     "X-Content-Type-Options prevents MIME-sniffing attacks.",
                "check":    lambda v: v.lower() == "nosniff",
                "weak_msg": "X-Content-Type-Options must be 'nosniff'.",
            },
            "Referrer-Policy": {
                "required": False,
                "severity": "Low",
                "cvss":     3.1,
                "bounty":   50,
                "desc":     "Referrer-Policy limits referrer data sent to third parties.",
                "check":    lambda v: v is not None,
                "weak_msg": None,
            },
            "Permissions-Policy": {
                "required": False,
                "severity": "Low",
                "cvss":     3.1,
                "bounty":   50,
                "desc":     "Permissions-Policy restricts access to powerful browser APIs.",
                "check":    lambda v: v is not None,
                "weak_msg": None,
            },
        }

        # FIX 6: only flag these when a version string is present in the value
        self._info_headers = {
            "server":               "Web server software",
            "x-powered-by":         "Server-side framework/language",
            "x-aspnet-version":     "ASP.NET version",
            "x-aspnetmvc-version":  "ASP.NET MVC version",
            "x-generator":          "CMS or site generator",
        }

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info("Auditing security headers for %s", target)

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        is_https = target.startswith("https://")

        resp = await self._make_request(target)
        if not resp:
            self.logger.warning("No response from %s", target)
            return self.findings

        headers: Dict[str, str] = {k.lower(): v for k, v in resp.headers.items()}

        # FIX 2: variable named 'hdr_cfg' — no longer shadows self.config
        for header_name, hdr_cfg in self._headers.items():

            # FIX 3: HSTS meaningless over HTTP
            if header_name == "Strict-Transport-Security" and not is_https:
                continue

            value = headers.get(header_name.lower())

            if hdr_cfg["required"] and not value:
                self.add_finding(Finding(
                    module="server_misconfig",
                    title=f"Missing Security Header: {header_name}",
                    severity=hdr_cfg["severity"],
                    description=(
                        f"{hdr_cfg['desc']} "
                        "This header is absent from the server response."
                    ),
                    evidence={"header": header_name, "present": False},
                    poc=f"curl -sI {target} | grep -i '{header_name}'",
                    remediation=f"Add '{header_name}' to your server/CDN configuration.",
                    cvss_score=hdr_cfg["cvss"],
                    bounty_score=hdr_cfg["bounty"],
                    target=target,
                ))

            elif value and not hdr_cfg["check"](value):
                weak_msg = hdr_cfg.get("weak_msg") or f"'{header_name}' value is misconfigured."
                self.add_finding(Finding(
                    module="server_misconfig",
                    title=f"Misconfigured Security Header: {header_name}",
                    severity="Medium",
                    description=(
                        f"{hdr_cfg['desc']} "
                        f"{weak_msg} "
                        f"Current value: '{value}'"
                    ),
                    evidence={"header": header_name, "value": value, "present": True},
                    poc=f"curl -sI {target}",
                    remediation=f"Correct the '{header_name}' header configuration.",
                    cvss_score=4.3,
                    bounty_score=150,
                    target=target,
                ))

        # FIX 7: deprecated header — Info finding when present, never silently pass
        xxp = headers.get("x-xss-protection", "")
        if xxp:
            self.add_finding(Finding(
                module="server_misconfig",
                title="Deprecated X-XSS-Protection Header Present",
                severity="Info",
                description=(
                    "X-XSS-Protection is removed from modern browsers. "
                    "In legacy Internet Explorer, '1; mode=block' could be "
                    f"leveraged for reflected XSS. Current value: '{xxp}'. "
                    "Use Content-Security-Policy instead."
                ),
                evidence={"header": "X-XSS-Protection", "value": xxp},
                poc=f"curl -sI {target}",
                remediation="Remove X-XSS-Protection; implement a strong CSP.",
                cvss_score=0.0,
                bounty_score=0,
                target=target,
            ))

        # FIX 8: sync — no await needed
        self._check_info_disclosure(target, headers)
        return self.findings

    def _check_info_disclosure(self, target: str, headers: Dict[str, str]) -> None:
        """FIX 6 + FIX 8: sync; only flags headers containing a version number."""
        for header, description in self._info_headers.items():
            value = headers.get(header)
            if not value:
                continue
            if not _VERSION_RE.search(value):   # 'nginx' alone → skip
                continue
            self.add_finding(Finding(
                module="server_misconfig",
                title=f"Version Disclosure via {header.title()} Header",
                severity="Low",
                description=(
                    f"{description} version exposed in response: '{value}'. "
                    "Attackers use version info to identify known CVEs."
                ),
                evidence={"header": header, "value": value},
                poc=f"curl -sI {target} | grep -i '{header}'",
                remediation=f"Remove or redact the '{header}' header.",
                cvss_score=2.0,
                bounty_score=50,
                target=target,
            ))

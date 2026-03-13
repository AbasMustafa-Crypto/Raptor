"""
sensitive_files.py — Exposed sensitive file scanner for RAPTOR.

FIXES vs original
─────────────────
 1. super().__init__() now passes graph_manager correctly
 2. Bare extension entries (.bak, .backup, .old, .orig, .save) replaced with
    real filename-based backup paths (e.g. index.php.bak, config.php.old)
 3. Dead variable content_length removed
 4. URL construction rstrips '/' from base_url to prevent double-slashes
 5. _is_error_page checks full body, not just first 500 chars; empty body
    for directory paths (e.g. .git/) is now treated as a valid finding
 6. 301/302 redirects on sensitive paths now reported (path existence confirmed)
 7. robots.txt / sitemap.xml correctly classified as 'Info' (intentionally public)
 8. Deduplication: paths already present in the target URL are skipped
"""

import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.base_module import BaseModule, Finding


class SensitiveFileScanner(BaseModule):
    """Probe for exposed sensitive files and directories."""

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        # FIX 1: pass graph_manager correctly
        super().__init__(config, stealth, db, graph_manager)

        # FIX 2: bare extensions replaced with actual backup filename patterns
        self.sensitive_paths = [
            # Environment / secrets
            ".env", ".env.local", ".env.production", ".env.development",
            ".env.backup", ".env.bak", ".env.old",

            # Config files
            "config.json", "config.php", "config.xml", "config.yaml", "config.yml",
            "settings.json", "settings.py", "settings.php",
            "database.yml", "database.json", "db_config.php",
            "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
            "configuration.php", "local.xml", "app.config",

            # Backup files — FIX 2: real filename.ext.bak patterns
            "index.php.bak", "index.php.old", "index.html.bak",
            "config.php.bak", "config.php.orig", "config.php.save",
            "backup.zip", "backup.tar.gz", "backup.tar", "backup.sql",
            "dump.sql", "database.sql", "db.sql", "data.sql",
            "site.zip", "www.zip", "web.zip",

            # Source control
            ".git/", ".git/config", ".git/HEAD", ".git/logs/HEAD",
            ".svn/", ".hg/", ".bzr/",

            # IDE / project files
            ".idea/", ".vscode/", ".sublime-project",
            "nbproject/", ".project", ".classpath",

            # Logs
            "error.log", "access.log", "debug.log",
            "log.txt", "logs/", "log/", "php_error.log",

            # PHP info / test files
            "phpinfo.php", "info.php", "test.php", "php.php",
            "eval.php", "shell.php", "cmd.php",

            # Well-known but intentionally public (FIX 7: low severity)
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "clientaccesspolicy.xml",

            # Server config / status
            ".htaccess", ".htpasswd",
            "server-status", "server-info",
            "cgi-bin/",

            # Cloud / container
            ".dockerenv", "docker-compose.yml", "docker-compose.yaml",
            "Dockerfile", "Makefile", ".travis.yml", ".github/",
            "terraform.tfstate", "terraform.tfstate.backup",

            # Package/dependency manifests (may leak dep versions)
            "package.json", "composer.json", "Gemfile", "requirements.txt",
            "yarn.lock", "package-lock.json",
        ]

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info("Scanning for sensitive files on %s", target)

        if not target.startswith(("http://", "https://")):
            base_url = f"https://{target}"
        else:
            base_url = target

        # FIX 4: strip trailing slash once so all path joins are clean
        base_url = base_url.rstrip("/")

        # FIX 8: build set of path suffixes already in the target URL
        target_path = urlparse(base_url).path.lstrip("/")
        paths_to_check = [
            p for p in self.sensitive_paths
            if p.rstrip("/") != target_path
        ]

        semaphore = asyncio.Semaphore(20)

        async def check_path(path: str) -> Optional[Dict]:
            async with semaphore:
                # FIX 4: clean URL construction — no double slashes
                url = f"{base_url}/{path}"
                response = await self._make_request(url, allow_redirects=False)
                if not response:
                    return None

                status = response.status

                # FIX 6: 301/302 on sensitive paths confirms path existence
                if status in (301, 302):
                    location = next(
                        (v for k, v in response.headers.items()
                         if k.lower() == "location"),
                        "",
                    )
                    # Only interesting if it redirects to login/auth (not just http→https)
                    is_auth_redirect = any(
                        kw in location.lower()
                        for kw in ("login", "signin", "auth", "sso", "account")
                    )
                    if is_auth_redirect:
                        return {
                            "path": path, "url": url,
                            "size": 0, "status": status,
                            "content_type": "redirect",
                            "note": f"Redirects to {location}",
                        }
                    return None

                if status != 200:
                    return None

                content = await response.text()

                # FIX 3: content_length dead variable removed
                # FIX 5: empty body for directory paths is still a valid finding
                is_dir_path = path.endswith("/")
                if not is_dir_path and len(content) == 0:
                    return None

                # FIX 5: check full body, not just first 500 chars
                if self._is_error_page(content):
                    return None

                ct = next(
                    (v for k, v in response.headers.items()
                     if k.lower() == "content-type"),
                    "unknown",
                )
                return {
                    "path": path, "url": url,
                    "size": len(content), "status": status,
                    "content_type": ct,
                }

        tasks = [check_path(p) for p in paths_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = [r for r in results if isinstance(r, dict)]

        for info in found:
            severity = self._classify_severity(info["path"])
            cvss = {"Critical": 9.1, "High": 7.5, "Medium": 5.3, "Low": 3.7, "Info": 0.0}
            bounty = {"Critical": 2000, "High": 1000, "Medium": 300, "Low": 100, "Info": 0}

            note = info.get("note", "")
            size_str = f"{info['size']} bytes" if info["size"] else "empty body / directory"
            self.add_finding(Finding(
                module="server_misconfig",
                title=f"Exposed Sensitive File: {info['path']}",
                severity=severity,
                description=(
                    f"Sensitive path accessible at {info['url']} "
                    f"(HTTP {info['status']}, {size_str}). "
                    + (f"Note: {note}" if note else "")
                ),
                evidence=info,
                poc=f"curl -i \"{info['url']}\"",
                remediation=(
                    "Remove the file from the web root, restrict access via "
                    "server config (.htaccess / nginx deny), or move it outside "
                    "the document root entirely."
                ),
                cvss_score=cvss.get(severity, 5.3),
                bounty_score=bounty.get(severity, 200),
                target=base_url,
            ))

        return self.findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_error_page(self, content: str) -> bool:
        """
        FIX 5: Check the full response body (not just first 500 chars).
        Returns True if the response looks like a generic 404/error page.
        """
        if not content:
            return False  # empty body is NOT an error page — it's a real 200
        error_markers = [
            "page not found", "does not exist", "no such file",
            "object not found", "404 not found", "file not found",
            "the requested url was not found", "error 404",
        ]
        content_lower = content.lower()
        return any(m in content_lower for m in error_markers)

    def _classify_severity(self, path: str) -> str:
        """
        FIX 7: robots.txt / sitemap.xml / crossdomain.xml are intentionally
        public — classified as Info, not Medium.
        """
        p = path.lower()

        # Intentionally public — Info only
        public_files = ("robots.txt", "sitemap.xml", "crossdomain.xml",
                        "clientaccesspolicy.xml")
        if any(p == pub for pub in public_files):
            return "Info"

        critical_patterns = (
            ".env", "config", "dump.sql", ".git/", ".htpasswd",
            "wp-config", "terraform.tfstate", "database.sql", "db.sql",
        )
        high_patterns = (
            ".bak", ".backup", ".old", ".orig", ".save",
            "backup.zip", "phpinfo", "shell.php", "eval.php", "cmd.php",
            "docker-compose", "dockerfile",
        )
        medium_patterns = (
            ".htaccess", "server-status", "server-info",
            "package.json", "composer.json", "requirements.txt",
            "yarn.lock", "package-lock.json", ".travis.yml",
        )

        for pat in critical_patterns:
            if pat in p:
                return "Critical"
        for pat in high_patterns:
            if pat in p:
                return "High"
        for pat in medium_patterns:
            if pat in p:
                return "Medium"

        return "Low"

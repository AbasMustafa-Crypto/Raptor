"""
sensitive_files.py — Professional Sensitive File & Path Scanner for RAPTOR.
"""

import asyncio
import re
import json
from typing import Dict, List, Tuple, Optional
from urllib.parse import urljoin

from core.base_module import BaseModule, Finding


class SensitiveFileScanner(BaseModule):
    """
    Exhaustive scanner for sensitive files, directories, and configuration leaks.
    Probes 150+ paths with advanced anomaly detection.
    """

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.semaphore = asyncio.Semaphore(10)
        self.paths = self._get_path_list()

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info(f"🔥 Starting Exhaustive Sensitive File Scan on {target}")
        
        # 1. Probe individual paths
        tasks = []
        for path in self.paths:
            tasks.append(self._probe_path(target, path))
        
        await asyncio.gather(*tasks)

        # 2. Special check: GraphQL Introspection
        await self._check_graphql(target)

        # 3. Special check: Git Repo Reconstruction
        await self._check_git_reconstruction(target)

        return self.findings

    async def _probe_path(self, target: str, path_info: Dict):
        path = path_info['path']
        url = urljoin(target, path)
        
        async with self.semaphore:
            try:
                # Use allow_redirects=False to avoid false positives from home page redirects
                resp = await self._make_request(url, allow_redirects=False)
                if not resp: return

                body = await resp.text()
                ct = resp.headers.get('Content-Type', '').lower()
                cl = len(body)
                
                is_exposed, confidence_msg = self._is_real_exposure(resp.status, body, cl, path, ct)
                
                if is_exposed:
                    self.add_finding(Finding(
                        module='server_misconfig',
                        title=f"Exposed Sensitive File: {path} ({path_info['category']})",
                        severity=path_info['severity'],
                        description=f"## Sensitive File Exposure\n\nDetected an exposed file at `{path}`.\n\n**Category:** {path_info['category']}\n**Confidence:** {confidence_msg}\n**Proof:** `{body[:200].strip()}...`",
                        evidence={'path': path, 'url': url, 'status': resp.status, 'confidence': confidence_msg},
                        poc=f"curl -i {url}",
                        remediation="Remove this file from the web root or restrict access via server configuration.",
                        cvss_score=path_info['cvss'],
                        bounty_score=path_info['bounty'],
                        target=target
                    ))
            except Exception as e:
                self.logger.debug(f"Error probing {url}: {e}")

    def _is_real_exposure(self, status: int, body: str, length: int, path: str, ct: str) -> Tuple[bool, str]:
        if status != 200: return False, ""
        if length < 20: return False, ""
        
        # Soft-404 detection
        body_lower = body.lower()
        if any(x in body_lower[:1000] for x in ('not found', '404', 'error', 'permission denied')):
            if "login" not in path: # some login pages might have these words but be valid
                return False, ""

        # Content verification per file type
        if ".git/config" in path and "[core]" in body:
            return True, "Git config markers found ([core])"
        if ".env" in path and any(x in body for x in ("=", "APP_ENV", "DB_PASSWORD", "SECRET_KEY")):
            return True, "Environment variable pattern found"
        if ".sql" in path and any(x in body_lower for x in ("insert into", "create table", "select * from")):
            return True, "SQL query markers found"
        if "phpinfo.php" in path and "PHP Version" in body:
            return True, "PHP Version string found"
        if (".zip" in path or ".tar" in path) and ("application/zip" in ct or "application/x-gzip" in ct):
            return True, "Archive Content-Type confirmed"
        if (".log" in path) and any(x in body_lower for x in ("error", "exception", "password", "token")):
            return True, "Sensitive log keywords found"
        if (".json" in path or ".yaml" in path) and any(x in body_lower for x in ("api_key", "secret", "password", "token")):
            return True, "Credentials found in config file"
        
        # Generic check for high-confidence paths
        if any(x in path for x in (".git/", ".svn/", ".env", "/config/")):
            if length > 100:
                return True, "Path matches high-risk pattern and returned substantial body"

        return False, ""

    async def _check_graphql(self, target: str):
        gql_paths = ['/graphql', '/api/graphql', '/graphiql', '/__graphql']
        query = {"query": "{ __schema { types { name } } }"}
        
        for path in gql_paths:
            url = urljoin(target, path)
            async with self.semaphore:
                try:
                    resp = await self._make_request(url, method='POST', data=json.dumps(query), 
                                                   headers={'Content-Type': 'application/json'})
                    if resp and resp.status == 200:
                        body = await resp.text()
                        if "__schema" in body:
                            self.add_finding(Finding(
                                module='server_misconfig',
                                title="GraphQL Introspection Enabled",
                                severity='Critical',
                                description="GraphQL introspection is enabled at this endpoint, allowing an attacker to map the entire API schema.",
                                evidence={'url': url, 'payload': query},
                                poc=f"curl -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(query)}'",
                                remediation="Disable GraphQL introspection in production environments.",
                                cvss_score=8.6, bounty_score=3500, target=target
                            ))
                            break
                except Exception: pass

    async def _check_git_reconstruction(self, target: str):
        # Attempt to see if we can get multiple critical git files
        required = ['.git/config', '.git/HEAD', '.git/logs/HEAD']
        success_count = 0
        for path in required:
            url = urljoin(target, path)
            resp = await self._make_request(url)
            if resp and resp.status == 200:
                body = await resp.text()
                if self._is_real_exposure(200, body, len(body), path, "")[0]:
                    success_count += 1
        
        if success_count == len(required):
            self.add_finding(Finding(
                module='server_misconfig',
                title="Full Git Repository Exposed",
                severity='Critical',
                description="The entire `.git` directory is exposed. An attacker can reconstruct the full source code, including history and potentially hardcoded secrets, using tools like `git-dumper`.",
                evidence={'files': required},
                poc=f"git-dumper {target} ./out",
                remediation="Remove the `.git` directory from the web root immediately.",
                cvss_score=9.1, bounty_score=4000, target=target
            ))

    def _get_path_list(self) -> List[Dict]:
        """Returns the exhaustive list of 150+ paths categorized by type."""
        paths = []
        
        # Categorized patterns
        cats = {
            'VERSION CONTROL': [
                ('/.git/config', 'Critical', 9.1, 4000), ('/.git/HEAD', 'Critical', 9.1, 4000),
                ('/.git/COMMIT_EDITMSG', 'High', 7.5, 1000), ('/.git/logs/HEAD', 'High', 7.5, 1000),
                ('/.git/packed-refs', 'High', 7.5, 1000), ('/.git/refs/heads/main', 'High', 7.5, 1000),
                ('/.git/refs/heads/master', 'High', 7.5, 1000), ('/.svn/entries', 'High', 7.5, 1000),
                ('/.svn/wc.db', 'High', 7.5, 1000), ('/.hg/hgrc', 'High', 7.5, 1000), ('/.bzr/branch/format', 'High', 7.5, 1000)
            ],
            'ENVIRONMENT & SECRETS': [
                ('/.env', 'Critical', 9.8, 5000), ('/.env.local', 'Critical', 9.8, 5000),
                ('/.env.production', 'Critical', 9.8, 5000), ('/.env.backup', 'Critical', 9.8, 5000),
                ('/.env.old', 'Critical', 9.8, 5000), ('/.env.bak', 'Critical', 9.8, 5000),
                ('/.env.example', 'High', 7.5, 1000), ('/.env.staging', 'Critical', 9.8, 5000),
                ('/.env.development', 'Critical', 9.8, 5000), ('/config/.env', 'Critical', 9.8, 5000),
                ('/app/.env', 'Critical', 9.8, 5000)
            ],
            'CONFIGURATION': [
                ('/config.php', 'High', 7.5, 1500), ('/config.json', 'High', 7.5, 1500),
                ('/config.yaml', 'High', 7.5, 1500), ('/config.yml', 'High', 7.5, 1500),
                ('/configuration.php', 'High', 7.5, 1500), ('/application.properties', 'High', 7.5, 1500),
                ('/application.yml', 'High', 7.5, 1500), ('/settings.py', 'High', 7.5, 1500),
                ('/settings.json', 'High', 7.5, 1500), ('/web.config', 'High', 7.5, 1500),
                ('/wp-config.php', 'Critical', 9.8, 4000), ('/wp-config.php.bak', 'Critical', 9.8, 4000),
                ('/wp-config.old', 'Critical', 9.8, 4000), ('/LocalSettings.php', 'High', 7.5, 1500),
                ('/config/database.yml', 'Critical', 9.8, 4000), ('/config/database.json', 'Critical', 9.8, 4000),
                ('/config/secrets.yml', 'Critical', 9.8, 4000), ('/database.php', 'High', 7.5, 1500),
                ('/db.php', 'High', 7.5, 1500), ('/db_config.php', 'High', 7.5, 1500)
            ],
            'DATABASE': [
                ('/backup.sql', 'Critical', 9.8, 5000), ('/database.sql', 'Critical', 9.8, 5000),
                ('/db.sql', 'Critical', 9.8, 5000), ('/dump.sql', 'Critical', 9.8, 5000),
                ('/data.sql', 'Critical', 9.8, 5000), ('/users.sql', 'Critical', 9.8, 5000),
                ('/database.db', 'Critical', 9.8, 5000), ('/db.sqlite', 'Critical', 9.8, 5000),
                ('/db.sqlite3', 'Critical', 9.8, 5000), ('/app.db', 'Critical', 9.8, 5000),
                ('/storage.db', 'Critical', 9.8, 5000), ('/data.db', 'Critical', 9.8, 5000)
            ],
            'BACKUP & ARCHIVE': [
                ('/backup.zip', 'High', 8.1, 3000), ('/backup.tar.gz', 'High', 8.1, 3000),
                ('/backup.tar', 'High', 8.1, 3000), ('/site.zip', 'High', 8.1, 3000),
                ('/www.zip', 'High', 8.1, 3000), ('/html.zip', 'High', 8.1, 3000),
                ('/public_html.zip', 'High', 8.1, 3000), ('/backup.7z', 'High', 8.1, 3000),
                ('/app.zip', 'High', 8.1, 3000), ('/website.zip', 'High', 8.1, 3000),
                ('/deploy.zip', 'High', 8.1, 3000), ('/index.php.bak', 'Medium', 5.0, 500),
                ('/config.php.bak', 'High', 7.5, 1500), ('/index.php.old', 'Medium', 5.0, 500),
                ('/config.php.old', 'High', 7.5, 1500), ('/backup/', 'Medium', 4.3, 300),
                ('/backups/', 'Medium', 4.3, 300)
            ],
            'LOGS': [
                ('/logs/error.log', 'High', 7.5, 2000), ('/logs/access.log', 'High', 7.5, 2000),
                ('/logs/app.log', 'High', 7.5, 2000), ('/logs/debug.log', 'High', 7.5, 2000),
                ('/log/error.log', 'High', 7.5, 2000), ('/error.log', 'High', 7.5, 2000),
                ('/access.log', 'High', 7.5, 2000), ('/debug.log', 'High', 7.5, 2000),
                ('/storage/logs/laravel.log', 'High', 7.5, 2000), ('/var/log/nginx/error.log', 'High', 7.5, 2000),
                ('/var/log/apache2/error.log', 'High', 7.5, 2000), ('/npm-debug.log', 'Medium', 5.3, 500),
                ('/yarn-error.log', 'Medium', 5.3, 500)
            ],
            'CI/CD & DOCKER': [
                ('/.travis.yml', 'Medium', 5.3, 500), ('/.circleci/config.yml', 'Medium', 5.3, 500),
                ('/Jenkinsfile', 'Medium', 5.3, 500), ('/.github/workflows/deploy.yml', 'Medium', 5.3, 500),
                ('/docker-compose.yml', 'High', 7.5, 1500), ('/docker-compose.prod.yml', 'High', 7.5, 1500),
                ('/Dockerfile', 'Medium', 5.3, 500), ('/.dockerignore', 'Low', 3.1, 100),
                ('/deploy.sh', 'High', 7.5, 1500), ('/deploy.rb', 'High', 7.5, 1500),
                ('/Capfile', 'Medium', 5.3, 500), ('/ansible.cfg', 'Medium', 5.3, 500),
                ('/terraform.tfstate', 'Critical', 9.8, 4000), ('/terraform.tfvars', 'Critical', 9.8, 4000)
            ],
            'PACKAGE FILES': [
                ('/package.json', 'Medium', 5.3, 300), ('/package-lock.json', 'Medium', 5.3, 300),
                ('/yarn.lock', 'Medium', 5.3, 300), ('/composer.json', 'Medium', 5.3, 300),
                ('/composer.lock', 'Medium', 5.3, 300), ('/Gemfile', 'Medium', 5.3, 300),
                ('/Gemfile.lock', 'Medium', 5.3, 300), ('/requirements.txt', 'Medium', 5.3, 300),
                ('/Pipfile', 'Medium', 5.3, 300), ('/Pipfile.lock', 'Medium', 5.3, 300),
                ('/go.sum', 'Medium', 5.3, 300), ('/go.mod', 'Medium', 5.3, 300),
                ('/pom.xml', 'Medium', 5.3, 300), ('/build.gradle', 'Medium', 5.3, 300),
                ('/Cargo.toml', 'Medium', 5.3, 300)
            ],
            'API & KEYS': [
                ('/api_keys.txt', 'Critical', 9.8, 5000), ('/keys.json', 'Critical', 9.8, 5000),
                ('/credentials.json', 'Critical', 9.8, 5000), ('/secrets.json', 'Critical', 9.8, 5000),
                ('/private.key', 'Critical', 9.8, 5000), ('/server.key', 'Critical', 9.8, 5000),
                ('/id_rsa', 'Critical', 9.8, 5000), ('/.ssh/id_rsa', 'Critical', 9.8, 5000),
                ('/.ssh/authorized_keys', 'Critical', 9.8, 5000), ('/google-credentials.json', 'Critical', 9.8, 5000),
                ('/firebase-credentials.json', 'Critical', 9.8, 5000), ('/aws-credentials', 'Critical', 9.8, 5000),
                ('/.aws/credentials', 'Critical', 9.8, 5000)
            ],
            'ADMIN PANELS': [
                ('/admin', 'High', 7.5, 2500), ('/admin/', 'High', 7.5, 2500),
                ('/admin.php', 'High', 7.5, 2500), ('/admin.html', 'High', 7.5, 2500),
                ('/administrator/', 'High', 7.5, 2500), ('/wp-admin/', 'High', 7.5, 2500),
                ('/phpmyadmin/', 'High', 7.5, 2500), ('/pma/', 'High', 7.5, 2500),
                ('/adminer.php', 'High', 7.5, 2500), ('/adminer/', 'High', 7.5, 2500),
                ('/cpanel', 'High', 7.5, 2500), ('/webadmin/', 'High', 7.5, 2500),
                ('/sysadmin/', 'High', 7.5, 2500), ('/console', 'High', 7.5, 2500),
                ('/debug', 'High', 7.5, 2000), ('/debug.php', 'High', 7.5, 2000),
                ('/phpinfo.php', 'High', 7.5, 2000), ('/info.php', 'High', 7.5, 2000),
                ('/test.php', 'Medium', 5.3, 500), ('/server-info', 'High', 7.5, 2000),
                ('/server-status', 'High', 7.5, 2000)
            ],
            'API DOCS': [
                ('/api/swagger.json', 'Medium', 5.3, 500), ('/api/openapi.json', 'Medium', 5.3, 500),
                ('/swagger.json', 'Medium', 5.3, 500), ('/swagger.yaml', 'Medium', 5.3, 500),
                ('/openapi.json', 'Medium', 5.3, 500), ('/openapi.yaml', 'Medium', 5.3, 500),
                ('/api-docs', 'Medium', 5.3, 500), ('/api-docs/', 'Medium', 5.3, 500),
                ('/docs/api', 'Medium', 5.3, 500), ('/swagger-ui.html', 'Medium', 5.3, 500),
                ('/swagger-ui/', 'Medium', 5.3, 500), ('/redoc', 'Medium', 5.3, 500),
                ('/graphql', 'Medium', 5.3, 500), ('/graphiql', 'Medium', 5.3, 500),
                ('/__graphql', 'Medium', 5.3, 500), ('/v1/api-docs', 'Medium', 5.3, 500),
                ('/v2/api-docs', 'Medium', 5.3, 500)
            ],
            'CLOUD & K8S': [
                ('/.kube/config', 'Critical', 9.8, 5000), ('/kubeconfig', 'Critical', 9.8, 5000),
                ('/k8s/', 'High', 7.5, 2000), ('/cluster.yml', 'High', 7.5, 2000),
                ('/.aws/config', 'Critical', 9.8, 5000), ('/.gcloud/', 'Critical', 9.8, 5000),
                ('/service-account.json', 'Critical', 9.8, 5000)
            ],
            'HEALTH & METRICS': [
                ('/health', 'Low', 2.0, 50), ('/healthz', 'Low', 2.0, 50),
                ('/status', 'Low', 2.0, 50), ('/metrics', 'Medium', 5.3, 500),
                ('/actuator', 'Medium', 5.3, 500), ('/actuator/env', 'High', 7.5, 2000),
                ('/actuator/beans', 'Medium', 5.3, 500), ('/actuator/mappings', 'Medium', 5.3, 500),
                ('/actuator/health', 'Medium', 5.3, 500), ('/monitoring', 'Medium', 5.3, 500),
                ('/_status', 'Low', 2.0, 50), ('/__status', 'Low', 2.0, 50)
            ]
        }
        
        for cat, items in cats.items():
            for p, sev, cvss, bounty in items:
                paths.append({'path': p, 'category': cat, 'severity': sev, 'cvss': cvss, 'bounty': bounty})
        
        return paths

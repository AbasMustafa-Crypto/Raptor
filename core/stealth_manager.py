import asyncio
import random
from typing import Dict, List, Optional

class StealthManager:
    """Manages stealth capabilities for evasion"""
    
    # Hardcoded list of realistic user agents (no external dependency needed)
    USER_AGENTS = [
        # Chrome on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        # Chrome on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        # Chrome on Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
        # Firefox on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
        # Firefox on Linux
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
        # Safari on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        # Edge on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        # Mobile - Chrome on Android
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        # Mobile - Safari on iOS
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    ]
    
    def __init__(self, config: Dict):
        self.config = config
        self.proxies: List[str] = []
        self.current_proxy_index = 0
        self.request_count = 0
        
        # Load proxies if configured
        if config.get('proxy_file'):
            self._load_proxies(config['proxy_file'])
            
    def _load_proxies(self, filepath: str):
        """Load proxy list from file"""
        try:
            with open(filepath, 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(self.proxies)} proxies")
        except FileNotFoundError:
            print(f"Proxy file not found: {filepath}")
            
    async def delay(self):
        """Apply random delay between requests"""
        if self.config.get('request_jitter', True):
            delay = random.uniform(
                self.config.get('delay_min', 0.5),
                self.config.get('delay_max', 3.0)
            )
            await asyncio.sleep(delay)
            
    async def get_headers(self) -> Dict[str, str]:
        """Generate randomized headers"""
        headers = {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'en-GB,en;q=0.5', 'en-CA,en;q=0.5']),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }
        
        # Add spoofed headers for IP bypass
        if self.config.get('header_spoofing', True):
            spoofed_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            headers.update({
                'X-Forwarded-For': spoofed_ip,
                'X-Real-IP': spoofed_ip,
                'X-Originating-IP': spoofed_ip,
                'X-Remote-IP': spoofed_ip,
                'X-Client-IP': spoofed_ip,
                'CF-Connecting-IP': spoofed_ip,
            })
            
        return headers
        
    def get_proxy(self) -> Optional[str]:
        """Get next proxy from rotation"""
        if not self.proxies:
            return None
            
        if self.config.get('proxy_rotation', True):
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
            
        return self.proxies[self.current_proxy_index]
        
    def adapt_rate_limit(self, status_code: int):
        """Adapt behavior based on rate limiting"""
        if status_code in [429, 503]:
            # Increase delays
            self.config['delay_min'] = min(self.config.get('delay_min', 0.5) * 2, 10.0)
            self.config['delay_max'] = min(self.config.get('delay_max', 3.0) * 2, 15.0)
            print(f"Rate limit detected. Increasing delays: {self.config['delay_min']:.1f}-{self.config['delay_max']:.1f}s")

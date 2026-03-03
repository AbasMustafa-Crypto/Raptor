import asyncio
import random
from typing import Dict, List, Optional
from fake_useragent import UserAgent

class StealthManager:
    """Manages stealth capabilities for evasion"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.ua = UserAgent()
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
            'User-Agent': self.ua.random,
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

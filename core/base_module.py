import asyncio
import aiohttp
import aiohttp.tcp_helpers
import logging
import ssl
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Finding:
    """Represents a security finding"""
    module: str
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    bounty_score: int = 0  # Estimated bounty value
    timestamp: datetime = field(default_factory=datetime.now)
    target: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'module': self.module,
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'poc': self.poc,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'bounty_score': self.bounty_score,
            'timestamp': self.timestamp.isoformat(),
            'target': self.target
        }

class BaseModule(ABC):
    """Base class for all RAPTOR modules"""
    
    def __init__(self, config: Dict, stealth_manager=None, db_manager=None):
        self.config = config
        self.stealth = stealth_manager
        self.db = db_manager
        self.findings: List[Finding] = []
        self.logger = logging.getLogger(self.__class__.__name__)
        self.session: Optional[aiohttp.ClientSession] = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        # Create SSL context that allows us to connect to sites with certificate issues
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=self.config.get('max_concurrent', 50),
            limit_per_host=5,
            enable_cleanup_closed=True,
            force_close=False,
            ssl=ssl_context,
            use_dns_cache=True,
            ttl_dns_cache=300,
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.get('request_timeout', 30),
            connect=self.config.get('connect_timeout', 10),
            sock_read=self.config.get('sock_read_timeout', 10)
        )
        
        headers = await self._get_headers() if self.stealth else {}
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            raise_for_status=False
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
            
    async def _get_headers(self) -> Dict[str, str]:
        """Get randomized headers for stealth"""
        if self.stealth:
            return await self.stealth.get_headers()
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
    async def _make_request(self, url: str, method: str = 'GET', 
                           data: Any = None, headers: Dict = None,
                           allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with stealth and retry logic"""
        max_retries = self.config.get('retry_attempts', 3)
        retry_delay = self.config.get('retry_delay', 2)
        
        for attempt in range(max_retries):
            try:
                # Apply stealth delays
                if self.stealth:
                    await self.stealth.delay()
                    
                request_headers = headers or await self._get_headers()
                
                # Ensure URL is properly formatted
                if not url.startswith(('http://', 'https://')):
                    url = f"https://{url}"
                
                request_kwargs = {
                    'headers': request_headers,
                    'allow_redirects': allow_redirects,
                    'ssl': False  # Disable SSL verification for testing
                }
                
                if method.upper() == 'GET':
                    async with self.session.get(url, **request_kwargs) as response:
                        # Read response to avoid connection issues
                        await response.read()
                        return response
                        
                elif method.upper() == 'POST':
                    request_kwargs['data'] = data
                    async with self.session.post(url, **request_kwargs) as response:
                        await response.read()
                        return response
                        
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(retry_delay * (attempt + 1))
                
            except aiohttp.ClientConnectorError as e:
                self.logger.warning(f"Connection error to {url}: {e}")
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(retry_delay * (attempt + 1))
                
            except aiohttp.ClientOSError as e:
                self.logger.warning(f"OS error on request to {url}: {e}")
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(retry_delay * (attempt + 1))
                
            except Exception as e:
                self.logger.error(f"Request error on {url}: {e}")
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(retry_delay * (attempt + 1))
                    
        return None
        
    def add_finding(self, finding: Finding):
        """Add a finding to the results"""
        self.findings.append(finding)
        self.logger.info(f"Finding: {finding.title} ({finding.severity})")
        
        # Save to database if available
        if self.db:
            self.db.save_finding(finding)
            
    @abstractmethod
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Main execution method - must be implemented by modules"""
        pass
        
    async def test_endpoint(self, url: str, method: str = 'GET', 
                           params: Dict = None, data: Any = None) -> Dict:
        """Test a specific endpoint and return analysis"""
        response = await self._make_request(url, method, data)
        if not response:
            return {'error': 'No response'}
            
        return {
            'status': response.status,
            'headers': dict(response.headers),
            'url': str(response.url),
            'method': method
        }

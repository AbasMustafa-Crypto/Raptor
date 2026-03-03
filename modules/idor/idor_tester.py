import asyncio
import re
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from core.base_module import BaseModule, Finding

class IDORTester(BaseModule):
    """Test for Insecure Direct Object Reference vulnerabilities"""
    
    def __init__(self, config, stealth=None, db=None):
        super().__init__(config, stealth, db)
        self.id_patterns = [
            r'[?&](id|user_id|account_id|doc_id|file_id|order_id|item_id)=\d+',
            r'[?&](uid|uuid|guid|pid|sid|tid)=\d+',
            r'/\d+(/|$)',  # Path-based IDs
        ]
        self.test_range = config.get('test_range', 100)
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run IDOR tests"""
        self.logger.info(f"Testing IDOR on {target}")
        
        # Crawl for endpoints with ID parameters
        endpoints = await self._discover_endpoints(target)
        
        # Test each endpoint
        semaphore = asyncio.Semaphore(10)
        
        async def test_endpoint_wrapper(endpoint):
            async with semaphore:
                return await self._test_endpoint(endpoint)
                
        results = await asyncio.gather(*[test_endpoint_wrapper(e) for e in endpoints])
        
        # Process results
        for result in results:
            if result and result.get('vulnerable'):
                finding = Finding(
                    module='idor',
                    title=f'IDOR Vulnerability: {result["parameter"]}',
                    severity='High',
                    description=f'Horizontal privilege escalation possible via {result["parameter"]}',
                    evidence=result,
                    poc=result.get('poc', ''),
                    remediation='Implement proper access control checks for all object references',
                    cvss_score=8.1,
                    bounty_score=1500,
                    target=result['url']
                )
                self.add_finding(finding)
                
        return self.findings
        
    async def _discover_endpoints(self, target: str) -> List[Dict]:
        """Discover endpoints with ID parameters"""
        endpoints = []
        
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        # Common IDOR patterns to test
        common_paths = [
            '/api/user/{id}', '/api/users/{id}', '/api/account/{id}',
            '/api/orders/{id}', '/api/documents/{id}', '/api/files/{id}',
            '/user/{id}', '/profile/{id}', '/account/{id}',
            '/order/{id}', '/invoice/{id}', '/download/{id}',
        ]
        
        # Get initial page to extract links
        response = await self._make_request(target)
        if response:
            text = await response.text()
            
            # Extract URLs with parameters
            for pattern in self.id_patterns:
                matches = re.finditer(pattern, text)
                for match in matches:
                    url = match.group(0)
                    full_url = urljoin(target, url) if not url.startswith('http') else url
                    
                    endpoints.append({
                        'url': full_url,
                        'method': 'GET',
                        'parameter': self._extract_param(full_url),
                        'type': 'url'
                    })
                    
        # Add common patterns
        for path in common_paths:
            # Replace {id} with actual test ID
            test_url = urljoin(target, path.replace('{id}', '1'))
            endpoints.append({
                'url': test_url,
                'method': 'GET',
                'parameter': 'id',
                'type': 'predicted'
            })
            
        # Remove duplicates
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            key = ep['url']
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
                
        return unique_endpoints
        
    async def _test_endpoint(self, endpoint: Dict) -> Dict:
        """Test a single endpoint for IDOR"""
        url = endpoint['url']
        param = endpoint['parameter']
        
        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Get baseline response
        baseline = await self._make_request(url)
        if not baseline:
            return None
            
        baseline_status = baseline.status
        baseline_text = await baseline.text()
        
        # Test ID manipulation
        test_results = []
        
        # Test 1: Increment ID
        for i in range(2, min(5, self.test_range)):
            test_url = self._modify_id(url, param, i)
            response = await self._make_request(test_url)
            
            if response and response.status == 200:
                text = await response.text()
                
                # Check if content is different (indicating access to different resource)
                if len(text) != len(baseline_text) or text != baseline_text:
                    test_results.append({
                        'test': f'increment_to_{i}',
                        'status': response.status,
                        'different_content': True
                    })
                    break
                    
        # Test 2: Decrement ID
        for i in range(0, -min(3, self.test_range), -1):
            if i == 0:
                continue
            test_url = self._modify_id(url, param, i)
            response = await self._make_request(test_url)
            
            if response and response.status == 200:
                text = await response.text()
                
                if len(text) != len(baseline_text):
                    test_results.append({
                        'test': f'decrement_to_{i}',
                        'status': response.status,
                        'different_content': True
                    })
                    break
                    
        if test_results:
            return {
                'vulnerable': True,
                'url': url,
                'parameter': param,
                'tests': test_results,
                'poc': f"Change {param} parameter to different values",
                'baseline_status': baseline_status
            }
            
        return None
        
    def _extract_param(self, url: str) -> str:
        """Extract ID parameter name from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        id_params = ['id', 'user_id', 'account_id', 'doc_id', 'uid', 'uuid']
        for param in id_params:
            if param in params:
                return param
                
        # Check path-based
        match = re.search(r'/(\d+)(/|$)', url)
        if match:
            return 'path_id'
            
        return 'unknown'
        
    def _modify_id(self, url: str, param: str, new_value: int) -> str:
        """Modify ID parameter in URL"""
        parsed = urlparse(url)
        
        if param == 'path_id':
            # Replace path-based ID
            new_path = re.sub(r'/\d+(/|$)', f'/{new_value}\\1', parsed.path)
            return parsed._replace(path=new_path).geturl()
        else:
            # Replace query parameter
            params = parse_qs(parsed.query)
            params[param] = [str(new_value)]
            new_query = urlencode(params, doseq=True)
            return parsed._replace(query=new_query).geturl()

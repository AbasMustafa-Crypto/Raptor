from typing import Dict, List
from bs4 import BeautifulSoup
import re
from core.base_module import BaseModule, Finding

class TechnologyFingerprinter(BaseModule):
    """Fingerprint web technologies and versions"""
    
    def __init__(self, config, stealth=None, db=None):
        super().__init__(config, stealth, db)
        self.tech_signatures = self._load_signatures()
        
    def _load_signatures(self) -> Dict:
        """Load technology detection signatures"""
        return {
            'WordPress': {
                'headers': ['X-Powered-By: WordPress', 'WP-'],
                'meta': ['generator.*WordPress'],
                'paths': ['/wp-content/', '/wp-includes/', '/wp-admin/'],
                'version_regex': r'WordPress/([\d.]+)'
            },
            'Drupal': {
                'headers': ['X-Generator: Drupal'],
                'meta': ['generator.*Drupal'],
                'paths': ['/sites/default/', '/misc/drupal.js'],
                'version_regex': r'Drupal (\d+)'
            },
            'Joomla': {
                'meta': ['generator.*Joomla'],
                'paths': ['/media/system/js/', '/templates/'],
            },
            'Apache': {
                'headers': ['Server: Apache'],
                'version_regex': r'Apache/([\d.]+)'
            },
            'Nginx': {
                'headers': ['Server: nginx'],
                'version_regex': r'nginx/([\d.]+)'
            },
            'PHP': {
                'headers': ['X-Powered-By: PHP'],
                'version_regex': r'PHP/([\d.]+)'
            },
            'Django': {
                'headers': ['Server: WSGIServer', 'X-Frame-Options: SAMEORIGIN'],
                'cookies': ['csrftoken', 'sessionid'],
            },
            'React': {
                'html': ['reactroot', 'data-react', '__REACT__'],
                'scripts': ['react.js', 'react-dom.js']
            },
            'Angular': {
                'html': ['ng-app', 'ng-controller', 'angular'],
                'scripts': ['angular.js']
            },
            'Vue.js': {
                'html': ['v-app', 'vue-', '__VUE__'],
                'scripts': ['vue.js']
            }
        }
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Fingerprint technologies on target"""
        self.logger.info(f"Fingerprinting technologies for {target}")
        
        # Ensure URL format
        if not target.startswith(('http://', 'https://')):
            urls = [f"https://{target}", f"http://{target}"]
        else:
            urls = [target]
            
        success = False
        
        for url in urls:
            try:
                response = await self._make_request(url)
                if not response:
                    continue
                
                # Check if response is valid
                if response.status >= 500:
                    self.logger.warning(f"Server error {response.status} for {url}")
                    continue
                
                success = True
                    
                try:
                    text = await response.text()
                    headers = dict(response.headers)
                    
                    detected = self._analyze_response(url, text, headers)
                    
                    for tech, details in detected.items():
                        self.logger.info(f"Detected: {tech} {details.get('version', '')}")
                        
                        # Save asset
                        if self.db:
                            self.db.save_asset(
                                'technology', 
                                tech, 
                                'recon',
                                metadata={'version': details.get('version'), 'url': url}
                            )
                            
                        # Check for known vulnerabilities based on version
                        await self._check_vulnerabilities(tech, details, url)
                        
                except Exception as e:
                    self.logger.error(f"Error analyzing response from {url}: {e}")
                    
            except Exception as e:
                self.logger.error(f"Error connecting to {url}: {e}")
                continue
        
        if not success:
            self.logger.warning(f"Could not fingerprint any technologies for {target}")
                
        return self.findings
        
    def _analyze_response(self, url: str, text: str, headers: Dict) -> Dict:
        """Analyze response for technology signatures"""
        detected = {}
        
        try:
            soup = BeautifulSoup(text, 'html.parser')
        except Exception:
            soup = None
            
        for tech, signatures in self.tech_signatures.items():
            detected[tech] = {'confidence': 0, 'version': None}
            
            # Check headers
            for header_sig in signatures.get('headers', []):
                header_name, header_val = header_sig.split(': ', 1) if ': ' in header_sig else (header_sig, '')
                for header, value in headers.items():
                    if header.lower() == header_name.lower() and header_val in value:
                        detected[tech]['confidence'] += 20
                        # Extract version
                        if 'version_regex' in signatures:
                            match = re.search(signatures['version_regex'], value)
                            if match:
                                detected[tech]['version'] = match.group(1)
                                
            # Check meta tags
            if soup:
                for meta_sig in signatures.get('meta', []):
                    meta_tags = soup.find_all('meta', attrs={'name': 'generator'})
                    for tag in meta_tags:
                        if tag.get('content') and re.search(meta_sig, tag.get('content'), re.I):
                            detected[tech]['confidence'] += 20
                            if 'version_regex' in signatures:
                                match = re.search(signatures['version_regex'], tag.get('content'))
                                if match:
                                    detected[tech]['version'] = match.group(1)
                                    
                # Check scripts
                scripts = soup.find_all('script', src=True)
                for script_sig in signatures.get('scripts', []):
                    for script in scripts:
                        if script_sig in script.get('src', ''):
                            detected[tech]['confidence'] += 15
            
            # Check HTML content
            for html_sig in signatures.get('html', []):
                if html_sig in text:
                    detected[tech]['confidence'] += 15
                        
            # Check cookies
            for cookie_sig in signatures.get('cookies', []):
                if 'Set-Cookie' in headers:
                    if cookie_sig in headers.get('Set-Cookie', ''):
                        detected[tech]['confidence'] += 10
                        
        # Filter low confidence
        return {k: v for k, v in detected.items() if v['confidence'] >= 30}
        
    async def _check_vulnerabilities(self, tech: str, details: Dict, url: str):
        """Check for known vulnerabilities in detected technology"""
        version = details.get('version')
        
        if not version:
            return
            
        # Example checks for outdated versions
        outdated_versions = {
            'WordPress': {'min_version': '5.8', 'severity': 'High'},
            'Apache': {'min_version': '2.4.50', 'severity': 'Medium'},
            'Nginx': {'min_version': '1.20', 'severity': 'Medium'},
            'PHP': {'min_version': '7.4', 'severity': 'High'},
        }
        
        if tech in outdated_versions:
            # Simple version comparison (you'd want proper semver comparison)
            min_ver = outdated_versions[tech]['min_version']
            
            finding = Finding(
                module='recon',
                title=f'Potentially Outdated {tech} Version: {version}',
                severity='Info',
                description=f'Detected {tech} version {version}. Current minimum recommended: {min_ver}',
                evidence={'technology': tech, 'version': version, 'detected_at': url},
                poc=f"Version detected in headers/meta tags at {url}",
                remediation=f'Update {tech} to latest stable version',
                cvss_score=0.0,
                bounty_score=0,
                target=url
            )
            self.add_finding(finding)

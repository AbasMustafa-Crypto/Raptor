from typing import Dict, List, Set
import re
from pathlib import Path
from html.parser import HTMLParser
from core.base_module import BaseModule, Finding


class _MiniSoup(HTMLParser):
    """Zero-dependency BeautifulSoup replacement using stdlib html.parser."""

    def __init__(self, html_text: str):
        super().__init__()
        self.tags: List[Dict] = []        # list of {tag, attrs_dict}
        self._current = []
        self.feed(html_text)

    def handle_starttag(self, tag: str, attrs):
        self.tags.append({'tag': tag.lower(), 'attrs': dict(attrs)})

    # ── BS4-compatible helpers ──────────────────────────────────────────────

    def find_all(self, tag: str, attrs: Dict = None, src: bool = False):
        """Return list of tag-dicts matching tag name and optional attr filter."""
        results = []
        for t in self.tags:
            if t['tag'] != tag.lower():
                continue
            if attrs:
                match = all(
                    re.search(str(v), str(t['attrs'].get(k, '')), re.I)
                    if isinstance(v, str) else t['attrs'].get(k) == v
                    for k, v in attrs.items()
                )
                if not match:
                    continue
            if src and 'src' not in t['attrs']:
                continue
            results.append(_TagProxy(t['attrs']))
        return results


class _TagProxy:
    """Proxy for a single tag — mimics BS4 tag.get() / tag['attr'] API."""

    def __init__(self, attrs: Dict):
        self._attrs = attrs

    def get(self, key: str, default=None):
        return self._attrs.get(key, default)

    def __getitem__(self, key: str):
        return self._attrs[key]

    def __contains__(self, key: str):
        return key in self._attrs

class TechnologyFingerprinter(BaseModule):
    """Fingerprint web technologies and versions"""
    
    def __init__(self, config, stealth=None, db=None):
        super().__init__(config, stealth, db)
        self.tech_signatures = self._load_signatures()
        self.additional_technologies = self._load_technologies_wordlist()
        self.wordlist_path = config.get('wordlist_path', 'wordlists')
        
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
        
    def _load_technologies_wordlist(self) -> List[str]:
        """Load additional technologies from wordlist file"""
        technologies = []
        
        # Try multiple possible paths
        possible_paths = [
            Path(self.config.get('wordlist_path', 'wordlists')) / 'technologies.txt',
            Path('wordlists') / 'technologies.txt',
            Path('../wordlists') / 'technologies.txt',
            Path(__file__).parent.parent.parent / 'wordlists' / 'technologies.txt',
        ]
        
        for tech_file in possible_paths:
            if tech_file.exists():
                try:
                    with open(tech_file, 'r', encoding='utf-8', errors='ignore') as f:
                        technologies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self.logger.info(f"Loaded {len(technologies)} technologies from {tech_file}")
                    return technologies
                except Exception as e:
                    self.logger.warning(f"Error reading technologies.txt: {e}")
                    continue
                    
        # If no file found, use default list
        self.logger.warning("technologies.txt not found, using default technology list")
        return [
            'WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify',
            'Laravel', 'Symfony', 'Django', 'Flask', 'Ruby on Rails',
            'Express.js', 'React', 'Angular', 'Vue.js', 'jQuery',
            'Bootstrap', 'Apache', 'Nginx', 'IIS', 'PHP', 'Python',
            'Node.js', 'MySQL', 'PostgreSQL', 'MongoDB', 'Redis',
            'Docker', 'Kubernetes', 'AWS', 'Azure', 'CloudFlare'
        ]
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Fingerprint technologies on target"""
        self.logger.info(f"Fingerprinting technologies for {target}")
        
        # Ensure URL format
        if not target.startswith(('http://', 'https://')):
            urls = [f"https://{target}", f"http://{target}"]
        else:
            urls = [target]
            
        all_detected = {}  # Collect all detected technologies across URLs
        
        for url in urls:
            try:
                response = await self._make_request(url)
                if not response:
                    continue
                
                # Check if response is valid
                if response.status >= 500:
                    self.logger.warning(f"Server error {response.status} for {url}")
                    continue
                    
                try:
                    text = await response.text()
                    headers = dict(response.headers)
                    
                    detected = self._analyze_response(url, text, headers)
                    
                    # Merge detected technologies
                    for tech, details in detected.items():
                        if tech not in all_detected:
                            all_detected[tech] = details
                            all_detected[tech]['urls'] = [url]
                        else:
                            all_detected[tech]['urls'].append(url)
                            # Keep highest confidence
                            if details['confidence'] > all_detected[tech]['confidence']:
                                all_detected[tech]['confidence'] = details['confidence']
                                all_detected[tech]['version'] = details.get('version') or all_detected[tech].get('version')
                    
                except Exception as e:
                    self.logger.error(f"Error analyzing response from {url}: {e}")
                    
            except Exception as e:
                self.logger.error(f"Error connecting to {url}: {e}")
                continue
        
        # Process all detected technologies
        for tech, details in all_detected.items():
            self.logger.info(f"Detected: {tech} {details.get('version', '')} (confidence: {details['confidence']})")
            
            # Save asset
            if self.db:
                self.db.save_asset(
                    'technology', 
                    tech, 
                    'recon',
                    metadata={
                        'version': details.get('version'), 
                        'urls': details.get('urls', []),
                        'confidence': details['confidence']
                    }
                )
                
            # Check for known vulnerabilities based on version
            await self._check_vulnerabilities(tech, details, target)
        
        if not all_detected:
            self.logger.warning(f"No technologies fingerprinted for {target}")
                
        return self.findings
        
    def _analyze_response(self, url: str, text: str, headers: Dict) -> Dict:
        """Analyze response for technology signatures"""
        detected = {}
        
        try:
            soup = _MiniSoup(text)
        except Exception:
            soup = None
            
        # Check hardcoded signatures first
        for tech, signatures in self.tech_signatures.items():
            detected[tech] = {'confidence': 0, 'version': None, 'urls': []}
            
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
                        
        # Check additional technologies from wordlist
        detected.update(self._check_wordlist_technologies(text, headers, soup))

        # Filter low confidence
        return {k: v for k, v in detected.items() if v['confidence'] >= 30}

    def _check_wordlist_technologies(self, text: str, headers: Dict, soup) -> Dict:
        """Check for additional technologies from wordlist"""
        detected = {}
        text_lower = text.lower()
        headers_str = str(headers).lower()
        
        for tech in self.additional_technologies:
            tech_lower = tech.lower()
            confidence = 0
            version = None
            
            # Check in response text
            if tech_lower in text_lower:
                confidence += 15
                
            # Check in headers
            if tech_lower in headers_str:
                confidence += 20
                
            # Check in script sources
            if soup:
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    src = script.get('src', '').lower()
                    if tech_lower.replace(' ', '').replace('.', '') in src.replace('-', '').replace('_', ''):
                        confidence += 15
                        
                # Check in link tags (CSS)
                links = soup.find_all('link', href=True)
                for link in links:
                    href = link.get('href', '').lower()
                    if tech_lower.replace(' ', '').replace('.', '') in href.replace('-', '').replace('_', ''):
                        confidence += 10
                        
                # Check in meta tags
                meta_tags = soup.find_all('meta')
                for meta in meta_tags:
                    content = str(meta.get('content', '')).lower()
                    if tech_lower in content:
                        confidence += 15
                        
            # Check for version patterns
            version_patterns = [
                rf'{re.escape(tech)}[/\s]?v?(\d+\.[\d.]*)',
                rf'{re.escape(tech_lower)}[/\s]?v?(\d+\.[\d.]*)',
                rf'{re.escape(tech.replace(" ", ""))}[/\s]?v?(\d+\.[\d.]*)',
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    confidence += 10
                    break
                    
            # Also check headers for version
            if not version:
                for header, value in headers.items():
                    if tech_lower in header.lower() or tech_lower in value.lower():
                        ver_match = re.search(r'[\d.]+', value)
                        if ver_match and len(ver_match.group()) > 1:
                            version = ver_match.group()
                            confidence += 10
                            break
            
            if confidence >= 30:
                detected[tech] = {
                    'confidence': min(confidence, 100),
                    'version': version,
                    'urls': []
                }
                
        return detected
        
    async def _check_vulnerabilities(self, tech: str, details: Dict, target: str):
        """Check for known vulnerabilities in detected technology"""
        version = details.get('version')
        urls = details.get('urls', [target])
        url = urls[0] if urls else target
        
        if not version:
            # Still report the technology even without version
            finding = Finding(
                module='recon',
                title=f'Technology Detected: {tech}',
                severity='Info',
                description=f'Detected {tech} (version unknown) on target',
                evidence={
                    'technology': tech,
                    'confidence': details.get('confidence', 0),
                    'detected_at': url
                },
                poc=f"Technology identified at {url}",
                remediation='Verify this technology is necessary and up to date',
                cvss_score=0.0,
                bounty_score=0,
                target=url
            )
            self.add_finding(finding)
            return
            
        # Check for outdated versions with known vulnerabilities
        vuln_database = {
            'WordPress': {
                'min_version': '5.8',
                'severity': 'High',
                'cwe': 'CWE-1035',
                'description': 'Outdated WordPress may contain known vulnerabilities'
            },
            'Apache': {
                'min_version': '2.4.50',
                'severity': 'Medium',
                'cwe': 'CWE-1035',
                'description': 'Outdated Apache HTTP Server may contain known vulnerabilities'
            },
            'Nginx': {
                'min_version': '1.20',
                'severity': 'Medium',
                'cwe': 'CWE-1035',
                'description': 'Outdated Nginx may contain known vulnerabilities'
            },
            'PHP': {
                'min_version': '7.4',
                'severity': 'High',
                'cwe': 'CWE-1035',
                'description': 'Outdated PHP version may have security vulnerabilities'
            },
            'Drupal': {
                'min_version': '9.0',
                'severity': 'High',
                'cwe': 'CWE-1035',
                'description': 'Outdated Drupal may contain critical vulnerabilities'
            },
            'Joomla': {
                'min_version': '4.0',
                'severity': 'High',
                'cwe': 'CWE-1035',
                'description': 'Outdated Joomla may contain known vulnerabilities'
            },
            'jQuery': {
                'min_version': '3.6.0',
                'severity': 'Medium',
                'cwe': 'CWE-1035',
                'description': 'Outdated jQuery may have XSS vulnerabilities'
            },
            'Bootstrap': {
                'min_version': '4.6',
                'severity': 'Low',
                'cwe': 'CWE-1035',
                'description': 'Outdated Bootstrap may have minor security issues'
            },
            'Node.js': {
                'min_version': '16.0',
                'severity': 'High',
                'cwe': 'CWE-1035',
                'description': 'Outdated Node.js may have security vulnerabilities'
            },
            'Angular': {
                'min_version': '12.0',
                'severity': 'Medium',
                'cwe': 'CWE-1035',
                'description': 'Outdated Angular may have security vulnerabilities'
            },
            'React': {
                'min_version': '17.0',
                'severity': 'Medium',
                'cwe': 'CWE-1035',
                'description': 'Outdated React may have security vulnerabilities'
            }
        }
        
        if tech in vuln_database:
            vuln_info = vuln_database[tech]
            min_ver = vuln_info['min_version']
            
            # Simple version comparison (major.minor)
            try:
                current_parts = version.split('.')[:2]
                min_parts = min_ver.split('.')[:2]
                
                current_major = int(current_parts[0]) if current_parts[0].isdigit() else 0
                current_minor = int(current_parts[1]) if len(current_parts) > 1 and current_parts[1].isdigit() else 0
                min_major = int(min_parts[0])
                min_minor = int(min_parts[1]) if len(min_parts) > 1 else 0
                
                is_outdated = (current_major < min_major) or (current_major == min_major and current_minor < min_minor)
                
                if is_outdated:
                    finding = Finding(
                        module='recon',
                        title=f'Outdated {tech} Version: {version}',
                        severity=vuln_info['severity'],
                        description=f"{vuln_info['description']}. Detected version {version}, minimum recommended: {min_ver}",
                        evidence={
                            'technology': tech,
                            'version': version,
                            'minimum_recommended': min_ver,
                            'cwe': vuln_info.get('cwe', 'CWE-1035'),
                            'detected_at': url
                        },
                        poc=f"Version detected at {url}",
                        remediation=f'Update {tech} to version {min_ver} or later',
                        cvss_score=5.3 if vuln_info['severity'] == 'Medium' else (7.5 if vuln_info['severity'] == 'High' else 3.7),
                        bounty_score=500 if vuln_info['severity'] == 'Medium' else (1000 if vuln_info['severity'] == 'High' else 100),
                        target=url
                    )
                    self.add_finding(finding)
                else:
                    # Version is up to date, just report detection
                    finding = Finding(
                        module='recon',
                        title=f'{tech} Detected: {version}',
                        severity='Info',
                        description=f'Detected {tech} version {version} (up to date)',
                        evidence={
                            'technology': tech,
                            'version': version,
                            'detected_at': url
                        },
                        poc=f"Version detected at {url}",
                        remediation='No action required - version is current',
                        cvss_score=0.0,
                        bounty_score=0,
                        target=url
                    )
                    self.add_finding(finding)
            except Exception as e:
                self.logger.error(f"Error comparing versions for {tech}: {e}")
        else:
            # Technology not in vulnerability database, just report detection
            finding = Finding(
                module='recon',
                title=f'Technology Detected: {tech} {version}',
                severity='Info',
                description=f'Detected {tech} version {version}',
                evidence={
                    'technology': tech,
                    'version': version,
                    'confidence': details.get('confidence', 0),
                    'detected_at': url
                },
                poc=f"Version identified at {url}",
                remediation='Verify this technology is necessary and up to date',
                cvss_score=0.0,
                bounty_score=0,
                target=url
            )
            self.add_finding(finding)

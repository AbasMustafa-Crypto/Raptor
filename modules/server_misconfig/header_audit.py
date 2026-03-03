from typing import Dict, List
from core.base_module import BaseModule, Finding

class HeaderAuditor(BaseModule):
    """Audit HTTP security headers"""
    
    def __init__(self, config, stealth=None, db=None):
        super().__init__(config, stealth, db)
        
        self.security_headers = {
            'Strict-Transport-Security': {
                'required': True,
                'description': 'HSTS - Forces HTTPS connections',
                'severity': 'High',
                'check': lambda v: v and 'max-age' in v,
                'bypass': 'Can be bypassed if first visit is over HTTP'
            },
            'Content-Security-Policy': {
                'required': True,
                'description': 'CSP - Prevents XSS and injection attacks',
                'severity': 'High',
                'check': lambda v: v and len(v) > 10,
                'bypass': 'Unsafe-inline, unsafe-eval, wildcard sources weaken protection'
            },
            'X-Frame-Options': {
                'required': True,
                'description': 'Prevents clickjacking',
                'severity': 'Medium',
                'check': lambda v: v and v.upper() in ['DENY', 'SAMEORIGIN'],
                'bypass': 'Can be bypassed via framing tricks if not DENY'
            },
            'X-Content-Type-Options': {
                'required': True,
                'description': 'Prevents MIME-sniffing',
                'severity': 'Medium',
                'check': lambda v: v and v.lower() == 'nosniff',
                'bypass': None
            },
            'Referrer-Policy': {
                'required': False,
                'description': 'Controls referrer information',
                'severity': 'Low',
                'check': lambda v: v is not None,
                'bypass': None
            },
            'Permissions-Policy': {
                'required': False,
                'description': 'Controls browser features',
                'severity': 'Low',
                'check': lambda v: v is not None,
                'bypass': None
            },
            'X-XSS-Protection': {
                'required': False,
                'description': 'Legacy XSS protection (deprecated)',
                'severity': 'Info',
                'check': lambda v: v is not None,
                'bypass': 'Can be abused for XSS in older browsers if set to 1; mode=block'
            }
        }
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run header security audit"""
        self.logger.info(f"Auditing security headers for {target}")
        
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        response = await self._make_request(target)
        if not response:
            return self.findings
            
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        for header_name, config in self.security_headers.items():
            header_value = headers.get(header_name.lower())
            
            if config['required'] and not header_value:
                # Missing required header
                finding = Finding(
                    module='server_misconfig',
                    title=f'Missing Security Header: {header_name}',
                    severity=config['severity'],
                    description=f"{config['description']}. This header is missing from the response.",
                    evidence={'header': header_name, 'present': False},
                    poc=f"curl -I {target} | grep -i {header_name}",
                    remediation=f"Add '{header_name}' header to server configuration",
                    cvss_score=5.0 if config['severity'] == 'High' else 3.0,
                    bounty_score=300 if config['severity'] == 'High' else 100,
                    target=target
                )
                self.add_finding(finding)
                
            elif header_value and not config['check'](header_value):
                # Header present but misconfigured
                finding = Finding(
                    module='server_misconfig',
                    title=f'Misconfigured Security Header: {header_name}',
                    severity='Medium',
                    description=f"{config['description']}. Current value: {header_value}",
                    evidence={'header': header_name, 'value': header_value, 'present': True},
                    poc=f"curl -I {target}",
                    remediation=f"Correct the '{header_name}' configuration",
                    cvss_score=4.0,
                    bounty_score=150,
                    target=target
                )
                self.add_finding(finding)
                
        # Check for dangerous headers
        await self._check_dangerous_headers(target, headers)
        
        return self.findings
        
    async def _check_dangerous_headers(self, target: str, headers: Dict):
        """Check for headers that leak information"""
        dangerous_headers = {
            'server': 'Server software version',
            'x-powered-by': 'Framework/technology version',
            'x-aspnet-version': 'ASP.NET version',
            'x-generator': 'CMS/generator information',
        }
        
        for header, description in dangerous_headers.items():
            value = headers.get(header)
            if value:
                finding = Finding(
                    module='server_misconfig',
                    title=f'Information Disclosure: {header.title()} Header',
                    severity='Low',
                    description=f"{description} exposed: {value}",
                    evidence={'header': header, 'value': value},
                    poc=f"curl -I {target} | grep -i {header}",
                    remediation=f"Remove or obfuscate the '{header}' header",
                    cvss_score=2.0,
                    bounty_score=50,
                    target=target
                )
                self.add_finding(finding)

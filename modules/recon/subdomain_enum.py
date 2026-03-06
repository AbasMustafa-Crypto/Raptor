import asyncio
import subprocess
import json
import shutil
from typing import List, Set, Dict
from core.base_module import BaseModule, Finding
class SubdomainEnumerator(BaseModule):
    """Subdomain enumeration using multiple tools"""
    
    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.tools = ['amass', 'subfinder', 'assetfinder']
        self.resolved_subdomains: Set[str] = set()
        
    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run subdomain enumeration"""
        self.logger.info(f"Starting subdomain enumeration for {target}")
        
        all_subdomains: Set[str] = set()
        
        # Check which tools are available
        available_tools = self._get_available_tools()
        
        if not available_tools:
            self.logger.warning("No external subdomain tools found. Using fallback methods only.")
        
        # Run available tools in parallel
        tasks = []
        for tool in available_tools:
            if kwargs.get(f'use_{tool}', True):
                tasks.append(self._run_tool(tool, target))
                
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, set):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Tool error: {result}")
        
        # Always try CT logs as fallback
        await self._check_ct_logs(target, all_subdomains)
        
        self.logger.info(f"Found {len(all_subdomains)} unique subdomains")
        
        # Resolve and validate subdomains
        if all_subdomains:
            valid_subdomains = await self._validate_subdomains(all_subdomains)
        else:
            valid_subdomains = []
        
        # Save to database
        for subdomain in valid_subdomains:
            if self.db:
                self.db.save_asset('subdomain', subdomain, 'recon', 
                                 metadata={'resolved': True})
                                 
        # Check for interesting findings
        if valid_subdomains:
            await self._analyze_subdomains(valid_subdomains, target)
        
        return self.findings
    
    def _get_available_tools(self) -> List[str]:
        """Check which tools are available in PATH"""
        available = []
        for tool in self.tools:
            if shutil.which(tool):
                available.append(tool)
            else:
                self.logger.warning(f"{tool} not found in PATH - skipping")
        return available
        
    async def _run_tool(self, tool: str, target: str) -> Set[str]:
        """Run a specific subdomain enumeration tool"""
        subdomains = set()
        
        try:
            if tool == 'amass':
                cmd = ['amass', 'enum', '-passive', '-d', target, '-json', '-']
            elif tool == 'subfinder':
                cmd = ['subfinder', '-d', target, '-all', '-silent', '-json']
            elif tool == 'assetfinder':
                cmd = ['assetfinder', '--subs-only', target]
            else:
                return subdomains
                
            self.logger.info(f"Running {tool}...")
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), 
                    timeout=300  # 5 minute timeout
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"{tool} timed out, killing process")
                proc.kill()
                await proc.wait()
                return subdomains
            
            if tool == 'assetfinder':
                # Assetfinder outputs plain text
                for line in stdout.decode().strip().split('\n'):
                    if line and target in line:
                        subdomains.add(line.strip())
            else:
                # Parse JSON output
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            if tool == 'amass':
                                name = data.get('name', '')
                            else:  # subfinder
                                name = data.get('host', '')
                                
                            if name and target in name:
                                subdomains.add(name)
                        except json.JSONDecodeError:
                            continue
                            
        except FileNotFoundError:
            self.logger.warning(f"{tool} not found in PATH")
        except Exception as e:
            self.logger.error(f"Error running {tool}: {e}")
            
        return subdomains
        
    async def _validate_subdomains(self, subdomains: Set[str]) -> List[str]:
        """Validate subdomains via DNS resolution"""
        valid = []
        
        if not subdomains:
            return valid
        
        # Use httpx or dns resolution
        semaphore = asyncio.Semaphore(20)  # Limit concurrent DNS lookups
        
        async def check_subdomain(subdomain):
            async with semaphore:
                try:
                    # Simple HTTP check with short timeout
                    url = f"http://{subdomain}"
                    response = await self._make_request(url, allow_redirects=True)
                    if response and response.status < 500:
                        valid.append(subdomain)
                        self.resolved_subdomains.add(subdomain)
                except Exception:
                    pass
                    
        await asyncio.gather(*[check_subdomain(s) for s in subdomains], return_exceptions=True)
        return valid
        
    async def _analyze_subdomains(self, subdomains: List[str], target: str):
        """Analyze subdomains for security findings"""
        # Check for staging/dev environments
        staging_keywords = ['staging', 'dev', 'test', 'uat', 'qa', 'preprod', 'preview']
        
        for subdomain in subdomains:
            subdomain_lower = subdomain.lower()
            
            # Check for staging environments
            for keyword in staging_keywords:
                if keyword in subdomain_lower:
                    finding = Finding(
                        module='recon',
                        title=f'Staging/Development Environment Found: {subdomain}',
                        severity='Medium',
                        description=f'Discovered {keyword} environment which may have weaker security controls',
                        evidence={'subdomain': subdomain, 'type': keyword},
                        poc=f"Visit: http://{subdomain}",
                        remediation='Ensure staging environments have equivalent security controls to production',
                        cvss_score=5.3,
                        bounty_score=500,
                        target=subdomain
                    )
                    self.add_finding(finding)
                    break
        
    async def _check_ct_logs(self, target: str, existing_subdomains: Set[str]):
        """Check Certificate Transparency logs (zero-dep, uses BaseModule._make_request)"""
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            response = await self._make_request(url)

            if not response:
                self.logger.warning("CT log check: no response from crt.sh")
                return

            if response.status == 200:
                try:
                    data = await response.json()

                    ct_subdomains = set()
                    for entry in data:
                        name = entry.get('name_value', '').strip()
                        if name and '*' not in name:
                            ct_subdomains.add(name)

                    self.logger.info(f"Found {len(ct_subdomains)} subdomains in CT logs")
                    existing_subdomains.update(ct_subdomains)

                    new_subdomains = ct_subdomains - self.resolved_subdomains
                    if new_subdomains:
                        finding = Finding(
                            module='recon',
                            title=f'Hidden Subdomains in CT Logs: {len(new_subdomains)}',
                            severity='Low',
                            description=f'Found {len(new_subdomains)} subdomains only in Certificate Transparency logs',
                            evidence={'subdomains': list(new_subdomains)[:10]},
                            poc=f"Check: https://crt.sh/?q=%.{target}",
                            remediation='Review all subdomains for proper security controls',
                            cvss_score=3.7,
                            bounty_score=100,
                            target=target
                        )
                        self.add_finding(finding)
                except Exception as e:
                    self.logger.warning(f"Failed to parse CT log response: {e}")
            else:
                self.logger.warning(f"CT log check returned status {response.status}")

        except Exception as e:
            self.logger.error(f"CT log check failed: {e}")

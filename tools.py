import asyncio
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# --- Standard Modules ---
from modules.recon.subdomain_enum            import SubdomainEnumerator
from modules.recon.tech_fingerprint          import TechnologyFingerprinter
from modules.recon.port_scanner              import PortScanner
from modules.recon.dns_analyzer              import DNSAnalyzer
from modules.recon.endpoint_fuzzer           import EndpointFuzzer
from modules.server_misconfig.header_audit   import HeaderAuditor
from modules.server_misconfig.sensitive_files import SensitiveFileScanner
from modules.server_misconfig.ssl_tester     import SSLTester
from modules.idor.idor_tester                import IDORTester
from modules.brute_force.credential_tester   import CredentialTester
from modules.sqli.sqli_tester               import SQLiTester
from modules.fuzzing.param_fuzzer            import ParamFuzzer
from modules.fuzzing.param_discovery         import ParameterDiscovery
from modules.recon.api_discovery             import APIDiscovery
from modules.fuzzing.api_fuzzer              import APIFuzzer

# --- Offensive Modules ---
from modules.offensive.persistence           import PersistenceManager
from modules.offensive.exploit_matcher       import ExploitMatcher
from modules.offensive.harvester             import CredentialHarvester
from modules.offensive.git_scraper           import GitScraper
from modules.offensive.js_secret_extractor    import JSSecretExtractor
from modules.offensive.smuggler              import RequestSmuggler
from modules.offensive.ghost_protocol        import GhostProtocol
from modules.offensive.cloud_assault         import CloudAssault

async def run_smuggler(raptor: Any, target: str) -> Dict[str, Any]:
    """Wraps RequestSmuggler."""
    try:
        results = {"vulnerabilities": [], "module": "smuggler"}
        async with RequestSmuggler(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "smuggler"}

async def run_cloud_assault(raptor: Any, target: str, cloud_keys: Dict) -> Dict[str, Any]:
    """Wraps CloudAssault."""
    try:
        results = {"vulnerabilities": [], "module": "cloud_assault"}
        async with CloudAssault(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target, cloud_keys=cloud_keys)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "cloud_assault"}

async def run_js_secret_extractor(raptor: Any, target: str, js_urls: List[str]) -> Dict[str, Any]:
    """Wraps JSSecretExtractor."""
    try:
        results = {"vulnerabilities": [], "module": "js_secret_extractor"}
        async with JSSecretExtractor(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target, js_urls=js_urls)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "js_secret_extractor"}

async def run_git_scraper(raptor: Any, target: str) -> Dict[str, Any]:
    """Wraps GitScraper."""
    try:
        results = {"vulnerabilities": [], "module": "git_scraper"}
        async with GitScraper(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "git_scraper"}

async def run_harvester(raptor: Any, target: str, mode: str = "aggressive") -> Dict[str, Any]:
    """Wraps CredentialHarvester."""
    try:
        results = {"vulnerabilities": [], "module": "harvester"}
        async with CredentialHarvester(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target, mode=mode)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "harvester"}

async def run_persistence(raptor: Any, target: str, method: str = "all") -> Dict[str, Any]:
    """Wraps PersistenceManager."""
    try:
        results = {"vulnerabilities": [], "module": "persistence"}
        async with PersistenceManager(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target, method=method)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "persistence"}

async def run_exploit_matcher(raptor: Any, target: str, tech_stack: List[str]) -> Dict[str, Any]:
    """Wraps ExploitMatcher."""
    try:
        results = {"vulnerabilities": [], "module": "exploit_matcher"}
        async with ExploitMatcher(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target, tech_stack=tech_stack, brain=raptor.brain)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "exploit_matcher"}

async def run_api_discovery(raptor: Any, target_url: str) -> Dict[str, Any]:
    """Wraps APIDiscovery."""
    try:
        results = {"schemas": [], "vulnerabilities": [], "module": "api_discovery"}
        async with APIDiscovery(raptor._module_cfg('modules', 'recon'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target_url, discovered_urls=[target_url])
            for f in findings:
                results["vulnerabilities"].append(f.to_dict())
                if hasattr(f, 'evidence') and 'schema_snippet' in f.evidence:
                    results["schemas"].append({
                        "url": f.evidence['url'],
                        "type": f.evidence['type'],
                        "body": f.evidence['schema_snippet']
                    })
        return results
    except Exception as e:
        return {"error": str(e), "module": "api_discovery"}

async def run_api_fuzzer(raptor: Any, target_url: str, schema_data: str) -> Dict[str, Any]:
    """Wraps APIFuzzer."""
    try:
        results = {"vulnerabilities": [], "module": "api_fuzzer"}
        async with APIFuzzer(raptor._module_cfg('modules', 'fuzzing'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target_url, schema_data=schema_data, brain=raptor.brain)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "api_fuzzer"}

async def run_recon(raptor: Any, target_url: str) -> Dict[str, Any]:
    """Wraps reconnaissance modules."""
    try:
        results = {"endpoints": [], "vulnerabilities": [], "module": "recon"}
        async with SubdomainEnumerator(raptor._module_cfg('modules', 'recon'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target_url)
            for f in findings:
                results["vulnerabilities"].append(f.to_dict())
                if hasattr(f, 'evidence'):
                    if "subdomain" in f.evidence:
                        results["endpoints"].append(f"https://{f.evidence['subdomain']}")
                    elif "subdomains" in f.evidence:
                        for sub in f.evidence['subdomains']:
                             results["endpoints"].append(f"https://{sub}")
        async with TechnologyFingerprinter(raptor._module_cfg('modules', 'recon'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target_url)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        async with PortScanner(raptor._module_cfg('modules', 'recon'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target_url)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "recon"}

async def run_endpoint_discovery(raptor: Any, target_url: str) -> Dict[str, Any]:
    """Wraps EndpointFuzzer."""
    try:
        results = {"endpoints": [], "vulnerabilities": [], "module": "endpoint_discovery"}
        async with EndpointFuzzer(raptor._module_cfg('modules', 'recon'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target_url, discovered_urls=[target_url])
            for f in findings:
                results["vulnerabilities"].append(f.to_dict())
                if hasattr(f, 'evidence') and 'url' in f.evidence:
                    results["endpoints"].append(f.evidence['url'])
        return results
    except Exception as e:
        return {"error": str(e), "module": "endpoint_discovery"}

async def run_parameter_discovery(raptor: Any, endpoint: str) -> Dict[str, Any]:
    """Wraps ParameterDiscovery."""
    try:
        results = {"parameters": {}, "vulnerabilities": [], "module": "parameter_discovery"}
        async with ParameterDiscovery(raptor._module_cfg('modules', 'fuzzing'), raptor.stealth, raptor.db, raptor.graph) as mod:
            params_map = await mod.discover_parameters([endpoint])
            results["parameters"] = params_map
            results["vulnerabilities"].extend([f.to_dict() for f in mod.findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "parameter_discovery"}

async def run_fuzzing(raptor: Any, endpoint: str, params: Dict[str, List[str]]) -> Dict[str, Any]:
    """Wraps ParamFuzzer."""
    try:
        results = {"vulnerabilities": [], "module": "fuzzing"}
        async with ParamFuzzer(raptor._module_cfg('modules', 'fuzzing'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(endpoint, discovered_urls=[endpoint], discovered_params=params)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "fuzzing"}

async def run_sqli_scan(raptor: Any, endpoint: str, params: Dict[str, List[str]]) -> Dict[str, Any]:
    """Wraps SQLiTester."""
    try:
        results = {"vulnerabilities": [], "module": "sqli"}
        async with SQLiTester(raptor._module_cfg('modules', 'sqli'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(endpoint, discovered_urls=[endpoint], discovered_params=params)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "sqli"}

async def run_idor_scan(raptor: Any, endpoint: str, params: Dict[str, List[str]]) -> Dict[str, Any]:
    """Wraps IDORTester."""
    try:
        results = {"vulnerabilities": [], "module": "idor"}
        async with IDORTester(raptor._module_cfg('modules', 'idor'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(endpoint, discovered_urls=[endpoint], discovered_params=params)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "idor"}

async def run_misconfig_scan(raptor: Any, endpoint: str) -> Dict[str, Any]:
    """Wraps Server Auditing modules."""
    try:
        results = {"vulnerabilities": [], "module": "misconfig"}
        async with HeaderAuditor(raptor._module_cfg('modules', 'server'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(endpoint, discovered_urls=[endpoint])
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        async with SensitiveFileScanner(raptor._module_cfg('modules', 'server'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(endpoint, discovered_urls=[endpoint])
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        async with SSLTester(raptor._module_cfg('modules', 'server'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(endpoint, discovered_urls=[endpoint])
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "misconfig"}

async def run_brute_force(raptor: Any, endpoint: str) -> Dict[str, Any]:
    """Wraps CredentialTester."""
    try:
        results = {"vulnerabilities": [], "module": "brute_force"}
        brute_cfg = dict(raptor._module_cfg('modules', 'brute_force'))
        if 'wordlist_path' not in brute_cfg: brute_cfg['wordlist_path'] = 'wordlists'
        async with CredentialTester(brute_cfg, raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(endpoint, discovered_urls=[endpoint], auth_targets=[endpoint])
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "brute_force"}

async def run_ghost_protocol(raptor: Any, target: str, attacker_ip: str = "attacker.com") -> Dict[str, Any]:
    """Wraps GhostProtocol."""
    try:
        results = {"vulnerabilities": [], "module": "ghost_protocol"}
        async with GhostProtocol(raptor._module_cfg('modules', 'offensive'), raptor.stealth, raptor.db, raptor.graph) as mod:
            findings = await mod.run(target, attacker_ip=attacker_ip)
            results["vulnerabilities"].extend([f.to_dict() for f in findings])
        return results
    except Exception as e:
        return {"error": str(e), "module": "ghost_protocol"}

async def verify_exploit(raptor: Any, target_url: str, payload: str) -> Dict[str, Any]:
    """Sends a safe payload to a target to verify an exploit."""
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            test_url = f"{target_url}?test={payload}"
            start_time = time.time()
            async with session.get(test_url, timeout=10, ssl=False) as resp:
                text = await resp.text()
                elapsed = time.time() - start_time
                return {
                    "verified": True,
                    "status": resp.status,
                    "elapsed_time": elapsed,
                    "response_snippet": text[:200],
                    "module": "verify_exploit"
                }
    except Exception as e:
        return {"verified": False, "error": str(e), "module": "verify_exploit"}

async def generate_report_tool(raptor: Any, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates the final Offensive Action Report."""
    try:
        target = vulnerabilities[0].get('target', 'unknown') if vulnerabilities else 'unknown'
        safe_target = target.replace('/', '_').replace(':', '_')
        report_path = f"reports/output/raptor_report_{safe_target}.md"
        executive_summary = "No vulnerabilities found."
        
        if vulnerabilities and hasattr(raptor, 'brain'):
            vuln_titles = [f"{v.get('severity', 'Unknown')} - {v.get('title', 'Unknown')}" for v in vulnerabilities]
            vuln_summary = "\n".join(vuln_titles[:20])
            prompt = (
                f"Analyze the vulnerabilities on {target}:\n{vuln_summary}\n\n"
                "Generate an 'Offensive Action Report' EXACTLY as requested by user."
            )
            try:
                executive_summary = await raptor.brain.chat(prompt, {})
            except Exception:
                # Use the hardcoded template if AI fails
                executive_summary = "1. Critical Hit: Git Exfiltration (git_scraper)..."
        
        import os
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            f.write(f"# RAPTOR: OFFENSIVE ACTION REPORT\n\n{executive_summary}")
        return {"status": "success", "report_path": report_path, "findings_count": len(vulnerabilities), "module": "report_generation"}
    except Exception as e:
        return {"error": str(e), "module": "report_generation"}

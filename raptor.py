#!/usr/bin/env python3
"""
RAPTOR - Advanced Automated Web Application Security Testing Framework
Optimised for Bug Bounty Hunting & Penetration Testing
"""

import asyncio
import argparse
import sys
import os

# ── Zero-dependency bundled libraries ──────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_CORE = os.path.join(_HERE, 'core')
for _p in [_HERE, _CORE]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _yaml_lite import safe_load as _yaml_safe_load
from _console   import Console, Table, Panel, Progress, SpinnerColumn, TextColumn, box

from pathlib import Path
from typing  import List, Dict, Optional

# ── Core components ─────────────────────────────────────────────────────────
from core.config_manager   import ConfigManager
from core.stealth_manager  import StealthManager
from core.database_manager import DatabaseManager
from core.report_manager   import ReportManager
from core.correlator       import AttackPathCorrelator

try:
    from core.graph_manager import GraphManager
except ImportError:
    class GraphManager:
        enabled = False
        def __init__(self, *a, **kw): pass
        def add_target(self, *a, **kw): return None
        def get_high_value_targets(self, **kw): return []
        def close(self): pass

# ── Modules ─────────────────────────────────────────────────────────────────
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

console = Console()


# ── Welcome / help text ─────────────────────────────────────────────────────

def show_welcome():
    console.print("""
[bold cyan]██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔══██╗   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝[/bold cyan]

[bold yellow]RAPTOR Security Framework v2.0[/bold yellow]
[dim]Full power. No options required.[/dim]

[bold green]Quick Start:[/bold green]
  python3 raptor.py -t [cyan]target.com[/cyan]
  python3 raptor.py -t [cyan]target.com[/cyan] --modules [green]sqli,idor[/green]
  
[bold green]New Features:[/bold green]
  [yellow]Interactive Neo4j Sync[/yellow] — Visualize attack paths at the end of any scan!

[bold green]Modules:[/bold green]
  [cyan]recon[/cyan]   Reconnaissance & Discovery
  [cyan]server[/cyan]  Server Misconfiguration
  [cyan]sqli[/cyan]    SQL Injection
  [cyan]idor[/cyan]    Insecure Direct Object Reference
  [cyan]fuzz[/cyan]    Parameter Fuzzing & Hidden Endpoint Discovery
  [cyan]brute[/cyan]   Brute Force (--enable-brute-force required)

[bold green]Brute Force Wordlists:[/bold green]
  Default path  : [cyan]wordlists/usernames.txt[/cyan]  +  [cyan]wordlists/passwords.txt[/cyan]
  Custom files  : [yellow]--userlist /path/to/users.txt[/yellow]
                  [yellow]--passlist /path/to/passwords.txt[/yellow]

  python3 raptor.py [bold]--help[/bold] for full documentation
""")


def create_help_text():
    return """
[bold cyan]██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔══██╗   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝[/bold cyan]
[bold yellow]RAPTOR Security Framework v2.0 — Full Power by Default[/bold yellow]

[bold cyan]MODULES[/bold cyan]
  [cyan]recon[/cyan]   Subdomain enumeration, tech fingerprinting, endpoint discovery
  [cyan]server[/cyan]  Security headers, sensitive file exposure, info disclosure
  [cyan]sqli[/cyan]    Error, Boolean, Time-based, UNION — all DB types
  [cyan]idor[/cyan]    Sequential IDs, REST manipulation, mass assignment
  [cyan]fuzz[/cyan]    Parameter Fuzzing & Hidden Endpoint Discovery
  [cyan]brute[/cyan]   Credential brute force (requires --enable-brute-force)
  [cyan]all[/cyan]     Run everything except brute

[bold cyan]NEO4J VISUALIZATION[/bold cyan]
  RAPTOR now supports interactive Neo4j synchronization. At the end of a scan, 
  you will be prompted to sync findings to your graph database for visual 
  attack path analysis.

[bold cyan]USAGE[/bold cyan]
  [green]python3 raptor.py -t target.com[/green]
  [green]python3 raptor.py -t target.com --modules sqli,idor,fuzz[/green]
  [green]python3 raptor.py -t target.com --full-scan[/green]
  [green]python3 raptor.py -t target.com --modules brute --enable-brute-force[/green]
  [green]python3 raptor.py -t target.com --modules brute --enable-brute-force --userlist users.txt --passlist passwords.txt[/green]

[bold cyan]OPTIONS[/bold cyan]
  [yellow]-t, --target[/yellow]            Target URL or domain (required)
  [yellow]--modules[/yellow]               Comma-separated modules (default: all)
  [yellow]--full-scan[/yellow]             Run all modules
  [yellow]--enable-brute-force[/yellow]    Enable brute force module
  [yellow]--userlist[/yellow]              Path to custom usernames file
                          (default: wordlists/usernames.txt)
  [yellow]--passlist[/yellow]              Path to custom passwords file
                          (default: wordlists/passwords.txt)
  [yellow]--stealth[/yellow]               Add delays between requests
  [yellow]--cookie[/yellow]                Auth cookie string
  [yellow]--auth-header[/yellow]           Authorization header value
  [yellow]--proxy[/yellow]                 Proxy URL (e.g. http://127.0.0.1:8080)
  [yellow]-o, --output[/yellow]            Custom report output path
  [yellow]--config[/yellow]                Config file path (default: config/config.yaml)
  [yellow]-v, --verbose[/yellow]           Verbose output

[bold cyan]WORDLIST EXAMPLES[/bold cyan]
  Use default wordlists (auto-detected from wordlists/ folder):
    [green]python3 raptor.py -t target.com --modules brute --enable-brute-force[/green]

  Use your own files:
    [green]python3 raptor.py -t target.com --modules brute --enable-brute-force \\[/green]
    [green]  --userlist /home/user/users.txt --passlist /home/user/rockyou.txt[/green]

  Use files inside the project:
    [green]python3 raptor.py -t target.com --modules brute --enable-brute-force \\[/green]
    [green]  --userlist wordlists/usernames.txt --passlist wordlists/passwords.txt[/green]

[bold red]Only test systems you own or have explicit permission to test.[/bold red]
"""


# ── Raptor controller ───────────────────────────────────────────────────────

class Raptor:
    """Main RAPTOR Framework Controller"""

    def __init__(self, config_path: str = "config/config.yaml", config_overrides: Dict = None):
        self.config     = self._load_config(config_path)
        if config_overrides:
            self._apply_overrides(self.config, config_overrides)
            
        self.stealth    = StealthManager(self.config.get('stealth', {}))
        db_path         = (
            self.config.get('database', {}).get('path') or
            'data/raptor.db'
        )
        self.db         = DatabaseManager(db_path)
        self.graph      = GraphManager(self.config.get('graph', {}))
        self.correlator = AttackPathCorrelator(self.db, self.graph)
        self.findings:  List[Dict] = []

    def _apply_overrides(self, config: Dict, overrides: Dict):
        """Deep merge overrides into config"""
        for k, v in overrides.items():
            if isinstance(v, dict) and k in config:
                self._apply_overrides(config[k], v)
            else:
                config[k] = v

    def _load_config(self, path: str) -> Dict:
        if not os.path.isabs(path) and not os.path.exists(path):
            candidate = os.path.join(_HERE, path)
            if os.path.exists(candidate):
                path = candidate
        try:
            with open(path, 'r') as f:
                return _yaml_safe_load(f.read()) or {}
        except FileNotFoundError:
            console.print(f"[yellow]Config file not found: {path} — using defaults[/yellow]")
            return {}

    def _module_cfg(self, *keys) -> Dict:
        node = self.config
        for k in keys:
            if not isinstance(node, dict):
                return {}
            node = node.get(k, {})
        return node if isinstance(node, dict) else {}

    async def run_scan(self, target: str, modules: List[str],
                       stealth_mode: bool = False, **kwargs) -> List[Dict]:
        """Execute security scan via Full Scan Workflow Engine"""

        target_id = self.graph.add_target(target, metadata={'modules': modules}) \
                    if self.graph.enabled else None

        console.print(Panel.fit(
            f"[bold cyan]RAPTOR Security Framework v4.0[/bold cyan]\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Modules: [green]{', '.join(modules)}[/green]\n"
            f"Mode: [red]{'Stealth' if stealth_mode else 'Aggressive'}[/red]\n"
            f"Graph DB: [blue]{'Connected' if self.graph.enabled else 'Disabled'}[/blue]",
            box=box.DOUBLE_EDGE
        ))

        # ── Centralized Workflow Data Structure ────────────────────────────────
        scan_results = {
            "domains": [target],
            "endpoints": [target],
            "parameters": {},
            "vulnerabilities": [],
            "auth_targets": []
        }

        stealth = self.stealth if stealth_mode else None

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:

            # 1. Recon ──────────────────────────────────────────────────────────
            if 'recon' in modules:
                task = progress.add_task("[cyan]1. Reconnaissance...", total=None)

                async with SubdomainEnumerator(self._module_cfg('modules', 'recon'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, **kwargs)
                    scan_results["vulnerabilities"].extend(findings)
                    for f in findings:
                        if hasattr(f, 'evidence') and "subdomain" in f.evidence:
                            sub = f.evidence['subdomain']
                            if sub not in scan_results["domains"]:
                                scan_results["domains"].append(sub)
                            sub_url = f"https://{sub}"
                            if sub_url not in scan_results["endpoints"]:
                                scan_results["endpoints"].append(sub_url)
                        elif hasattr(f, 'evidence') and "subdomains" in f.evidence:
                            for sub in f.evidence['subdomains']:
                                if sub not in scan_results["domains"]:
                                    scan_results["domains"].append(sub)
                                sub_url = f"https://{sub}"
                                if sub_url not in scan_results["endpoints"]:
                                    scan_results["endpoints"].append(sub_url)

                async with DNSAnalyzer(self._module_cfg('modules', 'recon'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)

                async with PortScanner(self._module_cfg('modules', 'recon'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, **kwargs)
                    scan_results["vulnerabilities"].extend(findings)

                async with TechnologyFingerprinter(self._module_cfg('modules', 'recon'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, **kwargs)
                    scan_results["vulnerabilities"].extend(findings)

                progress.update(task, completed=True)

            # 2. Endpoint Discovery (Fuzzing) ───────────────────────────────────
            if 'recon' in modules or 'fuzz' in modules:
                task = progress.add_task("[cyan]2. Endpoint Discovery...", total=None)
                async with EndpointFuzzer(self._module_cfg('modules', 'recon'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)
                    for f in findings:
                        if hasattr(f, 'evidence') and 'url' in f.evidence:
                            url = f.evidence['url']
                            if url not in scan_results["endpoints"]:
                                scan_results["endpoints"].append(url)
                progress.update(task, completed=True)

            # 3. Parameter Discovery ────────────────────────────────────────────
            if 'fuzz' in modules:
                task = progress.add_task("[cyan]3. Parameter Discovery...", total=None)
                async with ParameterDiscovery(self._module_cfg('modules', 'fuzzing'), stealth, self.db, self.graph) as mod:
                    params_map = await mod.discover_parameters(scan_results["endpoints"])
                    scan_results["parameters"].update(params_map)
                    scan_results["vulnerabilities"].extend(mod.findings)
                progress.update(task, completed=True)

            # 4. Fuzzing (ParamFuzzer) ──────────────────────────────────────────
            if 'fuzz' in modules:
                task = progress.add_task("[cyan]4. Parameter Fuzzing...", total=None)
                async with ParamFuzzer(self._module_cfg('modules', 'fuzzing'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, target_id=target_id, discovered_urls=scan_results["endpoints"], discovered_params=scan_results["parameters"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)
                progress.update(task, completed=True)

            # 5. SQL Injection ──────────────────────────────────────────────────
            if 'sqli' in modules:
                task = progress.add_task("[cyan]5. SQL Injection Testing...", total=None)
                async with SQLiTester(self._module_cfg('modules', 'sqli'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], discovered_params=scan_results["parameters"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)
                progress.update(task, completed=True)

            # 6. IDOR ───────────────────────────────────────────────────────────
            if 'idor' in modules:
                task = progress.add_task("[cyan]6. IDOR Testing...", total=None)
                async with IDORTester(self._module_cfg('modules', 'idor'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], discovered_params=scan_results["parameters"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)
                progress.update(task, completed=True)

            # 7. Server Misconfiguration ────────────────────────────────────────
            if 'server' in modules:
                task = progress.add_task("[cyan]7. Auditing Server Config...", total=None)
                async with HeaderAuditor(self._module_cfg('modules', 'server'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)

                async with SensitiveFileScanner(self._module_cfg('modules', 'server'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)

                async with SSLTester(self._module_cfg('modules', 'server'), stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)
                progress.update(task, completed=True)

            # 8. Brute Force ────────────────────────────────────────────────────
            if 'brute' in modules and kwargs.get('enable_brute_force'):
                task = progress.add_task("[cyan]8. Brute Forcing...", total=None)

                brute_cfg = dict(self._module_cfg('modules', 'brute_force'))
                if 'wordlist_path' not in brute_cfg:
                    brute_cfg['wordlist_path'] = 'wordlists'

                if kwargs.get('userlist'):
                    brute_cfg['userlist'] = kwargs['userlist']
                if kwargs.get('passlist'):
                    brute_cfg['passlist'] = kwargs['passlist']

                # Compile potential auth targets from endpoints
                scan_results["auth_targets"] = [
                    u for u in scan_results["endpoints"] 
                    if any(x in u.lower() for x in ['login', 'admin', 'auth', 'signin', 'wp-admin', 'api/user'])
                ]

                async with CredentialTester(brute_cfg, stealth, self.db, self.graph) as mod:
                    findings = await mod.run(target, discovered_urls=scan_results["endpoints"], auth_targets=scan_results["auth_targets"], **kwargs)
                    scan_results["vulnerabilities"].extend(findings)

                progress.update(task, completed=True)

        all_findings = [f.to_dict() for f in scan_results["vulnerabilities"]]

        # ── Correlate ──────────────────────────────────────────────────────
        console.print("\n[bold]Correlating attack paths...[/bold]")
        attack_paths = self.correlator.analyze(all_findings)

        if self.graph.enabled:
            high_value = self.graph.get_high_value_targets(min_cvss=7.0)
            if high_value:
                console.print(f"[yellow]High-value targets found: {len(high_value)}[/yellow]")

        self._display_results(all_findings, attack_paths)
        self.graph.close()

        return all_findings

    # ── Display ─────────────────────────────────────────────────────────────

    def _display_results(self, findings: List[Dict], attack_paths: List[Dict]):
        if not findings:
            console.print("[yellow]No findings discovered.[/yellow]")
            return

        table = Table(title="Security Findings Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in findings:
            sev = f.get('severity', 'Info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        colour_map = {
            'Critical': 'red', 'High': 'bright_red',
            'Medium':   'yellow', 'Low': 'green', 'Info': 'blue'
        }
        for sev, count in severity_counts.items():
            colour = colour_map.get(sev, 'white')
            table.add_row(f"[{colour}]{sev}[/{colour}]", str(count))

        console.print(table)

        brute_findings = [f for f in findings if f.get('module') == 'brute_force'
                          and 'CREDENTIALS FOUND' in f.get('title', '')]
        if brute_findings:
            console.print("\n[bold red]╔══ CREDENTIALS FOUND ══╗[/bold red]")
            for bf in brute_findings:
                ev = bf.get('evidence', {})
                console.print(
                    f"[bold green]  ✓ Username : {ev.get('username')}[/bold green]\n"
                    f"[bold green]    Password : {ev.get('password')}[/bold green]\n"
                    f"[bold green]    URL      : {ev.get('url')}[/bold green]\n"
                    f"[bold green]    Attempts : {ev.get('attempts')}[/bold green]"
                )
            console.print("[bold red]╚════════════════════════╝[/bold red]\n")

        console.print("\n[bold]Detailed Findings:[/bold]")
        sorted_findings = sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True)

        for finding in sorted_findings:
            colour = colour_map.get(finding.get('severity'), 'white')
            title  = finding.get('title', 'Unknown')
            desc   = finding.get('description', '')[:100]
            poc    = finding.get('poc', 'N/A')[:80]
            console.print(f"\n[{colour}]▶ {title} ({finding.get('severity')})[/{colour}]")
            if desc:
                console.print(f"  [dim]{desc}...[/dim]")
            if poc and poc != 'N/A':
                console.print(f"  [cyan]PoC:[/cyan] {poc}...")

        if attack_paths:
            console.print("\n[bold red]Discovered Attack Paths:[/bold red]")
            for path in attack_paths:
                console.print(f"\n[red]Chain: {path.get('name')}[/red]")
                console.print(
                    f"  Estimated Bounty: "
                    f"[green]${path.get('total_bounty', path.get('estimated_bounty', 0))}[/green]"
                )
                console.print(f"  Complexity: {path.get('complexity')}")
                if 'node_types' in path:
                    console.print(f"  Path: {' -> '.join(path['node_types'])}")

        if sorted_findings:
            report_target = sorted_findings[0].get('target', 'unknown')
        else:
            report_target = 'unknown'

        safe_target = report_target.replace('/', '_').replace(':', '_')
        report_path = f"reports/output/raptor_report_{safe_target}.md"
        self._generate_report(findings, attack_paths, report_path)
        console.print(f"\n[green]Report saved to: {report_path}[/green]")

    def _generate_report(self, findings: List[Dict], attack_paths: List[Dict], path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            f.write("# RAPTOR Security Assessment Report\n\n")
            f.write(f"**Target:** {findings[0].get('target', 'Unknown') if findings else 'N/A'}\n\n")
            f.write(f"**Total Findings:** {len(findings)}\n\n")
            f.write("## Executive Summary\n\n")

            critical_high = [x for x in findings if x.get('severity') in ['Critical', 'High']]
            if critical_high:
                f.write(f"⚠️ **{len(critical_high)} Critical/High severity issues found**\n\n")

            bf_success = [x for x in findings
                          if x.get('module') == 'brute_force'
                          and 'CREDENTIALS FOUND' in x.get('title', '')]
            if bf_success:
                f.write("### 🔑 Valid Credentials Found\n\n")
                for bf in bf_success:
                    ev = bf.get('evidence', {})
                    f.write(
                        f"| Field    | Value |\n"
                        f"|----------|-------|\n"
                        f"| Username | `{ev.get('username')}` |\n"
                        f"| Password | `{ev.get('password')}` |\n"
                        f"| URL      | {ev.get('url')} |\n"
                        f"| Attempts | {ev.get('attempts')} |\n\n"
                    )

            f.write("## Findings\n\n")
            for finding in sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True):
                f.write(f"### {finding.get('title')}\n\n")
                f.write(f"- **Severity:** {finding.get('severity')}\n")
                f.write(f"- **CVSS Score:** {finding.get('cvss_score')}\n")
                f.write(f"- **Bounty Score:** {finding.get('bounty_score')}\n")
                f.write(f"- **Description:** {finding.get('description')}\n")
                f.write(f"- **Proof of Concept:**\n```\n{finding.get('poc', 'N/A')}\n```\n")
                f.write(f"- **Remediation:** {finding.get('remediation')}\n\n")

            if attack_paths:
                f.write("## Attack Paths\n\n")
                for ap in attack_paths:
                    f.write(f"### {ap.get('name', 'Attack Chain')}\n")
                    f.write(f"- **Complexity:** {ap.get('complexity')}\n")
                    f.write(
                        f"- **Estimated Bounty:** "
                        f"${ap.get('total_bounty', ap.get('estimated_bounty', 0))}\n"
                    )
                    if 'node_types' in ap:
                        f.write(f"- **Chain:** {' -> '.join(ap['node_types'])}\n")
                    f.write(
                        f"- **Description:** "
                        f"{ap.get('description', 'Vulnerability chain discovered')}\n\n"
                    )


# ── Entry point ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) == 1:
        show_welcome()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="RAPTOR - Advanced Web Application Security Testing",
        add_help=False
    )
    parser.add_argument('-h', '--help',              action='store_true')
    parser.add_argument('-t', '--target')
    parser.add_argument('--modules',                 default='recon,server,sqli,idor,fuzz')
    parser.add_argument('--full-scan',               action='store_true')
    parser.add_argument('--enable-brute-force',      action='store_true')
    # ── Wordlist flags ────────────────────────────────────────────────────
    parser.add_argument('--userlist',                default=None,
                        help='Path to custom usernames file (default: wordlists/usernames.txt)')
    parser.add_argument('--passlist',                default=None,
                        help='Path to custom passwords file (default: wordlists/passwords.txt)')
    # ─────────────────────────────────────────────────────────────────────
    parser.add_argument('--stealth',                 action='store_true')
    # ── Neo4j flags ───────────────────────────────────────────────────────
    parser.add_argument('--neo4j-uri',               help='Neo4j URI (bolt://, bolt+s://, neo4j://)')
    parser.add_argument('--neo4j-user',              help='Neo4j Username')
    parser.add_argument('--neo4j-pass',              help='Neo4j Password')
    # ─────────────────────────────────────────────────────────────────────
    parser.add_argument('--cookie',                  default=None)
    parser.add_argument('--auth-header',             default=None)
    parser.add_argument('--proxy',                   default=None)
    parser.add_argument('--config',                  default='config/config.yaml')
    parser.add_argument('-o', '--output',            default=None)
    parser.add_argument('-v', '--verbose',           action='store_true')
    parser.add_argument('--version',                 action='version', version='RAPTOR 2.0')

    args = parser.parse_args()

    if args.help:
        console.print(create_help_text())
        sys.exit(0)

    if not args.target:
        console.print("[red]Error: Target is required. Use -t target.com[/red]")
        sys.exit(1)

    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"

    if args.full_scan or 'all' in args.modules:
        modules = ['recon', 'server', 'sqli', 'idor', 'fuzz']
    else:
        modules = [m.strip() for m in args.modules.split(',')]
        valid   = {'recon', 'server', 'sqli', 'idor', 'brute', 'fuzz', 'all'}
        invalid = set(modules) - valid
        if invalid:
            console.print(f"[red]Error: Invalid modules: {', '.join(invalid)}[/red]")
            console.print(f"[yellow]Valid: {', '.join(sorted(valid))}[/yellow]")
            sys.exit(1)

    if 'brute' in modules and not args.enable_brute_force:
        console.print("[red]Brute force requires --enable-brute-force flag[/red]")
        sys.exit(1)

    # ── Handle Neo4j Overrides ───────────────────────────────────────────
    overrides = {'graph': {}}
    if args.neo4j_uri:  overrides['graph']['neo4j_uri'] = args.neo4j_uri
    if args.neo4j_user: overrides['graph']['neo4j_user'] = args.neo4j_user
    if args.neo4j_pass: overrides['graph']['neo4j_password'] = args.neo4j_pass
    # ─────────────────────────────────────────────────────────────────────

    raptor = Raptor(args.config, config_overrides=overrides)

    try:
        findings = asyncio.run(raptor.run_scan(
            args.target,
            modules,
            stealth_mode        = args.stealth,
            scope               = 'aggressive',
            enable_brute_force  = args.enable_brute_force,
            # ── Pass wordlist paths all the way through to the module ──
            userlist            = args.userlist,
            passlist            = args.passlist,
            # ──────────────────────────────────────────────────────────
            evasion_level       = 5,
            rate_limit          = 50,
            timeout             = 30,
            max_depth           = 5,
            cookie              = args.cookie,
            auth_header         = args.auth_header,
            proxy               = args.proxy,
            output_format       = 'markdown',
            output_path         = args.output
        ))

        critical_high = [f for f in findings if f.get('severity') in ['Critical', 'High']]

        # ── Interactive Neo4j Prompt (at the end) ───────────────────────────
        from core.graph_manager import NEO4J_AVAILABLE
        if NEO4J_AVAILABLE and not raptor.graph.enabled:
            console.print("\n[bold cyan]Would you like to sync results to Neo4j for visual representation? (y/n)[/bold cyan]")
            choice = input(" > ").lower()
            if choice in ['y', 'yes']:
                import getpass
                uri = input(" Neo4j URI [bolt://localhost:7687]: ") or "bolt://localhost:7687"
                user = input(" Neo4j User [neo4j]: ") or "neo4j"
                pwd = getpass.getpass(" Neo4j Password: ")
                
                # Re-init GraphManager interactively
                raptor.graph.config = {
                    'neo4j_uri': uri,
                    'neo4j_user': user,
                    'neo4j_password': pwd,
                    'enabled': True
                }
                raptor.graph.enabled = True
                raptor.graph._connect()
                
                if raptor.graph.enabled:
                    raptor.graph.sync_findings(args.target, findings)
                    
                    # ── Dynamic Browser Link Calculation ──────────────────
                    import urllib.parse
                    try:
                        parsed = urllib.parse.urlparse(uri if "://" in uri else f"bolt://{uri}")
                        host = parsed.hostname or "localhost"
                        # Browser is usually on 7474, Bolt on 7687
                        browser_url = f"http://{host}:7474"
                        console.print(f"\n[bold green]📊 Graph Synced![/bold green] Open your browser to view the visualization:")
                        console.print(f"   👉 [bold cyan underline]{browser_url}[/bold cyan underline]")
                    except Exception:
                        console.print(f"\n[bold green]📊 Graph Synced![/bold green] View at: [bold cyan]http://localhost:7474[/bold cyan]")
                    
                    # ── Neo4j Tutorial ──────────────────────────────────
                    console.print(Panel(
                        "[bold yellow]Neo4j uses Cypher.[/bold yellow]\n\n"
                        "[bold cyan]Show all nodes:[/bold cyan]\n"
                        "[white]MATCH (n) RETURN n LIMIT 100[/white]\n\n"
                        "[bold cyan]Show all relationships:[/bold cyan]\n"
                        "[white]MATCH (n)-[r]->(m) RETURN n,r,m LIMIT 100[/white]",
                        title="[bold green]Neo4j Quick Start[/bold green]",
                        border_style="green"
                    ))
                    # ─────────────────────────────────────────────────────
                else:
                    console.print("[red]Failed to connect to Neo4j. Check credentials.[/red]")
        # ─────────────────────────────────────────────────────────────────────

        sys.exit(len(critical_high))

    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Fatal Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

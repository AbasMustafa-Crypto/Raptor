#!/usr/bin/env python3
"""
RAPTOR - Advanced Automated Web Application Security Testing Framework
Optimized for Bug Bounty Hunting & Penetration Testing
"""

import asyncio
import argparse
import sys
import os

# ── Zero-dependency bundled libraries (no pip needed) ──────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, 'core'))

from _yaml_lite import safe_load as _yaml_safe_load
from _console  import Console, Table, Panel, Progress, SpinnerColumn, TextColumn, box

from pathlib import Path
from typing import List, Dict

# Import core components
from core.config_manager import ConfigManager
from core.stealth_manager import StealthManager
from core.database_manager import DatabaseManager
from core.report_manager import ReportManager
from core.graph_manager import GraphManager
from core.correlator import AttackPathCorrelator

# Import modules
from modules.recon.subdomain_enum import SubdomainEnumerator
from modules.recon.tech_fingerprint import TechnologyFingerprinter
from modules.server_misconfig.header_audit import HeaderAuditor
from modules.server_misconfig.sensitive_files import SensitiveFileScanner
from modules.idor.idor_tester import IDORTester
from modules.brute_force.credential_tester import CredentialTester
from modules.xss.xss_tester import XSSTester
from modules.sqli.sqli_tester import SQLiTester

console = Console()


def show_welcome():
    """Show welcome screen when no arguments provided"""
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
  python3 raptor.py -t [cyan]target.com[/cyan] --modules [green]xss,sqli,idor[/green]
  python3 raptor.py -t [cyan]target.com[/cyan] --modules [green]brute[/green] --enable-brute-force

[bold green]Modules:[/bold green]
  [cyan]recon[/cyan]   Reconnaissance & Discovery
  [cyan]server[/cyan]  Server Misconfiguration
  [cyan]xss[/cyan]     Cross-Site Scripting
  [cyan]sqli[/cyan]    SQL Injection
  [cyan]idor[/cyan]    Insecure Direct Object Reference
  [cyan]brute[/cyan]   Brute Force (--enable-brute-force)

  python3 raptor.py [bold]--help[/bold] for full documentation
""")


def create_help_text():
    """Return help text — rendered via console.print so markup works"""
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
  [cyan]xss[/cyan]     Reflected, DOM, Blind XSS — all contexts, WAF bypass
  [cyan]sqli[/cyan]    Error, Boolean, Time-based, UNION — all DB types
  [cyan]idor[/cyan]    Sequential IDs, REST manipulation, mass assignment
  [cyan]brute[/cyan]   Credential brute force (requires --enable-brute-force)
  [cyan]all[/cyan]     Run everything except brute

[bold cyan]USAGE[/bold cyan]
  [green]python3 raptor.py -t target.com[/green]
  [green]python3 raptor.py -t target.com --modules xss,sqli,idor[/green]
  [green]python3 raptor.py -t target.com --full-scan[/green]
  [green]python3 raptor.py -t target.com --modules brute --enable-brute-force[/green]

[bold cyan]OPTIONS[/bold cyan]
  [yellow]-t, --target[/yellow]            Target URL or domain (required)
  [yellow]--modules[/yellow]               Comma-separated modules (default: all)
  [yellow]--full-scan[/yellow]             Run all modules
  [yellow]--enable-brute-force[/yellow]    Enable brute force module
  [yellow]--stealth[/yellow]               Add delays between requests
  [yellow]--cookie[/yellow]                Auth cookie string
  [yellow]--auth-header[/yellow]           Authorization header value
  [yellow]--proxy[/yellow]                 Proxy URL (e.g. http://127.0.0.1:8080)
  [yellow]-o, --output[/yellow]            Custom report output path
  [yellow]--config[/yellow]                Config file path (default: config/config.yaml)
  [yellow]-v, --verbose[/yellow]           Verbose output

[bold red]Only test systems you own or have explicit permission to test.[/bold red]
"""



class Raptor:
    """Main RAPTOR Framework Controller"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self._load_config(config_path)
        self.stealth = StealthManager(self.config.get('stealth', {}))
        self.db = DatabaseManager(self.config.get('database', {}).get('sqlite_path', 'data/raptor.db'))
        self.graph = GraphManager(self.config.get('graph', {}))  # Initialize GraphManager
        self.correlator = AttackPathCorrelator(self.db, self.graph)  # Pass graph to correlator
        self.findings: List[Dict] = []
        
    def _load_config(self, path: str) -> Dict:
        """Load configuration from YAML (bundled zero-dep parser)"""
        try:
            with open(path, 'r') as f:
                return _yaml_safe_load(f.read()) or {}
        except FileNotFoundError:
            console.print(f"[red]Config file not found: {path}[/red]")
            return {}
            
    async def run_scan(self, target: str, modules: List[str], 
                       stealth_mode: bool = False, **kwargs) -> List[Dict]:
        """Execute security scan"""
        
        # Add target to graph database
        target_id = self.graph.add_target(target, metadata={'modules': modules})
        
        console.print(Panel.fit(
            f"[bold cyan]RAPTOR Security Framework v2.0[/bold cyan]\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Modules: [green]{', '.join(modules)}[/green]\n"
            f"Mode: [red]{'Stealth' if stealth_mode else 'Aggressive'}[/red]\n"
            f"Graph DB: [blue]{'Connected' if self.graph.enabled else 'Disabled'}[/blue]",
            box=box.DOUBLE_EDGE
        ))
        
        all_findings = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Reconnaissance Module
            if 'recon' in modules:
                task = progress.add_task("[cyan]Running Reconnaissance...", total=None)
                
                async with SubdomainEnumerator(
                    self.config.get('modules', {}).get('recon', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph  # Pass graph manager
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                async with TechnologyFingerprinter(
                    self.config.get('modules', {}).get('recon', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # Server Misconfiguration Module
            if 'server' in modules:
                task = progress.add_task("[cyan]Auditing Server Configuration...", total=None)
                
                async with HeaderAuditor(
                    self.config.get('modules', {}).get('server_misconfig', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                async with SensitiveFileScanner(
                    self.config.get('modules', {}).get('server_misconfig', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # XSS Module
            if 'xss' in modules:
                task = progress.add_task("[cyan]Testing for XSS...", total=None)
                
                async with XSSTester(
                    self.config.get('modules', {}).get('xss', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # SQLi Module
            if 'sqli' in modules:
                task = progress.add_task("[cyan]Testing for SQL Injection...", total=None)
                
                async with SQLiTester(
                    self.config.get('modules', {}).get('sqli', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # IDOR Module
            if 'idor' in modules:
                task = progress.add_task("[cyan]Testing for IDOR...", total=None)
                
                async with IDORTester(
                    self.config.get('modules', {}).get('idor', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # Brute Force Module
            if 'brute' in modules and kwargs.get('enable_brute_force'):
                task = progress.add_task("[cyan]Testing Brute Force Protections...", total=None)
                
                async with CredentialTester(
                    self.config.get('modules', {}).get('brute_force', {}),
                    self.stealth if stealth_mode else None,
                    self.db,
                    self.graph
                ) as module:
                    findings = await module.run(target, target_id=target_id, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
        # Correlate findings using graph
        console.print("\n[bold]Correlating attack paths...[/bold]")
        attack_paths = self.correlator.analyze(all_findings)
        
        # Get high-value targets from graph
        if self.graph.enabled:
            high_value = self.graph.get_high_value_targets(min_cvss=7.0)
            if high_value:
                console.print(f"[yellow]High-value targets found: {len(high_value)}[/yellow]")
        
        # Display results
        self._display_results(all_findings, attack_paths)
        
        # Close graph connection
        self.graph.close()
        
        return all_findings
        
    def _display_results(self, findings: List[Dict], attack_paths: List[Dict]):
        """Display scan results"""
        if not findings:
            console.print("[yellow]No findings discovered.[/yellow]")
            return
            
        # Summary table
        table = Table(title="Security Findings Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in findings:
            sev = f.get('severity', 'Info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
        for sev, count in severity_counts.items():
            color = {
                'Critical': 'red',
                'High': 'bright_red',
                'Medium': 'yellow',
                'Low': 'green',
                'Info': 'blue'
            }.get(sev, 'white')
            table.add_row(f"[{color}]{sev}[/{color}]", str(count))
            
        console.print(table)
        
        # Detailed findings
        console.print("\n[bold]Detailed Findings:[/bold]")
        for finding in sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True):
            color = {
                'Critical': 'red',
                'High': 'bright_red',
                'Medium': 'yellow',
                'Low': 'green',
                'Info': 'blue'
            }.get(finding.get('severity'), 'white')
            
            console.print(f"\n[{color}]▶ {finding.get('title')} ({finding.get('severity')})[/{color}]")
            console.print(f"  [dim]{finding.get('description')[:100]}...[/dim]")
            console.print(f"  [cyan]PoC:[/cyan] {finding.get('poc', 'N/A')[:80]}...")
            
        # Attack paths
        if attack_paths:
            console.print("\n[bold red]Discovered Attack Paths:[/bold red]")
            for path in attack_paths:
                console.print(f"\n[red]Chain: {path.get('name')}[/red]")
                console.print(f"  Estimated Bounty: [green]${path.get('total_bounty', path.get('estimated_bounty', 0))}[/green]")
                console.print(f"  Complexity: {path.get('complexity')}")
                if 'node_types' in path:
                    console.print(f"  Path: {' -> '.join(path['node_types'])}")
                
        # Save report
        report_path = f"reports/output/raptor_report_{finding.get('target', 'unknown').replace('/', '_')}.md"
        self._generate_report(findings, attack_paths, report_path)
        console.print(f"\n[green]Report saved to: {report_path}[/green]")
        
    def _generate_report(self, findings: List[Dict], attack_paths: List[Dict], path: str):
        """Generate markdown report"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            f.write("# RAPTOR Security Assessment Report\n\n")
            f.write(f"**Target:** {findings[0].get('target', 'Unknown') if findings else 'N/A'}\n\n")
            f.write(f"**Total Findings:** {len(findings)}\n\n")
            f.write("## Executive Summary\n\n")
            
            critical_high = [f for f in findings if f.get('severity') in ['Critical', 'High']]
            if critical_high:
                f.write(f"⚠️ **{len(critical_high)} Critical/High severity issues found**\n\n")
                
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
                for path in attack_paths:
                    f.write(f"### {path.get('name', 'Attack Chain')}\n")
                    f.write(f"- **Complexity:** {path.get('complexity')}\n")
                    f.write(f"- **Estimated Bounty:** ${path.get('total_bounty', path.get('estimated_bounty', 0))}\n")
                    if 'node_types' in path:
                        f.write(f"- **Chain:** {' -> '.join(path['node_types'])}\n")
                    f.write(f"- **Description:** {path.get('description', 'Vulnerability chain discovered through graph analysis')}\n\n")


def main():
    # No args → show welcome
    if len(sys.argv) == 1:
        show_welcome()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="RAPTOR - Advanced Web Application Security Testing",
        add_help=False
    )

    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('-t', '--target')
    parser.add_argument('--modules', default='recon,server,xss,sqli,idor')
    parser.add_argument('--full-scan', action='store_true')
    parser.add_argument('--enable-brute-force', action='store_true')
    parser.add_argument('--stealth', action='store_true')
    parser.add_argument('--cookie', default=None)
    parser.add_argument('--auth-header', default=None)
    parser.add_argument('--proxy', default=None)
    parser.add_argument('--config', default='config/config.yaml')
    parser.add_argument('-o', '--output', default=None)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--version', action='version', version='RAPTOR 2.0')

    args = parser.parse_args()

    if args.help:
        console.print(create_help_text())
        sys.exit(0)

    if not args.target:
        console.print("[red]Error: Target is required. Use -t target.com[/red]")
        sys.exit(1)

    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"

    # Modules — default is ALL, full power
    if args.full_scan or 'all' in args.modules:
        modules = ['recon', 'server', 'xss', 'sqli', 'idor']
    else:
        modules = [m.strip() for m in args.modules.split(',')]
        valid = {'recon', 'server', 'xss', 'sqli', 'idor', 'brute', 'all'}
        invalid = set(modules) - valid
        if invalid:
            console.print(f"[red]Error: Invalid modules: {', '.join(invalid)}[/red]")
            console.print(f"[yellow]Valid: {', '.join(valid)}[/yellow]")
            sys.exit(1)

    if 'brute' in modules and not args.enable_brute_force:
        console.print("[red]Brute force requires --enable-brute-force flag[/red]")
        sys.exit(1)

    raptor = Raptor(args.config)

    try:
        findings = asyncio.run(raptor.run_scan(
            args.target,
            modules,
            stealth_mode=args.stealth,
            scope='aggressive',          # always max power
            enable_brute_force=args.enable_brute_force,
            evasion_level=5,             # always max evasion
            rate_limit=50,               # max concurrency
            timeout=30,
            max_depth=5,
            cookie=args.cookie,
            auth_header=args.auth_header,
            proxy=args.proxy,
            output_format='markdown',
            output_path=args.output
        ))

        critical_high = [f for f in findings if f.get('severity') in ['Critical', 'High']]
        sys.exit(len(critical_high))

    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Fatal Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()

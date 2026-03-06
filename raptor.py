#!/usr/bin/env python3
"""
RAPTOR - Advanced Automated Web Application Security Testing Framework
Optimized for Bug Bounty Hunting & Penetration Testing
"""

import asyncio
import argparse
import sys
import yaml
from pathlib import Path
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import box

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
    welcome_text = """
[bold cyan]
██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔══██╗   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
[/bold cyan]

[bold yellow]RAPTOR Security Framework v2.0[/bold yellow]
[dim]Advanced Web Application Penetration Testing[/dim]

[bold green]Quick Start:[/bold green]
  python3 raptor.py -t [cyan]target.com[/cyan] --modules [green]recon,xss,sqli[/green]
  python3 raptor.py -t [cyan]target.com[/cyan] --full-scan

[bold green]Available Modules:[/bold green]
  [cyan]recon[/cyan]  - Reconnaissance & Discovery
  [cyan]server[/cyan] - Server Misconfiguration
  [cyan]xss[/cyan]    - Cross-Site Scripting
  [cyan]sqli[/cyan]   - SQL Injection
  [cyan]idor[/cyan]   - Insecure Direct Object Reference
  [cyan]brute[/cyan]  - Brute Force (requires --enable-brute-force)

[bold yellow]Run --help for full documentation:[/bold yellow]
  python3 raptor.py [bold]--help[/bold]
"""
    console.print(welcome_text)


def create_help_text():
    """Create comprehensive help text"""
    
    banner = """
[bold cyan]
██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔══██╗   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
[/bold cyan]
[bold yellow]Advanced Web Application Security Testing Framework v2.0[/bold yellow]
"""
    
    description = """
[bold green]RAPTOR[/bold green] is an S-tier automated security testing framework for 
comprehensive web application assessment and bug bounty hunting.
"""

    modules_help = """
[bold cyan]AVAILABLE MODULES[/bold cyan]

[bold]recon[/bold]      Reconnaissance & Discovery
             • Subdomain enumeration
             • Technology fingerprinting
             • Endpoint discovery

[bold]server[/bold]     Server Misconfiguration
             • Security header audit
             • Sensitive file exposure
             • Information disclosure

[bold]xss[/bold]        Cross-Site Scripting
             • Reflected, Stored, DOM-based XSS
             • Blind XSS with callbacks
             • WAF evasion techniques

[bold]sqli[/bold]       SQL Injection
             • Error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
             • Boolean/Time-based blind
             • UNION-based exploitation

[bold]idor[/bold]       Insecure Direct Object Reference
             • Sequential ID detection
             • RESTful endpoint manipulation
             • Mass assignment testing

[bold]brute[/bold]      Brute Force & Authentication
             • Credential stuffing detection
             • Rate limit testing
             [red](Requires --enable-brute-force)[/red]

[bold]all[/bold]         Run all modules (recon,server,xss,sqli,idor)
"""

    usage_examples = """
[bold cyan]USAGE EXAMPLES[/bold cyan]

[dim]# Quick reconnaissance[/dim]
[bold green]python3 raptor.py -t example.com --modules recon[/bold green]

[dim]# Standard security scan[/dim]
[bold green]python3 raptor.py -t example.com --modules recon,server,xss,sqli[/bold green]

[dim]# Full penetration test[/dim]
[bold green]python3 raptor.py -t example.com --full-scan[/bold green]

[dim]# Stealth mode (evasive)[/dim]
[bold green]python3 raptor.py -t example.com --full-scan --stealth[/bold green]

[dim]# Bug bounty optimized[/dim]
[bold green]python3 raptor.py -t target.com --modules xss,sqli,idor --stealth[/bold green]
"""

    options_help = """
[bold cyan]COMMAND LINE OPTIONS[/bold cyan]

[bold]Required:[/bold]
  -t, --target [yellow]TEXT[/yellow]     Target domain or URL

[bold]Modules:[/bold]
  --modules [yellow]LIST[/yellow]       Comma-separated (default: recon,server)
  --full-scan              Enable all modules
  --enable-brute-force     Enable brute force [red](use with caution)[/red]

[bold]Configuration:[/bold]
  --stealth                Enable stealth mode with evasion
  --scope [yellow]CHOICE[/yellow]       quick/standard/comprehensive/aggressive
  --evasion [yellow]1-5[/yellow]        WAF evasion level (default: 2)
  --rate-limit [yellow]NUM[/yellow]      Requests per second (default: 10)
  --timeout [yellow]SEC[/yellow]         Request timeout (default: 30)
  --max-depth [yellow]NUM[/yellow]         Maximum crawl depth (default: 3)

[bold]Auth & Proxy:[/bold]
  --cookie [yellow]STR[/yellow]          Authentication cookie
  --auth-header [yellow]STR[/yellow]    Authorization header
  --proxy [yellow]URL[/yellow]          Proxy URL (e.g., http://127.0.0.1:8080)

[bold]Output:[/bold]
  --config [yellow]PATH[/yellow]         Config file (default: config/config.yaml)
  -o, --output [yellow]PATH[/yellow]     Custom report path
  --format [yellow]CHOICE[/yellow]      json/html/markdown/all
  -v, --verbose            Verbose output
  -q, --quiet              Minimal output
"""

    notes = """
[bold cyan]IMPORTANT NOTES[/bold cyan]

1. [bold]Legal:[/bold] Only use on systems you own or have explicit permission to test
2. [bold]Stealth:[/bold] Slower scanning with evasion techniques to avoid detection
3. [bold]Brute Force:[/bold] Can lock accounts - only use with permission
4. [bold]Exit Codes:[/bold] 0 = clean, N = number of Critical/High findings
"""
    
    return f"{banner}\n{description}\n{modules_help}\n{usage_examples}\n{options_help}\n{notes}"


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
        """Load configuration from YAML"""
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
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
    # Check if any arguments provided
    if len(sys.argv) == 1:
        show_welcome()
        sys.exit(0)
    
    # Custom formatter for rich text help
    class RichHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def __init__(self, prog):
            super().__init__(prog, max_help_position=40, width=100)
        
        def format_help(self):
            return create_help_text()
    
    # Create parser with custom formatter
    parser = argparse.ArgumentParser(
        description="RAPTOR - Advanced Web Application Security Testing",
        formatter_class=RichHelpFormatter,
        add_help=False
    )
    
    # Help argument
    parser.add_argument('-h', '--help', action='store_true', 
                       help='Show this help message and exit')
    
    # Required arguments
    parser.add_argument('-t', '--target', 
                       help='Target domain or URL (e.g., https://example.com or example.com)')
    
    # Module selection
    parser.add_argument('--modules', default='recon,server',
                       help='Comma-separated list of modules (default: recon,server)')
    parser.add_argument('--full-scan', action='store_true',
                       help='Enable all modules: recon,server,xss,sqli,idor (except brute force)')
    parser.add_argument('--enable-brute-force', action='store_true',
                       help='Enable brute force testing module (requires explicit permission)')
    
    # Scan configuration
    parser.add_argument('--stealth', action='store_true',
                       help='Enable stealth mode: evasion techniques, jitter, random delays')
    parser.add_argument('--scope', choices=['quick', 'standard', 'comprehensive', 'aggressive'],
                       default='standard', help='Scan intensity level (default: standard)')
    parser.add_argument('--evasion', type=int, choices=[1, 2, 3, 4, 5], default=2,
                       help='WAF evasion level 1-5, higher = more evasive (default: 2)')
    parser.add_argument('--rate-limit', type=int, default=10,
                       help='Maximum requests per second (default: 10)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request request timeout in seconds (default: 30)')
    parser.add_argument('--max-depth', type=int, default=3,
                       help='Maximum crawl depth for discovery (default: 3)')
    
    # Authentication
    parser.add_argument('--cookie', help='Authentication cookie string (e.g., "session=abc123")')
    parser.add_argument('--auth-header', help='Authorization header (e.g., "Bearer token123")')
    parser.add_argument('--proxy', help='Proxy URL for traffic routing (e.g., http://127.0.0.1:8080)')
    
    # Output control
    parser.add_argument('--config', default='config/config.yaml',
                       help='Path to YAML configuration file (default: config/config.yaml)')
    parser.add_argument('-o', '--output', help='Custom output path for reports')
    parser.add_argument('--format', choices=['json', 'html', 'markdown', 'all'], default='markdown',
                       help='Report output format (default: markdown)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored terminal output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (errors only)')
    
    # Version
    parser.add_argument('--version', action='version', version='%(prog)s 2.0')
    
    args = parser.parse_args()
    
    # Show help if requested
    if args.help:
        console.print(create_help_text())
        sys.exit(0)
    
    # Validate target
    if not args.target:
        console.print("[red]Error: Target is required. Use -t target.com[/red]")
        sys.exit(1)
    
    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"
    
    # Determine modules
    if args.full_scan:
        modules = ['recon', 'server', 'xss', 'sqli', 'idor']
    else:
        modules = [m.strip() for m in args.modules.split(',')]
        valid_modules = {'recon', 'server', 'xss', 'sqli', 'idor', 'brute', 'all'}
        invalid = set(modules) - valid_modules
        if invalid:
            console.print(f"[red]Error: Invalid modules: {', '.join(invalid)}[/red]")
            console.print(f"[yellow]Valid modules: {', '.join(valid_modules)}[/yellow]")
            sys.exit(1)
        
        if 'all' in modules:
            modules = ['recon', 'server', 'xss', 'sqli', 'idor']
    
    # Check brute force permission
    if 'brute' in modules and not args.enable_brute_force:
        console.print("[red]Error: Brute force module requires --enable-brute-force flag[/red]")
        console.print("[yellow]Warning: Only use with explicit permission![/yellow]")
        sys.exit(1)
    
    # Initialize and run
    raptor = Raptor(args.config)
    
    try:
        findings = asyncio.run(raptor.run_scan(
            args.target,
            modules,
            stealth_mode=args.stealth,
            scope=args.scope,
            enable_brute_force=args.enable_brute_force,
            evasion_level=args.evasion,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            max_depth=args.max_depth,
            cookie=args.cookie,
            auth_header=args.auth_header,
            proxy=args.proxy,
            output_format=args.format,
            output_path=args.output
        ))
        
        # Exit code based on findings
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

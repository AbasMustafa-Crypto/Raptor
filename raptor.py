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
from core.correlator import AttackPathCorrelator

# Import modules
from modules.recon.subdomain_enum import SubdomainEnumerator
from modules.recon.tech_fingerprint import TechnologyFingerprinter
from modules.server_misconfig.header_audit import HeaderAuditor
from modules.server_misconfig.sensitive_files import SensitiveFileScanner
from modules.idor.idor_tester import IDORTester
from modules.brute_force.credential_tester import CredentialTester

console = Console()

class Raptor:
    """Main RAPTOR Framework Controller"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self._load_config(config_path)
        self.stealth = StealthManager(self.config.get('stealth', {}))
        self.db = DatabaseManager(self.config.get('database', {}).get('sqlite_path', 'data/raptor.db'))
        self.correlator = AttackPathCorrelator(self.db)
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
        
        console.print(Panel.fit(
            f"[bold cyan]RAPTOR Security Framework v1.0[/bold cyan]\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Modules: [green]{', '.join(modules)}[/green]\n"
            f"Mode: [red]{'Stealth' if stealth_mode else 'Aggressive'}[/red]",
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
                
                # Subdomain enumeration
                async with SubdomainEnumerator(
                    self.config.get('modules', {}).get('recon', {}),
                    self.stealth if stealth_mode else None,
                    self.db
                ) as module:
                    findings = await module.run(target, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                # Technology fingerprinting
                async with TechnologyFingerprinter(
                    self.config.get('modules', {}).get('recon', {}),
                    self.stealth if stealth_mode else None,
                    self.db
                ) as module:
                    findings = await module.run(target, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # Server Misconfiguration Module
            if 'server' in modules:
                task = progress.add_task("[cyan]Auditing Server Configuration...", total=None)
                
                # Header audit
                async with HeaderAuditor(
                    self.config.get('modules', {}).get('server_misconfig', {}),
                    self.stealth if stealth_mode else None,
                    self.db
                ) as module:
                    findings = await module.run(target, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                # Sensitive file scan
                async with SensitiveFileScanner(
                    self.config.get('modules', {}).get('server_misconfig', {}),
                    self.stealth if stealth_mode else None,
                    self.db
                ) as module:
                    findings = await module.run(target, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # IDOR Module
            if 'idor' in modules:
                task = progress.add_task("[cyan]Testing for IDOR...", total=None)
                
                async with IDORTester(
                    self.config.get('modules', {}).get('idor', {}),
                    self.stealth if stealth_mode else None,
                    self.db
                ) as module:
                    findings = await module.run(target, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
            # Brute Force Module
            if 'brute' in modules and kwargs.get('enable_brute_force'):
                task = progress.add_task("[cyan]Testing Brute Force Protections...", total=None)
                
                async with CredentialTester(
                    self.config.get('modules', {}).get('brute_force', {}),
                    self.stealth if stealth_mode else None,
                    self.db
                ) as module:
                    findings = await module.run(target, **kwargs)
                    all_findings.extend([f.to_dict() for f in findings])
                    
                progress.update(task, completed=True)
                
        # Correlate findings
        console.print("\n[bold]Correlating attack paths...[/bold]")
        attack_paths = self.correlator.analyze(all_findings)
        
        # Display results
        self._display_results(all_findings, attack_paths)
        
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
                console.print(f"  Estimated Bounty: [green]${path.get('estimated_bounty')}[/green]")
                console.print(f"  Complexity: {path.get('complexity')}")
                
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
                    f.write(f"### {path.get('name')}\n")
                    f.write(f"- **Complexity:** {path.get('complexity')}\n")
                    f.write(f"- **Estimated Bounty:** ${path.get('estimated_bounty')}\n")
                    f.write(f"- **Description:** {path.get('description')}\n\n")

def main():
    parser = argparse.ArgumentParser(
        description="RAPTOR - Advanced Web Application Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 raptor.py -t example.com --full-scan --stealth
  python3 raptor.py -t example.com --modules recon,server --stealth
  python3 raptor.py -t example.com --modules idor,brute --enable-brute-force
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain or URL')
    parser.add_argument('--modules', default='recon,server', 
                       help='Comma-separated modules: recon,server,idor,brute,xss,sqli')
    parser.add_argument('--full-scan', action='store_true', 
                       help='Enable all modules (except brute force)')
    parser.add_argument('--stealth', action='store_true', 
                       help='Enable stealth mode with evasion techniques')
    parser.add_argument('--enable-brute-force', action='store_true',
                       help='Enable brute force testing (use with caution)')
    parser.add_argument('--config', default='config/config.yaml',
                       help='Path to configuration file')
    parser.add_argument('-o', '--output', help='Output report path')
    
    args = parser.parse_args()
    
    # Determine modules
    if args.full_scan:
        modules = ['recon', 'server', 'idor', 'xss', 'sqli']
    else:
        modules = [m.strip() for m in args.modules.split(',')]
        
    # Initialize and run
    raptor = Raptor(args.config)
    
    try:
        findings = asyncio.run(raptor.run_scan(
            args.target,
            modules,
            stealth_mode=args.stealth,
            enable_brute_force=args.enable_brute_force
        ))
        
        # Exit code based on findings
        critical_high = [f for f in findings if f.get('severity') in ['Critical', 'High']]
        sys.exit(len(critical_high))
        
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()

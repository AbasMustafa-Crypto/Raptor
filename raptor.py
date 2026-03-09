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
from modules.server_misconfig.header_audit   import HeaderAuditor
from modules.server_misconfig.sensitive_files import SensitiveFileScanner
from modules.idor.idor_tester                import IDORTester
from modules.brute_force.credential_tester   import CredentialTester
from modules.xss.xss_tester                 import XSSTester
from modules.sqli.sqli_tester               import SQLiTester

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
  python3 raptor.py -t [cyan]target.com[/cyan] --modules [green]xss,sqli,idor[/green]
  python3 raptor.py -t [cyan]target.com[/cyan] --modules [green]brute[/green] --enable-brute-force
  python3 raptor.py -t [cyan]target.com[/cyan] --modules [green]brute[/green] --enable-brute-force [yellow]--userlist users.txt --passlist passwords.txt[/yellow]

[bold green]Modules:[/bold green]
  [cyan]recon[/cyan]   Reconnaissance & Discovery
  [cyan]server[/cyan]  Server Misconfiguration
  [cyan]xss[/cyan]     Cross-Site Scripting
  [cyan]sqli[/cyan]    SQL Injection
  [cyan]idor[/cyan]    Insecure Direct Object Reference
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

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config     = self._load_config(config_path)
        self.stealth    = StealthManager(self.config.get('stealth', {}))
        db_path         = (
            self.config.get('database', {}).get('path') or
            'data/raptor.db'
        )
        self.db         = DatabaseManager(db_path)
        self.graph      = GraphManager(self.config.get('graph', {}))
        self.correlator = AttackPathCorrelator(self.db, self.graph)
        self.findings:  List[Dict] = []

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
        """Execute security scan"""

        target_id = self.graph.add_target(target, metadata={'modules': modules}) \
                    if self.graph.enabled else None

        console.print(Panel.fit(
            f"[bold cyan]RAPTOR Security Framework v2.0[/bold cyan]\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Modules: [green]{', '.join(modules)}[/green]\n"
            f"Mode: [red]{'Stealth' if stealth_mode else 'Aggressive'}[/red]\n"
            f"Graph DB: [blue]{'Connected' if self.graph.enabled else 'Disabled'}[/blue]",
            box=box.DOUBLE_EDGE
        ))

        all_findings = []
        stealth      = self.stealth if stealth_mode else None

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:

            # ── Recon ──────────────────────────────────────────────────────
            if 'recon' in modules:
                task = progress.add_task("[cyan]Running Reconnaissance...", total=None)

                async with SubdomainEnumerator(
                    self._module_cfg('modules', 'recon'),
                    stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                async with TechnologyFingerprinter(
                    self._module_cfg('modules', 'recon'),
                    stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                progress.update(task, completed=True)

            # ── Server misconfig ───────────────────────────────────────────
            if 'server' in modules:
                task = progress.add_task("[cyan]Auditing Server Configuration...", total=None)

                async with HeaderAuditor(
                    self._module_cfg('modules', 'server'),
                    stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                async with SensitiveFileScanner(
                    self._module_cfg('modules', 'server'),
                    stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                progress.update(task, completed=True)

            # ── XSS ───────────────────────────────────────────────────────
            if 'xss' in modules:
                task = progress.add_task("[cyan]Testing for XSS...", total=None)

                async with XSSTester(
                    self._module_cfg('modules', 'xss'),
                    stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                progress.update(task, completed=True)

            # ── SQLi ───────────────────────────────────────────────────────
            if 'sqli' in modules:
                task = progress.add_task("[cyan]Testing for SQL Injection...", total=None)

                async with SQLiTester(
                    self._module_cfg('modules', 'sqli'),
                    stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                progress.update(task, completed=True)

            # ── IDOR ───────────────────────────────────────────────────────
            if 'idor' in modules:
                task = progress.add_task("[cyan]Testing for IDOR...", total=None)

                async with IDORTester(
                    self._module_cfg('modules', 'idor'),
                    stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                progress.update(task, completed=True)

            # ── Brute force ────────────────────────────────────────────────
            if 'brute' in modules and kwargs.get('enable_brute_force'):
                task = progress.add_task("[cyan]Brute Forcing...", total=None)

                brute_cfg = dict(self._module_cfg('modules', 'brute_force'))
                if 'wordlist_path' not in brute_cfg:
                    brute_cfg['wordlist_path'] = 'wordlists'

                # ── Forward --userlist / --passlist into the module config ─
                if kwargs.get('userlist'):
                    brute_cfg['userlist'] = kwargs['userlist']
                if kwargs.get('passlist'):
                    brute_cfg['passlist'] = kwargs['passlist']

                async with CredentialTester(
                    brute_cfg, stealth, self.db, self.graph
                ) as mod:
                    all_findings.extend(
                        [f.to_dict() for f in await mod.run(target, **kwargs)]
                    )

                progress.update(task, completed=True)

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
    parser.add_argument('--modules',                 default='recon,server,xss,sqli,idor')
    parser.add_argument('--full-scan',               action='store_true')
    parser.add_argument('--enable-brute-force',      action='store_true')
    # ── Wordlist flags ────────────────────────────────────────────────────
    parser.add_argument('--userlist',                default=None,
                        help='Path to custom usernames file (default: wordlists/usernames.txt)')
    parser.add_argument('--passlist',                default=None,
                        help='Path to custom passwords file (default: wordlists/passwords.txt)')
    # ─────────────────────────────────────────────────────────────────────
    parser.add_argument('--stealth',                 action='store_true')
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
        modules = ['recon', 'server', 'xss', 'sqli', 'idor']
    else:
        modules = [m.strip() for m in args.modules.split(',')]
        valid   = {'recon', 'server', 'xss', 'sqli', 'idor', 'brute', 'all'}
        invalid = set(modules) - valid
        if invalid:
            console.print(f"[red]Error: Invalid modules: {', '.join(invalid)}[/red]")
            console.print(f"[yellow]Valid: {', '.join(sorted(valid))}[/yellow]")
            sys.exit(1)

    if 'brute' in modules and not args.enable_brute_force:
        console.print("[red]Brute force requires --enable-brute-force flag[/red]")
        sys.exit(1)

    raptor = Raptor(args.config)

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

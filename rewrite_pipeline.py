import re

with open("raptor.py", "r") as f:
    content = f.read()

# Find the run_scan method start
start_idx = content.find("    async def run_scan")
# Find the end (before Correlate section)
end_idx = content.find("        # ── Correlate ──────────────────────────────────────────────────────")

if start_idx == -1 or end_idx == -1:
    print("Could not find boundaries")
    exit(1)

new_run_scan = """    async def run_scan(self, target: str, modules: List[str],
                       stealth_mode: bool = False, **kwargs) -> List[Dict]:
        \"\"\"Execute security scan via Full Scan Workflow Engine\"\"\"

        target_id = self.graph.add_target(target, metadata={'modules': modules}) \\
                    if self.graph.enabled else None

        console.print(Panel.fit(
            f"[bold cyan]RAPTOR Security Framework v4.0[/bold cyan]\\n"
            f"Target: [yellow]{target}[/yellow]\\n"
            f"Modules: [green]{', '.join(modules)}[/green]\\n"
            f"Mode: [red]{'Stealth' if stealth_mode else 'Aggressive'}[/red]\\n"
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

"""

new_content = content[:start_idx] + new_run_scan + content[end_idx:]

with open("raptor.py", "w") as f:
    f.write(new_content)

print("raptor.py successfully updated with Full Scan Workflow Engine.")

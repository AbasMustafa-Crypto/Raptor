import asyncio
import json
import shutil
import os
import stat
import urllib.request
import urllib.parse
import zipfile
import tarfile
import tempfile
from typing import List, Set, Dict
from core.base_module import BaseModule, Finding

# ── Auto-installer for recon tools ────────────────────────────────────────────

_BIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'bin'
)

# GitHub API — resolves the REAL latest release URL at runtime (no more 404s)
_TOOL_APIS = {
    'subfinder':   'https://api.github.com/repos/projectdiscovery/subfinder/releases/latest',
    'assetfinder': 'https://api.github.com/repos/tomnomnom/assetfinder/releases/latest',
    'amass':       'https://api.github.com/repos/owasp-amass/amass/releases/latest',
}

# Keywords to find the right asset in the release
_TOOL_ASSET_KEYWORDS = {
    'subfinder':   ('linux_amd64', '.zip'),
    'assetfinder': ('linux-amd64', '.tgz'),
    'amass':       ('linux_amd64', '.zip'),
}

# Hardcoded fallback if API is unreachable
_TOOL_FALLBACK = {
    'subfinder': (
        'https://github.com/projectdiscovery/subfinder/releases/download/'
        'v2.6.6/subfinder_linux_amd64.zip', 'zip', 'subfinder'
    ),
    'assetfinder': (
        'https://github.com/tomnomnom/assetfinder/releases/download/'
        'v0.1.1/assetfinder-linux-amd64-0.1.1.tgz', 'tgz', 'assetfinder'
    ),
    'amass': (
        'https://github.com/owasp-amass/amass/releases/download/'
        'v4.2.0/amass_linux_amd64.zip', 'zip', 'amass'
    ),
}


def _ensure_bin_dir():
    os.makedirs(_BIN_DIR, exist_ok=True)
    if _BIN_DIR not in os.environ.get('PATH', '').split(os.pathsep):
        os.environ['PATH'] = _BIN_DIR + os.pathsep + os.environ.get('PATH', '')


def _make_executable(path: str):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _resolve_download_url(tool: str):
    """Query GitHub API for the real latest release URL. Falls back to hardcoded if API fails."""
    api_url = _TOOL_APIS[tool]
    kw1, ext = _TOOL_ASSET_KEYWORDS[tool]

    try:
        req = urllib.request.Request(api_url, headers={'User-Agent': 'RAPTOR-installer'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        for asset in data.get('assets', []):
            url = asset.get('browser_download_url', '')
            if kw1 in url and ext in url:
                fmt = 'zip' if url.endswith('.zip') else 'tgz'
                tag = data.get('tag_name', 'latest')
                print(f"  [*] {tool} latest release: {tag}")
                return (url, fmt, tool)

        print(f"  [!] No matching asset in latest release for {tool} — using fallback")
    except Exception as e:
        print(f"  [!] GitHub API failed for {tool} ({e}) — using fallback URL")

    return _TOOL_FALLBACK[tool]


def _install_tool(tool: str) -> bool:
    dest = os.path.join(_BIN_DIR, tool)
    print(f"  [*] Auto-installing {tool} → {dest}")

    try:
        url, fmt, binary_name = _resolve_download_url(tool)

        with tempfile.TemporaryDirectory() as tmpdir:
            archive = os.path.join(tmpdir, 'archive')
            urllib.request.urlretrieve(url, archive)

            if fmt == 'zip':
                with zipfile.ZipFile(archive, 'r') as zf:
                    zf.extractall(tmpdir)
            else:
                with tarfile.open(archive, 'r:gz') as tf:
                    tf.extractall(tmpdir)

            # Walk extracted files and find the binary
            found = None
            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    if fname == tool or fname == binary_name:
                        candidate = os.path.join(root, fname)
                        if os.path.getsize(candidate) > 1000:  # skip README/txt files
                            found = candidate
                            break
                if found:
                    break

            if not found:
                print(f"  [!] Could not locate {tool} binary in archive")
                return False

            import shutil as _sh
            _sh.copy2(found, dest)
            _make_executable(dest)

        print(f"  [+] {tool} installed successfully")
        return True

    except Exception as e:
        print(f"  [!] Failed to install {tool}: {e}")
        return False


def auto_install_recon_tools():
    _ensure_bin_dir()
    missing = [t for t in ('amass', 'subfinder', 'assetfinder') if not shutil.which(t)]
    if not missing:
        return

    print(f"\n  [!] Missing recon tools: {', '.join(missing)}")
    print(f"  [*] Auto-installing into {_BIN_DIR} ...\n")

    for tool in missing:
        _install_tool(tool)

    still_missing = [t for t in missing if not shutil.which(t)]
    if still_missing:
        print(f"\n  [!] Could not auto-install: {', '.join(still_missing)}")
        print(f"      Try manually: sudo apt install amass\n")
    else:
        print(f"\n  [+] All recon tools ready.\n")


# ── Domain extraction helper ──────────────────────────────────────────────────

def _extract_domain(target: str) -> str:
    """
    Extract bare hostname from any input.
    'https://example.com/path' → 'example.com'
    'example.com/path'         → 'example.com'
    'example.com'              → 'example.com'
    """
    if '://' not in target:
        target = 'https://' + target
    host = urllib.parse.urlparse(target).hostname or ''
    return host.split(':')[0].strip()


# ── Module ────────────────────────────────────────────────────────────────────

class SubdomainEnumerator(BaseModule):
    """Subdomain enumeration using multiple tools"""

    def __init__(self, config, stealth=None, db=None, graph_manager=None):
        super().__init__(config, stealth, db)
        self.graph = graph_manager
        self.tools = ['amass', 'subfinder', 'assetfinder']
        self.resolved_subdomains: Set[str] = set()
        auto_install_recon_tools()

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Run subdomain enumeration"""
        # ALWAYS pass bare domain to tools and CT logs — never a full URL
        domain = _extract_domain(target)
        self.logger.info(f"Starting subdomain enumeration for domain: {domain}")

        all_subdomains: Set[str] = set()

        available_tools = self._get_available_tools()

        if not available_tools:
            self.logger.warning("No external subdomain tools found. Using CT logs only.")

        tasks = [self._run_tool(tool, domain) for tool in available_tools
                 if kwargs.get(f'use_{tool}', True)]

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, set):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Tool error: {result}")

        # CT logs — always runs, uses clean domain
        await self._check_ct_logs(domain, all_subdomains)

        self.logger.info(f"Found {len(all_subdomains)} unique subdomains")

        valid_subdomains = await self._validate_subdomains(all_subdomains) if all_subdomains else []

        for subdomain in valid_subdomains:
            if self.db:
                self.db.save_asset('subdomain', subdomain, 'recon',
                                   metadata={'resolved': True})

        if valid_subdomains:
            await self._analyze_subdomains(valid_subdomains, domain)

        return self.findings

    def _get_available_tools(self) -> List[str]:
        available = []
        for tool in self.tools:
            if shutil.which(tool):
                available.append(tool)
            else:
                self.logger.warning(f"{tool} not found in PATH - skipping")
        return available

    async def _run_tool(self, tool: str, domain: str) -> Set[str]:
        """Run a recon tool against a bare domain (no scheme, no path)"""
        subdomains = set()
        try:
            if tool == 'amass':
                cmd = ['amass', 'enum', '-passive', '-d', domain, '-json', '-']
            elif tool == 'subfinder':
                cmd = ['subfinder', '-d', domain, '-all', '-silent', '-json']
            elif tool == 'assetfinder':
                cmd = ['assetfinder', '--subs-only', domain]
            else:
                return subdomains

            self.logger.info(f"Running {tool} against {domain}...")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                self.logger.warning(f"{tool} timed out")
                proc.kill()
                await proc.wait()
                return subdomains

            if tool == 'assetfinder':
                for line in stdout.decode().strip().split('\n'):
                    line = line.strip()
                    if line and domain in line:
                        subdomains.add(line)
            else:
                for line in stdout.decode().strip().split('\n'):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        name = data.get('name', '') if tool == 'amass' else data.get('host', '')
                        if name and domain in name:
                            subdomains.add(name)
                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            self.logger.warning(f"{tool} not found in PATH")
        except Exception as e:
            self.logger.error(f"Error running {tool}: {e}")

        return subdomains

    async def _validate_subdomains(self, subdomains: Set[str]) -> List[str]:
        valid = []
        semaphore = asyncio.Semaphore(20)

        async def check(sub):
            async with semaphore:
                try:
                    resp = await self._make_request(f"http://{sub}", allow_redirects=True)
                    if resp and resp.status < 500:
                        valid.append(sub)
                        self.resolved_subdomains.add(sub)
                except Exception:
                    pass

        await asyncio.gather(*[check(s) for s in subdomains], return_exceptions=True)
        return valid

    async def _analyze_subdomains(self, subdomains: List[str], domain: str):
        staging_keywords = ['staging', 'dev', 'test', 'uat', 'qa', 'preprod', 'preview']
        for subdomain in subdomains:
            for keyword in staging_keywords:
                if keyword in subdomain.lower():
                    self.add_finding(Finding(
                        module='recon',
                        title=f'Staging/Dev Environment Found: {subdomain}',
                        severity='Medium',
                        description=f'Discovered {keyword} environment which may have weaker security controls',
                        evidence={'subdomain': subdomain, 'type': keyword},
                        poc=f"Visit: http://{subdomain}",
                        remediation='Ensure staging environments have equivalent security controls to production',
                        cvss_score=5.3,
                        bounty_score=500,
                        target=subdomain
                    ))
                    break

    async def _check_ct_logs(self, domain: str, existing_subdomains: Set[str]):
        """Query crt.sh Certificate Transparency logs using a bare domain."""
        try:
            # Extra safety: strip any accidental scheme/path
            clean = _extract_domain(domain) if '/' in domain or '://' in domain else domain
            url = f"https://crt.sh/?q=%.{clean}&output=json"
            self.logger.info(f"Checking CT logs: crt.sh/?q=%.{clean}")

            response = await self._make_request(url)
            if not response:
                self.logger.warning("CT log check: no response from crt.sh")
                return

            if response.status == 200:
                try:
                    data = await response.json()
                    ct_subdomains = set()

                    for entry in data:
                        # name_value can contain multiple lines
                        for name in entry.get('name_value', '').split('\n'):
                            name = name.strip()
                            if name and '*' not in name and clean in name:
                                ct_subdomains.add(name)

                    self.logger.info(f"CT logs returned {len(ct_subdomains)} subdomains")
                    existing_subdomains.update(ct_subdomains)

                    new = ct_subdomains - self.resolved_subdomains
                    if new:
                        self.add_finding(Finding(
                            module='recon',
                            title=f'Subdomains Found via CT Logs: {len(new)}',
                            severity='Low',
                            description=f'Found {len(new)} subdomains in Certificate Transparency logs',
                            evidence={'subdomains': list(new)[:10]},
                            poc=f"https://crt.sh/?q=%.{clean}",
                            remediation='Review all subdomains for proper security controls',
                            cvss_score=3.7,
                            bounty_score=100,
                            target=clean
                        ))
                except Exception as e:
                    self.logger.warning(f"Failed to parse CT log response: {e}")
            else:
                self.logger.warning(f"crt.sh returned status {response.status}")

        except Exception as e:
            self.logger.error(f"CT log check failed: {e}")

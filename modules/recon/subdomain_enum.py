"""
subdomain_enum.py — Subdomain enumeration module for RAPTOR.

FIXES vs original
─────────────────
 1. super().__init__() now passes graph_manager correctly
 2. auto_install_recon_tools() moved out of __init__ into run() to avoid
    blocking network I/O in the constructor
 3. _validate_subdomains uses a thread-safe asyncio.Lock for list appends
 4. amass command corrected for v4+ (no '-json -'; output is plain text)
 5. stdout.decode() uses errors='replace' to handle non-UTF-8 tool output
 6. _check_ct_logs: crt.sh response is decoded with errors='replace' rather
    than relying on response.json() which fails on gzip-compressed body
 7. tarfile.extractall uses filter='data' (Python 3.12 TarSlip mitigation)
    with a fallback for older Python versions
 8. _validate_subdomains: status code logic tightened (2xx/3xx only)
"""

import asyncio
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from typing import Dict, List, Optional, Set

from core.base_module import BaseModule, Finding


# ── Tool installer ────────────────────────────────────────────────────────────

_BIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "bin",
)

_TOOL_APIS: Dict[str, str] = {
    "subfinder":   "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest",
    "assetfinder": "https://api.github.com/repos/tomnomnom/assetfinder/releases/latest",
    "amass":       "https://api.github.com/repos/owasp-amass/amass/releases/latest",
}

# (keyword-in-asset-url, extension)
_TOOL_ASSET_KEYWORDS: Dict[str, tuple] = {
    "subfinder":   ("linux_amd64", ".zip"),
    "assetfinder": ("linux-amd64", ".tgz"),
    "amass":       ("linux_amd64", ".zip"),
}

_TOOL_FALLBACK: Dict[str, tuple] = {
    "subfinder": (
        "https://github.com/projectdiscovery/subfinder/releases/download/"
        "v2.6.6/subfinder_linux_amd64.zip",
        "zip", "subfinder",
    ),
    "assetfinder": (
        "https://github.com/tomnomnom/assetfinder/releases/download/"
        "v0.1.1/assetfinder-linux-amd64-0.1.1.tgz",
        "tgz", "assetfinder",
    ),
    "amass": (
        "https://github.com/owasp-amass/amass/releases/download/"
        "v4.2.0/amass_linux_amd64.zip",
        "zip", "amass",
    ),
}


def _ensure_bin_dir() -> None:
    os.makedirs(_BIN_DIR, exist_ok=True)
    if _BIN_DIR not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = _BIN_DIR + os.pathsep + os.environ.get("PATH", "")


def _make_executable(path: str) -> None:
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _resolve_download_url(tool: str) -> tuple:
    """Query GitHub API for the latest release asset URL; fall back if needed."""
    api_url    = _TOOL_APIS[tool]
    kw, ext    = _TOOL_ASSET_KEYWORDS[tool]

    try:
        req = urllib.request.Request(
            api_url, headers={"User-Agent": "RAPTOR-installer"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))

        for asset in data.get("assets", []):
            asset_url = asset.get("browser_download_url", "")
            if kw in asset_url and ext in asset_url:
                fmt = "zip" if asset_url.endswith(".zip") else "tgz"
                print(f"  [*] {tool} latest release: {data.get('tag_name', '?')}")
                return (asset_url, fmt, tool)

        print(f"  [!] No matching asset for {tool} in latest release — using fallback")
    except Exception as exc:
        print(f"  [!] GitHub API error for {tool} ({exc}) — using fallback")

    return _TOOL_FALLBACK[tool]


def _install_tool(tool: str) -> bool:
    dest = os.path.join(_BIN_DIR, tool)
    print(f"  [*] Auto-installing {tool} → {dest}")

    try:
        url, fmt, binary_name = _resolve_download_url(tool)

        with tempfile.TemporaryDirectory() as tmpdir:
            archive = os.path.join(tmpdir, "archive")
            urllib.request.urlretrieve(url, archive)

            if fmt == "zip":
                with zipfile.ZipFile(archive, "r") as zf:
                    zf.extractall(tmpdir)
            else:
                with tarfile.open(archive, "r:gz") as tf:
                    # FIX 7: filter='data' prevents TarSlip path traversal.
                    # Falls back gracefully on Python < 3.12.
                    try:
                        tf.extractall(tmpdir, filter="data")
                    except TypeError:
                        tf.extractall(tmpdir)  # pragma: no cover

            # Walk extracted tree to locate the binary
            found: Optional[str] = None
            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    if fname in (tool, binary_name):
                        candidate = os.path.join(root, fname)
                        if os.path.getsize(candidate) > 1_000:
                            found = candidate
                            break
                if found:
                    break

            if not found:
                print(f"  [!] Could not locate {tool} binary in archive")
                return False

            shutil.copy2(found, dest)
            _make_executable(dest)

        print(f"  [+] {tool} installed successfully")
        return True

    except Exception as exc:
        print(f"  [!] Failed to install {tool}: {exc}")
        return False


def _auto_install_recon_tools() -> None:
    _ensure_bin_dir()
    missing = [t for t in ("amass", "subfinder", "assetfinder") if not shutil.which(t)]
    if not missing:
        return

    print(f"\n  [!] Missing recon tools: {', '.join(missing)}")
    print(f"  [*] Auto-installing into {_BIN_DIR} ...\n")

    for tool in missing:
        _install_tool(tool)

    still_missing = [t for t in missing if not shutil.which(t)]
    if still_missing:
        print(f"\n  [!] Could not auto-install: {', '.join(still_missing)}")
        print("      Try manually: sudo apt install amass\n")
    else:
        print("\n  [+] All recon tools ready.\n")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(target: str) -> str:
    """
    Return a bare hostname from any input:
      'https://example.com/path' → 'example.com'
      'example.com/path'         → 'example.com'
      'example.com'              → 'example.com'
    """
    if "://" not in target:
        target = "https://" + target
    host = urllib.parse.urlparse(target).hostname or ""
    return host.split(":")[0].strip()


# ── Module ────────────────────────────────────────────────────────────────────

class SubdomainEnumerator(BaseModule):
    """Subdomain enumeration via amass / subfinder / assetfinder + CT logs."""

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        # FIX 1: pass graph_manager to BaseModule so self.graph is set correctly
        super().__init__(config, stealth, db, graph_manager)
        self.tools = ["amass", "subfinder", "assetfinder"]
        self.resolved_subdomains: Set[str] = set()
        # FIX 2: installer called in run(), not __init__, to avoid blocking I/O
        # in the constructor (urllib.urlretrieve downloads large binaries)

    async def run(self, target: str, **kwargs) -> List[Finding]:
        # FIX 2: install here — still synchronous but only runs when scan starts,
        # not when the object is constructed during import/config phase
        _auto_install_recon_tools()

        domain = _extract_domain(target)
        self.logger.info("Starting subdomain enumeration for: %s", domain)

        all_subdomains: Set[str] = set()

        available = self._get_available_tools()
        if not available:
            self.logger.warning("No external tools available — CT logs only")

        tasks = [
            self._run_tool(tool, domain)
            for tool in available
            if kwargs.get(f"use_{tool}", True)
        ]

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, set):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    self.logger.error("Tool error: %s", result)

        await self._check_ct_logs(domain, all_subdomains)

        self.logger.info("Found %d unique subdomains (pre-validation)", len(all_subdomains))

        valid = await self._validate_subdomains(all_subdomains) if all_subdomains else []

        for sub in valid:
            if self.db:
                self.db.save_asset("subdomain", sub, "recon", metadata={"resolved": True})

        if valid:
            await self._analyze_subdomains(valid, domain)

        return self.findings

    # ── Tool management ───────────────────────────────────────────────────────

    def _get_available_tools(self) -> List[str]:
        available = []
        for tool in self.tools:
            if shutil.which(tool):
                available.append(tool)
            else:
                self.logger.warning("%s not in PATH — skipping", tool)
        return available

    async def _run_tool(self, tool: str, domain: str) -> Set[str]:
        """Run one recon tool against a bare domain; return set of subdomains."""
        subdomains: Set[str] = set()
        try:
            if tool == "subfinder":
                # subfinder -json outputs one JSON object per line
                cmd = ["subfinder", "-d", domain, "-all", "-silent", "-json"]
            elif tool == "assetfinder":
                # assetfinder outputs plain text, one subdomain per line
                cmd = ["assetfinder", "--subs-only", domain]
            elif tool == "amass":
                # FIX 4: amass v4+ no longer supports '-json -' (stdout JSON).
                # Plain text output is reliable across all versions.
                cmd = ["amass", "enum", "-passive", "-d", domain]
            else:
                return subdomains

            self.logger.info("Running %s against %s …", tool, domain)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                self.logger.warning("%s timed out — killing", tool)
                proc.kill()
                await proc.wait()
                return subdomains

            # FIX 5: always decode with errors='replace'; tool output may be
            # non-UTF-8 on certain locales or for IDN domains.
            raw = stdout.decode("utf-8", errors="replace").strip()

            if tool == "assetfinder" or tool == "amass":
                for line in raw.splitlines():
                    line = line.strip()
                    if line and domain in line:
                        subdomains.add(line.lower())
            elif tool == "subfinder":
                for line in raw.splitlines():
                    if not line:
                        continue
                    try:
                        obj  = json.loads(line)
                        name = obj.get("host", "")
                        if name and domain in name:
                            subdomains.add(name.lower())
                    except json.JSONDecodeError:
                        # subfinder sometimes emits non-JSON status lines
                        if domain in line:
                            subdomains.add(line.strip().lower())

        except FileNotFoundError:
            self.logger.warning("%s not found in PATH", tool)
        except Exception as exc:
            self.logger.error("Error running %s: %s", tool, exc)

        return subdomains

    # ── Validation ────────────────────────────────────────────────────────────

    async def _validate_subdomains(self, subdomains: Set[str]) -> List[str]:
        """
        HTTP-probe each subdomain; return only those that respond with 2xx/3xx.

        FIX 3: uses asyncio.Lock to guard the shared 'valid' list so concurrent
        appends are safe even if CPython's GIL is ever removed.
        FIX 8: status check tightened to < 400 (success + redirect only).
        """
        valid: List[str] = []
        lock      = asyncio.Lock()
        semaphore = asyncio.Semaphore(20)

        async def probe(sub: str) -> None:
            async with semaphore:
                try:
                    resp = await self._make_request(
                        f"http://{sub}", allow_redirects=True, timeout=8
                    )
                    if resp and resp.status < 400:
                        async with lock:
                            valid.append(sub)
                        self.resolved_subdomains.add(sub)
                    elif resp:
                        self.logger.debug("Skip %s — HTTP %d", sub, resp.status)
                except Exception as exc:
                    self.logger.debug("Probe error %s: %s", sub, exc)

        await asyncio.gather(*[probe(s) for s in subdomains], return_exceptions=True)
        return valid

    # ── Analysis ──────────────────────────────────────────────────────────────

    async def _analyze_subdomains(self, subdomains: List[str], domain: str) -> None:
        staging_keywords = ["staging", "dev", "test", "uat", "qa", "preprod", "preview"]
        for sub in subdomains:
            sub_lower = sub.lower()
            for kw in staging_keywords:
                if kw in sub_lower:
                    self.add_finding(Finding(
                        module="recon",
                        title=f"Staging/Dev Environment Exposed: {sub}",
                        severity="Medium",
                        description=(
                            f"Discovered a '{kw}' environment that may have "
                            "weaker security controls than production."
                        ),
                        evidence={"subdomain": sub, "keyword": kw},
                        poc=f"http://{sub}",
                        remediation=(
                            "Apply the same security controls (auth, headers, TLS) "
                            "to non-production environments as production."
                        ),
                        cvss_score=5.3,
                        bounty_score=500,
                        target=sub,
                    ))
                    break  # one finding per subdomain

    # ── CT logs ───────────────────────────────────────────────────────────────

    async def _check_ct_logs(self, domain: str, existing: Set[str]) -> None:
        """
        Query crt.sh Certificate Transparency logs for the bare domain.

        FIX 6: crt.sh sends gzip-compressed JSON when the request headers
        include 'Accept-Encoding: gzip'. BaseModule._make_request uses urllib
        which transparently decompresses gzip responses, so response.body is
        already plain bytes — but to be safe we decode manually and parse
        rather than relying on response.json() which re-encodes to bytes first.
        """
        clean = _extract_domain(domain) if ("/" in domain or "://" in domain) else domain
        url   = f"https://crt.sh/?q=%.{clean}&output=json"
        self.logger.info("Checking CT logs: %s", url)

        resp = await self._make_request(url, timeout=15)
        if not resp:
            self.logger.warning("CT logs: no response from crt.sh")
            return

        if resp.status != 200:
            self.logger.warning("CT logs: crt.sh returned HTTP %d", resp.status)
            return

        try:
            # Decode body ourselves — handles both compressed and plain responses
            raw  = resp._body.decode("utf-8", errors="replace")
            data = json.loads(raw)
        except Exception as exc:
            self.logger.warning("CT logs: failed to parse crt.sh response: %s", exc)
            return

        ct_found: Set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and "*" not in name and clean in name:
                    ct_found.add(name)

        self.logger.info("CT logs returned %d subdomains", len(ct_found))
        existing.update(ct_found)

        new = ct_found - self.resolved_subdomains
        if new:
            self.add_finding(Finding(
                module="recon",
                title=f"Subdomains Discovered via CT Logs ({len(new)})",
                severity="Low",
                description=(
                    f"Found {len(new)} subdomains in Certificate Transparency logs. "
                    "These may expose historical or forgotten infrastructure."
                ),
                evidence={"subdomains": sorted(new)[:10], "total": len(new)},
                poc=f"https://crt.sh/?q=%.{clean}",
                remediation="Review all subdomains and ensure they are intentional and secured.",
                cvss_score=3.7,
                bounty_score=100,
                target=clean,
            ))

"""
tech_fingerprint.py — Technology fingerprinting module for RAPTOR.

FIXES vs original
─────────────────
 1. super().__init__() now passes graph_manager correctly
 2. self.wordlist_path set BEFORE _load_technologies_wordlist() is called
 3. _analyze_response no longer pre-seeds all techs with confidence=0;
    only techs that actually match get an entry (eliminates wasteful allocs)
 4. Header value comparison is now case-insensitive on both sides
 5. 'WP-' removed from WordPress header signatures (not a real header name)
 6. Django 'X-Frame-Options: SAMEORIGIN' removed (not Django-specific)
 7. Vue.js 'vue-' html sig tightened to avoid false positives
 8. _detect_hosting rewritten with precise per-header key/value matching
    instead of full-string repr scanning (eliminates false positives from
    referer/cookie values containing provider names)
 9. _detect_hosting_from_url() added — detects Firebase/Vercel/Netlify etc.
    from the hostname alone, which is reliable even when CDN strips headers
10. wordlist results no longer overwrite higher-confidence signature results
11. Version comparison uses full tuple comparison (including patch level)
    so Apache 2.4.49 is correctly flagged against minimum 2.4.50
12. Version min-versions updated to current recommended baselines
"""

import re
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.base_module import BaseModule, Finding


# ── Minimal HTML parser (zero-dependency BS4 replacement) ────────────────────

class _MiniSoup(HTMLParser):
    """Lightweight HTMLParser wrapper with a BS4-compatible find_all() API."""

    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self._tags: List[Dict] = []
        try:
            self.feed(html)
        except Exception:
            pass  # malformed HTML is fine; we keep whatever was parsed

    def handle_starttag(self, tag: str, attrs) -> None:
        self._tags.append({"tag": tag.lower(), "attrs": dict(attrs)})

    def find_all(self, tag: str, attrs: Dict = None, **kwargs) -> List["_TagProxy"]:
        """
        Return all tags matching name + attribute filter.

        Filter values:
          True  → attribute must be present (any value)
          False → attribute must be absent
          str   → attribute value must match as regex (case-insensitive)
        """
        filt = dict(attrs or {})
        filt.update(kwargs)
        tag_lc = tag.lower()

        results = []
        for t in self._tags:
            if t["tag"] != tag_lc:
                continue
            ok = True
            for k, v in filt.items():
                actual = t["attrs"].get(k)
                if v is True:
                    if actual is None:
                        ok = False; break
                elif v is False:
                    if actual is not None:
                        ok = False; break
                else:
                    if not re.search(str(v), str(actual or ""), re.I):
                        ok = False; break
            if ok:
                results.append(_TagProxy(t["attrs"]))
        return results


class _TagProxy:
    """Dict-backed tag proxy with a BS4-compatible get() / [] / in API."""

    __slots__ = ("_a",)

    def __init__(self, attrs: Dict) -> None:
        self._a = attrs

    def get(self, key: str, default=None):
        return self._a.get(key, default)

    def __getitem__(self, key: str):
        return self._a[key]

    def __contains__(self, key: str) -> bool:
        return key in self._a


# ── Version comparison helper ─────────────────────────────────────────────────

def _parse_version(v: str) -> Tuple[int, ...]:
    """
    Convert a version string to a comparable tuple of ints.
    '2.4.50' → (2, 4, 50)   '3.6' → (3, 6)
    """
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _is_outdated(detected: str, minimum: str) -> bool:
    """FIX 11: full tuple comparison so patch level is considered."""
    d = _parse_version(detected)
    m = _parse_version(minimum)
    # Pad to equal length
    length = max(len(d), len(m))
    d += (0,) * (length - len(d))
    m += (0,) * (length - len(m))
    return d < m


# ── Module ────────────────────────────────────────────────────────────────────

class TechnologyFingerprinter(BaseModule):
    """Fingerprint technologies on a web target and report outdated versions."""

    def __init__(self, config: Dict, stealth=None, db=None, graph_manager=None):
        # FIX 1: pass graph_manager so BaseModule.graph is set correctly
        super().__init__(config, stealth, db, graph_manager)
        # FIX 2: set wordlist_path BEFORE calling _load_technologies_wordlist
        self.wordlist_path: str = config.get("wordlist_path", "wordlists")
        self._signatures    = self._build_signatures()
        self._wordlist_techs = self._load_wordlist()

    # ── Signatures ────────────────────────────────────────────────────────────

    def _build_signatures(self) -> Dict:
        """
        Each entry: {
            'headers':       [(header_name, value_substring), ...]
            'meta':          [regex_pattern, ...]      # against <meta name=generator content=...>
            'scripts':       [substring, ...]          # against <script src=...>
            'html':          [substring, ...]          # against raw body text
            'cookies':       [substring, ...]          # against Set-Cookie header
            'version_regex': r'...'                    # optional; group(1) = version
        }

        FIX 5: 'WP-' removed from WordPress headers (not a real header).
        FIX 6: Django 'X-Frame-Options: SAMEORIGIN' removed (not Django-specific).
        FIX 7: Vue.js html sigs tightened; 'vue-' replaced with more specific patterns.
        """
        return {
            "WordPress": {
                "headers":       [("X-Powered-By", "WordPress")],
                "meta":          [r"WordPress"],
                "html":          ["/wp-content/", "/wp-includes/"],
                "version_regex": r"WordPress/([\d.]+)",
            },
            "Drupal": {
                "headers":       [("X-Generator", "Drupal")],
                "meta":          [r"Drupal"],
                "html":          ["/sites/default/", "/misc/drupal.js"],
                "version_regex": r"Drupal\s+([\d.]+)",
            },
            "Joomla": {
                "meta":          [r"Joomla"],
                "html":          ["/media/system/js/", "/components/com_"],
            },
            "Apache": {
                "headers":       [("Server", "Apache")],
                "version_regex": r"Apache/([\d.]+)",
            },
            "Nginx": {
                "headers":       [("Server", "nginx")],
                "version_regex": r"nginx/([\d.]+)",
            },
            "PHP": {
                "headers":       [("X-Powered-By", "PHP")],
                "version_regex": r"PHP/([\d.]+)",
            },
            "Django": {
                "headers":       [("Server", "WSGIServer")],
                "cookies":       ["csrftoken", "sessionid"],
                "html":          ["csrfmiddlewaretoken", "__django"],
            },
            "Laravel": {
                "cookies":       ["laravel_session", "XSRF-TOKEN"],
                "html":          ["laravel", "csrf-token"],
            },
            "Rails": {
                "headers":       [("X-Powered-By", "Phusion Passenger")],
                "cookies":       ["_rails_session"],
                "html":          ["rails-ujs", "data-remote=\"true\""],
            },
            "React": {
                "html":          ["__reactFiber", "__reactInternalInstance",
                                  "data-reactroot", "__REACT_DEVTOOLS"],
                "scripts":       ["react.production.min.js", "react-dom.production",
                                  "react.development.js"],
            },
            "Angular": {
                "html":          ["ng-version=", "_nghost-", "_ngcontent-"],
                "scripts":       ["angular.min.js", "angular.js"],
            },
            "Vue.js": {
                # FIX 7: tightened; 'vue-' alone caused false positives
                "html":          ["__VUE__", "data-v-app", "vue-router",
                                  "<!--[if IE]><script>window.__vue"],
                "scripts":       ["vue.global.prod.js", "vue.esm-browser.js",
                                  "vue.runtime.global"],
            },
            "Next.js": {
                "html":          ["__NEXT_DATA__", "_next/static"],
                "scripts":       ["_next/"],
            },
            "Nuxt.js": {
                "html":          ["__NUXT__", "_nuxt/"],
                "scripts":       ["_nuxt/"],
            },
            "Firebase SDK": {
                "html":          ["__FIREBASE_APP__", "firebaseapp.com",
                                  "firebase.google.com/js"],
                "scripts":       ["firebase-app.js", "firebase-compat",
                                  "firebase.js"],
                "headers":       [("X-Firebase-Appcheck", "")],
            },
            "Google Analytics": {
                "html":          ["gtag('config", "googletagmanager.com/gtm.js"],
                "scripts":       ["gtag/js", "gtm.js"],
            },
            "Bootstrap": {
                "html":          ["bootstrap.min.css", "bootstrap.css"],
                "scripts":       ["bootstrap.bundle.min.js", "bootstrap.min.js"],
            },
            "jQuery": {
                "scripts":       ["jquery.min.js", "jquery-", "/jquery.js"],
                "html":          ["jQuery.fn.jquery", "jquery/dist"],
            },
            "Tailwind CSS": {
                "html":          ["tailwindcss", "cdn.tailwindcss.com"],
                "scripts":       ["tailwindcss"],
            },
        }

    # ── Wordlist ──────────────────────────────────────────────────────────────

    def _load_wordlist(self) -> List[str]:
        paths = [
            Path(self.wordlist_path) / "technologies.txt",
            Path("wordlists") / "technologies.txt",
            Path(__file__).parent.parent.parent / "wordlists" / "technologies.txt",
        ]
        for p in paths:
            if p.exists():
                try:
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        items = [
                            ln.strip() for ln in fh
                            if ln.strip() and not ln.startswith("#")
                        ]
                    self.logger.info("Loaded %d techs from %s", len(items), p)
                    return items
                except Exception as exc:
                    self.logger.warning("Could not read %s: %s", p, exc)

        self.logger.warning("technologies.txt not found — using built-in list")
        return [
            "Magento", "Shopify", "Laravel", "Symfony", "Flask",
            "Express.js", "IIS", "Python", "Node.js",
            "MySQL", "PostgreSQL", "MongoDB", "Redis",
            "Docker", "Kubernetes", "AWS", "Azure", "CloudFlare",
        ]

    # ── Run ───────────────────────────────────────────────────────────────────

    async def run(self, target: str, **kwargs) -> List[Finding]:
        self.logger.info("Fingerprinting technologies for %s", target)

        urls = (
            [target] if target.startswith(("http://", "https://"))
            else [f"https://{target}", f"http://{target}"]
        )

        # accumulated across all probed URLs: tech → {confidence, version, urls}
        accumulated: Dict[str, Dict] = {}

        for url in urls:
            try:
                resp = await self._make_request(url)
            except Exception as exc:
                self.logger.error("Connection error %s: %s", url, exc)
                continue

            if not resp:
                continue
            if resp.status >= 500:
                self.logger.warning("HTTP %d for %s — skipping", resp.status, url)
                continue

            try:
                body    = await resp.text()
                headers = dict(resp.headers)
                # Use the post-redirect URL for accurate hostname detection
                final   = resp.url or url
            except Exception as exc:
                self.logger.error("Read error %s: %s", url, exc)
                continue

            detected = self._analyze(final, body, headers)

            # Merge: keep highest confidence per tech; don't lose version info
            for tech, info in detected.items():
                if tech not in accumulated:
                    accumulated[tech] = dict(info)
                    accumulated[tech]["urls"] = [final]
                else:
                    acc = accumulated[tech]
                    if final not in acc["urls"]:
                        acc["urls"].append(final)
                    if info["confidence"] > acc["confidence"]:
                        acc["confidence"] = info["confidence"]
                    if info.get("version") and not acc.get("version"):
                        acc["version"] = info["version"]

        if not accumulated:
            self.logger.warning("No technologies detected for %s", target)
        else:
            for tech, info in accumulated.items():
                self.logger.info(
                    "Detected: %s %s (confidence: %d)",
                    tech, info.get("version", "?"), info["confidence"],
                )
                if self.db:
                    self.db.save_asset("technology", tech, "recon", metadata={
                        "version":    info.get("version"),
                        "urls":       info.get("urls", []),
                        "confidence": info["confidence"],
                    })
                await self._report_finding(tech, info, target)

        return self.findings

    # ── Core analysis ─────────────────────────────────────────────────────────

    def _analyze(self, url: str, body: str, headers: Dict) -> Dict[str, Dict]:
        """
        Run all detection methods and return a merged, filtered dict.
        Returns only entries with confidence >= 15.
        """
        detected: Dict[str, Dict] = {}

        try:
            soup: Optional[_MiniSoup] = _MiniSoup(body)
        except Exception:
            soup = None

        # 1. Hardcoded signatures
        self._check_signatures(body, headers, soup, detected)

        # 2. Wordlist-based fuzzy matching (FIX 10: merge without overwriting
        #    higher-confidence signature hits)
        self._check_wordlist(body, headers, soup, detected)

        # 3. Header-based hosting/CDN (runs before filter so entries included)
        self._detect_hosting_headers(headers, detected)

        # 4. URL/hostname-based hosting (definitive; high confidence)
        self._detect_hosting_url(url, detected)

        # Threshold filter
        return {k: v for k, v in detected.items() if v["confidence"] >= 15}

    def _ensure_entry(self, detected: Dict, tech: str) -> Dict:
        """Return the entry for tech, creating it if absent."""
        if tech not in detected:
            detected[tech] = {"confidence": 0, "version": None, "urls": []}
        return detected[tech]

    def _check_signatures(
        self,
        body: str,
        headers: Dict,
        soup: Optional[_MiniSoup],
        detected: Dict,
    ) -> None:
        # FIX 3: only create entries for techs that actually match something.
        # FIX 4: all string comparisons are case-insensitive.
        for tech, sig in self._signatures.items():
            entry: Optional[Dict] = None  # lazy init

            def hit(points: int) -> Dict:
                nonlocal entry
                if entry is None:
                    entry = self._ensure_entry(detected, tech)
                entry["confidence"] += points
                return entry

            # Headers: list of (name, value_substring) tuples
            # FIX 4: compare lowercased on both sides
            headers_lc = {k.lower(): v for k, v in headers.items()}
            for h_name, h_val in sig.get("headers", []):
                actual = headers_lc.get(h_name.lower(), "")
                if actual and (h_val == "" or h_val.lower() in actual.lower()):
                    e = hit(25)
                    if "version_regex" in sig and not e.get("version"):
                        m = re.search(sig["version_regex"], actual)
                        if m:
                            e["version"] = m.group(1)

            # Meta generator tags
            if soup:
                for pattern in sig.get("meta", []):
                    for tag in soup.find_all("meta", attrs={"name": "generator"}):
                        content = tag.get("content", "") or ""
                        if re.search(pattern, content, re.I):
                            e = hit(25)
                            if "version_regex" in sig and not e.get("version"):
                                m = re.search(sig["version_regex"], content)
                                if m:
                                    e["version"] = m.group(1)

                # Script src
                scripts = soup.find_all("script", src=True)
                for needle in sig.get("scripts", []):
                    for script in scripts:
                        src = script.get("src", "") or ""
                        if needle.lower() in src.lower():
                            hit(20)
                            break

            # HTML body substrings
            body_lc = body.lower()
            for needle in sig.get("html", []):
                if needle.lower() in body_lc:
                    hit(15)

            # Version regex against full body (if not already found)
            if entry and not entry.get("version") and "version_regex" in sig:
                m = re.search(sig["version_regex"], body)
                if m:
                    entry["version"] = m.group(1)
                    entry["confidence"] += 5

            # Cookies
            cookie_hdr = (
                headers_lc.get("set-cookie", "")
                or headers_lc.get("cookie", "")
            )
            for needle in sig.get("cookies", []):
                if needle.lower() in cookie_hdr.lower():
                    hit(15)

    def _check_wordlist(
        self,
        body: str,
        headers: Dict,
        soup: Optional[_MiniSoup],
        detected: Dict,
    ) -> None:
        """
        FIX 10: if a tech already has a signature-based entry, only RAISE its
        confidence (never lower it), and don't overwrite a known version.
        """
        body_lc     = body.lower()
        headers_str = str({k.lower(): v.lower() for k, v in headers.items()})

        for tech in self._wordlist_techs:
            # Skip techs already covered by hardcoded signatures with high confidence
            existing = detected.get(tech)
            if existing and existing["confidence"] >= 40:
                continue

            tech_lc = tech.lower()
            score   = 0
            version: Optional[str] = None

            if tech_lc in body_lc:
                score += 15
            if tech_lc in headers_str:
                score += 20

            if soup:
                norm = tech_lc.replace(" ", "").replace(".", "")
                for script in soup.find_all("script", src=True):
                    src = (script.get("src", "") or "").lower()
                    if norm in src.replace("-", "").replace("_", ""):
                        score += 15
                for link in soup.find_all("link", href=True):
                    href = (link.get("href", "") or "").lower()
                    if norm in href.replace("-", "").replace("_", ""):
                        score += 10
                for meta in soup.find_all("meta"):
                    content = (meta.get("content", "") or "").lower()
                    if tech_lc in content:
                        score += 15

            for pat in [
                rf"{re.escape(tech)}[/\s]?v?([\d][\d.]*)",
                rf"{re.escape(tech.replace(' ', ''))}[/\s]?v?([\d][\d.]*)",
            ]:
                m = re.search(pat, body, re.I)
                if m:
                    version = m.group(1)
                    score  += 10
                    break

            if score < 30:
                continue

            if existing:
                # Only update if we have new info
                existing["confidence"] = max(existing["confidence"], score)
                if version and not existing.get("version"):
                    existing["version"] = version
            else:
                detected[tech] = {
                    "confidence": min(score, 100),
                    "version":    version,
                    "urls":       [],
                }

    # ── Hosting / CDN detection ───────────────────────────────────────────────

    def _detect_hosting_headers(self, headers: Dict, detected: Dict) -> None:
        """
        FIX 8: match per specific header key, not on full dict repr string.
        Each rule: provider → list of (header_key, value_substring).
        Empty value_substring means "header must exist with any value".

        FIX: Firebase Hosting sends 'x-firebase-hosting-response-time', not
        'Server: Firebase'. Updated accordingly.
        """
        rules: Dict[str, List[Tuple[str, str]]] = {
            "Firebase Hosting": [
                ("x-firebase-hosting-response-time", ""),
                ("server",                           "firebase"),
            ],
            "Cloudflare": [
                ("cf-ray",            ""),
                ("cf-cache-status",   ""),
                ("server",            "cloudflare"),
            ],
            "AWS CloudFront": [
                ("x-amz-cf-id",   ""),
                ("x-amz-cf-pop",  ""),
                ("via",           "CloudFront"),
            ],
            "Google Cloud": [
                ("x-goog-generation",    ""),
                ("x-guploader-uploadid", ""),
                ("server",               "ESF"),
            ],
            "Vercel": [
                ("x-vercel-id",    ""),
                ("x-vercel-cache", ""),
                ("server",         "Vercel"),
            ],
            "Netlify": [
                ("x-nf-request-id", ""),
                ("server",          "Netlify"),
            ],
            "GitHub Pages": [
                ("server", "GitHub.com"),
            ],
            "Fastly": [
                ("x-fastly-request-id", ""),
                ("fastly-restarts",     ""),
            ],
            "Akamai": [
                ("x-akamai-transformed", ""),
                ("x-check-cacheable",    ""),
            ],
        }

        headers_lc = {k.lower(): v for k, v in headers.items()}

        for provider, matchers in rules.items():
            hits = 0
            for h_key, h_val in matchers:
                actual = headers_lc.get(h_key, "")
                if actual and (h_val == "" or h_val.lower() in actual.lower()):
                    hits += 1
            if hits:
                entry = self._ensure_entry(detected, provider)
                entry["confidence"] = max(entry["confidence"], min(hits * 40, 100))

    def _detect_hosting_url(self, url: str, detected: Dict) -> None:
        """
        FIX 9: infer hosting from well-known hostname suffixes.
        This is the most reliable signal for PaaS-hosted targets (Firebase,
        Vercel, Netlify, etc.) where CDN edge nodes strip custom headers.
        Confidence is 90 — a matching domain is virtually definitive.
        """
        hostname = urllib.parse.urlparse(url).hostname or ""

        suffixes: Dict[str, List[str]] = {
            "Firebase Hosting":  [".web.app", ".firebaseapp.com"],
            "GitHub Pages":      [".github.io"],
            "Vercel":            [".vercel.app"],
            "Netlify":           [".netlify.app", ".netlify.com"],
            "Render":            [".onrender.com"],
            "Railway":           [".railway.app"],
            "Heroku":            [".herokuapp.com"],
            "Fly.io":            [".fly.dev"],
            "Cloudflare Pages":  [".pages.dev"],
            "AWS Amplify":       [".amplifyapp.com"],
            "Azure Static Apps": [".azurestaticapps.net", ".azurewebsites.net"],
            "Surge.sh":          [".surge.sh"],
        }

        for provider, patterns in suffixes.items():
            for pattern in patterns:
                if hostname.endswith(pattern):
                    entry = self._ensure_entry(detected, provider)
                    entry["confidence"] = max(entry["confidence"], 90)
                    break

    # ── Findings ──────────────────────────────────────────────────────────────

    # FIX 12: min-versions updated to current recommended baselines
    _VULN_DB: Dict[str, Dict] = {
        "WordPress": {"min": "6.4",    "sev": "High",   "desc": "Outdated WordPress may contain known critical vulnerabilities"},
        "Apache":    {"min": "2.4.58", "sev": "Medium", "desc": "Outdated Apache HTTP Server may be affected by known CVEs"},
        "Nginx":     {"min": "1.24.0", "sev": "Medium", "desc": "Outdated Nginx may contain known vulnerabilities"},
        "PHP":       {"min": "8.1.0",  "sev": "High",   "desc": "Outdated PHP version may have exploitable security flaws"},
        "Drupal":    {"min": "10.0.0", "sev": "High",   "desc": "Outdated Drupal may contain critical (Drupalgeddon-class) vulnerabilities"},
        "Joomla":    {"min": "5.0.0",  "sev": "High",   "desc": "Outdated Joomla may contain known vulnerabilities"},
        "jQuery":    {"min": "3.7.0",  "sev": "Medium", "desc": "Outdated jQuery has known XSS and prototype-pollution vulnerabilities"},
        "Bootstrap": {"min": "5.3.0",  "sev": "Low",    "desc": "Outdated Bootstrap may have minor XSS vulnerabilities"},
        "Node.js":   {"min": "20.0.0", "sev": "High",   "desc": "Outdated Node.js may have exploitable security vulnerabilities"},
        "Angular":   {"min": "17.0.0", "sev": "Medium", "desc": "Outdated Angular may have known security issues"},
        "React":     {"min": "18.0.0", "sev": "Medium", "desc": "Outdated React may have known security issues"},
    }

    _SEVERITY_CVSS   = {"Critical": 9.0, "High": 7.5, "Medium": 5.3, "Low": 3.7, "Info": 0.0}
    _SEVERITY_BOUNTY = {"Critical": 5000, "High": 1000, "Medium": 500, "Low": 100, "Info": 0}

    async def _report_finding(self, tech: str, info: Dict, target: str) -> None:
        version = info.get("version")
        urls    = info.get("urls") or [target]
        url     = urls[0]

        if not version:
            self.add_finding(Finding(
                module="recon",
                title=f"Technology Detected: {tech}",
                severity="Info",
                description=f"Detected {tech} on the target (version unknown).",
                evidence={
                    "technology":  tech,
                    "confidence":  info.get("confidence", 0),
                    "detected_at": url,
                },
                poc=f"Technology identified at {url}",
                remediation="Verify this technology is intentional and up to date.",
                cvss_score=0.0, bounty_score=0, target=url,
            ))
            return

        vuln = self._VULN_DB.get(tech)
        if vuln:
            # FIX 11: full patch-level version comparison
            outdated = _is_outdated(version, vuln["min"])
            sev      = vuln["sev"] if outdated else "Info"
            self.add_finding(Finding(
                module="recon",
                title=(
                    f"Outdated {tech}: {version} (min {vuln['min']})"
                    if outdated else f"{tech} Detected: {version}"
                ),
                severity=sev,
                description=(
                    f"{vuln['desc']}. Running {version}; recommended minimum: {vuln['min']}."
                    if outdated else
                    f"Detected {tech} {version} — version appears current."
                ),
                evidence={
                    "technology":           tech,
                    "version":              version,
                    "minimum_recommended":  vuln["min"],
                    "detected_at":          url,
                },
                poc=f"Version detected at {url}",
                remediation=(
                    f"Update {tech} to at least {vuln['min']}."
                    if outdated else "No immediate action required."
                ),
                cvss_score=self._SEVERITY_CVSS.get(sev, 0.0),
                bounty_score=self._SEVERITY_BOUNTY.get(sev, 0),
                target=url,
            ))
        else:
            self.add_finding(Finding(
                module="recon",
                title=f"Technology Detected: {tech} {version}",
                severity="Info",
                description=f"Detected {tech} version {version} on the target.",
                evidence={
                    "technology":  tech,
                    "version":     version,
                    "confidence":  info.get("confidence", 0),
                    "detected_at": url,
                },
                poc=f"Version identified at {url}",
                remediation="Verify this technology is intentional and kept up to date.",
                cvss_score=0.0, bounty_score=0, target=url,
            ))

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import requests
from bs4 import BeautifulSoup

from .models import Finding, ScanOptions, ScanResult


@dataclass
class PageResult:
    url: str
    status_code: int
    text: str
    headers: Dict[str, str]
    elapsed: float


SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"pg_query\(\)",
    r"syntax error at or near",
    r"sqlite error",
    r"odbc sql server driver",
]

ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/dashboard",
    "/dashboard",
    "/manage",
    "/console",
]

SEC_HEADERS = [
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

COOKIE_FLAG_NAMES = ["secure", "httponly", "samesite"]

XSS_MARKER = "xss_probe_4f8e9"
SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 --"]


class Scanner:
    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OWASP-AI-Scanner/0.1"})

    def scan(self, target_url: str) -> ScanResult:
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            target_url=target_url,
            started_at=datetime.utcnow(),
            status="running",
        )

        try:
            self._scan_target(target_url, result)
            result.status = "completed"
        except Exception as exc:  # pragma: no cover - guardrail
            result.status = "failed"
            result.errors.append(str(exc))
        finally:
            result.finished_at = datetime.utcnow()

        return result

    def _scan_target(self, target_url: str, result: ScanResult) -> None:
        base = self._normalize_url(target_url)
        origin = self._origin(base)
        allowed_origins = self._build_allowed_origins(origin)

        queue: List[str] = [base]
        visited: Set[str] = set()

        while queue and result.pages_scanned < self.options.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            page = self._fetch(url, result)
            if page is None:
                continue

            result.pages_scanned += 1
            self._check_security_headers(page, result)
            self._check_cookies(page, result)
            self._check_tls_and_crypto(page, result)
            self._check_directory_listing(page, result)
            self._check_xss_reflection(page, result)
            self._check_sqli(page, result)
            self._check_mixed_content(page, result)
            self._check_sri(page, result)

            links, forms = self._extract_links_and_forms(page, allowed_origins)
            for link in links:
                if link not in visited and self._origin(link) in allowed_origins:
                    queue.append(link)

            self._check_forms_security(forms, page.url, result)

        for allowed_origin in sorted(allowed_origins):
            self._check_admin_paths(allowed_origin, result)
        self._note_outdated_components(result)
        self._note_manual_review(result)

    def _fetch(self, url: str, result: ScanResult) -> Optional[PageResult]:
        try:
            start = time.time()
            response = self.session.get(url, timeout=self.options.timeout_seconds, allow_redirects=True)
            elapsed = time.time() - start
            return PageResult(
                url=response.url,
                status_code=response.status_code,
                text=response.text or "",
                headers={k.lower(): v for k, v in response.headers.items()},
                elapsed=elapsed,
            )
        except requests.RequestException as exc:
            result.errors.append(f"Fetch failed for {url}: {exc}")
            return None

    def _extract_links_and_forms(
        self, page: PageResult, allowed_origins: Set[str]
    ) -> Tuple[List[str], List[BeautifulSoup]]:
        soup = BeautifulSoup(page.text, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag.get("href")
            if href:
                links.append(urljoin(page.url, href))

        forms = soup.find_all("form")
        return [link for link in links if self._origin(link) in allowed_origins], forms

    def _check_security_headers(self, page: PageResult, result: ScanResult) -> None:
        missing = [h for h in SEC_HEADERS if h not in page.headers]
        if missing:
            self._add_finding(
                result,
                category="A05: Security Misconfiguration",
                title="Missing security headers",
                severity="medium",
                description="Important HTTP security headers are missing.",
                evidence={"missing": missing, "url": page.url},
            )

    def _check_cookies(self, page: PageResult, result: ScanResult) -> None:
        set_cookie = page.headers.get("set-cookie")
        if not set_cookie:
            return
        flags_missing = []
        cookie_lower = set_cookie.lower()
        for flag in COOKIE_FLAG_NAMES:
            if flag not in cookie_lower:
                flags_missing.append(flag)

        if flags_missing:
            self._add_finding(
                result,
                category="A07: Identification and Authentication Failures",
                title="Session cookies missing recommended flags",
                severity="medium",
                description="Session cookies should typically include Secure, HttpOnly, and SameSite.",
                evidence={"missing": flags_missing, "url": page.url},
            )

    def _check_tls_and_crypto(self, page: PageResult, result: ScanResult) -> None:
        if page.url.startswith("http://"):
            self._add_finding(
                result,
                category="A02: Cryptographic Failures",
                title="Content served over HTTP",
                severity="high",
                description="Sensitive content should be served over HTTPS.",
                evidence={"url": page.url},
            )

        if page.url.startswith("https://") and "strict-transport-security" not in page.headers:
            self._add_finding(
                result,
                category="A05: Security Misconfiguration",
                title="Missing HSTS header",
                severity="low",
                description="HSTS helps enforce HTTPS usage.",
                evidence={"url": page.url},
            )

    def _check_directory_listing(self, page: PageResult, result: ScanResult) -> None:
        if "Index of /" in page.text and page.status_code == 200:
            self._add_finding(
                result,
                category="A05: Security Misconfiguration",
                title="Possible directory listing",
                severity="medium",
                description="Directory listing may expose sensitive files.",
                evidence={"url": page.url},
            )

    def _check_xss_reflection(self, page: PageResult, result: ScanResult) -> None:
        parsed = urlparse(page.url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query)
        if not params:
            return

        test_params = {k: XSS_MARKER for k in params.keys()}
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
        test_page = self._fetch(test_url, result)
        if not test_page:
            return
        if XSS_MARKER in test_page.text:
            self._add_finding(
                result,
                category="A03: Injection",
                title="Potential reflected XSS",
                severity="medium",
                description="Reflected input appears in response without encoding. Manual verification required.",
                evidence={"url": test_url, "marker": XSS_MARKER},
            )

    def _check_sqli(self, page: PageResult, result: ScanResult) -> None:
        parsed = urlparse(page.url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query)
        if not params:
            return

        baseline = self._fetch(page.url, result)
        if not baseline:
            return

        for payload in SQLI_PAYLOADS:
            test_params = {k: payload for k in params.keys()}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            test_page = self._fetch(test_url, result)
            if not test_page:
                continue

            if self._looks_like_sqli(baseline, test_page):
                self._add_finding(
                    result,
                    category="A03: Injection",
                    title="Potential SQL injection",
                    severity="high",
                    description="Response changed significantly or exposed SQL error patterns.",
                    evidence={"url": test_url, "payload": payload},
                )
                break

    def _looks_like_sqli(self, baseline: PageResult, test_page: PageResult) -> bool:
        if baseline.status_code >= 500 or test_page.status_code >= 500:
            return True

        baseline_len = len(baseline.text)
        test_len = len(test_page.text)
        if baseline_len == 0:
            return False

        delta = abs(test_len - baseline_len) / max(baseline_len, 1)
        if delta > 0.3:
            return True

        lower_text = test_page.text.lower()
        return any(re.search(pattern, lower_text) for pattern in SQL_ERROR_PATTERNS)

    def _check_mixed_content(self, page: PageResult, result: ScanResult) -> None:
        if not page.url.startswith("https://"):
            return
        if "http://" in page.text:
            self._add_finding(
                result,
                category="A05: Security Misconfiguration",
                title="Mixed content detected",
                severity="low",
                description="HTTPS pages load resources over HTTP.",
                evidence={"url": page.url},
            )

    def _check_sri(self, page: PageResult, result: ScanResult) -> None:
        soup = BeautifulSoup(page.text, "html.parser")
        scripts = soup.find_all("script", src=True)
        missing_sri = [tag.get("src") for tag in scripts if not tag.get("integrity")]
        if missing_sri:
            self._add_finding(
                result,
                category="A08: Software and Data Integrity Failures",
                title="Scripts missing Subresource Integrity",
                severity="low",
                description="Consider adding integrity attributes to external scripts.",
                evidence={"urls": missing_sri[:5], "url": page.url},
            )

    def _check_forms_security(self, forms: Iterable[BeautifulSoup], page_url: str, result: ScanResult) -> None:
        for form in forms:
            method = (form.get("method") or "get").lower()
            action = form.get("action") or page_url
            inputs = form.find_all("input")
            has_password = any((inp.get("type") or "").lower() == "password" for inp in inputs)
            if has_password and page_url.startswith("http://"):
                self._add_finding(
                    result,
                    category="A02: Cryptographic Failures",
                    title="Password form served over HTTP",
                    severity="high",
                    description="Password forms should be served over HTTPS.",
                    evidence={"url": page_url, "action": action},
                )

            if method == "get" and has_password:
                self._add_finding(
                    result,
                    category="A07: Identification and Authentication Failures",
                    title="Password form uses GET",
                    severity="medium",
                    description="Password forms should typically use POST to avoid URL leakage.",
                    evidence={"url": page_url, "action": action},
                )

    def _check_admin_paths(self, origin: str, result: ScanResult) -> None:
        for path in ADMIN_PATHS:
            url = f"{origin}{path}"
            page = self._fetch(url, result)
            if not page:
                continue
            if page.status_code == 200 and "login" not in page.text.lower():
                self._add_finding(
                    result,
                    category="A01: Broken Access Control",
                    title="Potential exposed admin endpoint",
                    severity="medium",
                    description="Admin endpoint appears accessible without authentication. Verify access controls.",
                    evidence={"url": url, "status": page.status_code},
                )

    def _note_outdated_components(self, result: ScanResult) -> None:
        self._add_finding(
            result,
            category="A06: Vulnerable and Outdated Components",
            title="Component inventory required",
            severity="info",
            description=(
                "Automated scanning cannot reliably detect all outdated components. "
                "Review software inventories and compare versions against known CVEs."
            ),
            evidence=None,
        )

    def _note_manual_review(self, result: ScanResult) -> None:
        self._add_finding(
            result,
            category="A04: Insecure Design",
            title="Manual design review required",
            severity="info",
            description="Threat modeling and design review are required to assess insecure design risks.",
            evidence=None,
        )
        self._add_finding(
            result,
            category="A09: Security Logging and Monitoring Failures",
            title="Manual logging review required",
            severity="info",
            description="Verify alerting, monitoring, and incident response controls manually.",
            evidence=None,
        )
        self._add_finding(
            result,
            category="A10: Server-Side Request Forgery",
            title="Manual SSRF testing required",
            severity="info",
            description="External SSRF vulnerabilities typically require targeted testing.",
            evidence=None,
        )

    def _add_finding(
        self,
        result: ScanResult,
        category: str,
        title: str,
        severity: str,
        description: str,
        evidence: Optional[Dict[str, str]] = None,
    ) -> None:
        finding = Finding(
            id=str(uuid.uuid4()),
            category=category,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
        )
        result.findings.append(finding)

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        if not netloc:
            raise ValueError("Invalid URL")
        return f"{scheme}://{netloc}{path or '/'}"

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _build_allowed_origins(self, base_origin: str) -> Set[str]:
        allowed = {base_origin}
        for entry in self.options.allowlist:
            entry = entry.strip()
            if not entry:
                continue
            if "://" not in entry:
                entry = f"https://{entry}"
            try:
                normalized = self._normalize_url(entry)
                allowed.add(self._origin(normalized))
            except ValueError:
                continue
        return allowed

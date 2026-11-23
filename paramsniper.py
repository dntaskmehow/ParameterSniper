import argparse
import asyncio
import json
import re
import socket
import ssl
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

DEFAULT_PARAMS: Dict[str, str] = {
    "id": "1",
    "page": "1",
    "limit": "10",
    "offset": "0",
    "sort": "asc",
    "order": "asc",
    "filter": "all",
    "search": "test",
    "query": "test",
    "q": "test",
    "category": "general",
    "tag": "default",
    "type": "item",
    "format": "json",
    "view": "summary",
    "lang": "en",
    "debug": "0",
    "test": "0",
    "role": "user",
    "status": "active",
    "action": "list",
    "callback": "cb",
    "endpoint": "default",
    "include": "basic",
    "fields": "id",
}

API_CANDIDATE_PATHS: Tuple[str, ...] = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/health",
    "/api/status",
    "/api/users",
    "/api/items",
    "/api/config",
    "/graphql",
    "/openapi.json",
    "/swagger.json",
    "/wp-json",
    "/wp-json/wp/v2/posts",
)

SCHEMA_PATHS: Tuple[str, ...] = ("/openapi.json", "/swagger.json")

HEADER_VARIATIONS: Tuple[Dict[str, str], ...] = (
    {"User-Agent": "ParamSniperTUI/7.0 (FerobusterTheme)"},
    {"User-Agent": "ParamSniperTUI/7.0", "X-Requested-With": "XMLHttpRequest"},
    {"User-Agent": "ParamSniperTUI/7.0", "X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/"},
    {"User-Agent": "ParamSniperTUI/7.0", "Accept": "application/json"},
)

DEBUG_MARKERS: Tuple[str, ...] = (
    "traceback (most recent call last)",
    "stack trace",
    "unhandled exception",
    "system.nullreferenceexception",
    "fatal error:",
    "at java.",
    "at org.springframework",
    "error: at ",
)

DB_MARKERS: Tuple[str, ...] = (
    "sql syntax",
    "mysql_fetch",
    "ora-009",
    "ora-017",
    "pg::syntaxerror",
    "sqlite3::",
    "pdoexception",
    "database error",
    "unclosed quotation mark",
    "sqlstate[",
)

CMS_MARKERS: Tuple[str, ...] = (
    "/wp-content/",
    "/wp-includes/",
    "/wp-json/",
    "wp-admin",
    "wordpress",
)

AJAX_PATTERNS: Tuple[str, ...] = (
    r"\bfetch\s*\(",
    r"\bxmlhttprequest\b",
    r"\baxios\.",
    r"\$\.(?:ajax|get|post)\s*\(",
    r"/api/v[0-9]+/",
    r"/graphql\b",
)

NODE_MARKERS: Tuple[str, ...] = (
    "__next_data__",
    "next.js",
    "nuxt",
    "express",
    "x-powered-by: express",
    "node_modules",
    "webpack",
    "vite",
)

FRONTEND_MARKERS: Tuple[str, ...] = (
    "<!doctype html",
    "<html",
    "<div id=\"root\"",
    "<div id=\"app\"",
    "react",
    "vue",
    "angular",
    "svelte",
    "tailwind",
)

BACKEND_MARKERS: Tuple[str, ...] = (
    "application/json",
    "application/problem+json",
    "django",
    "flask",
    "fastapi",
    "laravel",
    "symfony",
    "asp.net",
    "werkzeug",
    "uvicorn",
    "gunicorn",
)

SECURITY_HEADERS: Tuple[str, ...] = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)

CLOUD_MARKERS: Tuple[str, ...] = (
    "x-amz-",
    "x-goog-",
    "x-azure-",
    "cf-ray",
    "cloudfront",
    "akamai",
)

AUTH_MARKERS: Tuple[str, ...] = (
    "bearer ",
    "authorization",
    "set-cookie",
    "csrf",
    "xsrf",
    "session",
)


@dataclass
class ProbeTask:
    label: str
    url: str
    headers: Dict[str, str]
    stage: str


@dataclass
class AuditFinding:
    variant: str
    stage: str
    url: str
    status: str
    latency_ms: float
    bytes_read: int
    size_delta: int
    latency_delta_ms: float
    architecture: str
    discovered_params: List[str]
    discovered_apis: List[str]
    findings: List[str]

    @property
    def findings_text(self) -> str:
        return ", ".join(self.findings) if self.findings else "none"


class ParamSniperTUI:
    def __init__(
        self,
        target_url: str,
        params: Dict[str, str],
        concurrency: int = 6,
        timeout: float = 4.0,
        view_mode: str = "flagged",
    ) -> None:
        parsed = urlparse(target_url)
        existing_query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        self.clean_base_url = urlunparse(parsed._replace(query="", fragment=""))
        self.root_origin = (
            f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else self.clean_base_url
        )
        self.params = {**DEFAULT_PARAMS, **existing_query, **params}
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.view_mode = view_mode if view_mode in ("flagged", "all", "chains") else "flagged"

        self.completed = 0
        self.total = 0
        self.rate_limited_count = 0
        self.backoff_lock = asyncio.Lock()
        self.status_counts: Counter[str] = Counter()
        self.all_findings: List[AuditFinding] = []
        self.flagged_findings: List[AuditFinding] = []
        self.correlated_chains: List[str] = []
        self.discovered_params: Set[str] = set(self.params.keys())
        self.discovered_apis: Set[str] = set()
        self.schema_paths: Set[str] = set()
        self.cert_info: Dict[str, object] = {"status": "Pending"}
        self.architecture_summary = "Detecting..."
        self.baseline_status: Optional[str] = None
        self.baseline_bytes: Optional[int] = None
        self.baseline_latency_ms: Optional[float] = None
        self.done_event = asyncio.Event()
        self.export_status = "Not exported"

    def _parse_cert_expiry(self, not_after_str: str) -> Tuple[Optional[int], str]:
        try:
            exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp_dt - datetime.now(timezone.utc)).days
            if days_left < 0:
                return days_left, "EXPIRED"
            if days_left <= 30:
                return days_left, f"EXPIRING ({days_left}d)"
            return days_left, f"OK ({days_left}d)"
        except Exception:
            return None, "UNPARSED"

    def _inspect_ssl_tls(self) -> Dict[str, object]:
        parsed = urlparse(self.clean_base_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return {"status": "HTTP (no TLS)", "tls_version": "none", "cipher": "none", "expiry_state": "N/A"}

        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as sock:
                    cert = sock.getpeercert()
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    san_entries = [
                        entry[1]
                        for entry in cert.get("subjectAltName", ())
                        if isinstance(entry, tuple) and len(entry) >= 2
                    ]
                    not_after = str(cert.get("notAfter", ""))
                    days_left, expiry_state = self._parse_cert_expiry(not_after)
                    cipher_info = sock.cipher()
                    return {
                        "status": "Verified TLS",
                        "host": host,
                        "port": port,
                        "tls_version": sock.version() or "unknown",
                        "cipher": cipher_info[0] if cipher_info else "unknown",
                        "subject_cn": str(subject.get("commonName", "unknown")),
                        "issuer_cn": str(issuer.get("commonName", "unknown")),
                        "not_after": not_after or "unknown",
                        "days_remaining": days_left if days_left is not None else "unknown",
                        "expiry_state": expiry_state,
                        "san_count": len(san_entries),
                        "san_preview": san_entries[:5],
                    }
        except Exception as exc:
            return {
                "status": f"TLS error ({type(exc).__name__})",
                "host": host,
                "port": port,
                "expiry_state": "CHECK_FAILED",
                "detail": str(exc),
            }

    def _discover_openapi_schema(self) -> Tuple[Set[str], Set[str]]:
        found_paths: Set[str] = set()
        found_params: Set[str] = set()
        for spath in SCHEMA_PATHS:
            url = f"{self.root_origin}{spath}"
            req = Request(url, method="GET", headers={"User-Agent": "ParamSniperTUI/7.0", "Accept": "application/json"})
            try:
                with urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read(262144).decode("utf-8", errors="ignore")
                    doc = json.loads(raw)
            except Exception:
                continue

            if not isinstance(doc, dict):
                continue
            paths_obj = doc.get("paths")
            if isinstance(paths_obj, dict):
                for p_key, methods_obj in paths_obj.items():
                    if isinstance(p_key, str) and p_key.startswith("/"):
                        found_paths.add(p_key)
                    if isinstance(methods_obj, dict):
                        for _, op_obj in methods_obj.items():
                            if isinstance(op_obj, dict):
                                op_params = op_obj.get("parameters", [])
                                if isinstance(op_params, list):
                                    for prm in op_params:
                                        if isinstance(prm, dict) and isinstance(prm.get("name"), str):
                                            found_params.add(prm["name"])
        return found_paths, found_params

    def _build_tasks(self) -> List[ProbeTask]:
        tasks: List[ProbeTask] = []
        base_query = urlencode(self.params)
        base_target = f"{self.clean_base_url}?{base_query}" if base_query else self.clean_base_url

        tasks.append(ProbeTask("baseline", base_target, dict(HEADER_VARIATIONS[0]), "baseline"))
        for idx, hdrs in enumerate(HEADER_VARIATIONS[1:], start=1):
            tasks.append(ProbeTask(f"hdr-profile:{idx}", base_target, dict(hdrs), "header-variation"))

        for key, val in self.params.items():
            mutated = dict(self.params)
            mutated[key] = f"{val}_mutated"
            tasks.append(
                ProbeTask(
                    f"mutate:{key}",
                    f"{self.clean_base_url}?{urlencode(mutated)}",
                    dict(HEADER_VARIATIONS[0]),
                    "param-mutation",
                )
            )
            polluted_items = list(self.params.items()) + [(key, f"{val}_polluted")]
            tasks.append(
                ProbeTask(
                    f"pollute:{key}",
                    f"{self.clean_base_url}?{urlencode(polluted_items)}",
                    dict(HEADER_VARIATIONS[0]),
                    "param-pollution",
                )
            )

        combined_apis = list(dict.fromkeys((*API_CANDIDATE_PATHS, *sorted(self.schema_paths))))
        for api_path in combined_apis[:35]:
            tasks.append(
                ProbeTask(
                    f"api:{api_path}",
                    f"{self.root_origin}{api_path}",
                    dict(HEADER_VARIATIONS[3]),
                    "api-discovery",
                )
            )

        return tasks

    def _extract_params(self, raw_text: str) -> List[str]:
        found_keys: Set[str] = set()
        for match in re.findall(r"(?:name|id)=[\"']([A-Za-z0-9_\-\[\]]{1,40})[\"']", raw_text, flags=re.I):
            found_keys.add(match)
        for match in re.findall(r"[?&]([A-Za-z0-9_\-]{1,40})=", raw_text):
            found_keys.add(match)
        return sorted(found_keys)[:15]

    def _extract_apis(self, raw_text: str) -> List[str]:
        found_apis: Set[str] = set()
        for match in re.findall(r"(/api/[A-Za-z0-9_./-]{1,60}|/graphql\b|/wp-json/[A-Za-z0-9_./-]{1,60})", raw_text):
            found_apis.add(match.rstrip("/.,;\"'"))
        return sorted(found_apis)[:15]

    def _classify_stack(self, combined_lower: str, content_type: str) -> str:
        has_fe = any(m in combined_lower for m in FRONTEND_MARKERS) or "text/html" in content_type
        has_be = (
            any(m in combined_lower for m in BACKEND_MARKERS)
            or any(m in combined_lower for m in NODE_MARKERS)
            or "application/json" in content_type
        )
        if has_fe and has_be:
            return "full-stack"
        if has_fe:
            return "frontend"
        if has_be:
            return "backend"
        return "undetermined"

    def _detect_markers(
        self,
        raw_text: str,
        headers_lower: str,
        content_type: str,
        elapsed_ms: float,
        bytes_read: int,
        status: str,
        size_delta: int,
    ) -> Tuple[List[str], str]:
        body_lower = raw_text.lower()
        combined = f"{headers_lower}\n{body_lower}"
        found: List[str] = []

        if any(marker in body_lower for marker in DEBUG_MARKERS):
            found.append("stacktrace/debug")
        if any(marker in body_lower for marker in DB_MARKERS):
            found.append("sql/database")
        if any(marker in combined for marker in CMS_MARKERS):
            found.append("wordpress/cms")
        if any(re.search(pat, raw_text, flags=re.IGNORECASE) for pat in AJAX_PATTERNS):
            found.append("ajax/api-calls")
        if any(marker in combined for marker in NODE_MARKERS):
            found.append("node/js-runtime")

        missing_sec = [h for h in SECURITY_HEADERS if h not in headers_lower]
        if missing_sec:
            found.append(f"missing-sec-hdrs:{len(missing_sec)}")
        if any(m in combined for m in CLOUD_MARKERS):
            found.append("cdn/cloud-edge")
        if any(m in combined for m in AUTH_MARKERS):
            found.append("auth/session-marker")
        if "access-control-allow-origin" in headers_lower:
            found.append("cors-header")
        if "<form" in body_lower or "multipart/form-data" in body_lower:
            found.append("form-surface")
        if "websocket" in body_lower or "upgrade" in headers_lower:
            found.append("realtime/ws-hint")
        if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", raw_text):
            found.append("email-pattern")
        if re.search(r"(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)", raw_text):
            found.append("internal-host-ref")
        if elapsed_ms >= 1500.0:
            found.append("slow-response")
        if bytes_read >= 32768:
            found.append("large-payload")

        if self.baseline_status is not None and status != self.baseline_status:
            found.append(f"status-shift:{self.baseline_status}->{status}")
        if abs(size_delta) >= 256:
            found.append(f"size-delta:{size_delta:+d}B")

        expiry_state = str(self.cert_info.get("expiry_state", ""))
        if expiry_state.startswith(("EXPIRED", "EXPIRING", "CHECK_FAILED")):
            found.append(f"tls-cert:{expiry_state}")

        arch = self._classify_stack(combined, content_type.lower())
        found.append(f"stack:{arch}")
        return found, arch

    def _update_chains(self, finding: AuditFinding) -> None:
        has_error_signal = any(tag in finding.findings for tag in ("stacktrace/debug", "sql/database"))
        has_surface_signal = bool(
            finding.discovered_apis or finding.discovered_params or "ajax/api-calls" in finding.findings
        )
        if has_error_signal and has_surface_signal:
            chain_desc = f"{finding.variant} -> error-signal + surface-markers ({finding.architecture})"
            if chain_desc not in self.correlated_chains:
                self.correlated_chains.append(chain_desc)
        elif finding.stage == "api-discovery" and finding.status.startswith("2"):
            chain_desc = f"{finding.variant} -> active-api-endpoint ({finding.status})"
            if chain_desc not in self.correlated_chains:
                self.correlated_chains.append(chain_desc)

    def _parse_retry_after(self, retry_hdr: Optional[str]) -> float:
        if not retry_hdr:
            return 1.5
        try:
            return max(0.2, min(10.0, float(retry_hdr.strip())))
        except ValueError:
            try:
                dt = parsedate_to_datetime(retry_hdr)
                delta = (dt - datetime.now(timezone.utc)).total_seconds()
                return max(0.2, min(10.0, delta))
            except Exception:
                return 1.5

    def _send_probe(self, task: ProbeTask) -> Tuple[AuditFinding, Optional[float]]:
        t0 = time.perf_counter()
        req = Request(task.url, method="GET", headers=task.headers)
        body_bytes = b""
        headers_text = ""
        content_type = ""
        retry_after_val: Optional[str] = None
        status = "ERR"
        extra_note = ""

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                status = str(resp.status)
                content_type = resp.headers.get("Content-Type", "")
                retry_after_val = resp.headers.get("Retry-After")
                headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
                body_bytes = resp.read(65536)
        except HTTPError as exc:
            status = str(exc.code)
            content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
            retry_after_val = exc.headers.get("Retry-After") if exc.headers else None
            if exc.headers:
                headers_text = "\n".join(f"{k}: {v}" for k, v in exc.headers.items()).lower()
            if exc.fp:
                body_bytes = exc.read(65536)
        except URLError as exc:
            extra_note = f"network-error:{exc.reason}"
        except Exception as exc:
            extra_note = f"error:{type(exc).__name__}"

        elapsed_ms = (time.perf_counter() - t0) * 1000
        bytes_count = len(body_bytes)

        if self.baseline_status is None:
            self.baseline_status = status
            self.baseline_bytes = bytes_count
            self.baseline_latency_ms = elapsed_ms

        size_delta = bytes_count - (self.baseline_bytes if self.baseline_bytes is not None else bytes_count)
        latency_delta_ms = elapsed_ms - (
            self.baseline_latency_ms if self.baseline_latency_ms is not None else elapsed_ms
        )

        raw_text = body_bytes.decode("utf-8", errors="ignore")
        markers, arch = self._detect_markers(
            raw_text, headers_text, content_type, elapsed_ms, bytes_count, status, size_delta
        )
        extracted_params = self._extract_params(raw_text)
        extracted_apis = self._extract_apis(raw_text)

        backoff_sec: Optional[float] = None
        if status == "429" or retry_after_val is not None:
            backoff_sec = self._parse_retry_after(retry_after_val)
            markers.append(f"rate-limit:backoff-{backoff_sec:.1f}s")

        if extracted_params:
            markers.append(f"params:{','.join(extracted_params[:5])}")
        if extracted_apis:
            markers.append(f"apis:{','.join(extracted_apis[:4])}")
        if extra_note:
            markers.append(extra_note)

        finding = AuditFinding(
            variant=task.label,
            stage=task.stage,
            url=task.url,
            status=status,
            latency_ms=round(elapsed_ms, 2),
            bytes_read=bytes_count,
            size_delta=size_delta,
            latency_delta_ms=round(latency_delta_ms, 2),
            architecture=arch,
            discovered_params=extracted_params,
            discovered_apis=extracted_apis,
            findings=markers,
        )
        return finding, backoff_sec

    async def _worker(
        self, queue: asyncio.Queue[ProbeTask], loop: asyncio.AbstractEventLoop
    ) -> None:
        while True:
            try:
                task = queue.get_nowait()
            except asyncio.QueueEmpty:
                return

            finding, backoff_sec = await loop.run_in_executor(None, self._send_probe, task)
            if backoff_sec is not None:
                self.rate_limited_count += 1
                async with self.backoff_lock:
                    await asyncio.sleep(backoff_sec)

            self.completed += 1
            self.status_counts[finding.status] += 1
            self.architecture_summary = finding.architecture
            self.discovered_params.update(finding.discovered_params)
            self.discovered_apis.update(finding.discovered_apis)
            self._update_chains(finding)
            self.all_findings.append(finding)

            if any(
                f.startswith(prefix)
                for f in finding.findings
                for prefix in (
                    "stacktrace/debug",
                    "sql/database",
                    "wordpress/cms",
                    "ajax/api-calls",
                    "node/js-runtime",
                    "missing-sec-hdrs:",
                    "cdn/cloud-edge",
                    "auth/session-marker",
                    "cors-header",
                    "form-surface",
                    "realtime/ws-hint",
                    "email-pattern",
                    "internal-host-ref",
                    "slow-response",
                    "large-payload",
                    "status-shift:",
                    "size-delta:",
                    "tls-cert:",
                    "rate-limit:",
                    "params:",
                    "apis:",
                )
            ):
                self.flagged_findings.append(finding)
            queue.task_done()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        self.cert_info = await loop.run_in_executor(None, self._inspect_ssl_tls)
        schema_paths, schema_params = await loop.run_in_executor(None, self._discover_openapi_schema)
        self.schema_paths = schema_paths
        self.discovered_apis.update(schema_paths)
        self.discovered_params.update(schema_params)
        for sp in sorted(schema_params)[:10]:
            if sp not in self.params:
                self.params[sp] = "test"

        tasks = self._build_tasks()
        self.total = len(tasks)
        queue: asyncio.Queue[ProbeTask] = asyncio.Queue()
        for item in tasks:
            queue.put_nowait(item)

        workers = [
            asyncio.create_task(self._worker(queue, loop))
            for _ in range(self.concurrency)
        ]
        await queue.join()
        await asyncio.gather(*workers, return_exceptions=True)
        self.done_event.set()

    def export_json(self, output_path: str) -> str:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_url": self.clean_base_url,
            "architecture": self.architecture_summary,
            "baseline": {
                "status": self.baseline_status,
                "bytes_read": self.baseline_bytes,
                "latency_ms": self.baseline_latency_ms,
            },
            "parameters_tested": self.params,
            "discovered_parameters": sorted(self.discovered_params),
            "discovered_apis": sorted(self.discovered_apis),
            "correlated_chains": self.correlated_chains,
            "ssl_tls_certificate": self.cert_info,
            "summary": {
                "total_probes": self.total,
                "completed_probes": self.completed,
                "rate_limit_events": self.rate_limited_count,
                "flagged_count": len(self.flagged_findings),
                "chain_count": len(self.correlated_chains),
                "status_counts": dict(self.status_counts),
            },
            "flagged_findings": [asdict(item) for item in self.flagged_findings],
            "all_findings": [asdict(item) for item in self.all_findings],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        self.export_status = f"Saved to {output_path}"
        return self.export_status

    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=2),
        )
        layout["left"].split_column(
            Layout(name="cert", size=12),
            Layout(name="chains", size=8),
            Layout(name="statuses"),
        )

        cert_cn = str(self.cert_info.get("subject_cn") or self.cert_info.get("status", "Unknown"))
        header_text = Text.assemble(
            ("TARGET: ", "bold bright_cyan"),
            (f"{self.clean_base_url}  ", "bright_white"),
            ("STACK: ", "bold bright_cyan"),
            (f"{self.architecture_summary}  ", "gold1"),
            ("CERT: ", "bold bright_cyan"),
            (f"{cert_cn}  ", "bright_green"),
            ("PROBES: ", "bold bright_cyan"),
            (f"{self.completed}/{self.total}  ", "bright_green"),
            ("429s: ", "bold bright_cyan"),
            (f"{self.rate_limited_count}  ", "indian_red" if self.rate_limited_count else "bright_white"),
            ("VIEW: ", "bold bright_cyan"),
            (f"{self.view_mode}  ", "gold1"),
            ("EXPORT: ", "bold bright_cyan"),
            (self.export_status, "bright_green" if "Saved" in self.export_status else "gold1"),
        )
        layout["header"].update(
            Panel(header_text, title="[bold bright_cyan]PARAMSNIPER // FEROBUSTER TUI[/]", border_style="bright_cyan")
        )

        cert_lines = "\n".join(f"{k}: {v}" for k, v in self.cert_info.items())
        layout["cert"].update(
            Panel(Text(cert_lines, style="bright_white"), title="[bold gold1]TLS / CERT INSPECTOR[/]", border_style="gold1")
        )

        chain_text = "\n".join(self.correlated_chains[-4:]) if self.correlated_chains else "No correlated chains yet"
        layout["chains"].update(
            Panel(
                Text(chain_text, style="indian_red" if self.correlated_chains else "grey50"),
                title="[bold indian_red]SIGNAL CHAINS[/]",
                border_style="indian_red",
            )
        )

        status_table = Table(title="[bold bright_cyan]STATUS CODES[/]", expand=True, border_style="bright_cyan")
        status_table.add_column("Code", style="bold gold1")
        status_table.add_column("Count", justify="right", style="bright_green")
        for code, count in sorted(self.status_counts.items()):
            status_table.add_row(code, str(count))
        layout["statuses"].update(Panel(status_table, border_style="bright_cyan"))

        if self.view_mode == "chains":
            chain_table = Table(title="[bold indian_red]CORRELATED CHAINS[/]", expand=True, border_style="indian_red")
            chain_table.add_column("Index", width=7, style="gold1")
            chain_table.add_column("Chain", style="bright_white")
            for idx, ch in enumerate(self.correlated_chains[-20:], start=1):
                chain_table.add_row(str(idx), ch)
            if not self.correlated_chains:
                chain_table.add_row("-", "No correlated chains recorded yet")
            layout["right"].update(Panel(chain_table, border_style="indian_red"))
        else:
            if self.view_mode == "all":
                visible_items = self.all_findings
                panel_title = "[bold bright_cyan]ALL PROBE RESULTS[/]"
            else:
                visible_items = self.flagged_findings if self.flagged_findings else self.all_findings
                panel_title = "[bold bright_green]FLAGGED FINDINGS[/]" if self.flagged_findings else "[bold bright_cyan]PROBE RESULTS[/]"

            findings_table = Table(title=panel_title, expand=True, border_style="bright_green")
            findings_table.add_column("Variant", style="bright_cyan", no_wrap=True)
            findings_table.add_column("Code", width=7, style="gold1")
            findings_table.add_column("dSize", justify="right", width=8, style="bright_white")
            findings_table.add_column("ms", justify="right", width=8, style="bright_white")
            findings_table.add_column("Findings", style="indian_red" if self.flagged_findings else "bright_white")

            for item in visible_items[-20:]:
                findings_table.add_row(
                    item.variant,
                    item.status,
                    f"{item.size_delta:+d}",
                    f"{item.latency_ms:.1f}",
                    item.findings_text,
                )
            layout["right"].update(Panel(findings_table, border_style="bright_green"))

        footer_msg = (
            "Finished. Press Enter to export JSON & exit, or Ctrl+C to quit without exporting."
            if self.done_event.is_set()
            else "Scanning... Press Ctrl+C to abort."
        )
        layout["footer"].update(Panel(Text(footer_msg, style="gold1"), border_style="grey50"))
        return layout


def parse_params(raw_pairs: Optional[List[str]]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    if not raw_pairs:
        return parsed
    for pair in raw_pairs:
        if "=" in pair:
            key, val = pair.split("=", 1)
            parsed[key] = val
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ParamSniper HTTP Parameter & Response TUI")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://127.0.0.1:8000/items)")
    parser.add_argument(
        "-p",
        "--params",
        nargs="*",
        default=[],
        help="Additional/override query parameters as key=value pairs",
    )
    parser.add_argument("-c", "--concurrency", type=int, default=6, help="Concurrent worker count")
    parser.add_argument("-t", "--timeout", type=float, default=4.0, help="Request timeout in seconds")
    parser.add_argument(
        "--view",
        choices=("flagged", "all", "chains"),
        default="flagged",
        help="Main TUI view mode (flagged, all, or chains)",
    )
    parser.add_argument(
        "-o",
        "--json-out",
        default="paramsniper_report.json",
        help="Output path for JSON report export",
    )
    parser.add_argument(
        "--auto-export",
        action="store_true",
        help="Automatically write JSON report on completion without waiting for Enter",
    )
    return parser.parse_args()


async def wait_for_completion_action(
    done_event: asyncio.Event,
    auditor: ParamSniperTUI,
    json_out: str,
    auto_export: bool,
) -> None:
    await done_event.wait()
    if auto_export:
        auditor.export_json(json_out)
        return
    loop = asyncio.get_running_loop()
    if sys.stdin and sys.stdin.isatty():
        await loop.run_in_executor(None, sys.stdin.readline)
        auditor.export_json(json_out)
    else:
        await asyncio.Event().wait()


async def main() -> None:
    args = parse_args()
    console = Console()
    auditor = ParamSniperTUI(
        target_url=args.url,
        params=parse_params(args.params),
        concurrency=args.concurrency,
        timeout=args.timeout,
        view_mode=args.view,
    )

    runner_task = asyncio.create_task(auditor.run())
    action_task = asyncio.create_task(
        wait_for_completion_action(
            auditor.done_event,
            auditor,
            args.json_out,
            args.auto_export,
        )
    )

    try:
        with Live(auditor.render(), console=console, refresh_per_second=10, screen=True) as live:
            while not action_task.done():
                live.update(auditor.render())
                await asyncio.sleep(0.1)
            live.update(auditor.render())
            await asyncio.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        runner_task.cancel()
        action_task.cancel()
        await asyncio.gather(runner_task, action_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())

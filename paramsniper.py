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

HEADER_VARIATIONS: Tuple[Dict[str, str], ...] = (
    {"User-Agent": "ParamSniperTUI/4.0"},
    {"User-Agent": "Mozilla/5.0 (compatible; AuditCheck/4.0)", "X-Requested-With": "XMLHttpRequest"},
    {"User-Agent": "ParamSniperTUI/4.0", "X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/"},
    {"User-Agent": "ParamSniperTUI/4.0", "Accept": "application/json"},
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
    ) -> None:
        parsed = urlparse(target_url)
        existing_query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        self.clean_base_url = urlunparse(parsed._replace(query="", fragment=""))
        self.root_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else self.clean_base_url
        self.params = {**DEFAULT_PARAMS, **existing_query, **params}
        self.concurrency = max(1, concurrency)
        self.timeout = timeout

        self.completed = 0
        self.total = 0
        self.status_counts: Counter[str] = Counter()
        self.all_findings: List[AuditFinding] = []
        self.flagged_findings: List[AuditFinding] = []
        self.correlated_chains: List[str] = []
        self.discovered_params: Set[str] = set(self.params.keys())
        self.discovered_apis: Set[str] = set()
        self.cert_info: Dict[str, object] = {"status": "Pending"}
        self.architecture_summary = "Detecting..."
        self.done_event = asyncio.Event()
        self.export_status = "Not exported"

    def _inspect_ssl_tls(self) -> Dict[str, object]:
        parsed = urlparse(self.clean_base_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return {"status": "HTTP (no TLS)", "tls_version": "none", "cipher": "none"}

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
                    cipher_info = sock.cipher()
                    return {
                        "status": "Verified TLS",
                        "host": host,
                        "port": port,
                        "tls_version": sock.version() or "unknown",
                        "cipher": cipher_info[0] if cipher_info else "unknown",
                        "subject_cn": str(subject.get("commonName", "unknown")),
                        "issuer_cn": str(issuer.get("commonName", "unknown")),
                        "not_before": str(cert.get("notBefore", "unknown")),
                        "not_after": str(cert.get("notAfter", "unknown")),
                        "san_count": len(san_entries),
                        "san_preview": san_entries[:5],
                    }
        except Exception as exc:
            return {
                "status": f"TLS error ({type(exc).__name__})",
                "host": host,
                "port": port,
                "detail": str(exc),
            }

    def _build_tasks(self) -> List[ProbeTask]:
        tasks: List[ProbeTask] = []
        base_query = urlencode(self.params)
        base_target = f"{self.clean_base_url}?{base_query}" if base_query else self.clean_base_url

        # Stage 1: Baseline + header & query parameter mutation/pollution
        tasks.append(ProbeTask("baseline", base_target, dict(HEADER_VARIATIONS[0]), "param-audit"))
        for idx, hdrs in enumerate(HEADER_VARIATIONS[1:], start=1):
            tasks.append(
                ProbeTask(f"hdr-profile:{idx}", base_target, dict(hdrs), "header-variation")
            )

        for key, val in self.params.items():
            mutated = dict(self.params)
            mutated[key] = f"{val}_mutated"
            m_url = f"{self.clean_base_url}?{urlencode(mutated)}"
            tasks.append(ProbeTask(f"mutate:{key}", m_url, dict(HEADER_VARIATIONS[0]), "param-mutation"))

            polluted_items = list(self.params.items()) + [(key, f"{val}_polluted")]
            p_url = f"{self.clean_base_url}?{urlencode(polluted_items)}"
            tasks.append(ProbeTask(f"pollute:{key}", p_url, dict(HEADER_VARIATIONS[0]), "param-pollution"))

        # Stage 2: Common API path probing
        for api_path in API_CANDIDATE_PATHS:
            api_url = f"{self.root_origin}{api_path}"
            tasks.append(
                ProbeTask(f"api:{api_path}", api_url, dict(HEADER_VARIATIONS[3]), "api-discovery")
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

    def _detect_markers(self, raw_text: str, headers_lower: str, content_type: str) -> Tuple[List[str], str]:
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

        arch = self._classify_stack(combined, content_type.lower())
        found.append(f"stack:{arch}")
        return found, arch

    def _update_chains(self, finding: AuditFinding) -> None:
        has_error_signal = any(tag in finding.findings for tag in ("stacktrace/debug", "sql/database"))
        has_surface_signal = bool(finding.discovered_apis or finding.discovered_params or "ajax/api-calls" in finding.findings)
        if has_error_signal and has_surface_signal:
            chain_desc = f"{finding.variant} -> error-signal + surface-markers ({finding.architecture})"
            if chain_desc not in self.correlated_chains:
                self.correlated_chains.append(chain_desc)
        elif finding.stage == "api-discovery" and finding.status.startswith("2"):
            chain_desc = f"{finding.variant} -> active-api-endpoint ({finding.status})"
            if chain_desc not in self.correlated_chains:
                self.correlated_chains.append(chain_desc)

    def _send_probe(self, task: ProbeTask) -> AuditFinding:
        t0 = time.perf_counter()
        req = Request(task.url, method="GET", headers=task.headers)
        body_bytes = b""
        headers_text = ""
        content_type = ""
        status = "ERR"
        extra_note = ""

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                status = str(resp.status)
                content_type = resp.headers.get("Content-Type", "")
                headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
                body_bytes = resp.read(65536)
        except HTTPError as exc:
            status = str(exc.code)
            content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
            if exc.headers:
                headers_text = "\n".join(f"{k}: {v}" for k, v in exc.headers.items()).lower()
            if exc.fp:
                body_bytes = exc.read(65536)
        except URLError as exc:
            extra_note = f"network-error:{exc.reason}"
        except Exception as exc:
            extra_note = f"error:{type(exc).__name__}"

        elapsed_ms = (time.perf_counter() - t0) * 1000
        raw_text = body_bytes.decode("utf-8", errors="ignore")
        markers, arch = self._detect_markers(raw_text, headers_text, content_type)
        extracted_params = self._extract_params(raw_text)
        extracted_apis = self._extract_apis(raw_text)

        if extracted_params:
            markers.append(f"params:{','.join(extracted_params[:5])}")
        if extracted_apis:
            markers.append(f"apis:{','.join(extracted_apis[:4])}")
        if extra_note:
            markers.append(extra_note)

        return AuditFinding(
            variant=task.label,
            stage=task.stage,
            url=task.url,
            status=status,
            latency_ms=round(elapsed_ms, 2),
            bytes_read=len(body_bytes),
            architecture=arch,
            discovered_params=extracted_params,
            discovered_apis=extracted_apis,
            findings=markers,
        )

    async def _worker(
        self, queue: asyncio.Queue[ProbeTask], loop: asyncio.AbstractEventLoop
    ) -> None:
        while True:
            try:
                task = queue.get_nowait()
            except asyncio.QueueEmpty:
                return

            finding = await loop.run_in_executor(None, self._send_probe, task)
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
                    "params:",
                    "apis:",
                )
            ):
                self.flagged_findings.append(finding)
            queue.task_done()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        self.cert_info = await loop.run_in_executor(None, self._inspect_ssl_tls)

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
            "parameters_tested": self.params,
            "discovered_parameters": sorted(self.discovered_params),
            "discovered_apis": sorted(self.discovered_apis),
            "correlated_chains": self.correlated_chains,
            "ssl_tls_certificate": self.cert_info,
            "summary": {
                "total_probes": self.total,
                "completed_probes": self.completed,
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
            Layout(name="cert", size=11),
            Layout(name="chains", size=8),
            Layout(name="statuses"),
        )

        cert_cn = str(self.cert_info.get("subject_cn") or self.cert_info.get("status", "Unknown"))
        header_text = Text.assemble(
            ("Target: ", "bold cyan"),
            (f"{self.clean_base_url}  ", "white"),
            ("Stack: ", "bold cyan"),
            (f"{self.architecture_summary}  ", "yellow"),
            ("Cert: ", "bold cyan"),
            (f"{cert_cn}  ", "green"),
            ("Progress: ", "bold cyan"),
            (f"{self.completed}/{self.total}  ", "green"),
            ("APIs: ", "bold cyan"),
            (f"{len(self.discovered_apis)}  ", "cyan"),
            ("Export: ", "bold cyan"),
            (self.export_status, "magenta"),
        )
        layout["header"].update(Panel(header_text, title="ParamSniper TUI"))

        cert_lines = "\n".join(f"{k}: {v}" for k, v in self.cert_info.items())
        layout["cert"].update(Panel(Text(cert_lines), title="SSL/TLS Certificate"))

        chain_text = "\n".join(self.correlated_chains[-4:]) if self.correlated_chains else "No correlated chains yet"
        layout["chains"].update(Panel(Text(chain_text), title="Correlated Signals"))

        status_table = Table(title="HTTP Status Counts", expand=True)
        status_table.add_column("Status")
        status_table.add_column("Count", justify="right")
        for code, count in sorted(self.status_counts.items()):
            status_table.add_row(code, str(count))
        layout["statuses"].update(Panel(status_table))

        visible_items = self.flagged_findings if self.flagged_findings else self.all_findings
        findings_table = Table(
            title="Flagged Findings" if self.flagged_findings else "All Probe Results",
            expand=True,
        )
        findings_table.add_column("Variant", style="cyan", no_wrap=True)
        findings_table.add_column("Code", width=7)
        findings_table.add_column("ms", justify="right", width=8)
        findings_table.add_column("Findings")

        for item in visible_items[-20:]:
            findings_table.add_row(
                item.variant,
                item.status,
                f"{item.latency_ms:.1f}",
                item.findings_text,
            )
        layout["right"].update(Panel(findings_table))

        footer_msg = (
            "Finished. Press Enter to export JSON & exit, or Ctrl+C to quit without exporting."
            if self.done_event.is_set()
            else "Scanning... Press Ctrl+C to abort."
        )
        layout["footer"].update(Panel(Text(footer_msg, style="dim")))
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

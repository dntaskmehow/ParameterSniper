# ParameterSniper

> A terminal-based HTTP surface-auditing utility for **authorized systems and isolated test environments**.

ParameterSniper gathers response-level signals from a supplied URL and presents them in a live terminal interface. It can summarize observed query parameters, API-like paths, response status codes, TLS certificate details, and heuristic indicators in an optional JSON report.

**Use it only on systems you own or have explicit permission to assess.** Running it sends HTTP requests, including parameter variations and requests to common API paths. Do not point it at third-party services without written authorization.

---

## What it does

- **Observes HTTP responses:** records status, response time, and a bounded portion of response content.
- **Varies query parameters:** compares responses after changing supplied and built-in parameter values, including duplicate-parameter checks.
- **Checks common paths:** requests a fixed set of API-related paths on the URL's origin.
- **Summarizes signals:** looks for response markers associated with technologies, API calls, and error messages. These are heuristics—not proof of a vulnerability or a reliable technology fingerprint.
- **Inspects TLS:** reports certificate and connection details for HTTPS targets.
- **Presents and exports results:** displays progress in a Rich terminal UI and can serialize findings as JSON.

## Important limitations

ParameterSniper is an early-stage utility, not a validated vulnerability scanner. A marker can be a false positive, and the absence of a marker does not establish that a system is secure. Its requests may be logged, trigger rate limits, or affect an application. Review the code and assess operational impact before use; obtain authorization and define a narrow target scope first.

The tool does not provide a built-in target allowlist or rate-limit policy. Its concurrency and timeout settings are operational controls, not authorization safeguards. Use an isolated lab whenever possible.

## Requirements

- Python 3.9 or newer
- [`rich`](https://pypi.org/project/rich/) for the terminal interface

The HTTP, TLS, JSON, and asynchronous components use Python's standard library. The repository currently has no dependency lockfile or automated test suite.

## Running in an authorized lab

The entry point is [`paramsniper.py`](paramsniper.py). It accepts a target URL and optional parameters, concurrency, timeout, and JSON output settings. Review its command-line help and source code before running it, and use only a target explicitly in scope for your assessment.

When the scan completes, the interactive interface waits for Enter before exporting by default. In non-interactive use, select automatic export so the process can finish without a terminal input prompt. The default report filename is `paramsniper_report.json`.

## Report contents

The JSON report includes the target URL, timestamp, tested and discovered parameter names, discovered API-like paths, TLS information, response status counts, correlated heuristic signals, and individual response findings. Treat the report as potentially sensitive: responses and target details may reveal internal information. Store and share it according to your organization's security policies.

## Responsible use

1. Confirm written authorization and the exact host/path scope.
2. Prefer a local, disposable test application; avoid production systems unless specifically approved.
3. Review the request behavior in the source before execution, especially parameter mutations and common-path checks.
4. Stop if the target behaves unexpectedly or the activity exceeds the approved scope.
5. Protect exported reports and securely remove them when no longer needed.

## Project status

This repository is a small Python CLI project. It currently has no published release, dependency manifest, or documented automated tests. Contributions that improve safe scoping, predictable request behavior, test coverage, and result accuracy are welcome.

---

**Repository:** [dntaskmehow/ParameterSniper](https://github.com/dntaskmehow/ParameterSniper) · **Source:** [`paramsniper.py`](paramsniper.py) · **Issues:** [Report a problem or propose an improvement](https://github.com/dntaskmehow/ParameterSniper/issues)

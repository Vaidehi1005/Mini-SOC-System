from __future__ import annotations

from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

try:
    import requests
except Exception:  # pragma: no cover - handled gracefully at runtime
    requests = None

ERROR_KEYWORDS = (
    "sql syntax",
    "mysql",
    "postgres",
    "sqlite",
    "odbc",
    "sqlstate",
    "ora-",
)


def _result(name: str, severity: str, status: str, details: str, recommendation: str) -> dict[str, str]:
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "name": name,
        "severity": severity,
        "status": status,
        "details": details,
        "recommendation": recommendation,
    }


def _normalize_url(url: str) -> str:
    clean_url = url.strip()
    if not clean_url:
        raise ValueError("Enter a target URL before starting the scan.")
    if "://" not in clean_url:
        clean_url = f"https://{clean_url}"
    parsed = urlparse(clean_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("The target URL is not valid. Use a full host such as https://example.com.")
    return clean_url


def _with_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[key] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def summarize_scan_results(results: list[dict[str, str]]) -> dict[str, int]:
    return {
        "total_checks": len(results),
        "finding_count": sum(result["status"] in {"Finding", "Error"} for result in results),
        "high_severity_count": sum(
            result["severity"] in {"High", "Critical"} and result["status"] in {"Finding", "Error"}
            for result in results
        ),
    }


def scan_url(url: str, timeout: int = 6) -> list[dict[str, str]]:
    if requests is None:
        return [
            _result(
                "Scanner Engine",
                "High",
                "Error",
                "The requests library is not installed in this environment.",
                "Install requests to enable the defensive scanner module.",
            )
        ]

    try:
        target_url = _normalize_url(url)
    except ValueError as error:
        return [_result("Target Validation", "High", "Error", str(error), "Provide a reachable HTTP or HTTPS URL.")]

    session = requests.Session()
    session.headers.update({"User-Agent": "Mini-SOC-Scanner/1.0"})
    results: list[dict[str, str]] = []

    try:
        response = session.get(target_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as error:
        return [
            _result(
                "Reachability",
                "High",
                "Error",
                f"Could not reach the target: {error}",
                "Verify the URL and confirm the application is online before scanning again.",
            )
        ]

    results.append(
        _result(
            "Reachability",
            "Info",
            "Pass",
            f"Received HTTP {response.status_code} from {response.url}.",
            "The application responded to a baseline connectivity check.",
        )
    )

    if response.url.startswith("http://"):
        results.append(
            _result(
                "Transport Security",
                "Medium",
                "Finding",
                "The final page loaded over HTTP instead of HTTPS.",
                "Enable TLS and redirect all traffic to HTTPS.",
            )
        )
    else:
        results.append(
            _result(
                "Transport Security",
                "Info",
                "Pass",
                "The application responded over HTTPS.",
                "Transport encryption is enabled for the tested endpoint.",
            )
        )

    missing_headers = [
        header
        for header in (
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
        )
        if header not in response.headers
    ]
    if missing_headers:
        results.append(
            _result(
                "Security Headers",
                "Medium",
                "Finding",
                f"Missing recommended headers: {', '.join(missing_headers)}.",
                "Add baseline browser security headers to reduce common client-side risks.",
            )
        )
    else:
        results.append(
            _result(
                "Security Headers",
                "Info",
                "Pass",
                "The target returned the recommended baseline security headers.",
                "Header hardening is present for the tested endpoint.",
            )
        )

    server_header = response.headers.get("Server")
    if server_header:
        results.append(
            _result(
                "Server Disclosure",
                "Low",
                "Finding",
                f"The Server header exposes technology details: {server_header}.",
                "Limit server fingerprinting information where practical.",
            )
        )

    reflection_marker = "soc-reflection-probe-314159"
    try:
        reflection_response = session.get(
            _with_query(target_url, "soc_probe", reflection_marker),
            timeout=timeout,
            allow_redirects=True,
        )
        if reflection_marker in reflection_response.text:
            results.append(
                _result(
                    "Reflected Input Handling",
                    "Medium",
                    "Finding",
                    "A probe marker was reflected in the response body.",
                    "Review output encoding and input handling for reflected input paths.",
                )
            )
        else:
            results.append(
                _result(
                    "Reflected Input Handling",
                    "Info",
                    "Pass",
                    "The response did not reflect the benign probe marker.",
                    "No simple reflection was observed during this lightweight check.",
                )
            )
    except requests.RequestException as error:
        results.append(
            _result(
                "Reflected Input Handling",
                "Low",
                "Error",
                f"The reflection check could not be completed: {error}",
                "Re-run the scan after confirming the target is stable.",
            )
        )

    try:
        sql_error_response = session.get(
            _with_query(target_url, "soc_input", "soc-quote-check'"),
            timeout=timeout,
            allow_redirects=True,
        )
        lower_text = sql_error_response.text.lower()
        if any(keyword in lower_text for keyword in ERROR_KEYWORDS):
            results.append(
                _result(
                    "SQL Error Handling",
                    "High",
                    "Finding",
                    "Database-style error text appeared after submitting a quote marker.",
                    "Use parameterized queries and generic error messages for invalid input.",
                )
            )
        else:
            results.append(
                _result(
                    "SQL Error Handling",
                    "Info",
                    "Pass",
                    "No obvious SQL-style error leakage was observed in the response.",
                    "The lightweight error-handling probe did not trigger database disclosure.",
                )
            )
    except requests.RequestException as error:
        results.append(
            _result(
                "SQL Error Handling",
                "Low",
                "Error",
                f"The SQL-style error check could not be completed: {error}",
                "Retry when the application is reachable and able to process requests reliably.",
            )
        )

    try:
        options_response = session.options(target_url, timeout=timeout, allow_redirects=True)
        allow_header = options_response.headers.get("Allow", "")
        risky_methods = sorted(
            method for method in {"PUT", "DELETE", "TRACE"} if method in allow_header.upper()
        )
        if risky_methods:
            results.append(
                _result(
                    "HTTP Methods",
                    "Medium",
                    "Finding",
                    f"Potentially risky methods are advertised: {', '.join(risky_methods)}.",
                    "Restrict unnecessary methods at the application or proxy layer.",
                )
            )
        else:
            results.append(
                _result(
                    "HTTP Methods",
                    "Info",
                    "Pass",
                    "No risky methods were advertised in the Allow header.",
                    "The endpoint does not publicly expose risky HTTP verbs in this check.",
                )
            )
    except requests.RequestException as error:
        results.append(
            _result(
                "HTTP Methods",
                "Low",
                "Error",
                f"The HTTP methods check could not be completed: {error}",
                "Confirm the target supports OPTIONS requests if you need this validation.",
            )
        )

    return results

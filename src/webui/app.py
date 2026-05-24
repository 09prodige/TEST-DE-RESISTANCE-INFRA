"""Flask Web UI for RIG Security Scanner.

Provides a local web interface to:
- Launch scans with module selection
- View real-time scan results via AJAX polling
- Download reports in JSON/HTML/PDF formats
- Browse scan history
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from src import __version__
from src.config import load_config
from src.core.report import Report, _compute_grade
from src.core.scanner import Scanner

from .db import generate_scan_id, get_all_scans, get_scan, save_scan, update_scan_status

# In-memory tracking of active scans (scan_id -> {'results': dict|None, 'progress': dict})
active_scans: dict[str, dict[str, Any]] = {}
active_scans_lock = threading.Lock()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"
REPORTS_DIR = PROJECT_ROOT / "reports"

app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
)
app.config["SECRET_KEY"] = "rig-scanner-local-dev-key"  # nosec
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


def _sanitize_target(target: str) -> str:
    """Sanitize and validate user-provided target.

    Args:
        target: User input URL or domain.

    Returns:
        Cleaned target string.

    Raises:
        ValueError: If target is invalid.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target cannot be empty")

    target = target.strip()

    if len(target) > 2048:
        raise ValueError("Target URL too long")

    # Basic validation - must look like a domain or URL
    if "://" in target:
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError("Invalid URL format")
        hostname = parsed.hostname
    else:
        hostname = target

    # Reject obvious injection attempts
    dangerous_chars = [";", "`", "$", "(", ")", "<", ">", "|", "\n", "\r"]
    for char in dangerous_chars:
        if char in target:
            raise ValueError(f"Invalid character in target: {repr(char)}")

    return target


def _count_total_findings(results: dict[str, Any]) -> int:
    """Count total findings from scan results.

    Args:
        results: Scan results dict from Scanner.run().

    Returns:
        Total count of findings/vulnerabilities.
    """
    count = 0
    modules = results.get("modules", {})

    def _scan_node(node: Any) -> None:
        nonlocal count
        if isinstance(node, dict):
            data = node.get("data", {})
            if isinstance(data, dict):
                findings = data.get("findings", [])
                vulnerabilities = data.get("vulnerabilities", [])
                if isinstance(findings, list):
                    count += len(findings)
                if isinstance(vulnerabilities, list):
                    count += len(vulnerabilities)
            for val in node.values():
                _scan_node(val)
        elif isinstance(node, list):
            for item in node:
                _scan_node(item)

    _scan_node(modules)
    return count


def _extract_vuln_summary(results: dict[str, Any]) -> dict[str, int]:
    """Extract severity counts from results.

    Args:
        results: Scan results dict.

    Returns:
        Dict with keys: critical, high, medium, low, info.
    """
    summary: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }

    def _scan_node(node: Any) -> None:
        if isinstance(node, dict):
            # Check data.findings
            data = node.get("data", {})
            if isinstance(data, dict):
                for key in ("findings", "vulnerabilities"):
                    items = data.get(key, [])
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                sev = (item.get("severity") or "info").lower()
                                if sev in summary:
                                    summary[sev] += 1
                                else:
                                    summary["info"] += 1
            for val in node.values():
                _scan_node(val)
        elif isinstance(node, list):
            for item in node:
                _scan_node(item)

    modules = results.get("modules", {})
    _scan_node(modules)
    return summary


def _run_scan_thread(
    scan_id: str,
    target: str,
    modules: list[str],
    config: dict[str, Any],
) -> None:
    """Execute a scan in a background thread.

    Args:
        scan_id: UUID for the scan.
        target: Target URL/domain.
        modules: List of modules to run.
        config: Configuration dict.
    """
    start_time = time.monotonic()
    results: dict[str, Any] = {"target": target, "modules": {}}

    try:
        with active_scans_lock:
            active_scans[scan_id] = {
                "status": "running",
                "results": None,
                "progress": {"module": None, "started_at": datetime.now().isoformat()},
            }

        update_scan_status(scan_id, "running")

        scanner = Scanner(target, modules=modules, config=config)
        results = scanner.run()

        duration = time.monotonic() - start_time

        # Generate reports
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        base_path = str(REPORTS_DIR / f"scan_{scan_id}")

        report = Report(results, scan_duration=duration)
        json_path = report.save(base_path, fmt="json")

        # Calculate metadata
        findings_count = _count_total_findings(results)
        vuln_summary = _extract_vuln_summary(results)
        grade = _compute_grade(vuln_summary)

        with active_scans_lock:
            active_scans[scan_id] = {
                "status": "done",
                "results": results,
                "progress": {
                    "grade": grade,
                    "findings_count": findings_count,
                    "vuln_summary": vuln_summary,
                    "duration": duration,
                    "completed_at": datetime.now().isoformat(),
                },
                "report_path": base_path,
            }

        update_scan_status(
            scan_id,
            "done",
            results_path=json_path,
            grade=grade,
            findings_count=findings_count,
            duration=duration,
        )

    except Exception as exc:
        duration = time.monotonic() - start_time
        with active_scans_lock:
            active_scans[scan_id] = {
                "status": "error",
                "results": {"error": str(exc)},
                "progress": {"error": str(exc)},
            }
        update_scan_status(scan_id, "error", findings_count=0, duration=duration)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index() -> str:
    """Dashboard page with scan form and history."""
    recent_scans = get_all_scans(limit=10)
    return render_template(
        "index.html",
        version=__version__,
        recent_scans=recent_scans,
    )


@app.route("/scan", methods=["POST"])
def start_scan() -> Any:
    """Launch a new scan (POST only).

    Expects form data:
    - target: URL or domain
    - modules: list of module names (recon, web, vuln) via checkboxes
    """
    target = request.form.get("target", "").strip()
    selected_modules = request.form.getlist("modules")  # type: ignore[no-untyped-call]

    try:
        target = _sanitize_target(target)
    except ValueError as exc:
        return render_template(
            "index.html",
            version=__version__,
            recent_scans=get_all_scans(limit=10),
            error=str(exc),
            previous_target=target,
        )

    if not selected_modules:
        selected_modules = ["recon", "web", "vuln"]

    scan_id = generate_scan_id()
    config = load_config()

    save_scan(scan_id, target, modules=selected_modules, status="pending")

    # Start scan in background thread
    thread = threading.Thread(
        target=_run_scan_thread,
        args=(scan_id, target, selected_modules, config),
        daemon=True,
    )
    thread.start()

    return redirect(url_for("scan_results", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_results(scan_id: str) -> Any:
    """Scan results page with real-time AJAX polling.

    Args:
        scan_id: UUID of the scan to display.
    """
    scan_record = get_scan(scan_id)

    if scan_record is None:
        return render_template("404.html", message="Scan not found"), 404

    # Check if results are in memory (active or recently completed)
    with active_scans_lock:
        scan_data = active_scans.get(scan_id)

    # If done and we have results on disk, load them
    results = None
    report_data = None
    vuln_summary = None

    if scan_data and scan_data.get("status") == "done":
        results = scan_data.get("results")
        progress = scan_data.get("progress", {})
        vuln_summary = progress.get("vuln_summary")
    elif scan_record.get("status") == "done" and scan_record.get("results_path"):
        # Load from disk
        try:
            results_path = Path(scan_record["results_path"])
            if results_path.exists():
                with open(results_path, "r", encoding="utf-8") as f:
                    full_report = json.load(f)
                results = {
                    "target": full_report.get("target"),
                    "modules": full_report.get("modules", {}),
                }
                exec_summary = full_report.get("executive_summary", {})
                vuln_summary = exec_summary.get("vuln_summary")
        except Exception:
            pass

    # For done scans with results, build template-compatible context
    if results:
        modules = results.get("modules", {})
        report_data = {
            "recon": modules.get("recon"),
            "web": modules.get("web"),
            "vuln": modules.get("vuln"),
            "grade": scan_record.get("grade") or "?",
            "vuln_summary": vuln_summary or {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            },
        }

    return render_template(
        "scan.html",
        version=__version__,
        scan_id=scan_id,
        scan_record=scan_record,
        results=results,
        report_data=report_data,
    )


@app.route("/api/scan/<scan_id>/status")
def api_scan_status(scan_id: str) -> Any:
    """AJAX endpoint for scan status polling.

    Returns JSON with:
    - status: pending|running|done|error
    - progress: dict with progress info
    - results: full results dict only when done
    """
    scan_record = get_scan(scan_id)

    if scan_record is None:
        return jsonify({"error": "Scan not found"}), 404

    with active_scans_lock:
        scan_data = active_scans.get(scan_id)

    if scan_data:
        status = scan_data.get("status", "pending")
        progress = scan_data.get("progress", {})

        response: dict[str, Any] = {
            "status": status,
            "progress": progress,
            "scan_record": scan_record,
        }

        if status == "done":
            response["results"] = scan_data.get("results")
        elif status == "error":
            response["error"] = scan_data.get("results", {}).get("error")

        return jsonify(response)

    # Not in memory - just return DB status
    return jsonify(
        {
            "status": scan_record.get("status", "unknown"),
            "progress": {},
            "scan_record": scan_record,
        }
    )


@app.route("/api/history")
def api_history() -> Any:
    """Return scan history as JSON."""
    scans = get_all_scans(limit=50)
    return jsonify({"scans": scans})


@app.route("/download/<scan_id>/<fmt>")
def download_report(scan_id: str, fmt: str) -> Any:
    """Download a scan report in the requested format.

    Args:
        scan_id: UUID of the scan.
        fmt: Format: json, html, or pdf.
    """
    if fmt not in ("json", "html", "pdf"):
        return "Invalid format", 400

    scan_record = get_scan(scan_id)
    if scan_record is None:
        return "Scan not found", 404

    # First check in-memory results
    results = None
    duration = scan_record.get("duration")

    with active_scans_lock:
        scan_data = active_scans.get(scan_id)

    if scan_data and scan_data.get("status") == "done":
        results = scan_data.get("results")
    elif scan_record.get("results_path"):
        # Load from disk
        try:
            results_path = Path(scan_record["results_path"])
            if results_path.exists():
                with open(results_path, "r", encoding="utf-8") as f:
                    full_report = json.load(f)
                results = {
                    "target": full_report.get("target"),
                    "modules": full_report.get("modules", {}),
                    "scan_duration": full_report.get("metadata", {}).get("scan_duration"),
                }
                if not duration:
                    duration = results.get("scan_duration")
        except Exception:
            pass

    if results is None:
        return "Scan results not available", 404

    report = Report(results, scan_duration=duration)

    if fmt == "json":
        content = report.to_json()
        return send_file(
            _make_temp_file(content, f"scan_{scan_id}.json"),
            as_attachment=True,
            download_name=f"rig_scan_{scan_id}.json",
            mimetype="application/json",
        )
    elif fmt == "html":
        content = report.to_html()
        return send_file(
            _make_temp_file(content, f"scan_{scan_id}.html"),
            as_attachment=True,
            download_name=f"rig_scan_{scan_id}.html",
            mimetype="text/html",
        )
    elif fmt == "pdf":
        try:
            pdf_bytes = report.to_pdf()
            return send_file(
                _make_temp_file(pdf_bytes, f"scan_{scan_id}.pdf", binary=True),
                as_attachment=True,
                download_name=f"rig_scan_{scan_id}.pdf",
                mimetype="application/pdf",
            )
        except NotImplementedError:
            return (
                "PDF generation requires weasyprint or pdfkit. "
                "Download HTML instead.",
                501,
            )

    return "Unknown error", 500


import tempfile


def _make_temp_file(content: str | bytes, name_hint: str, binary: bool = False) -> tempfile.NamedTemporaryFile:
    """Create a named temporary file with the given content for send_file.

    Args:
        content: String or bytes to write.
        name_hint: Hint for the filename (used for suffix).
        binary: Whether content is bytes.

    Returns:
        NamedTemporaryFile in delete=False mode.
    """
    suffix = Path(name_hint).suffix or ".tmp"
    mode = "wb" if binary else "w"
    encoding = None if binary else "utf-8"

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)  # nosec
    try:
        with open(tmp.name, mode, encoding=encoding) as f:
            f.write(content)
    except Exception:
        pass
    return tmp


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------


@app.errorhandler(404)
def page_not_found(_e: Any) -> tuple[str, int]:
    """404 handler."""
    return render_template("404.html", message="Page not found"), 404


if __name__ == "__main__":
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)

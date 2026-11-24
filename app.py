import os
import threading
import time
import uuid

from datetime import datetime, timezone

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
)

from report.pdf_report import generate_report
from report.exporters import export_scan

from scanner.formatter import build_scan_summary
from scanner.metasploit_database import (
    initialize_metasploit_database,
    save_metasploit_modules,
)
from scanner.metasploit_scan import (
    discover_metasploit_for_assessment,
)
from scanner.nmap_parser import parse_nmap_xml
from scanner.nmap_runner import run_nmap_xml_scan

from vulnerability_engine.database import (
    compare_scan_findings,
    compare_scan_ports,
    delete_scan,
    get_findings_by_scan,
    get_ports_by_scan,
    get_scan_by_id,
    get_scan_history,
    initialize_database,
    save_finding,
    save_port,
    save_scan,
)

from vulnerability_engine.engine import analyze_scan

from vulnerability_engine.asset_context import load_host_context

from vulnerability_engine.web_assessment import run_web_assessment


# -------------------------------------------------------------------
# Flask application
# -------------------------------------------------------------------

app = Flask(__name__)


# -------------------------------------------------------------------
# Database initialization
# -------------------------------------------------------------------

initialize_database()
initialize_metasploit_database()


# -------------------------------------------------------------------
# Allowed VulnX environmental context values
# -------------------------------------------------------------------

ALLOWED_ASSET_CRITICALITY = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

ALLOWED_NETWORK_EXPOSURE = {
    "LOCAL",
    "INTERNAL",
    "DMZ",
    "INTERNET",
}

ALLOWED_SERVICE_IMPORTANCE = {
    "LOW",
    "NORMAL",
    "HIGH",
    "CRITICAL",
}


# -------------------------------------------------------------------
# Default environmental context
# -------------------------------------------------------------------

DEFAULT_CONTEXT = {
    "asset_criticality": "MEDIUM",
    "network_exposure": "INTERNAL",
    "service_importance": "NORMAL",
}


# -------------------------------------------------------------------
# Context normalization
# -------------------------------------------------------------------

def normalize_context(
    asset_criticality: str,
    network_exposure: str,
    service_importance: str,
) -> dict[str, str]:
    """
    Validate and normalize environmental context
    submitted through the Flask interface.

    Invalid or missing values fall back to
    neutral defaults.
    """

    asset_criticality = (
        asset_criticality
        or DEFAULT_CONTEXT["asset_criticality"]
    ).upper().strip()

    network_exposure = (
        network_exposure
        or DEFAULT_CONTEXT["network_exposure"]
    ).upper().strip()

    service_importance = (
        service_importance
        or DEFAULT_CONTEXT["service_importance"]
    ).upper().strip()

    if asset_criticality not in ALLOWED_ASSET_CRITICALITY:
        asset_criticality = DEFAULT_CONTEXT[
            "asset_criticality"
        ]

    if network_exposure not in ALLOWED_NETWORK_EXPOSURE:
        network_exposure = DEFAULT_CONTEXT[
            "network_exposure"
        ]

    if service_importance not in ALLOWED_SERVICE_IMPORTANCE:
        service_importance = DEFAULT_CONTEXT[
            "service_importance"
        ]

    return {
        "asset_criticality": asset_criticality,
        "network_exposure": network_exposure,
        "service_importance": service_importance,
    }


# -------------------------------------------------------------------
# Home page
# -------------------------------------------------------------------

@app.route(
    "/",
    methods=["GET"],
)
def home():

    return render_template(
        "index.html"
    )


# -------------------------------------------------------------------
# Scan route
# -------------------------------------------------------------------

# -------------------------------------------------------------------
# Background scan jobs
#
# A scan runs several phases (nmap, CVE correlation, Metasploit, web
# checks, saving) and can take a few minutes. Running it in a worker
# thread lets the browser show a live progress page instead of a
# frozen request. Job state lives in memory, which is fine for this
# single-user local/Docker deployment.
# -------------------------------------------------------------------

SCAN_JOBS: dict[str, dict] = {}
SCAN_JOBS_LOCK = threading.Lock()


# Each phase reports the percentage reached when it begins, plus a
# "soft cap" the progress bar may drift toward while that phase is
# still running (so the bar keeps moving during the long steps).
SCAN_PHASES = {
    "starting":   {"percent": 3,   "soft_cap": 5,   "label": "Starting scan..."},
    "nmap":       {"percent": 8,   "soft_cap": 58,  "label": "Running nmap port scan (this is the longest step)..."},
    "parsing":    {"percent": 60,  "soft_cap": 63,  "label": "Parsing scan results..."},
    "risk":       {"percent": 65,  "soft_cap": 70,  "label": "Analyzing vulnerabilities and context-aware risk..."},
    "metasploit": {"percent": 72,  "soft_cap": 87,  "label": "Discovering Metasploit modules..."},
    "web":        {"percent": 89,  "soft_cap": 92,  "label": "Running passive web checks..."},
    "saving":     {"percent": 94,  "soft_cap": 98,  "label": "Saving results to the database..."},
    "done":       {"percent": 100, "soft_cap": 100, "label": "Scan complete."},
}


def _set_phase(job_id, phase):
    """Update a job's progress to the named phase."""

    info = SCAN_PHASES[phase]

    with SCAN_JOBS_LOCK:

        job = SCAN_JOBS.get(job_id)

        if job is None:
            return

        job["phase"] = phase
        job["percent"] = info["percent"]
        job["soft_cap"] = info["soft_cap"]
        job["label"] = info["label"]


def _run_scan_job(job_id, target, password, context):
    """Execute the full scan pipeline, updating job progress as it goes."""

    try:

        _set_phase(job_id, "starting")

        # --- 1. Nmap through Kali (longest step) ---
        _set_phase(job_id, "nmap")

        xml_result = run_nmap_xml_scan(
            password=password,
            target=target,
        )

        # --- 2. Parse + summary ---
        _set_phase(job_id, "parsing")

        parsed_result = parse_nmap_xml(xml_result)
        summary = build_scan_summary(parsed_result)

        # --- 3. Vulnerability + context-aware risk analysis ---
        _set_phase(job_id, "risk")

        host_context = load_host_context()

        assessment = analyze_scan(
            parsed_result,
            context=context,
            host_context=host_context,
        )

        # --- 4. Metasploit intelligence discovery (module discovery only) ---
        _set_phase(job_id, "metasploit")

        metasploit = discover_metasploit_for_assessment(
            assessment=assessment,
            parsed_scan=parsed_result,
            password=password,
        )

        assessment["metasploit"] = metasploit

        # --- 5. Passive web assessment ---
        _set_phase(job_id, "web")

        try:

            web_findings = run_web_assessment(
                password,
                parsed_result,
                scan_context=context,
                host_context=host_context,
            )

        except Exception:

            web_findings = []

        if web_findings:

            assessment["findings"].extend(web_findings)
            assessment["finding_count"] = len(assessment["findings"])

            web_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }

            for item in assessment["findings"]:

                band = item.get("risk_level")

                if band in web_counts:
                    web_counts[band] += 1

            assessment["risk_counts"] = web_counts

        # --- 6. Save everything ---
        _set_phase(job_id, "saving")

        started_at = datetime.now(timezone.utc).isoformat()

        scan_id = save_scan(
            target=target,
            started_at=started_at,
            hosts_scanned=summary["hosts_scanned"],
            open_ports=summary["total_open_ports"],
            findings=assessment["finding_count"],
            asset_criticality=context["asset_criticality"],
            network_exposure=context["network_exposure"],
            service_importance=context["service_importance"],
        )

        save_metasploit_modules(
            scan_id=scan_id,
            intelligence=metasploit,
        )

        for host_data in parsed_result.get("hosts", []):

            host = "unknown"

            for address in host_data.get("addresses", []):

                if address.get("type") == "ipv4":
                    host = address.get("address", "unknown")
                    break

            for port in host_data.get("ports", []):

                if port.get("state") != "open":
                    continue

                save_port(
                    scan_id=scan_id,
                    host=host,
                    port=port,
                )

        for finding in assessment["findings"]:

            save_finding(
                scan_id=scan_id,
                finding=finding,
            )

        # --- 7. Done: stash the render context for the result view ---
        _set_phase(job_id, "done")

        with SCAN_JOBS_LOCK:

            job = SCAN_JOBS.get(job_id)

            if job is not None:

                job["done"] = True
                job["scan_id"] = scan_id
                job["result"] = {
                    "target": target,
                    "summary": summary,
                    "assessment": assessment,
                    "scan_id": scan_id,
                    "context": context,
                }

    except Exception as exc:

        with SCAN_JOBS_LOCK:

            job = SCAN_JOBS.get(job_id)

            if job is not None:

                job["done"] = True
                job["error"] = str(exc)


@app.route(
    "/scan",
    methods=["POST"],
)
def scan():

    # ---------------------------------------------------------------
    # Read basic inputs
    # ---------------------------------------------------------------

    target = request.form.get(
        "target",
        "",
    ).strip()

    password = request.form.get(
        "password",
        "",
    )

    # ---------------------------------------------------------------
    # Read environmental context
    # ---------------------------------------------------------------

    asset_criticality = request.form.get(
        "asset_criticality",
        DEFAULT_CONTEXT["asset_criticality"],
    )

    network_exposure = request.form.get(
        "network_exposure",
        DEFAULT_CONTEXT["network_exposure"],
    )

    service_importance = request.form.get(
        "service_importance",
        DEFAULT_CONTEXT["service_importance"],
    )

    context = normalize_context(
        asset_criticality=asset_criticality,
        network_exposure=network_exposure,
        service_importance=service_importance,
    )

    # ---------------------------------------------------------------
    # Required field validation
    # ---------------------------------------------------------------

    if not target:

        return render_template(
            "index.html",
            error="Target IP is required.",
            context=context,
        )

    if not password:

        return render_template(
            "index.html",
            error="Kali password is required.",
            context=context,
        )

    # ---------------------------------------------------------------
    # Launch the scan in the background and hand the user a live
    # progress page.
    # ---------------------------------------------------------------

    job_id = uuid.uuid4().hex

    with SCAN_JOBS_LOCK:

        SCAN_JOBS[job_id] = {
            "phase": "starting",
            "percent": SCAN_PHASES["starting"]["percent"],
            "soft_cap": SCAN_PHASES["starting"]["soft_cap"],
            "label": SCAN_PHASES["starting"]["label"],
            "done": False,
            "error": None,
            "scan_id": None,
            "result": None,
            "target": target,
            "started": time.time(),
        }

    worker = threading.Thread(
        target=_run_scan_job,
        args=(job_id, target, password, context),
        daemon=True,
    )

    worker.start()

    return redirect(f"/scan/progress/{job_id}")


# -------------------------------------------------------------------
# Scan progress page + status polling
# -------------------------------------------------------------------

@app.route(
    "/scan/progress/<job_id>",
    methods=["GET"],
)
def scan_progress(job_id):

    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)

    if job is None:
        return redirect("/")

    return render_template(
        "progress.html",
        job_id=job_id,
        target=job.get("target", ""),
    )


@app.route(
    "/scan/status/<job_id>",
    methods=["GET"],
)
def scan_status(job_id):

    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)

        if job is None:
            return jsonify({"missing": True}), 404

        elapsed = time.time() - job.get("started", time.time())

        return jsonify(
            {
                "phase": job.get("phase"),
                "label": job.get("label"),
                "percent": job.get("percent", 0),
                "soft_cap": job.get("soft_cap", job.get("percent", 0)),
                "done": job.get("done", False),
                "error": job.get("error"),
                "scan_id": job.get("scan_id"),
                "elapsed": round(elapsed, 1),
            }
        )


@app.route(
    "/scan/result/<job_id>",
    methods=["GET"],
)
def scan_result(job_id):

    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)

    if job is None or not job.get("done"):
        return redirect("/history")

    if job.get("error"):

        return render_template(
            "index.html",
            error=f"Scan failed: {job['error']}",
            context=DEFAULT_CONTEXT,
        )

    result = job.get("result") or {}

    return render_template(
        "results.html",
        target=result.get("target"),
        summary=result.get("summary"),
        assessment=result.get("assessment"),
        scan_id=result.get("scan_id"),
        context=result.get("context"),
    )


# -------------------------------------------------------------------
# Scan History
# -------------------------------------------------------------------

@app.route(
    "/history",
    methods=["GET"],
)
def history():

    scans = get_scan_history()

    return render_template(
        "history.html",
        scans=scans,
    )


# -------------------------------------------------------------------
# Scan Details
# -------------------------------------------------------------------

@app.route(
    "/scan/<int:scan_id>",
    methods=["GET"],
)
def scan_details(
    scan_id: int,
):

    # ---------------------------------------------------------------
    # Retrieve scan
    # ---------------------------------------------------------------

    scan = get_scan_by_id(
        scan_id
    )

    if scan is None:

        return (
            render_template(
                "history.html",
                scans=get_scan_history(),
                error="Scan not found.",
            ),
            404,
        )

    # ---------------------------------------------------------------
    # Retrieve findings
    # ---------------------------------------------------------------

    findings = get_findings_by_scan(
        scan_id
    )

    # ---------------------------------------------------------------
    # Retrieve ports
    # ---------------------------------------------------------------

    ports = get_ports_by_scan(
        scan_id
    )

    # ---------------------------------------------------------------
    # Display scan details
    # ---------------------------------------------------------------

    return render_template(
        "scan_details.html",
        scan=scan,
        findings=findings,
        ports=ports,
    )


# -------------------------------------------------------------------
# Scan Comparison
# -------------------------------------------------------------------

@app.route(
    "/compare",
    methods=["GET"],
)
def compare():

    # ---------------------------------------------------------------
    # Read selected scan IDs
    # ---------------------------------------------------------------

    old_scan_id = request.args.get(
        "old",
        type=int,
    )

    new_scan_id = request.args.get(
        "new",
        type=int,
    )

    # ---------------------------------------------------------------
    # Get scan history
    # ---------------------------------------------------------------

    scans = get_scan_history()

    # ---------------------------------------------------------------
    # No scan selection
    # ---------------------------------------------------------------

    if (
        old_scan_id is None
        or new_scan_id is None
    ):

        return render_template(
            "compare.html",
            scans=scans,
            comparison=None,
            port_comparison=None,
        )

    # ---------------------------------------------------------------
    # Same scan selected twice
    # ---------------------------------------------------------------

    if old_scan_id == new_scan_id:

        return render_template(
            "compare.html",
            scans=scans,
            comparison=None,
            port_comparison=None,
            error="Select two different scans.",
        )

    # ---------------------------------------------------------------
    # Retrieve both scans
    # ---------------------------------------------------------------

    old_scan = get_scan_by_id(
        old_scan_id
    )

    new_scan = get_scan_by_id(
        new_scan_id
    )

    # ---------------------------------------------------------------
    # Validate scan IDs
    # ---------------------------------------------------------------

    if (
        old_scan is None
        or new_scan is None
    ):

        return render_template(
            "compare.html",
            scans=scans,
            comparison=None,
            port_comparison=None,
            error="One or both scans could not be found.",
        )

    # ---------------------------------------------------------------
    # Compare findings
    # ---------------------------------------------------------------

    comparison = compare_scan_findings(
        old_scan_id,
        new_scan_id,
    )

    # ---------------------------------------------------------------
    # Compare ports
    # ---------------------------------------------------------------

    port_comparison = compare_scan_ports(
        old_scan_id,
        new_scan_id,
    )

    # ---------------------------------------------------------------
    # Render comparison
    # ---------------------------------------------------------------

    return render_template(
        "compare.html",
        scans=scans,
        comparison=comparison,
        port_comparison=port_comparison,
        old_scan=old_scan,
        new_scan=new_scan,
    )


# -------------------------------------------------------------------
# Delete Scan
# -------------------------------------------------------------------

@app.route(
    "/scan/<int:scan_id>/delete",
    methods=["POST"],
)
def delete_scan_route(
    scan_id: int,
):

    # ---------------------------------------------------------------
    # Delete scan
    # ---------------------------------------------------------------

    deleted = delete_scan(
        scan_id
    )

    # ---------------------------------------------------------------
    # Scan not found
    # ---------------------------------------------------------------

    if not deleted:

        return (
            render_template(
                "history.html",
                scans=get_scan_history(),
                error="Scan not found.",
            ),
            404,
        )

    # ---------------------------------------------------------------
    # Return updated history
    # ---------------------------------------------------------------

    return render_template(
        "history.html",
        scans=get_scan_history(),
        message=(
            f"Scan #{scan_id} deleted successfully."
        ),
    )


# -------------------------------------------------------------------
# PDF report download
# -------------------------------------------------------------------

@app.route(
    "/report/<int:scan_id>",
    methods=["GET"],
)
def download_report(
    scan_id,
):
    """Generate and download a PDF report for a saved scan."""

    try:

        path = generate_report(
            scan_id
        )

    except ValueError:

        return (
            "Scan not found",
            404,
        )

    return send_file(
        path,
        as_attachment=True,
        download_name=f"VulnX_Report_scan{scan_id}.pdf",
    )


# -------------------------------------------------------------------
# Data export (CSV / JSON / XML)
# -------------------------------------------------------------------

@app.route(
    "/export/<int:scan_id>/<fmt>",
    methods=["GET"],
)
def export_scan_route(
    scan_id,
    fmt,
):
    """Export a saved scan as CSV, JSON or XML."""

    try:

        path = export_scan(
            scan_id,
            fmt,
        )

    except ValueError as error:

        message = str(error)

        if "not found" in message.lower():
            return ("Scan not found", 404)

        return (message, 400)

    return send_file(
        path,
        as_attachment=True,
        download_name=f"VulnX_scan{scan_id}.{fmt.lower()}",
    )


# -------------------------------------------------------------------
# Application entry point
# -------------------------------------------------------------------

if __name__ == "__main__":

    # Bind/port/debug are configurable so the same app can run locally
    # (127.0.0.1) or inside a container exposed to the host (0.0.0.0).
    app.run(
        host=os.getenv("VULNX_BIND", "127.0.0.1"),
        port=int(os.getenv("VULNX_PORT", "5000")),
        debug=os.getenv("VULNX_DEBUG", "0") == "1",
    )
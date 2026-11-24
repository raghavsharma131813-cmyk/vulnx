"""
VulnX scan exporters.

Turns a saved scan (its metadata, findings and ports) into the common
file formats people actually use downstream: CSV for spreadsheets,
JSON for tooling, and XML for structured interchange. PDF is handled
separately by report/pdf_report.py.

Each function writes a file to a temporary path and returns that path,
so the Flask layer can hand it straight to send_file.
"""

import csv
import io
import json
import os
import tempfile
import time
from xml.sax.saxutils import escape, quoteattr

from vulnerability_engine.database import (
    get_scan_by_id,
    get_findings_by_scan,
    get_ports_by_scan,
)


# -------------------------------------------------------------------
# Shared data collection
# -------------------------------------------------------------------

def _collect_scan(scan_id):
    """Gather the scan, its findings and its ports in one structure."""

    scan = get_scan_by_id(scan_id)

    if scan is None:
        raise ValueError("Scan not found")

    findings = get_findings_by_scan(scan_id)
    ports = get_ports_by_scan(scan_id)

    return scan, findings, ports


def _temp_path(scan_id, extension):
    """Return a writable temp file path for the export."""

    directory = tempfile.gettempdir()

    return os.path.join(
        directory,
        f"VulnX_scan{scan_id}.{extension}",
    )


# Columns used for the findings CSV, in a sensible reading order.
_FINDING_COLUMNS = [
    "id",
    "host",
    "port",
    "protocol",
    "service",
    "product",
    "version",
    "title",
    "severity",
    "risk_level",
    "risk_score",
    "confidence",
    "status",
    "cvss",
    "cves",
    "context_multiplier",
    "asset_criticality",
    "network_exposure",
    "service_importance",
    "recommendation",
]


def _flatten_value(value):
    """Make a DB value safe for flat formats (CSV cells, XML text)."""

    if value is None:
        return ""

    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)

    return str(value)


# -------------------------------------------------------------------
# CSV
# -------------------------------------------------------------------

def export_csv(scan_id):
    """Write the scan's findings to a CSV file. Returns the path."""

    scan, findings, _ports = _collect_scan(scan_id)

    path = _temp_path(scan_id, "csv")

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    # A short header block so the file is self-describing.
    writer.writerow(["VulnX Scan Export"])
    writer.writerow(["Scan ID", scan.get("id")])
    writer.writerow(["Target", scan.get("target")])
    writer.writerow(["Started", scan.get("started_at")])
    writer.writerow(["Hosts", scan.get("hosts_scanned")])
    writer.writerow(["Open Ports", scan.get("open_ports")])
    writer.writerow(["Findings", scan.get("findings")])
    writer.writerow([])

    # Findings table.
    writer.writerow(_FINDING_COLUMNS)

    for finding in findings:
        writer.writerow(
            [_flatten_value(finding.get(col)) for col in _FINDING_COLUMNS]
        )

    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(buffer.getvalue())

    return path


# -------------------------------------------------------------------
# JSON
# -------------------------------------------------------------------

def export_json(scan_id):
    """Write the full scan (scan + findings + ports) to JSON."""

    scan, findings, ports = _collect_scan(scan_id)

    path = _temp_path(scan_id, "json")

    document = {
        "tool": "VulnX",
        "scan": scan,
        "findings": findings,
        "ports": ports,
    }

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, default=str)

    return path


# -------------------------------------------------------------------
# XML
# -------------------------------------------------------------------

def _xml_element(tag, value, indent):
    """Build one escaped XML element line."""

    text = escape(_flatten_value(value))

    return f"{indent}<{tag}>{text}</{tag}>"


def export_xml(scan_id):
    """
    Write the scan as Nmap-format XML.

    Metasploit's db_import detects a file by its root <nmaprun> element
    and ingests the hosts, ports and services inside it. Reconstructing
    that structure from the stored ports means the exported file can be
    imported straight into Metasploit (db_import VulnX_scanNN.xml), after
    which `hosts` and `services` are populated and modules can be matched
    against the discovered services.

    Any CVEs VulnX attached to a port are added as an nmap <script>
    element on that port so the information travels with the file.
    """

    scan, findings, ports = _collect_scan(scan_id)

    path = _temp_path(scan_id, "xml")

    now = int(time.time())

    # Group ports by host, and collect CVEs per (host, port).
    hosts = {}
    for port in ports:
        host = port.get("host") or "unknown"
        hosts.setdefault(host, []).append(port)

    cve_by_port = {}
    for finding in findings:
        cves = finding.get("cves") or []
        if not cves:
            continue
        key = (finding.get("host"), finding.get("port"))
        bucket = cve_by_port.setdefault(key, [])
        for cve in cves:
            if cve and cve not in bucket:
                bucket.append(cve)

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append("<!DOCTYPE nmaprun>")
    lines.append(
        f'<nmaprun scanner="nmap" args="VulnX export" '
        f'start="{now}" version="7.94" xmloutputversion="1.05">'
    )
    lines.append(
        '<scaninfo type="connect" protocol="tcp" '
        'numservices="1000" services="1-1000"/>'
    )

    for host, host_ports in hosts.items():

        lines.append(f'<host starttime="{now}" endtime="{now}">')
        lines.append('  <status state="up" reason="user-set" reason_ttl="0"/>')
        lines.append(f'  <address addr={quoteattr(host)} addrtype="ipv4"/>')
        lines.append("  <hostnames></hostnames>")
        lines.append("  <ports>")

        for port in host_ports:

            portid = port.get("port")
            protocol = port.get("protocol") or "tcp"
            state = port.get("state") or "open"

            lines.append(
                f'    <port protocol={quoteattr(str(protocol))} '
                f'portid={quoteattr(str(portid))}>'
            )
            lines.append(
                f'      <state state={quoteattr(str(state))} '
                'reason="syn-ack" reason_ttl="0"/>'
            )

            # Service element with product/version/cpe where known.
            service_attrs = [
                f'name={quoteattr(str(port.get("service") or "unknown"))}'
            ]
            if port.get("product"):
                service_attrs.append(
                    f'product={quoteattr(str(port.get("product")))}'
                )
            if port.get("version"):
                service_attrs.append(
                    f'version={quoteattr(str(port.get("version")))}'
                )
            service_attrs.append('method="probed"')
            service_attrs.append('conf="10"')

            cpes = port.get("cpes") or []

            if cpes:
                lines.append(f'      <service {" ".join(service_attrs)}>')
                for cpe in cpes:
                    lines.append(f"        <cpe>{escape(str(cpe))}</cpe>")
                lines.append("      </service>")
            else:
                lines.append(f'      <service {" ".join(service_attrs)}/>')

            # Attach CVEs (if any) as a script element on this port.
            cves = cve_by_port.get((host, portid))
            if cves:
                cve_text = ", ".join(cves)
                lines.append(
                    f'      <script id="vulnx-cve" '
                    f'output={quoteattr(cve_text)}/>'
                )

            lines.append("    </port>")

        lines.append("  </ports>")
        lines.append("</host>")

    host_count = len(hosts)
    lines.append(
        f'<runstats><finished time="{now}" elapsed="0"/>'
        f'<hosts up="{host_count}" down="0" total="{host_count}"/>'
        "</runstats>"
    )
    lines.append("</nmaprun>")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    return path


# -------------------------------------------------------------------
# Dispatcher
# -------------------------------------------------------------------

_EXPORTERS = {
    "csv": export_csv,
    "json": export_json,
    "xml": export_xml,
}


def export_scan(scan_id, fmt):
    """Export a scan in the requested format. Returns the file path."""

    fmt = (fmt or "").lower()

    exporter = _EXPORTERS.get(fmt)

    if exporter is None:
        raise ValueError(f"Unsupported export format: {fmt}")

    return exporter(scan_id)

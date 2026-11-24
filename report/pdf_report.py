"""
VulnX PDF report generator.

Reads a saved scan from the VulnX database and produces a professional
assessment report (fpdf2). Used by the Flask app's report route and
runnable from the command line.

    python -m report.pdf_report 27            # writes report/VulnX_Report_scan27.pdf
    python -m report.pdf_report 27 out.pdf    # custom path
"""

import os
import sys
from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from vulnerability_engine.database import (
    get_scan_by_id,
    get_findings_by_scan,
)


# Ocean Blue brand, matching the UI.
BLUE = (2, 132, 199)
BLUE_DARK = (3, 105, 161)
INK = (12, 42, 63)
MUTED = (107, 114, 128)

BAND_COLORS = {
    "CRITICAL": (185, 28, 28),
    "HIGH": (194, 65, 12),
    "MEDIUM": (146, 97, 10),
    "LOW": (4, 120, 87),
    "INFO": (71, 85, 105),
}

BAND_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _ascii(text: Any) -> str:
    """fpdf core fonts are latin-1; strip anything that will not encode."""
    s = "" if text is None else str(text)
    return s.encode("latin-1", "replace").decode("latin-1")


class VulnXReport(FPDF):
    def header(self):
        self.set_fill_color(*BLUE)
        self.rect(0, 0, self.w, 22, "F")
        self.set_xy(12, 6)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, "VulnX  Vulnerability Assessment Report", align="L")
        self.ln(20)

    def footer(self):
        self.set_y(-14)
        self.set_text_color(*MUTED)
        self.set_font("Helvetica", "", 8)
        self.cell(0, 8,
                  _ascii("For authorized security testing only.  "
                         f"Page {self.page_no()}/{{nb}}"),
                  align="C")


def _section_title(pdf: VulnXReport, text: str):
    pdf.ln(3)
    pdf.set_text_color(*INK)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _ascii(text))
    pdf.ln(9)
    pdf.set_draw_color(*BLUE)
    pdf.set_line_width(0.5)
    x = pdf.get_x()
    y = pdf.get_y()
    pdf.line(x, y, x + 40, y)
    pdf.ln(4)


def _kv(pdf: VulnXReport, key: str, value: str):
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*MUTED)
    pdf.cell(45, 6, _ascii(key))
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 6, _ascii(value))
    pdf.ln(6)


def _cvss_value(cvss: Any) -> str:
    if cvss is None:
        return "n/a"
    if isinstance(cvss, dict):
        return str(cvss.get("base_score", "n/a"))
    return str(cvss)


def generate_report(scan_id: int, out_path: str | None = None) -> str:
    scan = get_scan_by_id(scan_id)
    if scan is None:
        raise ValueError(f"No scan with id {scan_id} in the database.")

    findings = get_findings_by_scan(scan_id)
    # Sort by band then risk score, highest priority first.
    findings.sort(key=lambda f: (
        BAND_ORDER.get(str(f.get("risk_level", "INFO")).upper(), 5),
        -float(f.get("risk_score") or 0),
    ))

    # Risk band counts.
    counts = {b: 0 for b in BAND_ORDER}
    for f in findings:
        b = str(f.get("risk_level", "INFO")).upper()
        if b in counts:
            counts[b] += 1

    pdf = VulnXReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ---- Scan overview ----
    _section_title(pdf, "Scan Overview")
    _kv(pdf, "Target", scan.get("target", ""))
    _kv(pdf, "Scan ID", str(scan.get("id", "")))
    _kv(pdf, "Started", scan.get("started_at", ""))
    _kv(pdf, "Hosts scanned", str(scan.get("hosts_scanned", "")))
    _kv(pdf, "Open ports", str(scan.get("open_ports", "")))
    _kv(pdf, "Total findings", str(scan.get("findings", len(findings))))

    # ---- Environmental context ----
    _section_title(pdf, "Environmental Risk Context")
    _kv(pdf, "Asset criticality", scan.get("asset_criticality", ""))
    _kv(pdf, "Network exposure", scan.get("network_exposure", ""))
    _kv(pdf, "Service importance", scan.get("service_importance", ""))
    if findings:
        _kv(pdf, "Context multiplier", str(findings[0].get("context_multiplier", "")))

    # ---- Risk summary ----
    _section_title(pdf, "Risk Summary")
    pdf.set_font("Helvetica", "B", 10)
    box_w = (pdf.w - 24) / 5
    for band in BAND_ORDER:
        r, g, b = BAND_COLORS[band]
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(box_w, 9, _ascii(f"{band} {counts[band]}"), border=0, align="C", fill=True)
    pdf.ln(14)

    # ---- Findings ----
    _section_title(pdf, "Findings (highest priority first)")
    for f in findings:
        band = str(f.get("risk_level", "INFO")).upper()
        r, g, b = BAND_COLORS.get(band, MUTED)

        # Title on its own line.
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*INK)
        title = f.get("title") or f.get("service") or "Finding"
        pdf.multi_cell(0, 6, _ascii(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Colored band chip at the left, then the meta line wraps after it.
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(24, 6, _ascii(band), align="C", fill=True,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_text_color(*MUTED)
        pdf.set_font("Helvetica", "", 9)
        cves = f.get("cves")
        cve_str = ", ".join(cves) if isinstance(cves, list) else (cves or "")
        pdf.multi_cell(0, 6, _ascii(
            f"  Risk {f.get('risk_score','')}  |  CVSS {_cvss_value(f.get('cvss'))}  "
            f"|  {f.get('status','')}  |  {f.get('host','')}:{f.get('port','')}  "
            f"|  {cve_str}"),
            new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

        rec = f.get("recommendation")
        if rec:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*INK)
            pdf.multi_cell(0, 5, _ascii("Recommendation: " + rec))
        pdf.ln(2)
        pdf.set_draw_color(230, 236, 240)
        pdf.set_line_width(0.2)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.w - 12, pdf.get_y())
        pdf.ln(3)

    if out_path is None:
        out_dir = os.path.dirname(__file__)
        out_path = os.path.join(out_dir, f"VulnX_Report_scan{scan_id}.pdf")
    pdf.output(out_path)
    return out_path


def main():
    if len(sys.argv) < 2:
        print("usage: python -m report.pdf_report <scan_id> [out.pdf]")
        return
    scan_id = int(sys.argv[1])
    out = sys.argv[2] if len(sys.argv) > 2 else None
    path = generate_report(scan_id, out)
    print("Report written to:", path)


if __name__ == "__main__":
    main()

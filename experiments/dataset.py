"""
Fixed finding dataset and scenario definitions for the VulnX
evaluation experiments.

The dataset is a controlled, synthetic set of findings. Each finding
carries its own asset context so that CVSS-only and context-aware
rankings can genuinely diverge. Synthetic scenarios isolate the effect
of each variable and must not be presented as real-world validation.
"""

from typing import Any


# -------------------------------------------------------------------
# Controlled finding set
# -------------------------------------------------------------------
#
# Designed so that technical severity (CVSS) and organizational
# context pull in different directions for several findings. Every
# field maps to an input the real risk_engine already consumes.
# -------------------------------------------------------------------

FINDINGS: list[dict[str, Any]] = [
    {
        "id": "F1",
        "title": "vsftpd 2.3.4 backdoor",
        "host": "10.0.0.10",
        "severity": "CRITICAL", "confidence": "MEDIUM",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 9.8},
        "asset_criticality": "LOW",
        "network_exposure": "LOCAL",
        "service_importance": "LOW",
    },
    {
        "id": "F2",
        "title": "OpenSSL vuln on payment API",
        "host": "10.0.0.20",
        "severity": "HIGH", "confidence": "HIGH",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 7.5},
        "asset_criticality": "CRITICAL",
        "network_exposure": "INTERNET",
        "service_importance": "CRITICAL",
    },
    {
        "id": "F3",
        "title": "Apache info disclosure (lab box)",
        "host": "10.0.0.11",
        "severity": "MEDIUM", "confidence": "MEDIUM",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 5.3},
        "asset_criticality": "LOW",
        "network_exposure": "LOCAL",
        "service_importance": "LOW",
    },
    {
        "id": "F4",
        "title": "MySQL weak config on internal DB",
        "host": "10.0.0.30",
        "severity": "HIGH", "confidence": "MEDIUM",
        "status": "REQUIRES_VALIDATION",
        "cvss": {"base_score": 8.1},
        "asset_criticality": "HIGH",
        "network_exposure": "INTERNAL",
        "service_importance": "HIGH",
    },
    {
        "id": "F5",
        "title": "Outdated nginx on marketing site",
        "host": "10.0.0.21",
        "severity": "MEDIUM", "confidence": "HIGH",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 6.1},
        "asset_criticality": "MEDIUM",
        "network_exposure": "DMZ",
        "service_importance": "NORMAL",
    },
    {
        "id": "F6",
        "title": "SMB signing disabled (critical file server)",
        "host": "10.0.0.31",
        "severity": "HIGH", "confidence": "HIGH",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 7.0},
        "asset_criticality": "CRITICAL",
        "network_exposure": "INTERNAL",
        "service_importance": "CRITICAL",
    },
    {
        "id": "F7",
        "title": "TLS misconfig on public portal",
        "host": "10.0.0.22",
        "severity": "MEDIUM", "confidence": "MEDIUM",
        "status": "REQUIRES_VALIDATION",
        "cvss": {"base_score": 5.9},
        "asset_criticality": "HIGH",
        "network_exposure": "INTERNET",
        "service_importance": "HIGH",
    },
    {
        "id": "F8",
        "title": "PostgreSQL CVE on isolated test host",
        "host": "10.0.0.12",
        "severity": "CRITICAL", "confidence": "MEDIUM",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 9.1},
        "asset_criticality": "LOW",
        "network_exposure": "LOCAL",
        "service_importance": "NORMAL",
    },
    # ---- Conflicting-context findings ----
    # Dimensions deliberately disagree so the weighting choice can
    # actually change the ranking (stress test for weight sensitivity).
    {
        "id": "F9",
        "title": "Important but isolated DB server",
        "host": "10.0.0.40",
        "severity": "HIGH", "confidence": "HIGH",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 7.2},
        "asset_criticality": "CRITICAL",   # high value
        "network_exposure": "LOCAL",       # but isolated
        "service_importance": "LOW",       # and minor service
    },
    {
        "id": "F10",
        "title": "Exposed low-value kiosk, critical service",
        "host": "10.0.0.41",
        "severity": "HIGH", "confidence": "HIGH",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 7.2},
        "asset_criticality": "LOW",        # throwaway asset
        "network_exposure": "INTERNET",    # but internet-facing
        "service_importance": "CRITICAL",  # and runs a critical service
    },
    {
        "id": "F11",
        "title": "High-value host, quiet service, internal",
        "host": "10.0.0.42",
        "severity": "HIGH", "confidence": "HIGH",
        "status": "POTENTIALLY_VULNERABLE",
        "cvss": {"base_score": 7.2},
        "asset_criticality": "HIGH",       # important
        "network_exposure": "LOCAL",       # isolated
        "service_importance": "NORMAL",    # ordinary service
    },
]


# -------------------------------------------------------------------
# Scenario grid (single-finding sensitivity analysis)
# -------------------------------------------------------------------
#
# Used to show how one fixed finding's score reacts as environmental
# context changes while its technical characteristics stay constant.
# -------------------------------------------------------------------

SCENARIOS: list[dict[str, str]] = [
    {"id": "S1", "asset_criticality": "LOW", "network_exposure": "LOCAL", "service_importance": "LOW"},
    {"id": "S2", "asset_criticality": "MEDIUM", "network_exposure": "INTERNAL", "service_importance": "NORMAL"},
    {"id": "S3", "asset_criticality": "HIGH", "network_exposure": "INTERNAL", "service_importance": "HIGH"},
    {"id": "S4", "asset_criticality": "CRITICAL", "network_exposure": "INTERNET", "service_importance": "CRITICAL"},
    {"id": "S5", "asset_criticality": "CRITICAL", "network_exposure": "DMZ", "service_importance": "HIGH"},
    {"id": "S6", "asset_criticality": "LOW", "network_exposure": "INTERNET", "service_importance": "NORMAL"},
]


# A single fixed finding used for the scenario sensitivity test.
SENSITIVITY_FINDING: dict[str, Any] = {
    "id": "FX",
    "title": "Fixed CVSS 7.5 finding",
    "severity": "HIGH", "confidence": "HIGH",
    "status": "POTENTIALLY_VULNERABLE",
    "cvss": {"base_score": 7.5},
}

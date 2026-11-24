"""
The three prioritization models compared in the evaluation.

All three reuse the real VulnX risk engine so the experiment reflects
the actual tool, not a reimplementation.

    1. cvss_only       - rank purely by CVSS base score (baseline)
    2. base_vulnx      - VulnX technical score with NEUTRAL context
                         (severity, confidence, status, CVSS, exposure)
    3. context_aware   - full VulnX score including asset context

Comparing (1) vs (3) shows the effect of adding context. Comparing
(2) vs (3) isolates the context contribution from the rest of the
VulnX model.
"""

from typing import Any

from vulnerability_engine.risk_engine import (
    calculate_risk_score,
    _normalize_cvss,
)


# Neutral context forces the context multiplier to 1.0.
NEUTRAL_CONTEXT = {
    "asset_criticality": "MEDIUM",
    "network_exposure": "INTERNAL",
    "service_importance": "NORMAL",
}


def cvss_only_score(finding: dict[str, Any]) -> float:
    """
    Baseline: the raw CVSS base score (0 - 10).
    """

    # Reuse the engine's normalizer, then rescale back to 0 - 10 so
    # the number is readable in the output tables.
    return round(_normalize_cvss(finding.get("cvss")) * 10.0, 2)


def base_vulnx_score(finding: dict[str, Any]) -> float:
    """
    VulnX technical score with neutral context (multiplier = 1.0).
    """

    neutral = dict(finding)
    neutral.update(NEUTRAL_CONTEXT)
    return calculate_risk_score(neutral)


def context_aware_score(finding: dict[str, Any]) -> float:
    """
    Full VulnX context-aware score using the finding's own asset
    context. Missing context falls back to the engine's defaults.
    """

    return calculate_risk_score(finding)


MODELS = {
    "cvss_only": cvss_only_score,
    "base_vulnx": base_vulnx_score,
    "context_aware": context_aware_score,
}

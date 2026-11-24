"""
Weight sensitivity analysis for the VulnX context-aware model.

The context multiplier combines three dimensions with fixed weights:

    context = asset*0.40 + exposure*0.35 + service*0.25

A reviewer will ask why those numbers. This experiment answers that by
perturbing the weights and measuring how much the resulting ranking
changes versus the default. A ranking that stays highly correlated
under a range of reasonable weightings is robust: the exact weights do
not drive the conclusions, so the model is defensible.

It also sweeps the per-level spread (how far LOW..CRITICAL fan out) to
show the ranking does not depend on that exact calibration either.

Run from the project root:

    python -m experiments.weight_sensitivity
"""

import csv
import os
from typing import Any

from vulnerability_engine.risk_engine import (
    SEVERITY_WEIGHTS, CONFIDENCE_WEIGHTS, STATUS_WEIGHTS,
    ASSET_CRITICALITY_WEIGHTS, NETWORK_EXPOSURE_WEIGHTS,
    SERVICE_IMPORTANCE_WEIGHTS, _normalize_cvss,
)
from experiments.dataset import FINDINGS
from experiments.metrics import spearman, kendall_tau

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")

# Default VulnX dimension weights.
DEFAULT_W = (0.40, 0.35, 0.25)


def _lvl(table: dict[str, float], value: Any, default: str) -> float:
    key = str(value).upper().strip() if value else default
    return table.get(key, table[default])


def risk_with_weights(finding: dict[str, Any],
                      w: tuple[float, float, float],
                      level_scale: float = 1.0) -> float:
    """
    Recompute the VulnX risk score with custom dimension weights and an
    optional level-spread scale. level_scale compresses (<1) or expands
    (>1) how far each context level sits from the neutral value 1.0.
    """

    def scaled(table, value, default):
        f = _lvl(table, value, default)
        return 1.0 + (f - 1.0) * level_scale

    asset = scaled(ASSET_CRITICALITY_WEIGHTS, finding.get("asset_criticality"), "MEDIUM")
    expo = scaled(NETWORK_EXPOSURE_WEIGHTS, finding.get("network_exposure"), "INTERNAL")
    svc = scaled(SERVICE_IMPORTANCE_WEIGHTS, finding.get("service_importance"), "NORMAL")

    ctx = asset * w[0] + expo * w[1] + svc * w[2]

    sev = _lvl(SEVERITY_WEIGHTS, finding.get("severity"), "UNKNOWN")
    conf = _lvl(CONFIDENCE_WEIGHTS, finding.get("confidence"), "LOW")
    status = _lvl(STATUS_WEIGHTS, finding.get("status"), "OBSERVED")
    cvss_w = 0.5 + _normalize_cvss(finding.get("cvss"))

    return sev * conf * status * cvss_w * ctx


def _scores(w, level_scale=1.0):
    return [risk_with_weights(f, w, level_scale) for f in FINDINGS]


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    base = _scores(DEFAULT_W)

    # 1) Alternative dimension weightings (each sums to 1.0).
    weightings = {
        "default 40/35/25": (0.40, 0.35, 0.25),
        "equal 33/33/33": (1/3, 1/3, 1/3),
        "asset-heavy 50/30/20": (0.50, 0.30, 0.20),
        "exposure-heavy 30/45/25": (0.30, 0.45, 0.25),
        "service-heavy 25/30/45": (0.25, 0.30, 0.45),
        "reversed 25/35/40": (0.25, 0.35, 0.40),
    }

    print("=== Dimension-weight sensitivity (ranking vs default) ===")
    print(f"{'weighting':<26}{'Spearman':<11}{'Kendall'}")
    rows = []
    for name, w in weightings.items():
        s = _scores(w)
        sp = round(spearman(base, s), 3)
        kt = round(kendall_tau(base, s), 3)
        print(f"{name:<26}{sp:<11}{kt}")
        rows.append([name, f"{w[0]:.3f}", f"{w[1]:.3f}", f"{w[2]:.3f}", sp, kt])

    with open(os.path.join(RESULTS_DIR, "weight_sensitivity.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["weighting", "w_asset", "w_exposure", "w_service", "spearman_vs_default", "kendall_vs_default"])
        wr.writerows(rows)

    # 2) Level-spread sensitivity (how aggressive the per-level fan-out is).
    print("\n=== Level-spread sensitivity (ranking vs default spread) ===")
    print(f"{'level_scale':<14}{'Spearman':<11}{'Kendall'}")
    rows2 = []
    for scale in [0.5, 0.75, 1.0, 1.25, 1.5]:
        s = _scores(DEFAULT_W, level_scale=scale)
        sp = round(spearman(base, s), 3)
        kt = round(kendall_tau(base, s), 3)
        tag = f"{scale:.2f}" + (" (default)" if scale == 1.0 else "")
        print(f"{tag:<14}{sp:<11}{kt}")
        rows2.append([scale, sp, kt])

    with open(os.path.join(RESULTS_DIR, "level_spread_sensitivity.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["level_scale", "spearman_vs_default", "kendall_vs_default"])
        wr.writerows(rows2)

    # 3) Headline stability number.
    sp_vals = [spearman(base, _scores(w)) for w in weightings.values()]
    print(f"\nMean Spearman across all weightings: {sum(sp_vals)/len(sp_vals):.3f}")
    print("Interpretation: values near 1.0 mean the ranking barely moves "
          "when the weights change, so the exact weights are not load-bearing.")
    print("\nCSVs written to experiments/results/.")


if __name__ == "__main__":
    main()

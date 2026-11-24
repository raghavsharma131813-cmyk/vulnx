"""
VulnX evaluation harness.

Runs three experiments and writes reproducible CSV output to
experiments/results/:

    1. Scenario sensitivity  - one fixed finding across S1..S6
    2. Ranking comparison    - cvss_only vs base_vulnx vs context_aware
                               over the controlled finding set, with
                               Spearman and Kendall agreement
    3. Ablation              - drop each context factor, measure how
                               much the ranking moves vs the full model

Run from the project root:

    python -m experiments.run_experiments
"""

import csv
import os
from typing import Any, Callable

from vulnerability_engine.risk_engine import (
    calculate_risk_score,
    classify_risk,
    calculate_context_multiplier,
)

from experiments.dataset import (
    FINDINGS,
    SCENARIOS,
    SENSITIVITY_FINDING,
)
from experiments.models import MODELS
from experiments.metrics import (
    spearman, kendall_tau, rank_with_ties, ndcg_at_k, topk_overlap,
)


RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def _ensure_results_dir() -> None:
    os.makedirs(RESULTS_DIR, exist_ok=True)


def _write_csv(name: str, header: list[str], rows: list[list[Any]]) -> str:
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)
    return path


# -------------------------------------------------------------------
# Experiment 1: scenario sensitivity
# -------------------------------------------------------------------

def experiment_scenario_sensitivity() -> None:
    print("\n=== Experiment 1: scenario sensitivity (one fixed finding) ===")
    print(f"{'Scenario':<10}{'ctx_mult':<10}{'risk':<8}{'band'}")

    rows: list[list[Any]] = []
    for sc in SCENARIOS:
        finding = dict(SENSITIVITY_FINDING)
        finding.update({
            "asset_criticality": sc["asset_criticality"],
            "network_exposure": sc["network_exposure"],
            "service_importance": sc["service_importance"],
        })
        mult = calculate_context_multiplier(finding)
        score = calculate_risk_score(finding)
        band = classify_risk(score)
        print(f"{sc['id']:<10}{mult:<10}{score:<8}{band}")
        rows.append([
            sc["id"], sc["asset_criticality"], sc["network_exposure"],
            sc["service_importance"], mult, score, band,
        ])

    path = _write_csv(
        "scenario_sensitivity.csv",
        ["scenario", "asset_criticality", "network_exposure",
         "service_importance", "context_multiplier", "risk_score", "risk_band"],
        rows,
    )
    print(f"written: {path}")


# -------------------------------------------------------------------
# Experiment 2: ranking comparison
# -------------------------------------------------------------------

def _priority_order(ids: list[str], scores: list[float]) -> dict[str, int]:
    """Map finding id -> integer priority position (1 = top)."""
    ranks = rank_with_ties(scores)
    return {fid: int(round(r)) for fid, r in zip(ids, ranks)}


def experiment_ranking_comparison(findings=None, label="synthetic") -> None:
    print(f"\n=== Experiment 2: ranking comparison across models [{label}] ===")

    findings = findings if findings is not None else FINDINGS
    ids = [str(f.get("id")) for f in findings]
    titles = {str(f.get("id")): f.get("title", "") for f in findings}

    # Score every finding under every model.
    scores: dict[str, list[float]] = {}
    for name, fn in MODELS.items():
        scores[name] = [fn(f) for f in findings]

    # Per-finding table.
    header = ["id", "title", "cvss_only", "base_vulnx", "context_aware",
              "rank_cvss", "rank_context"]
    rank_cvss = _priority_order(ids, scores["cvss_only"])
    rank_ctx = _priority_order(ids, scores["context_aware"])

    rows: list[list[Any]] = []
    print(f"{'id':<5}{'cvss':<8}{'base':<8}{'ctx':<8}{'rCVSS':<7}{'rCTX':<6}title")
    for i, fid in enumerate(ids):
        rows.append([
            fid, titles[fid],
            scores["cvss_only"][i], scores["base_vulnx"][i],
            scores["context_aware"][i], rank_cvss[fid], rank_ctx[fid],
        ])
        print(f"{fid:<5}{scores['cvss_only'][i]:<8}{scores['base_vulnx'][i]:<8}"
              f"{scores['context_aware'][i]:<8}{rank_cvss[fid]:<7}{rank_ctx[fid]:<6}{titles[fid]}")

    _write_csv(f"ranking_comparison_{label}.csv", header, rows)

    # Agreement matrix between models.
    print("\n-- ranking agreement (Spearman / Kendall) --")
    names = list(MODELS.keys())
    corr_rows: list[list[Any]] = []
    for a in names:
        for b in names:
            if a >= b:
                continue
            s = round(spearman(scores[a], scores[b]), 3)
            k = round(kendall_tau(scores[a], scores[b]), 3)
            print(f"{a:<15} vs {b:<15} Spearman={s:<7} Kendall={k}")
            corr_rows.append([a, b, s, k])

    _write_csv(f"ranking_agreement_{label}.csv",
               ["model_a", "model_b", "spearman", "kendall_tau"], corr_rows)
    print(f"written: ranking_comparison_{label}.csv, ranking_agreement_{label}.csv")


# -------------------------------------------------------------------
# Experiment 3: ablation
# -------------------------------------------------------------------

CONTEXT_FACTORS = {
    "asset_criticality": "MEDIUM",
    "network_exposure": "INTERNAL",
    "service_importance": "NORMAL",
}


def experiment_ablation(findings=None, label="synthetic") -> None:
    print(f"\n=== Experiment 3: ablation (drop one context factor at a time) [{label}] ===")

    findings = findings if findings is not None else FINDINGS
    full = [calculate_risk_score(f) for f in findings]

    rows: list[list[Any]] = []
    print(f"{'dropped_factor':<22}{'Spearman_vs_full':<18}{'Kendall_vs_full'}")
    for factor, neutral_value in CONTEXT_FACTORS.items():
        ablated: list[float] = []
        for f in findings:
            g = dict(f)
            g[factor] = neutral_value  # neutralize this one factor
            ablated.append(calculate_risk_score(g))
        s = round(spearman(full, ablated), 3)
        k = round(kendall_tau(full, ablated), 3)
        print(f"{factor:<22}{s:<18}{k}")
        rows.append([factor, s, k])

    _write_csv(f"ablation_{label}.csv",
               ["dropped_factor", "spearman_vs_full", "kendall_vs_full"], rows)
    print(f"written: ablation_{label}.csv")
    print("note: lower correlation means removing that factor changes the "
          "ranking more, i.e. that factor carries more weight.")


def experiment_ranking_quality(findings=None, label="synthetic") -> None:
    """
    Top-of-list quality: how well each baseline recovers the
    context-aware priority order at the top k. Relevance = the
    context-aware risk score (the order VulnX argues is correct).
    """
    print(f"\n=== Experiment 4: top-of-list quality vs context-aware [{label}] ===")

    findings = findings if findings is not None else FINDINGS
    ctx_scores = [MODELS["context_aware"](f) for f in findings]

    rows = []
    print(f"{'baseline':<16}{'NDCG@3':<9}{'NDCG@5':<9}{'top3 overlap':<14}{'top5 overlap'}")
    for name in ["cvss_only", "base_vulnx"]:
        base_scores = [MODELS[name](f) for f in findings]
        # relevance values in the order this baseline ranks findings
        order = sorted(range(len(findings)), key=lambda i: base_scores[i], reverse=True)
        ordered_rel = [ctx_scores[i] for i in order]
        n3 = round(ndcg_at_k(ordered_rel, 3), 3)
        n5 = round(ndcg_at_k(ordered_rel, 5), 3)
        o3 = round(topk_overlap(ctx_scores, base_scores, 3), 3)
        o5 = round(topk_overlap(ctx_scores, base_scores, 5), 3)
        print(f"{name:<16}{n3:<9}{n5:<9}{o3:<14}{o5}")
        rows.append([name, n3, n5, o3, o5])

    _write_csv(f"ranking_quality_{label}.csv",
               ["baseline", "ndcg@3", "ndcg@5", "top3_overlap", "top5_overlap"], rows)
    print(f"written: ranking_quality_{label}.csv")
    print("note: lower NDCG/overlap means the baseline buries findings that "
          "context-aware ranks near the top.")


def main() -> None:
    _ensure_results_dir()
    experiment_scenario_sensitivity()
    experiment_ranking_comparison()
    experiment_ablation()
    experiment_ranking_quality()
    print("\nAll experiments complete. CSVs are in experiments/results/.")


if __name__ == "__main__":
    main()

"""
Rank-correlation metrics for the VulnX evaluation.

Pure Python, no external dependencies. Implements:

    - average-tie ranking
    - Pearson correlation
    - Spearman rank correlation (Pearson on ranks)
    - Kendall tau-b (tie corrected)

These compare two prioritization rankings produced by different
scoring models over the same set of findings.
"""

from typing import Sequence


def rank_with_ties(values: Sequence[float]) -> list[float]:
    """
    Return fractional (average-tie) ranks for a list of values.

    Highest value gets rank 1 (priority ordering). Ties share the
    average of the ranks they span.
    """

    n = len(values)
    order = sorted(range(n), key=lambda i: values[i], reverse=True)

    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        # Group equal values.
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0  # 1-based average rank
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1

    return ranks


def pearson(x: Sequence[float], y: Sequence[float]) -> float:
    """
    Pearson correlation coefficient. Returns 0.0 if either series
    has zero variance.
    """

    n = len(x)
    if n == 0:
        return 0.0

    mean_x = sum(x) / n
    mean_y = sum(y) / n

    cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
    var_x = sum((x[i] - mean_x) ** 2 for i in range(n))
    var_y = sum((y[i] - mean_y) ** 2 for i in range(n))

    if var_x == 0 or var_y == 0:
        return 0.0

    return cov / ((var_x ** 0.5) * (var_y ** 0.5))


def spearman(x: Sequence[float], y: Sequence[float]) -> float:
    """
    Spearman rank correlation: Pearson on average-tie ranks.
    """

    return pearson(rank_with_ties(x), rank_with_ties(y))


def kendall_tau(x: Sequence[float], y: Sequence[float]) -> float:
    """
    Kendall tau-b (handles ties in either series).
    """

    n = len(x)
    if n < 2:
        return 0.0

    concordant = 0
    discordant = 0
    ties_x = 0
    ties_y = 0

    for i in range(n):
        for j in range(i + 1, n):
            dx = x[i] - x[j]
            dy = y[i] - y[j]
            sign = (dx > 0) - (dx < 0)
            sign_y = (dy > 0) - (dy < 0)

            if dx == 0 and dy == 0:
                ties_x += 1
                ties_y += 1
            elif dx == 0:
                ties_x += 1
            elif dy == 0:
                ties_y += 1
            else:
                if sign == sign_y:
                    concordant += 1
                else:
                    discordant += 1

    total_pairs = n * (n - 1) / 2.0
    denom = ((total_pairs - ties_x) * (total_pairs - ties_y)) ** 0.5
    if denom == 0:
        return 0.0

    return (concordant - discordant) / denom


# -------------------------------------------------------------------
# Top-of-list quality metrics (NDCG@k, top-k agreement)
# -------------------------------------------------------------------

import math


def dcg_at_k(relevances: Sequence[float], k: int) -> float:
    """Discounted cumulative gain of the first k relevance values."""
    return sum(
        rel / math.log2(i + 2)
        for i, rel in enumerate(list(relevances)[:k])
    )


def ndcg_at_k(ordered_relevances: Sequence[float], k: int) -> float:
    """
    NDCG@k given the relevance values IN THE ORDER a model ranked them.
    1.0 means the model put the most relevant items first; lower means
    it buried high-relevance items below the top k.
    """
    dcg = dcg_at_k(ordered_relevances, k)
    ideal = dcg_at_k(sorted(ordered_relevances, reverse=True), k)
    return dcg / ideal if ideal > 0 else 0.0


def topk_overlap(scores_a: Sequence[float], scores_b: Sequence[float], k: int) -> float:
    """
    Fraction of the top-k items shared between two score vectors
    (precision@k of one ranking against the other's top set).
    """
    if k <= 0:
        return 0.0
    idx_a = set(sorted(range(len(scores_a)), key=lambda i: scores_a[i], reverse=True)[:k])
    idx_b = set(sorted(range(len(scores_b)), key=lambda i: scores_b[i], reverse=True)[:k])
    return len(idx_a & idx_b) / float(k)

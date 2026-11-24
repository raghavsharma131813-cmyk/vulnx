from __future__ import annotations

from typing import Any

from scanner.metasploit_mapper import (
    map_finding_to_metasploit,
    split_metasploit_modules,
)
from scanner.metasploit_runner import MetasploitRunner


def discover_cve_modules(
    finding: dict[str, Any],
    runner: MetasploitRunner,
) -> dict[str, list[dict[str, Any]]]:
    """
    Discover Metasploit modules directly associated with
    the CVEs stored on a VulnX finding.

    These are returned separately from broader service-based
    candidates.

    Discovery only:
        No module is executed.
    """

    modules = map_finding_to_metasploit(
        finding,
        runner,
    )

    grouped = split_metasploit_modules(
        modules
    )

    return {
        "auxiliary": grouped["auxiliary"],
        "exploit": grouped["exploit"],
        "errors": grouped["error"],
    }


def discover_service_candidates(
    finding: dict[str, Any],
    runner: MetasploitRunner,
) -> dict[str, list[dict[str, Any]]]:
    """
    Discover broader Metasploit candidates based on the
    observed service.

    These are analyst candidates, not vulnerability confirmation.
    """

    service = (
        finding.get("service")
        or ""
    ).strip().lower()

    if not service:
        return {
            "auxiliary": [],
            "exploit": [],
            "errors": [],
        }

    search_query = f"name:{service}"

    try:
        auxiliary = runner.search_auxiliary(
            search_query
        )

        exploits = runner.search_exploits(
            search_query
        )

        return {
            "auxiliary": auxiliary,
            "exploit": exploits,
            "errors": [],
        }

    except Exception as exc:
        return {
            "auxiliary": [],
            "exploit": [],
            "errors": [
                {
                    "module_type": "error",
                    "module_name": "",
                    "disclosure_date": "",
                    "rank": "",
                    "check": "",
                    "description": str(exc),
                }
            ],
        }


def discover_for_finding(
    finding: dict[str, Any],
    runner: MetasploitRunner,
) -> dict[str, Any]:
    """
    Build the complete Metasploit intelligence object
    for one VulnX finding.

    Structure:

        {
            "cve_linked": {
                "auxiliary": [...],
                "exploit": [...],
                "errors": [...]
            },
            "service_candidates": {
                "auxiliary": [...],
                "exploit": [...],
                "errors": [...]
            }
        }

    No execution is performed.
    """

    cve_modules = discover_cve_modules(
        finding,
        runner,
    )

    service_candidates = discover_service_candidates(
        finding,
        runner,
    )

    return {
        "cve_linked": cve_modules,
        "service_candidates": service_candidates,
    }


def summarize_intelligence(
    intelligence: dict[str, Any],
) -> dict[str, int]:
    """
    Produce simple counts for dashboard/test use.
    """

    cve_linked = intelligence.get(
        "cve_linked",
        {},
    )

    service_candidates = intelligence.get(
        "service_candidates",
        {},
    )

    return {
        "cve_auxiliary": len(
            cve_linked.get(
                "auxiliary",
                [],
            )
        ),
        "cve_exploit": len(
            cve_linked.get(
                "exploit",
                [],
            )
        ),
        "cve_errors": len(
            cve_linked.get(
                "errors",
                [],
            )
        ),
        "service_auxiliary": len(
            service_candidates.get(
                "auxiliary",
                [],
            )
        ),
        "service_exploit": len(
            service_candidates.get(
                "exploit",
                [],
            )
        ),
        "service_errors": len(
            service_candidates.get(
                "errors",
                [],
            )
        ),
    }
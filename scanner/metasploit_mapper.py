from __future__ import annotations

from typing import Any

from scanner.metasploit_runner import MetasploitRunner


def map_finding_to_metasploit(
    finding: dict[str, Any],
    runner: MetasploitRunner,
) -> list[dict[str, Any]]:
    """
    Discover Metasploit modules associated with the CVEs
    present in a VulnX finding.

    This function performs module discovery only.
    It does not execute or validate any module.

    Returns a de-duplicated list of module metadata.
    """

    cves = finding.get("cves") or []

    if isinstance(cves, str):
        cves = [cves]

    modules: list[dict[str, Any]] = []
    seen: set[str] = set()

    for cve_id in cves:
        if not isinstance(cve_id, str):
            continue

        cve_id = cve_id.strip().upper()

        if not cve_id:
            continue

        try:
            discovered = runner.search_for_cve(cve_id)
        except Exception as exc:
            # Preserve scan operation even if Metasploit
            # cannot answer one CVE query.
            modules.append(
                {
                    "module_type": "error",
                    "module_name": "",
                    "disclosure_date": "",
                    "rank": "",
                    "check": "",
                    "description": (
                        f"Metasploit search failed for "
                        f"{cve_id}: {exc}"
                    ),
                    "cve": cve_id,
                }
            )
            continue

        for module in discovered:
            module_name = (
                module.get("module_name") or ""
            ).strip()

            if not module_name:
                continue

            # De-duplicate modules that appear through
            # multiple CVE references.
            dedupe_key = (
                f"{cve_id}:{module_name}"
            )

            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)

            module_record = dict(module)

            module_record["cve"] = cve_id

            modules.append(module_record)

    return modules


def split_metasploit_modules(
    modules: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """
    Separate discovered modules into auxiliary and exploit groups.
    """

    result = {
        "auxiliary": [],
        "exploit": [],
        "error": [],
    }

    for module in modules:
        module_type = module.get(
            "module_type"
        )

        if module_type == "auxiliary":
            result["auxiliary"].append(module)

        elif module_type == "exploit":
            result["exploit"].append(module)

        else:
            result["error"].append(module)

    return result

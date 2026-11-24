from vulnerability_engine.risk_engine import (
    calculate_context_multiplier,
    calculate_risk_score,
    classify_risk,
)


BASE_FINDING = {
    "host": "192.168.56.200",
    "port": 21,
    "service": "ftp",
    "title": "CVE-2011-2523",
    "severity": "CRITICAL",
    "confidence": "MEDIUM",
    "status": "POTENTIALLY_VULNERABLE",
    "cvss": {
        "version": "3.1",
        "base_score": 9.8,
        "severity": "CRITICAL",
        "vector": None,
    },
}


SCENARIOS = [
    {
        "name": "Low-context internal asset",
        "asset_criticality": "LOW",
        "network_exposure": "LOCAL",
        "service_importance": "LOW",
    },
    {
        "name": "Normal internal server",
        "asset_criticality": "MEDIUM",
        "network_exposure": "INTERNAL",
        "service_importance": "NORMAL",
    },
    {
        "name": "High-value internal server",
        "asset_criticality": "HIGH",
        "network_exposure": "INTERNAL",
        "service_importance": "HIGH",
    },
    {
        "name": "Internet-facing critical service",
        "asset_criticality": "CRITICAL",
        "network_exposure": "INTERNET",
        "service_importance": "CRITICAL",
    },
]


print("=== VulnX Context-Aware Risk Test ===")
print()

for scenario in SCENARIOS:

    finding = dict(BASE_FINDING)

    finding.update(
        {
            "asset_criticality": scenario["asset_criticality"],
            "network_exposure": scenario["network_exposure"],
            "service_importance": scenario["service_importance"],
        }
    )

    multiplier = calculate_context_multiplier(
        finding
    )

    score = calculate_risk_score(
        finding
    )

    risk_level = classify_risk(
        score
    )

    print("--------------------------------")
    print(
        f"Scenario            : {scenario['name']}"
    )
    print(
        f"Asset Criticality   : {scenario['asset_criticality']}"
    )
    print(
        f"Network Exposure    : {scenario['network_exposure']}"
    )
    print(
        f"Service Importance  : {scenario['service_importance']}"
    )
    print(
        f"Context Multiplier  : {multiplier}"
    )
    print(
        f"Risk Score          : {score}"
    )
    print(
        f"Risk Level          : {risk_level}"
    )

print()
print("Context-aware risk testing completed.")
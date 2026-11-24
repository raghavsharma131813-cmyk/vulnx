from vulnerability_engine.engine import analyze_scan
from vulnerability_engine.test_data import get_test_scan


def main() -> None:
    print("=== VulnX Risk Engine Test ===")

    scan = get_test_scan()
    result = analyze_scan(scan)

    print(f"Total findings: {result['finding_count']}")

    for finding in result["findings"]:
        print("\n--------------------------------")
        print(f"Host        : {finding['host']}")
        print(f"Port        : {finding['port']}")
        print(f"Service     : {finding['service']}")
        print(f"Title       : {finding['title']}")
        print(f"Severity    : {finding['severity']}")
        print(f"Confidence  : {finding['confidence']}")
        print(f"Status      : {finding['status']}")
        print(f"Risk Score  : {finding['risk_score']}")
        print(f"Risk Level  : {finding['risk_level']}")

        if "cvss" in finding:
            print(f"CVSS        : {finding['cvss']}")

        if finding.get("cves"):
            print(f"CVE         : {', '.join(finding['cves'])}")


if __name__ == "__main__":
    main()

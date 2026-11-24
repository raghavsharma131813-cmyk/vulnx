from vulnerability_engine.engine import analyze_scan
from vulnerability_engine.test_data import get_test_scan


def main() -> None:
    scan = get_test_scan()

    result = analyze_scan(scan)

    print("=== VulnX Service Check Test ===")
    print(f"Findings: {result['finding_count']}")

    for finding in result["findings"]:
        print()
        print("--------------------------------")
        print(f"Host       : {finding['host']}")
        print(f"Port       : {finding['port']}")
        print(f"Service    : {finding['service']}")
        print(f"Title      : {finding['title']}")
        print(f"Severity   : {finding['severity']}")
        print(f"Confidence : {finding['confidence']}")
        print(f"Status     : {finding['status']}")


if __name__ == "__main__":
    main()
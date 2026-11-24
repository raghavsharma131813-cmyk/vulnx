from vulnerability_engine.nvd_client import (
    fetch_cves_for_cpe,
    normalize_cpe,
)


def main() -> None:
    print("=== VulnX NVD Client Test ===")

    test_cpe = (
        "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:"
        "*:*:*:*:*:*:*"
    )

    print()
    print("Input CPE:")
    print(test_cpe)

    print()
    print("Normalized CPE:")
    print(normalize_cpe(test_cpe))

    print()
    print("Querying NVD...")

    try:
        cves = fetch_cves_for_cpe(test_cpe)

    except Exception as exc:
        print()
        print(f"NVD error: {exc}")
        return

    print()
    print(f"CVE records returned: {len(cves)}")

    for record in cves[:10]:
        print()
        print("--------------------------------")

        print(f"CVE         : {record['cve']}")

        print(
            f"Description : "
            f"{record['description'][:200]}"
        )

        if record["cvss"]:
            print(
                f"CVSS        : "
                f"{record['cvss']['base_score']}"
            )

            print(
                f"Severity    : "
                f"{record['cvss']['severity']}"
            )

            print(
                f"CVSS Ver.   : "
                f"{record['cvss']['version']}"
            )

        print(
            f"Published   : "
            f"{record['published']}"
        )

        print(
            f"URL         : "
            f"{record['url']}"
        )


if __name__ == "__main__":
    main()
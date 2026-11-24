from getpass import getpass

from scanner.formatter import build_scan_summary
from scanner.nmap_parser import parse_nmap_xml
from scanner.nmap_runner import run_nmap_xml_scan
from report.scan_writer import save_scan_json


def main() -> None:
    print("=== VulnX Day 2 Scanner ===")

    target = input(
        "Enter authorized lab target IPv4 address: "
    ).strip()

    password = getpass("Enter Kali password: ")

    try:
        # 1. Run Nmap through Kali
        xml_result = run_nmap_xml_scan(
            password=password,
            target=target,
        )

        # 2. Parse XML
        parsed_result = parse_nmap_xml(xml_result)

        # 3. Build readable summary
        summary = build_scan_summary(parsed_result)

        # 4. Save result
        output_path = save_scan_json(parsed_result)

        print("\n=== VulnX Scan Summary ===")
        print(f"Hosts scanned : {summary['hosts_scanned']}")
        print(f"Open ports    : {summary['total_open_ports']}")

        for host in summary["hosts"]:
            print("\nHost:")

            for address in host["addresses"]:
                print(
                    f"  {address['type']}: "
                    f"{address['address']}"
                )

            if not host["open_ports"]:
                print("  No open ports found.")

            for port in host["open_ports"]:
                print(
                    f"  {port['port']}/"
                    f"{port['protocol']} "
                    f"{port['service'] or 'unknown'}"
                )

                if port["product"]:
                    print(
                        f"    Product: "
                        f"{port['product']}"
                    )

                if port["version"]:
                    print(
                        f"    Version: "
                        f"{port['version']}"
                    )

                if port["cpe"]:
                    print(
                        f"    CPE: "
                        f"{', '.join(port['cpe'])}"
                    )

        print(
            f"\nJSON report saved to: "
            f"{output_path}"
        )

    except Exception as exc:
        print(f"\nScanner error: {exc}")


if __name__ == "__main__":
    main()
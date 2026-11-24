from typing import Any


def build_scan_summary(scan_result: dict[str, Any]) -> dict[str, Any]:
    """
    Convert parsed Nmap data into a compact VulnX scan summary.
    """

    summary: dict[str, Any] = {
        "scanner": scan_result.get("scanner"),
        "hosts_scanned": len(scan_result.get("hosts", [])),
        "total_open_ports": 0,
        "hosts": [],
    }

    for host in scan_result.get("hosts", []):
        addresses = host.get("addresses", [])
        ports = host.get("ports", [])

        open_ports = [
            port for port in ports
            if port.get("state") == "open"
        ]

        host_summary = {
            "addresses": addresses,
            "hostnames": host.get("hostnames", []),
            "open_port_count": len(open_ports),
            "open_ports": open_ports,
        }

        summary["hosts"].append(host_summary)
        summary["total_open_ports"] += len(open_ports)

    return summary
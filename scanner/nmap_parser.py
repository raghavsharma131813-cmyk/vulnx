import xml.etree.ElementTree as ET
from typing import Any


def parse_nmap_xml(xml_data: str) -> dict[str, Any]:
    """
    Parse Nmap XML into structured VulnX data.
    """

    root = ET.fromstring(xml_data)

    result: dict[str, Any] = {
        "scanner": "nmap",
        "hosts": [],
    }

    for host in root.findall("host"):
        host_data: dict[str, Any] = {
            "addresses": [],
            "hostnames": [],
            "ports": [],
        }

        # IP / MAC / other addresses
        for address in host.findall("address"):
            host_data["addresses"].append({
                "type": address.get("addrtype"),
                "address": address.get("addr"),
            })

        # Hostnames
        hostnames = host.find("hostnames")

        if hostnames is not None:
            for hostname in hostnames.findall("hostname"):
                host_data["hostnames"].append({
                    "name": hostname.get("name"),
                    "type": hostname.get("type"),
                })

        # Ports
        ports = host.find("ports")

        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                service = port.find("service")

                port_data: dict[str, Any] = {
                    "protocol": port.get("protocol"),
                    "port": int(port.get("portid", "0")),
                    "state": None,
                    "service": None,
                    "product": None,
                    "version": None,
                    "cpe": [],
                }

                if state is not None:
                    port_data["state"] = state.get("state")

                if service is not None:
                    port_data["service"] = service.get("name")
                    port_data["product"] = service.get("product")
                    port_data["version"] = service.get("version")

                    for cpe in service.findall("cpe"):
                        if cpe.text:
                            port_data["cpe"].append(cpe.text)

                host_data["ports"].append(port_data)

        result["hosts"].append(host_data)

    return result
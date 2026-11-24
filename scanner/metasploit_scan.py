from __future__ import annotations

from typing import Any

import paramiko

from scanner.metasploit_intelligence import (
    split_metasploit_modules,
)
from scanner.metasploit_runner import MetasploitRunner

from scanner.metasploit_database import (
    cache_get,
    cache_put,
)


import os

# Scanner (Kali) SSH target. Configurable via environment so VulnX can
# run in a container that scans through its own localhost.
KALI_HOST = os.getenv("VULNX_SCANNER_HOST", "192.168.56.101")
KALI_USERNAME = os.getenv("VULNX_SCANNER_USER", "kali")


# -------------------------------------------------------------------
# Kali SSH connection
# -------------------------------------------------------------------

def create_kali_ssh_client(
    password: str,
) -> paramiko.SSHClient:
    """
    Create an SSH connection to the Kali VM.

    This connection is used only for Metasploit
    module discovery.
    """

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    client.connect(
        hostname=KALI_HOST,
        username=KALI_USERNAME,
        password=password,
        timeout=15,
        banner_timeout=15,
        auth_timeout=15,
    )

    return client


# -------------------------------------------------------------------
# Host extraction helper
# -------------------------------------------------------------------

def _get_host_from_host_data(
    host_data: dict[str, Any],
) -> str:
    """
    Extract the IPv4 address from one parsed Nmap host.

    Falls back to another address representation or
    the stored host value when necessary.
    """

    addresses = host_data.get(
        "addresses",
        [],
    )

    for address in addresses:

        if not isinstance(
            address,
            dict,
        ):
            continue

        address_type = (
            address.get("type")
            or ""
        ).lower()

        if address_type == "ipv4":

            return str(
                address.get(
                    "address"
                )
                or address.get(
                    "addr"
                )
                or "unknown"
            )

    if addresses:

        first_address = addresses[0]

        if isinstance(
            first_address,
            dict,
        ):

            return str(
                first_address.get(
                    "address"
                )
                or first_address.get(
                    "addr"
                )
                or "unknown"
            )

        return str(
            first_address
        )

    return str(
        host_data.get(
            "host",
            "unknown",
        )
    )


# -------------------------------------------------------------------
# Port key helper
# -------------------------------------------------------------------

def _build_port_key(
    host: str,
    port_number: int,
    protocol: str,
) -> str:
    """
    Build a stable identifier for one observed open port.
    """

    return (
        f"{host}:{port_number}/"
        f"{protocol.lower()}"
    )


# -------------------------------------------------------------------
# Main Metasploit discovery
# -------------------------------------------------------------------

def discover_metasploit_for_assessment(
    assessment: dict[str, Any],
    parsed_scan: dict[str, Any],
    password: str,
) -> dict[str, Any]:
    """
    Add Metasploit module intelligence to one VulnX assessment.

    VulnX maintains two distinct discovery paths:

    1. CVE-linked modules
       Modules returned specifically for a CVE associated
       with an individual VulnX vulnerability finding.

    2. Port/service-based modules
       All auxiliary and exploit modules discovered from the
       service actually observed on an open Nmap port.

    The port/service collection is additionally organized by:

        host -> port -> protocol

    so the dashboard can later provide a dedicated
    "View All Modules" action for each open port.

    Module discovery only:
        No auxiliary or exploit module is executed.
    """

    result: dict[str, Any] = {
        "cve_linked": {},
        "service_candidates": {},
        "port_candidates": {},
        "errors": [],
    }

    # ---------------------------------------------------------------
    # Password validation
    # ---------------------------------------------------------------

    if not password:

        result[
            "errors"
        ].append(
            "Kali password was not supplied."
        )

        return result

    findings = assessment.get(
        "findings",
        [],
    )

    client: paramiko.SSHClient | None = None

    try:

        # -----------------------------------------------------------
        # Connect to Kali
        # -----------------------------------------------------------

        client = create_kali_ssh_client(
            password
        )

        runner = MetasploitRunner(
            ssh_client=client
        )

        # -----------------------------------------------------------
        # CVE cache
        #
        # One Metasploit search is performed per unique CVE.
        # -----------------------------------------------------------

        cve_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        # -----------------------------------------------------------
        # Service cache
        #
        # One broad service search is performed per unique
        # observed service.
        # -----------------------------------------------------------

        service_cache: dict[
            str,
            dict[
                str,
                list[dict[str, Any]],
            ],
        ] = {}

        # ===========================================================
        # 1. CVE-LINKED MODULE DISCOVERY
        # ===========================================================

        for finding in findings:

            cves = finding.get(
                "cves",
                [],
            )

            if isinstance(
                cves,
                str,
            ):

                cves = [
                    cves
                ]

            finding_cve_modules: list[
                dict[str, Any]
            ] = []

            for cve_id in cves:

                if not isinstance(
                    cve_id,
                    str,
                ):
                    continue

                cve_id = (
                    cve_id
                    .strip()
                    .upper()
                )

                if not cve_id:
                    continue

                try:

                    # ------------------------------------------------
                    # Search Metasploit once per unique CVE
                    # ------------------------------------------------

                    if cve_id not in cve_cache:

                        # Persistent cross-scan cache first.
                        cached = cache_get(
                            f"cve:{cve_id}"
                        )

                        if cached is not None:

                            cve_cache[
                                cve_id
                            ] = cached

                        else:

                            found = runner.search_for_cve(
                                cve_id
                            )

                            cve_cache[
                                cve_id
                            ] = found

                            cache_put(
                                f"cve:{cve_id}",
                                found,
                            )

                    discovered = cve_cache[
                        cve_id
                    ]

                    # ------------------------------------------------
                    # Attach CVE to each module record
                    # ------------------------------------------------

                    for module in discovered:

                        module_record = dict(
                            module
                        )

                        module_record[
                            "cve"
                        ] = cve_id

                        # Preserve the finding's location so the
                        # dashboard can associate the module with
                        # the exact vulnerability/port.

                        module_record[
                            "host"
                        ] = finding.get(
                            "host",
                            "unknown",
                        )

                        module_record[
                            "port"
                        ] = finding.get(
                            "port",
                            0,
                        )

                        module_record[
                            "protocol"
                        ] = finding.get(
                            "protocol",
                            "tcp",
                        )

                        module_record[
                            "service"
                        ] = finding.get(
                            "service"
                        )

                        finding_cve_modules.append(
                            module_record
                        )

                    # ------------------------------------------------
                    # Save grouped CVE information once
                    # ------------------------------------------------

                    if cve_id not in result[
                        "cve_linked"
                    ]:

                        grouped = (
                            split_metasploit_modules(
                                discovered
                            )
                        )

                        result[
                            "cve_linked"
                        ][
                            cve_id
                        ] = {
                            "auxiliary": grouped[
                                "auxiliary"
                            ],
                            "exploit": grouped[
                                "exploit"
                            ],
                            "errors": grouped[
                                "error"
                            ],
                        }

                except Exception as exc:

                    result[
                        "errors"
                    ].append(
                        {
                            "scope": "cve",
                            "cve": cve_id,
                            "error": str(
                                exc
                            ),
                        }
                    )

                    if cve_id not in result[
                        "cve_linked"
                    ]:

                        result[
                            "cve_linked"
                        ][
                            cve_id
                        ] = {
                            "auxiliary": [],
                            "exploit": [],
                            "errors": [
                                str(exc)
                            ],
                        }

            # -------------------------------------------------------
            # Attach CVE-linked modules directly to the finding.
            #
            # This is what the main dashboard will eventually use.
            # -------------------------------------------------------

            finding[
                "metasploit_cve_linked"
            ] = finding_cve_modules

        # ===========================================================
        # 2. DISCOVER SERVICES FROM ACTUAL OPEN NMAP PORTS
        # ===========================================================

        observed_ports: list[
            dict[str, Any]
        ] = []

        observed_services: set[str] = set()

        for host_data in parsed_scan.get(
            "hosts",
            [],
        ):

            host = _get_host_from_host_data(
                host_data
            )

            for port in host_data.get(
                "ports",
                [],
            ):

                # Only consider ports actually reported open.
                if port.get(
                    "state"
                ) != "open":

                    continue

                service = (
                    port.get(
                        "service"
                    )
                    or ""
                ).strip().lower()

                port_number = port.get(
                    "port",
                    0,
                )

                protocol = (
                    port.get(
                        "protocol",
                        "tcp",
                    )
                    or "tcp"
                ).strip().lower()

                # ---------------------------------------------------
                # Store the complete observed-port identity.
                # ---------------------------------------------------

                port_record = {
                    "host": host,
                    "port": port_number,
                    "protocol": protocol,
                    "service": service,
                    "product": port.get(
                        "product"
                    ),
                    "version": port.get(
                        "version"
                    ),
                }

                observed_ports.append(
                    port_record
                )

                if service:

                    observed_services.add(
                        service
                    )

        # ===========================================================
        # 3. BROAD SERVICE MODULE DISCOVERY
        #
        # This is intentionally retained.
        #
        # Example:
        #
        #     observed port = 22/tcp
        #     service = ssh
        #
        #     search name:ssh
        #
        # The result is later attached specifically to 22/tcp.
        # ===========================================================

        for service in sorted(
            observed_services
        ):

            if service in service_cache:

                grouped = service_cache[
                    service
                ]

            else:

                cached_svc = cache_get(
                    f"svc:{service}"
                )

                if cached_svc is not None:

                    grouped = cached_svc

                else:

                    try:

                        auxiliary = (
                            runner.search_auxiliary(
                                f"name:{service}"
                            )
                        )

                        exploits = (
                            runner.search_exploits(
                                f"name:{service}"
                            )
                        )

                        grouped = {
                            "auxiliary": auxiliary,
                            "exploit": exploits,
                            "errors": [],
                        }

                        cache_put(
                            f"svc:{service}",
                            grouped,
                        )

                    except Exception as exc:

                        grouped = {
                            "auxiliary": [],
                            "exploit": [],
                            "errors": [
                                str(exc)
                            ],
                        }

                        result[
                            "errors"
                        ].append(
                            {
                                "scope": "service",
                                "service": service,
                                "error": str(
                                    exc
                                ),
                            }
                        )

                service_cache[
                    service
                ] = grouped

            # -------------------------------------------------------
            # Keep the existing service-level structure.
            #
            # This preserves compatibility with the current
            # dashboard/database code.
            # -------------------------------------------------------

            result[
                "service_candidates"
            ][
                service
            ] = grouped

        # ===========================================================
        # 4. ORGANIZE ALL SERVICE MODULES BY EXACT OPEN PORT
        # ===========================================================

        for port_record in observed_ports:

            host = port_record[
                "host"
            ]

            port_number = port_record[
                "port"
            ]

            protocol = port_record[
                "protocol"
            ]

            service = port_record[
                "service"
            ]

            port_key = _build_port_key(
                host=host,
                port_number=port_number,
                protocol=protocol,
            )

            # -------------------------------------------------------
            # A port without an identified service cannot currently
            # receive service-based Metasploit candidates.
            # -------------------------------------------------------

            if not service:

                result[
                    "port_candidates"
                ][
                    port_key
                ] = {
                    "host": host,
                    "port": port_number,
                    "protocol": protocol,
                    "service": "",
                    "product": port_record.get(
                        "product"
                    ),
                    "version": port_record.get(
                        "version"
                    ),
                    "auxiliary": [],
                    "exploit": [],
                    "errors": [],
                }

                continue

            grouped = service_cache.get(
                service,
                {
                    "auxiliary": [],
                    "exploit": [],
                    "errors": [],
                },
            )

            # -------------------------------------------------------
            # Copy records rather than reusing the exact dictionaries.
            #
            # This allows every module to know the exact port it was
            # associated with.
            # -------------------------------------------------------

            port_auxiliary: list[
                dict[str, Any]
            ] = []

            for module in grouped.get(
                "auxiliary",
                [],
            ):

                module_record = dict(
                    module
                )

                module_record[
                    "host"
                ] = host

                module_record[
                    "port"
                ] = port_number

                module_record[
                    "protocol"
                ] = protocol

                module_record[
                    "service"
                ] = service

                port_auxiliary.append(
                    module_record
                )

            port_exploit: list[
                dict[str, Any]
            ] = []

            for module in grouped.get(
                "exploit",
                [],
            ):

                module_record = dict(
                    module
                )

                module_record[
                    "host"
                ] = host

                module_record[
                    "port"
                ] = port_number

                module_record[
                    "protocol"
                ] = protocol

                module_record[
                    "service"
                ] = service

                port_exploit.append(
                    module_record
                )

            # -------------------------------------------------------
            # Store the exact port-level grouping.
            # -------------------------------------------------------

            result[
                "port_candidates"
            ][
                port_key
            ] = {
                "host": host,
                "port": port_number,
                "protocol": protocol,
                "service": service,
                "product": port_record.get(
                    "product"
                ),
                "version": port_record.get(
                    "version"
                ),
                "auxiliary": port_auxiliary,
                "exploit": port_exploit,
                "errors": grouped.get(
                    "errors",
                    [],
                ),
            }

        # ===========================================================
        # 5. SUMMARY COUNTS
        # ===========================================================

        cve_auxiliary_count = 0
        cve_exploit_count = 0

        for grouped in result[
            "cve_linked"
        ].values():

            cve_auxiliary_count += len(
                grouped.get(
                    "auxiliary",
                    [],
                )
            )

            cve_exploit_count += len(
                grouped.get(
                    "exploit",
                    [],
                )
            )

        service_auxiliary_count = 0
        service_exploit_count = 0

        for grouped in result[
            "service_candidates"
        ].values():

            service_auxiliary_count += len(
                grouped.get(
                    "auxiliary",
                    [],
                )
            )

            service_exploit_count += len(
                grouped.get(
                    "exploit",
                    [],
                )
            )

        port_auxiliary_count = 0
        port_exploit_count = 0

        for grouped in result[
            "port_candidates"
        ].values():

            port_auxiliary_count += len(
                grouped.get(
                    "auxiliary",
                    [],
                )
            )

            port_exploit_count += len(
                grouped.get(
                    "exploit",
                    [],
                )
            )

        # -----------------------------------------------------------
        # Final summary
        # -----------------------------------------------------------

        result[
            "summary"
        ] = {
            # CVE-related
            "cve_count": len(
                result[
                    "cve_linked"
                ]
            ),
            "cve_auxiliary": (
                cve_auxiliary_count
            ),
            "cve_exploit": (
                cve_exploit_count
            ),

            # Service-related
            "service_count": len(
                result[
                    "service_candidates"
                ]
            ),
            "service_auxiliary": (
                service_auxiliary_count
            ),
            "service_exploit": (
                service_exploit_count
            ),

            # Exact port-level organization
            "port_count": len(
                result[
                    "port_candidates"
                ]
            ),
            "port_auxiliary": (
                port_auxiliary_count
            ),
            "port_exploit": (
                port_exploit_count
            ),

            # Errors
            "errors": len(
                result["errors"]
            ),
        }

        return result

    finally:

        if client is not None:

            client.close()
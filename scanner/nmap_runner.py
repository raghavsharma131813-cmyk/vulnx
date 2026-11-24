import ipaddress
import os
import shlex

import paramiko


# Scanner (Kali) SSH target. Configurable so VulnX can run anywhere,
# including a Docker container that scans via its own localhost.
KALI_HOST = os.getenv("VULNX_SCANNER_HOST", "192.168.56.101")
KALI_USERNAME = os.getenv("VULNX_SCANNER_USER", "kali")


def validate_target(target: str) -> str:
    """
    Validate that the target is an IPv4 address.

    VulnX will initially accept only IPv4 targets.
    """
    target = target.strip()

    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Invalid target IP address.") from exc

    if address.version != 4:
        raise ValueError("Only IPv4 targets are supported right now.")

    return str(address)


def connect_to_kali(password: str) -> paramiko.SSHClient:
    """Create an SSH connection to the Kali scanner VM."""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=KALI_HOST,
        port=22,
        username=KALI_USERNAME,
        password=password,
        timeout=10,
        allow_agent=False,
        look_for_keys=False,
    )

    return client


def run_nmap_xml_scan(password: str, target: str) -> str:
    """
    Run a full TCP port and service/version scan on Kali
    and return Nmap XML.
    """

    target = validate_target(target)

    client = connect_to_kali(password)

    try:
        safe_target = shlex.quote(target)

        # -sT: TCP connect scan. Uses normal socket connections instead
        #      of raw packets, so it works without root privileges. The
        #      scanner runs as a non-root user, and a raw-socket scan
        #      (the default) fails for it with "Operation not permitted".
        # -Pn: skip host discovery and scan anyway. Many hosts (and
        #      targets seen through Docker/NAT) do not answer pings, and
        #      without this nmap marks them "down" and finds nothing.
        # -T4: faster timing, sensible for a responsive network.
        # --top-ports 1000: scan the 1000 most common ports instead of
        #      all 65535. A full -p- scan over the internet is far too
        #      slow and times out; the top 1000 covers real services
        #      (22, 80, 443, ...) and finishes in well under a minute.
        command = (
            f"nmap -sT -sV -Pn -T4 --top-ports 1000 -oX - {safe_target}"
        )

        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=900,
        )

        xml_output = stdout.read().decode(
            "utf-8",
            errors="replace",
        )

        error_output = stderr.read().decode(
            "utf-8",
            errors="replace",
        )

        if not xml_output.strip():
            raise RuntimeError(
                f"Nmap returned no XML output.\n{error_output}"
            )

        return xml_output

    finally:
        client.close()
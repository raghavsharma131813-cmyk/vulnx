from getpass import getpass

import paramiko

from scanner.metasploit_runner import MetasploitRunner


KALI_HOST = "192.168.56.101"
KALI_USERNAME = "kali"


def create_ssh_client() -> paramiko.SSHClient:
    """Create and connect an SSH client to the Kali VM."""

    password = getpass(
        f"Enter password for {KALI_USERNAME}@{KALI_HOST}: "
    )

    client = paramiko.SSHClient()

    # Accept the Kali VM host key for this controlled lab environment.
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    print("\nConnecting to Kali...")

    client.connect(
        hostname=KALI_HOST,
        username=KALI_USERNAME,
        password=password,
        timeout=15,
        banner_timeout=15,
        auth_timeout=15,
    )

    print("SSH connection: OK")

    return client


def print_modules(
    title: str,
    modules: list[dict],
) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    print(f"Module count: {len(modules)}")

    for index, module in enumerate(modules, start=1):
        print(f"\n[{index}]")
        print(f"Type:           {module['module_type']}")
        print(f"Name:           {module['module_name']}")
        print(f"Disclosure:     {module['disclosure_date']}")
        print(f"Rank:           {module['rank']}")
        print(f"Check:          {module['check']}")
        print(f"Description:    {module['description']}")


def main() -> None:
    print("=== VulnX Metasploit Runner Test ===")

    client = None

    try:
        client = create_ssh_client()

        runner = MetasploitRunner(
            ssh_client=client
        )

        print("\nSearching auxiliary SSH modules...")

        auxiliary_modules = runner.search_auxiliary(
            "name:ssh"
        )

        print_modules(
            "AUXILIARY MODULES",
            auxiliary_modules,
        )

        print("\nSearching exploit SSH modules...")

        exploit_modules = runner.search_exploits(
            "name:ssh"
        )

        print_modules(
            "EXPLOIT MODULES",
            exploit_modules,
        )

        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(
            f"Auxiliary modules discovered: "
            f"{len(auxiliary_modules)}"
        )
        print(
            f"Exploit modules discovered:    "
            f"{len(exploit_modules)}"
        )

        if auxiliary_modules and exploit_modules:
            print("\nMetasploit module discovery: SUCCESS")
        else:
            print("\nMetasploit module discovery: INCOMPLETE")

    except Exception as exc:
        print("\nMetasploit runner test failed:")
        print(type(exc).__name__)
        print(str(exc))

    finally:
        if client is not None:
            client.close()
            print("\nSSH connection closed.")


if __name__ == "__main__":
    main()
    
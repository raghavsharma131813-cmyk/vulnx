from getpass import getpass

import paramiko

from scanner.metasploit_runner import MetasploitRunner


KALI_HOST = "192.168.56.101"
KALI_USERNAME = "kali"


def main() -> None:
    print("=== VulnX CVE Metasploit Discovery Test ===")

    password = getpass(
        f"Enter password for {KALI_USERNAME}@{KALI_HOST}: "
    )

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:
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

        runner = MetasploitRunner(
            ssh_client=client
        )

        cve_id = "CVE-2018-15473"

        print(
            f"\nSearching Metasploit for {cve_id}..."
        )

        modules = runner.search_for_cve(cve_id)

        print("\n" + "=" * 70)
        print("CVE SEARCH RESULTS")
        print("=" * 70)

        print(f"CVE: {cve_id}")
        print(f"Module count: {len(modules)}")

        for index, module in enumerate(
            modules,
            start=1,
        ):
            print(f"\n[{index}]")

            print(
                f"Type:        {module['module_type']}"
            )

            print(
                f"Name:        {module['module_name']}"
            )

            print(
                f"Disclosure:  {module['disclosure_date']}"
            )

            print(
                f"Rank:        {module['rank']}"
            )

            print(
                f"Check:       {module['check']}"
            )

            print(
                f"Description: {module['description']}"
            )

        print("\n" + "=" * 70)

        if modules:
            print(
                "CVE-specific Metasploit discovery: SUCCESS"
            )
        else:
            print(
                "CVE-specific Metasploit discovery: "
                "NO MODULES FOUND"
            )

    except Exception as exc:
        print("\nTest failed:")
        print(type(exc).__name__)
        print(str(exc))

    finally:
        client.close()
        print("\nSSH connection closed.")


if __name__ == "__main__":
    main()
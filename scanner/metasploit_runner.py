from __future__ import annotations

import csv
import io
import shlex
import uuid
from typing import Any

import paramiko


class MetasploitRunner:
    """
    Discover Metasploit modules on the Kali VM.

    This component performs SEARCH/DISCOVERY only.
    It does not execute exploits or auxiliary modules.
    """

    def __init__(
        self,
        ssh_client: paramiko.SSHClient,
        workdir: str = "/tmp",
    ) -> None:
        self.ssh_client = ssh_client
        self.workdir = workdir

    def _run_command(
        self,
        command: str,
        timeout: int = 60,
    ) -> str:
        """
        Execute a command on Kali through SSH.
        """

        stdin, stdout, stderr = self.ssh_client.exec_command(
            command,
            timeout=timeout,
        )

        output = stdout.read().decode(
            "utf-8",
            errors="replace",
        )

        error = stderr.read().decode(
            "utf-8",
            errors="replace",
        )

        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            raise RuntimeError(
                "Kali command failed "
                f"(exit status {exit_status}): "
                f"{error.strip()}"
            )

        return output

    def search_modules(
        self,
        search_query: str,
        module_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search Metasploit's module database.

        The search itself performs discovery only.
        No module is executed.

        A search returning zero modules is treated as a
        valid empty result, not as an error.
        """

        search_query = search_query.strip()

        if not search_query:
            raise ValueError(
                "Metasploit search query cannot be empty."
            )

        if module_type not in {
            None,
            "auxiliary",
            "exploit",
        }:
            raise ValueError(
                "module_type must be "
                "auxiliary, exploit, or None."
            )

        if module_type:
            if not search_query.startswith("type:"):
                search_query = (
                    f"type:{module_type} "
                    f"{search_query}"
                )

        output_file = (
            f"{self.workdir}/"
            f"vulnx_msf_{uuid.uuid4().hex}.csv"
        )

        try:
            msf_query = (
                f"search -o {output_file} "
                f"{search_query}; exit"
            )

            command = (
                "msfconsole -q -x "
                f"{shlex.quote(msf_query)}"
            )

            # Run Metasploit search.
            self._run_command(
                command,
                timeout=120,
            )

            # Metasploit may not create the output file when
            # a search produces zero results.
            #
            # Therefore check for its existence first.
            cat_command = (
                f"if [ -f {shlex.quote(output_file)} ]; "
                f"then cat {shlex.quote(output_file)}; "
                f"fi"
            )

            csv_text = self._run_command(
                cat_command,
                timeout=30,
            )

            # No CSV content means no matching modules.
            if not csv_text.strip():
                return []

            return self._parse_csv(
                csv_text,
                requested_type=module_type,
            )

        finally:
            cleanup_command = (
                f"rm -f {shlex.quote(output_file)}"
            )

            try:
                self._run_command(
                    cleanup_command,
                    timeout=10,
                )
            except Exception:
                pass

    @staticmethod
    def _parse_csv(
        csv_text: str,
        requested_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Parse Metasploit CSV search output.

        Child rows such as:

            _ action: ...
            _ target: ...

        are ignored.

        Only real auxiliary/... and exploit/...
        module paths are retained.
        """

        reader = csv.DictReader(
            io.StringIO(csv_text)
        )

        modules: list[dict[str, Any]] = []

        for row in reader:
            name = (
                row.get("Name") or ""
            ).strip()

            if not name:
                continue

            if not (
                name.startswith("auxiliary/")
                or name.startswith("exploit/")
            ):
                continue

            if requested_type == "auxiliary":
                if not name.startswith("auxiliary/"):
                    continue

            if requested_type == "exploit":
                if not name.startswith("exploit/"):
                    continue

            modules.append(
                {
                    "module_type": (
                        "auxiliary"
                        if name.startswith("auxiliary/")
                        else "exploit"
                    ),
                    "module_name": name,
                    "disclosure_date": (
                        row.get(
                            "Disclosure Date"
                        ) or ""
                    ).strip(),
                    "rank": (
                        row.get("Rank") or ""
                    ).strip(),
                    "check": (
                        row.get("Check") or ""
                    ).strip(),
                    "description": (
                        row.get("Description") or ""
                    ).strip(),
                }
            )

        return modules

    def search_for_cve(
        self,
        cve_id: str,
    ) -> list[dict[str, Any]]:
        """
        Discover Metasploit modules associated with a CVE.

        This performs discovery only.
        It does not execute or validate a module.
        """

        cve_id = cve_id.strip().upper()

        if not cve_id.startswith("CVE-"):
            raise ValueError(
                "CVE identifier must start with 'CVE-'."
            )

        return self.search_modules(
            f"cve:{cve_id}"
        )

    def search_auxiliary(
        self,
        search_query: str,
    ) -> list[dict[str, Any]]:
        """Search auxiliary modules only."""

        return self.search_modules(
            search_query,
            module_type="auxiliary",
        )

    def search_exploits(
        self,
        search_query: str,
    ) -> list[dict[str, Any]]:
        """Search exploit modules only."""

        return self.search_modules(
            search_query,
            module_type="exploit",
        )
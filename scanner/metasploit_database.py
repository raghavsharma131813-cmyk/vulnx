from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


DATABASE_PATH = Path("report/vulnx.db")


def get_connection() -> sqlite3.Connection:
    """
    Create a SQLite connection to the VulnX database.
    """

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_metasploit_database() -> None:
    """
    Create the Metasploit intelligence table.

    Existing VulnX scan, port, and finding data is preserved.
    """

    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS metasploit_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_id INTEGER NOT NULL,

                association_type TEXT NOT NULL,

                cve TEXT,

                service TEXT,

                module_type TEXT NOT NULL,

                module_name TEXT NOT NULL,

                disclosure_date TEXT,

                rank TEXT,

                check_support TEXT,

                description TEXT,

                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
            """
        )

        # Persistent cross-scan cache of Metasploit search results.
        # Keyed by search ("cve:<id>" or "svc:<service>"), so repeat
        # scans reuse earlier module discovery instead of re-running
        # slow msfconsole searches over SSH.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS metasploit_cache (
                cache_key TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        connection.commit()

    finally:
        connection.close()


def cache_get(
    cache_key: str,
    max_age_days: int = 30,
) -> Any | None:
    """
    Return a cached Metasploit search payload, or None on a miss or if
    the entry is older than max_age_days. Never raises: a cache problem
    just behaves as a miss so discovery still runs normally.
    """

    import datetime

    try:
        connection = get_connection()
        try:
            row = connection.execute(
                "SELECT payload, created_at FROM metasploit_cache "
                "WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        finally:
            connection.close()

        if row is None:
            return None

        created = datetime.datetime.fromisoformat(row["created_at"])
        age = datetime.datetime.now(datetime.timezone.utc) - created
        if age.days > max_age_days:
            return None

        return json.loads(row["payload"])

    except Exception:
        return None


def cache_put(
    cache_key: str,
    payload: Any,
) -> None:
    """
    Store a Metasploit search payload under cache_key. Never raises.
    """

    import datetime

    try:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        connection = get_connection()
        try:
            connection.execute(
                "INSERT INTO metasploit_cache (cache_key, payload, created_at) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(cache_key) DO UPDATE SET "
                "payload = excluded.payload, created_at = excluded.created_at",
                (cache_key, json.dumps(payload), now),
            )
            connection.commit()
        finally:
            connection.close()
    except Exception:
        pass


def save_metasploit_modules(
    *,
    scan_id: int,
    intelligence: dict[str, Any],
) -> int:
    """
    Persist Metasploit intelligence for one VulnX scan.

    association_type values:

        CVE_LINKED
        SERVICE_CANDIDATE

    Returns the number of module records stored.
    """

    connection = get_connection()

    stored_count = 0

    try:

        cursor = connection.cursor()

        # ---------------------------------------------------------
        # Prevent accidental duplication if the same scan is
        # processed more than once.
        # ---------------------------------------------------------

        cursor.execute(
            """
            DELETE FROM metasploit_modules
            WHERE scan_id = ?
            """,
            (scan_id,),
        )

        # ---------------------------------------------------------
        # CVE-linked modules
        # ---------------------------------------------------------

        cve_linked = intelligence.get(
            "cve_linked",
            {},
        )

        for cve_id, groups in cve_linked.items():

            for module in groups.get(
                "auxiliary",
                [],
            ):

                cursor.execute(
                    """
                    INSERT INTO metasploit_modules (
                        scan_id,
                        association_type,
                        cve,
                        service,
                        module_type,
                        module_name,
                        disclosure_date,
                        rank,
                        check_support,
                        description
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        "CVE_LINKED",
                        cve_id,
                        None,
                        "auxiliary",
                        module.get(
                            "module_name",
                            "",
                        ),
                        module.get(
                            "disclosure_date",
                            "",
                        ),
                        module.get(
                            "rank",
                            "",
                        ),
                        module.get(
                            "check",
                            "",
                        ),
                        module.get(
                            "description",
                            "",
                        ),
                    ),
                )

                stored_count += 1

            for module in groups.get(
                "exploit",
                [],
            ):

                cursor.execute(
                    """
                    INSERT INTO metasploit_modules (
                        scan_id,
                        association_type,
                        cve,
                        service,
                        module_type,
                        module_name,
                        disclosure_date,
                        rank,
                        check_support,
                        description
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        "CVE_LINKED",
                        cve_id,
                        None,
                        "exploit",
                        module.get(
                            "module_name",
                            "",
                        ),
                        module.get(
                            "disclosure_date",
                            "",
                        ),
                        module.get(
                            "rank",
                            "",
                        ),
                        module.get(
                            "check",
                            "",
                        ),
                        module.get(
                            "description",
                            "",
                        ),
                    ),
                )

                stored_count += 1

        # ---------------------------------------------------------
        # Service-based candidate modules
        # ---------------------------------------------------------

        service_candidates = intelligence.get(
            "service_candidates",
            {},
        )

        for service, groups in service_candidates.items():

            for module in groups.get(
                "auxiliary",
                [],
            ):

                cursor.execute(
                    """
                    INSERT INTO metasploit_modules (
                        scan_id,
                        association_type,
                        cve,
                        service,
                        module_type,
                        module_name,
                        disclosure_date,
                        rank,
                        check_support,
                        description
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        "SERVICE_CANDIDATE",
                        None,
                        service,
                        "auxiliary",
                        module.get(
                            "module_name",
                            "",
                        ),
                        module.get(
                            "disclosure_date",
                            "",
                        ),
                        module.get(
                            "rank",
                            "",
                        ),
                        module.get(
                            "check",
                            "",
                        ),
                        module.get(
                            "description",
                            "",
                        ),
                    ),
                )

                stored_count += 1

            for module in groups.get(
                "exploit",
                [],
            ):

                cursor.execute(
                    """
                    INSERT INTO metasploit_modules (
                        scan_id,
                        association_type,
                        cve,
                        service,
                        module_type,
                        module_name,
                        disclosure_date,
                        rank,
                        check_support,
                        description
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        "SERVICE_CANDIDATE",
                        None,
                        service,
                        "exploit",
                        module.get(
                            "module_name",
                            "",
                        ),
                        module.get(
                            "disclosure_date",
                            "",
                        ),
                        module.get(
                            "rank",
                            "",
                        ),
                        module.get(
                            "check",
                            "",
                        ),
                        module.get(
                            "description",
                            "",
                        ),
                    ),
                )

                stored_count += 1

        connection.commit()

        return stored_count

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_metasploit_modules_by_scan(
    scan_id: int,
) -> list[dict[str, Any]]:
    """
    Return all persisted Metasploit modules for a scan.
    """

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                id,
                scan_id,
                association_type,
                cve,
                service,
                module_type,
                module_name,
                disclosure_date,
                rank,
                check_support,
                description
            FROM metasploit_modules
            WHERE scan_id = ?
            ORDER BY association_type,
                     service,
                     cve,
                     module_type,
                     module_name
            """,
            (scan_id,),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


def get_metasploit_summary(
    scan_id: int,
) -> dict[str, int]:
    """
    Return persisted Metasploit module counts.
    """

    modules = get_metasploit_modules_by_scan(
        scan_id
    )

    summary = {
        "cve_auxiliary": 0,
        "cve_exploit": 0,
        "service_auxiliary": 0,
        "service_exploit": 0,
    }

    for module in modules:

        association = module.get(
            "association_type"
        )

        module_type = module.get(
            "module_type"
        )

        if (
            association == "CVE_LINKED"
            and module_type == "auxiliary"
        ):
            summary["cve_auxiliary"] += 1

        elif (
            association == "CVE_LINKED"
            and module_type == "exploit"
        ):
            summary["cve_exploit"] += 1

        elif (
            association == "SERVICE_CANDIDATE"
            and module_type == "auxiliary"
        ):
            summary["service_auxiliary"] += 1

        elif (
            association == "SERVICE_CANDIDATE"
            and module_type == "exploit"
        ):
            summary["service_exploit"] += 1

    summary["total"] = len(
        modules
    )

    return summary
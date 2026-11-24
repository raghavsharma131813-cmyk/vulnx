import json
from pathlib import Path
from typing import Any


REPORT_DIR = Path("report")


def save_scan_json(
    scan_result: dict[str, Any],
    filename: str = "latest_scan.json",
) -> Path:
    """
    Save a structured VulnX scan result as JSON.
    """

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    output_path = REPORT_DIR / filename

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            scan_result,
            file,
            indent=4,
        )

    return output_path
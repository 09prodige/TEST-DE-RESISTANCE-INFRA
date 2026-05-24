"""SQLite database manager for scan history.

Provides a lightweight persistence layer for tracking scans, their status,
and metadata for the web UI.

Schema:
    scans: id (UUID), target, modules (JSON), status, grade, findings_count,
           duration, results_path, created_at, updated_at
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "rig_scans.db"


def get_db_path() -> Path:
    """Return the path to the SQLite database file, creating parent dirs."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return DB_PATH


@contextmanager
def get_db() -> sqlite3.Connection:
    """Context manager for database connections with row factory enabled.

    Yields:
        SQLite connection with dict-like row access via sqlite3.Row.
    """
    conn = sqlite3.connect(str(get_db_path()))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Initialize the database schema if tables don't exist."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                modules TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                grade TEXT,
                findings_count INTEGER DEFAULT 0,
                duration REAL,
                results_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _now_iso() -> str:
    """Return current UTC time as ISO formatted string."""
    return datetime.now(timezone.utc).isoformat()


def generate_scan_id() -> str:
    """Generate a unique UUID for a scan.

    Returns:
        UUID string.
    """
    return str(uuid.uuid4())


def save_scan(
    scan_id: str,
    target: str,
    modules: list[str],
    status: str = "pending",
    results_path: str | None = None,
) -> None:
    """Save a new scan record to the database.

    Args:
        scan_id: UUID string identifying the scan.
        target: Target URL/domain being scanned.
        modules: List of module names to run.
        status: Initial status (pending, running, done, error).
        results_path: Optional path to the JSON results file.
    """
    now = _now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans
            (id, target, modules, status, results_path, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                target,
                json.dumps(modules),
                status,
                results_path,
                now,
                now,
            ),
        )
        conn.commit()


def update_scan_status(
    scan_id: str,
    status: str,
    results_path: str | None = None,
    grade: str | None = None,
    findings_count: int | None = None,
    duration: float | None = None,
) -> None:
    """Update an existing scan's status and metadata.

    Args:
        scan_id: UUID of the scan to update.
        status: New status (running, done, error).
        results_path: Optional path to results file.
        grade: Optional security grade (A-F).
        findings_count: Optional total number of findings.
        duration: Optional scan duration in seconds.
    """
    now = _now_iso()

    fields = ["status = ?", "updated_at = ?"]
    values: list[Any] = [status, now]

    if results_path is not None:
        fields.append("results_path = ?")
        values.append(results_path)
    if grade is not None:
        fields.append("grade = ?")
        values.append(grade)
    if findings_count is not None:
        fields.append("findings_count = ?")
        values.append(findings_count)
    if duration is not None:
        fields.append("duration = ?")
        values.append(duration)

    values.append(scan_id)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE scans SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        conn.commit()


def get_scan(scan_id: str) -> dict[str, Any] | None:
    """Retrieve a single scan by ID.

    Args:
        scan_id: UUID string of the scan.

    Returns:
        Dict with scan data, or None if not found.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return _row_to_dict(row)


def get_all_scans(limit: int = 20) -> list[dict[str, Any]]:
    """Retrieve recent scans, most recent first.

    Args:
        limit: Maximum number of scans to return.

    Returns:
        List of scan dicts.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [_row_to_dict(row) for row in cursor.fetchall()]


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a sqlite3.Row to a regular dict with proper type conversions.

    Args:
        row: SQLite row object.

    Returns:
        Dict with parsed JSON for 'modules' field.
    """
    data = dict(row)
    try:
        data["modules"] = json.loads(data["modules"])
    except (json.JSONDecodeError, KeyError, TypeError):
        data["modules"] = []
    return data


# Initialize on module import
init_db()

if __name__ == "__main__":
    print("RIG Web UI Database — initialized")
    print(f"DB path: {get_db_path()}")
    print(f"Recent scans: {len(get_all_scans(10))}")

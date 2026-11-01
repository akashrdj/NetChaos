"""SQLite database helpers for test result logging and compliance audit trails.

Provides initialization, schema migration, insertion, and query functions for
the test_results table. Uses WAL journal mode to prevent locking issues when
multiple tests write concurrently.
"""

import json
import os
import sqlite3
from typing import Dict, List, Optional


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS test_results (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id             TEXT NOT NULL,
    attack_type        TEXT NOT NULL,
    detected           BOOLEAN NOT NULL,
    response_time_ms   REAL,
    timestamp          DATETIME DEFAULT CURRENT_TIMESTAMP,
    severity           TEXT DEFAULT 'HIGH',
    packets_sent       INTEGER,
    signals_fired      TEXT,
    total_score        INTEGER,
    notes              TEXT,
    mitre_id           TEXT,
    mitre_tactic       TEXT,
    pci_requirement    TEXT,
    remediation_action TEXT
);

CREATE INDEX IF NOT EXISTS idx_run_id ON test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_attack_type ON test_results(attack_type);
"""


def init_db(db_path: str) -> None:
    """Initialize the database, creating or migrating the schema if needed.

    Args:
        db_path: Absolute path to the SQLite database file.
    """
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(DB_SCHEMA)

    # Perform lightweight migration for existing databases missing new columns
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(test_results)")
    columns = [row[1] for row in cursor.fetchall()]

    new_columns = {
        "mitre_id": "TEXT",
        "mitre_tactic": "TEXT",
        "pci_requirement": "TEXT",
        "remediation_action": "TEXT",
    }
    for col_name, col_type in new_columns.items():
        if col_name not in columns:
            cursor.execute(f"ALTER TABLE test_results ADD COLUMN {col_name} {col_type}")

    conn.commit()
    conn.close()


def log_result(
    db_path: str,
    run_id: str,
    attack_type: str,
    detected: bool,
    response_time_ms: float = None,
    severity: str = "HIGH",
    packets_sent: int = None,
    signals_fired: List[str] = None,
    total_score: int = None,
    notes: str = None,
    mitre_id: str = None,
    mitre_tactic: str = None,
    pci_requirement: str = None,
    remediation_action: str = None,
) -> None:
    """Log a single test result with compliance audit metadata to the database.

    Args:
        db_path: Path to the SQLite database.
        run_id: UUID identifying this test session.
        attack_type: Category of attack tested.
        detected: Whether the detector successfully caught the attack.
        response_time_ms: Time from attack start to first alert (ms).
        severity: Alert severity level string.
        packets_sent: Number of attack packets sent.
        signals_fired: List of detection layer names that triggered.
        total_score: Cumulative signal weight at alert time.
        notes: Optional free-text notes.
        mitre_id: MITRE ATT&CK technique ID (e.g. T1557.002).
        mitre_tactic: MITRE ATT&CK tactic category.
        pci_requirement: PCI-DSS 4.0 requirement mapping.
        remediation_action: Active healing / defense action taken.
    """
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO test_results
        (run_id, attack_type, detected, response_time_ms, severity,
         packets_sent, signals_fired, total_score, notes,
         mitre_id, mitre_tactic, pci_requirement, remediation_action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            attack_type,
            detected,
            response_time_ms,
            severity,
            packets_sent,
            json.dumps(signals_fired) if signals_fired else None,
            total_score,
            notes,
            mitre_id,
            mitre_tactic,
            pci_requirement,
            remediation_action,
        ),
    )
    conn.commit()
    conn.close()


def get_results(db_path: str, run_id: str = None) -> List[Dict]:
    """Query test results, optionally filtered by run_id."""
    if not os.path.exists(db_path):
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if run_id:
        cursor.execute(
            "SELECT * FROM test_results WHERE run_id = ? ORDER BY id ASC",
            (run_id,),
        )
    else:
        cursor.execute("SELECT * FROM test_results ORDER BY id ASC")

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    for r in rows:
        if r.get("signals_fired"):
            try:
                r["signals_fired"] = json.loads(r["signals_fired"])
            except json.JSONDecodeError:
                pass
    return rows

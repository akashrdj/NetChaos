"""Shared pytest fixtures for L2 security validation tests.

Provides network topology configuration, database initialization,
and test result logging fixtures used across all test modules.
"""

import os
import uuid

import pytest

from common.db import init_db, log_result


# ---------------------------------------------------------------------------
# Network topology constants — MUST match docker/docker-compose.yml
# ---------------------------------------------------------------------------
NETWORK_CONFIG = {
    "interface": "eth0",
    "gateway_ip": "172.20.0.2",
    "gateway_mac": "02:42:ac:14:00:02",
    "victim_ip": "172.20.0.3",
    "victim_mac": "02:42:ac:14:00:03",
    "attacker_ip": "172.20.0.10",
    "attacker_mac": "02:42:ac:14:00:0a",
    "subnet": "172.20.0.0/24",
}

DB_PATH = os.environ.get("L2_DB_PATH", "/app/db/results.db")

# Time to wait after launching an attack for the detector to process
# packets and accumulate signals. Increase if tests fail intermittently.
DETECTION_WINDOW = 3.0  # seconds


# ---------------------------------------------------------------------------
# Session-scoped fixtures (shared across all tests in a run)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def network_config():
    """Network topology configuration matching docker-compose.yml."""
    return NETWORK_CONFIG.copy()


@pytest.fixture(scope="session")
def db_path():
    """Initialize and return the SQLite database path.

    Creates the database and schema if they don't exist. Uses WAL mode
    to avoid locking issues.
    """
    init_db(DB_PATH)
    return DB_PATH


@pytest.fixture(scope="session")
def run_id():
    """Unique identifier for this test session.

    Used to group all results from a single pytest invocation in the
    database, enabling per-run queries and trend analysis.
    """
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Per-test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def log_test_result(db_path, run_id):
    """Helper fixture to log a test result to SQLite.

    Returns a callable that wraps common.db.log_result() with the
    current session's db_path and run_id pre-filled.

    Usage in tests:
        log_test_result("arp_spoof", detected=True, response_time_ms=150.0)
    """
    def _log(
        attack_type,
        detected,
        response_time_ms=None,
        packets_sent=None,
        severity="HIGH",
        signals_fired=None,
        total_score=None,
        notes=None,
    ):
        log_result(
            db_path=db_path,
            run_id=run_id,
            attack_type=attack_type,
            detected=detected,
            response_time_ms=response_time_ms,
            severity=severity,
            packets_sent=packets_sent,
            signals_fired=signals_fired,
            total_score=total_score,
            notes=notes,
        )
    return _log

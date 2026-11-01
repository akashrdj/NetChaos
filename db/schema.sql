-- NetChaos SQLite Results & Compliance Audit Schema
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

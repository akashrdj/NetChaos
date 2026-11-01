"""Tests for Phase 3: NetChaos CLI, Profiles, and SIEM Telemetry Dispatcher."""

import subprocess
import sys
from datetime import datetime

from common.models import Alert, Severity, Signal
from chaos.engine import ChaosEngine
from chaos.profiles import PROFILES
from telemetry.dispatcher import WebhookDispatcher


def test_webhook_dispatcher_siem_formatting():
    """Verify SIEM event format adheres to common elastic / CEF standard."""
    dispatcher = WebhookDispatcher(dry_run=True)
    alert = Alert(
        attack_type="arp_spoof",
        source_key="172.20.0.2",
        signals=[Signal("binding_change", 2, "IP changed MAC")],
        total_score=4,
        severity=Severity.HIGH,
        mitre_attack_id="T1557.002",
        mitre_tactic="Adversary-in-the-Middle: ARP Poisoning",
        pci_dss_requirement="PCI-DSS 4.0 Req 1.3",
        remediation_action="Injected 5x Gratuitous ARP frames",
    )

    siem_event = dispatcher.format_siem_event(alert, latency_ms=12.5)

    assert siem_event["event"]["outcome"] == "detected"
    assert siem_event["threat"]["technique"]["id"] == "T1557.002"
    assert siem_event["compliance"]["requirement"] == "PCI-DSS 4.0 Req 1.3"
    assert siem_event["alert"]["remediation"] == "Injected 5x Gratuitous ARP frames"
    assert siem_event["event"]["duration_ms"] == 12.5


def test_webhook_dispatcher_slack_formatting():
    """Verify rich ChatOps notification payload structure."""
    dispatcher = WebhookDispatcher(dry_run=True)
    alert = Alert(
        attack_type="rogue_dhcp",
        source_key="02:42:ac:14:00:ff",
        signals=[Signal("untrusted_server", 3, "Unauthorized DHCP Offer")],
        total_score=6,
        severity=Severity.CRITICAL,
        mitre_attack_id="T1557.001",
        pci_dss_requirement="PCI-DSS 4.0 Req 1.3",
    )

    slack = dispatcher.format_slack_payload(alert, latency_ms=1.2)
    attachment = slack["attachments"][0]

    assert attachment["color"] == "#e01e5a"  # Critical red
    assert "ROGUE_DHCP" in attachment["title"]
    assert any(f["title"] == "MITRE ATT&CK" and f["value"] == "T1557.001" for f in attachment["fields"])


def test_chaos_engine_smoke_profile():
    """Verify executing the 'smoke' pre-flight profile."""
    engine = ChaosEngine(
        interface="eth0",
        db_path="db/test_smoke.db",
        dry_run=True,
    )
    summary = engine.execute_profile("smoke")

    assert summary.total_attacks == 2
    assert summary.passed_attacks == 2
    assert summary.failed_attacks == 0
    assert summary.all_passed is True


def test_chaos_engine_compliance_audit_profile():
    """Verify executing the full 6-attack 'compliance-audit' profile."""
    engine = ChaosEngine(
        interface="eth0",
        db_path="db/test_compliance.db",
        dry_run=True,
        active_defense=True,
    )
    summary = engine.execute_profile("compliance-audit")

    assert summary.total_attacks == 6
    assert summary.passed_attacks == 6
    assert summary.all_passed is True
    # Verify ARP active defense executed
    arp_report = next(r for r in summary.reports if r.attack_type == "arp_spoof")
    assert arp_report.remediation_action is not None
    assert "Active Inoculation" in arp_report.remediation_action


def test_netchaos_cli_gate_subprocess():
    """Verify CLI gate returns exit code 0 when invoked as a subprocess."""
    res = subprocess.run(
        [sys.executable, "netchaos.py", "gate", "--profile", "smoke"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "[GATE PASSED]" in res.stdout

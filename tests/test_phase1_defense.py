"""Tests for Phase 1: Dynamic Baseline, Active Defense Healing, and Compliance Telemetry."""

import os
import tempfile
from scapy.all import ARP, BOOTP, DHCP, Ether, IP, UDP

from common.db import get_results, init_db, log_result
from common.models import NetworkBaseline, Severity
from defense.arp_healer import ARPCacheHealer
from detectors.arp_detector import ARPDetector
from detectors.baseline import NetworkProfiler
from detectors.dhcp_detector import DHCPDetector
from detectors.mac_flood_detector import MACFloodDetector


def test_network_profiler_export_and_load():
    """Verify creating, exporting, and reloading a NetworkBaseline."""
    baseline = NetworkProfiler.mock_baseline(
        gateway_ip="192.168.1.1",
        gateway_mac="aa:bb:cc:dd:ee:01",
        subnet_cidr="192.168.1.0/24",
    )
    assert baseline.gateway_ip == "192.168.1.1"
    assert baseline.gateway_mac == "aa:bb:cc:dd:ee:01"
    assert "aa:bb:cc:dd:ee:01" in baseline.trusted_dhcp_servers

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "baseline.json")
        profiler = NetworkProfiler()
        profiler._baseline = baseline
        profiler.export_baseline(json_path)

        loaded = NetworkProfiler.load_baseline(json_path)
        assert loaded.gateway_ip == baseline.gateway_ip
        assert loaded.gateway_mac == baseline.gateway_mac
        assert loaded.ip_mac_bindings == baseline.ip_mac_bindings


def test_arp_healer_frame_construction():
    """Verify authentic Gratuitous ARP healing frame structure."""
    healer = ARPCacheHealer(
        interface="eth0",
        trusted_bindings={"172.20.0.2": "02:42:ac:14:00:02"},
        burst_count=3,
        dry_run=True,
    )
    frames = healer.build_healing_frames(
        target_ip="172.20.0.2",
        legitimate_mac="02:42:ac:14:00:02",
    )

    assert len(frames) == 3
    for frame in frames:
        assert frame[Ether].src == "02:42:ac:14:00:02"
        assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
        assert frame[ARP].op == 2  # ARP reply
        assert frame[ARP].psrc == "172.20.0.2"
        assert frame[ARP].hwsrc == "02:42:ac:14:00:02"


def test_arp_healer_remediation():
    """Verify remediation execution and history recording."""
    healer = ARPCacheHealer(
        interface="eth0",
        trusted_bindings={"172.20.0.2": "02:42:ac:14:00:02"},
        burst_count=5,
        dry_run=True,
    )

    result = healer.remediate(
        poisoned_ip="172.20.0.2",
        attacker_mac="02:42:ac:14:00:ff",
    )

    assert result.success is True
    assert result.packets_transmitted == 5
    assert result.target_ip == "172.20.0.2"
    assert result.restored_mac == "02:42:ac:14:00:02"
    assert "Active Inoculation" in result.details
    assert len(healer.history) == 1


def test_arp_detector_active_defense_integration():
    """Verify ARPDetector triggers active defense when poisoning is detected."""
    baseline = NetworkProfiler.mock_baseline(
        gateway_ip="172.20.0.2",
        gateway_mac="02:42:ac:14:00:02",
    )
    healer = ARPCacheHealer(
        interface="eth0",
        trusted_bindings=baseline.ip_mac_bindings,
        burst_count=4,
        dry_run=True,
    )
    detector = ARPDetector(
        interface="eth0",
        alert_threshold=3,
        baseline=baseline,
        active_defense=True,
        healer=healer,
    )

    # Spoofed packet claiming gateway is at attacker MAC
    spoofed = Ether(src="02:42:ac:14:00:ff", dst="02:42:ac:14:00:03") / ARP(
        op=2,
        psrc="172.20.0.2",
        hwsrc="02:42:ac:14:00:ff",
        pdst="172.20.0.3",
        hwdst="02:42:ac:14:00:03",
    )

    # Inject spoofed replies
    for _ in range(5):
        detector._packet_handler(spoofed)

    alerts = detector.get_alerts()
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.mitre_attack_id == "T1557.002"
    assert alert.remediation_action is not None
    assert "Active Inoculation" in alert.remediation_action
    assert healer.history[0].packets_transmitted == 4


def test_compliance_metadata_and_db_persistence():
    """Verify storing and retrieving MITRE and PCI compliance fields from SQLite."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "compliance_test.db")
        init_db(db_path)

        log_result(
            db_path=db_path,
            run_id="audit-run-001",
            attack_type="arp_spoof",
            detected=True,
            response_time_ms=45.2,
            severity="HIGH",
            packets_sent=10,
            signals_fired=["binding_change", "unsolicited_reply"],
            total_score=4,
            notes="Automated NetChaos CI test",
            mitre_id="T1557.002",
            mitre_tactic="MitM",
            pci_requirement="PCI-DSS 4.0 Req 1.3",
            remediation_action="Injected 5x GARP frames",
        )

        results = get_results(db_path, run_id="audit-run-001")
        assert len(results) == 1
        record = results[0]
        assert record["mitre_id"] == "T1557.002"
        assert record["mitre_tactic"] == "MitM"
        assert record["pci_requirement"] == "PCI-DSS 4.0 Req 1.3"
        assert record["remediation_action"] == "Injected 5x GARP frames"
        assert record["detected"] == 1


def test_dhcp_detector_baseline_seeding():
    """Verify DHCPDetector seeded with dynamic baseline detects rogue server."""
    baseline = NetworkProfiler.mock_baseline(
        gateway_ip="172.20.0.2",
        gateway_mac="02:42:ac:14:00:02",
    )
    detector = DHCPDetector(
        interface="eth0",
        alert_threshold=3,
        baseline=baseline,
    )
    assert detector.mitre_attack_id == "T1557.001"

    # Rogue offer from untrusted server
    rogue_offer = (
        Ether(src="02:42:ac:14:00:66", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="172.20.0.66", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="172.20.0.100", siaddr="172.20.0.66", xid=12345)
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id", "172.20.0.66"),
            ("router", "172.20.0.66"),
            ("name_server", "172.20.0.66"),
            "end",
        ])
    )

    detector._packet_handler(rogue_offer)
    alerts = detector.get_alerts()
    assert len(alerts) >= 1
    assert alerts[0].mitre_attack_id == "T1557.001"

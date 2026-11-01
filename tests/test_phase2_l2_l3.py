"""Tests for Phase 2: Expanded L2 & L3 Chaos Attacks and Heuristic Detectors."""

from scapy.all import Ether, ICMP, IP, UDP

from attacks.dhcp_starvation import DHCPStarvation
from attacks.icmp_redirect import ICMPRedirect
from attacks.ip_spoof import IPSpoof
from common.models import NetworkBaseline
from detectors.baseline import NetworkProfiler
from detectors.dhcp_starvation_detector import DHCPStarvationDetector
from detectors.icmp_redirect_detector import ICMPRedirectDetector
from detectors.ip_spoof_detector import IPSpoofDetector


def test_dhcp_starvation_detection():
    """Verify DHCPStarvation test generator and multi-layer detector."""
    starvation_attack = DHCPStarvation(
        interface="eth0",
        target_server="255.255.255.255",
        dry_run=True,
    )
    detector = DHCPStarvationDetector(
        interface="eth0",
        alert_threshold=3,
        rate_window=5.0,
        rate_threshold=5,
        unique_chaddr_threshold=5,
    )

    assert detector.mitre_attack_id == "T1499"

    # Inject 10 discover frames with rotating MAC addresses
    for _ in range(10):
        frame = starvation_attack.build_discover_frame()
        detector._packet_handler(frame)

    assert detector.is_detected() is True
    alerts = detector.get_alerts()
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.mitre_attack_id == "T1499"
    signals_fired = [s.layer_name for s in alert.signals]
    assert "discover_rate_anomaly" in signals_fired or "unique_chaddr_rate" in signals_fired


def test_icmp_redirect_detection():
    """Verify ICMPRedirect test generator and detector."""
    baseline = NetworkProfiler.mock_baseline(
        gateway_ip="172.20.0.2",
        subnet_cidr="172.20.0.0/24",
    )
    redirect_attack = ICMPRedirect(
        victim_ip="172.20.0.3",
        original_gateway_ip="172.20.0.2",
        redirect_to_gateway_ip="172.20.0.99",
        destination_ip="8.8.8.8",
        dry_run=True,
    )
    detector = ICMPRedirectDetector(
        interface="eth0",
        alert_threshold=3,
        baseline=baseline,
    )

    assert detector.mitre_attack_id == "T1557"

    # Inject redirect from an untrusted source IP (172.20.0.50 claiming to redirect)
    rogue_frame = redirect_attack.build_redirect_packet(spoof_source_ip="172.20.0.50")
    for _ in range(3):
        detector._packet_handler(rogue_frame)

    assert detector.is_detected() is True
    alerts = detector.get_alerts()
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.mitre_attack_id == "T1557"
    signals_fired = [s.layer_name for s in alert.signals]
    assert "untrusted_redirect_source" in signals_fired


def test_ip_spoof_bogon_detection():
    """Verify detector catches packets carrying martian/bogon source addresses."""
    detector = IPSpoofDetector(
        interface="eth0",
        alert_threshold=3,
        subnet_cidr="172.20.0.0/24",
    )

    # Frame with 127.0.0.1 (loopback/martian) source
    bogon_frame = (
        Ether(src="02:42:ac:14:00:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="127.0.0.5", dst="172.20.0.3")
        / UDP(sport=1234, dport=1234)
    )

    detector._packet_handler(bogon_frame)
    assert detector.is_detected() is True
    alerts = detector.get_alerts()
    assert alerts[0].signals[0].layer_name == "bogon_source_ip"


def test_ip_spoof_boundary_violation():
    """Verify detector enforces BCP-38 ingress filtering against external IPs."""
    detector = IPSpoofDetector(
        interface="eth0",
        alert_threshold=3,
        subnet_cidr="172.20.0.0/24",
    )

    # External IP (8.8.8.8) originating directly inside local L2 broadcast domain
    external_frame = (
        Ether(src="02:42:ac:14:00:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="8.8.8.8", dst="172.20.0.3")
        / UDP(sport=1234, dport=1234)
    )

    detector._packet_handler(external_frame)
    assert detector.is_detected() is True
    alerts = detector.get_alerts()
    assert alerts[0].signals[0].layer_name == "subnet_boundary_violation"


def test_ip_spoof_mac_binding_conflict():
    """Verify detector catches internal server IP impersonation from rogue MAC."""
    baseline = NetworkProfiler.mock_baseline(
        gateway_ip="172.20.0.2",
        gateway_mac="02:42:ac:14:00:02",
        subnet_cidr="172.20.0.0/24",
    )
    detector = IPSpoofDetector(
        interface="eth0",
        alert_threshold=2,
        baseline=baseline,
    )

    # Packet claims source IP 172.20.0.2, but transmitted from rogue MAC 02:42:ac:14:00:ff
    conflict_frame = (
        Ether(src="02:42:ac:14:00:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="172.20.0.2", dst="172.20.0.3")
        / UDP(sport=53, dport=53)
    )

    detector._packet_handler(conflict_frame)
    assert detector.is_detected() is True
    alerts = detector.get_alerts()
    assert alerts[0].signals[0].layer_name == "mac_binding_conflict"

"""Tests for rogue DHCP server attack detection.

Validates that the multi-layered DHCP detector correctly identifies
unauthorized DHCP OFFERs through signal convergence (untrusted server,
duplicate offer, parameter anomaly, fingerprint mismatch).
"""

import time

from attacks.rogue_dhcp import RogueDHCP
from common.models import Severity
from detectors.dhcp_detector import DHCPDetector
from tests.conftest import DETECTION_WINDOW


class TestRogueDHCPDetection:
    """Verify that the DHCP detector catches rogue server attacks."""

    def _run_attack(self, network_config, count=5, interval=0.2):
        """Helper: start detector, run rogue DHCP, return (detector, result, elapsed_ms)."""
        detector = DHCPDetector(
            interface=network_config["interface"],
            alert_threshold=3,
            trusted_dhcp_servers={network_config["gateway_mac"]},
            expected_gateway=network_config["gateway_ip"],
            expected_dns=network_config["gateway_ip"],
        )
        detector.start()

        attack = RogueDHCP(
            attacker_ip=network_config["attacker_ip"],
            victim_mac=network_config["victim_mac"],
            interface=network_config["interface"],
        )

        start = time.monotonic()
        result = attack.launch(count=count, interval=interval)
        time.sleep(DETECTION_WINDOW)
        detector.stop()

        elapsed_ms = (time.monotonic() - start) * 1000
        return detector, result, elapsed_ms

    def test_rogue_dhcp_detected(self, network_config, log_test_result):
        """Rogue DHCP OFFER should be detected by the multi-layer engine."""
        detector, result, elapsed_ms = self._run_attack(network_config)
        detected = detector.is_detected()
        alerts = detector.get_alerts()

        log_test_result(
            attack_type="rogue_dhcp",
            detected=detected,
            response_time_ms=elapsed_ms,
            packets_sent=result.packets_sent,
            severity=alerts[0].severity.value if alerts else "NONE",
            signals_fired=[s.layer_name for a in alerts for s in a.signals],
            total_score=alerts[0].total_score if alerts else 0,
        )

        assert detected, "Rogue DHCP attack was NOT detected"

    def test_rogue_dhcp_param_anomaly(self, network_config, log_test_result):
        """Parameter anomaly or trust layer should fire for rogue gateway."""
        detector, _, _ = self._run_attack(network_config)
        alerts = detector.get_alerts()

        assert alerts, "No alerts generated"
        all_layers = {s.layer_name for a in alerts for s in a.signals}
        assert "param_anomaly" in all_layers or "untrusted_server" in all_layers, (
            f"Expected param_anomaly or untrusted_server layer, got: {all_layers}"
        )

    def test_rogue_dhcp_severity(self, network_config, log_test_result):
        """Rogue DHCP should generate HIGH or CRITICAL severity."""
        detector, _, _ = self._run_attack(network_config)
        alerts = detector.get_alerts()

        assert alerts, "No alerts generated"
        assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL), (
            f"Expected HIGH/CRITICAL, got {alerts[0].severity}"
        )

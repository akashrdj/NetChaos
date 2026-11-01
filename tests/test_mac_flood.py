"""Tests for MAC flooding attack detection.

Validates that the multi-layered MAC flood detector correctly identifies
CAM table overflow attacks through signal convergence (unique MAC rate,
OUI validation, MAC churn, adaptive baseline).
"""

import time

from attacks.mac_flood import MACFlood
from common.models import Severity
from detectors.mac_flood_detector import MACFloodDetector
from tests.conftest import DETECTION_WINDOW


class TestMACFloodDetection:
    """Verify that the MAC flood detector catches flooding attacks."""

    def _run_attack(self, network_config, count=200, interval=0.001):
        """Helper: start detector, run MAC flood, return (detector, result, elapsed_ms)."""
        detector = MACFloodDetector(
            interface=network_config["interface"],
            alert_threshold=3,
            rate_threshold=50,
        )
        detector.start()

        attack = MACFlood(interface=network_config["interface"])

        start = time.monotonic()
        result = attack.launch(count=count, interval=interval)
        time.sleep(DETECTION_WINDOW)
        detector.stop()

        elapsed_ms = (time.monotonic() - start) * 1000
        return detector, result, elapsed_ms

    def test_mac_flood_detected(self, network_config, log_test_result):
        """MAC flood attack should be detected by the multi-layer engine."""
        detector, result, elapsed_ms = self._run_attack(network_config)
        detected = detector.is_detected()
        alerts = detector.get_alerts()

        log_test_result(
            attack_type="mac_flood",
            detected=detected,
            response_time_ms=elapsed_ms,
            packets_sent=result.packets_sent,
            severity=alerts[0].severity.value if alerts else "NONE",
            signals_fired=[s.layer_name for a in alerts for s in a.signals],
            total_score=alerts[0].total_score if alerts else 0,
        )

        assert detected, "MAC flood attack was NOT detected"

    def test_mac_flood_oui_layer(self, network_config, log_test_result):
        """OUI validation or rate layer should fire for random MACs."""
        detector, _, _ = self._run_attack(network_config)
        alerts = detector.get_alerts()

        assert alerts, "No alerts generated"
        all_layers = {s.layer_name for a in alerts for s in a.signals}
        assert "invalid_oui" in all_layers or "unique_mac_rate" in all_layers, (
            f"Expected OUI or rate layer to fire, got: {all_layers}"
        )

    def test_mac_flood_severity_critical(self, network_config, log_test_result):
        """High-volume MAC flood should generate HIGH or CRITICAL severity."""
        detector, _, _ = self._run_attack(network_config, count=300)
        alerts = detector.get_alerts()

        assert alerts, "No alerts generated"
        assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL), (
            f"Expected HIGH/CRITICAL, got {alerts[0].severity}"
        )

"""Tests for ARP spoofing attack detection.

Validates that the multi-layered ARP detector correctly identifies
spoofed ARP replies through signal convergence from multiple heuristic
layers (binding change, unsolicited reply, header mismatch, rate anomaly).
"""

import time

from attacks.arp_spoof import ARPSpoof
from common.models import Severity
from detectors.arp_detector import ARPDetector
from tests.conftest import DETECTION_WINDOW


class TestARPSpoofDetection:
    """Verify that the ARP detector catches spoofing attacks."""

    def _run_attack(self, network_config, count=10, interval=0.1):
        """Helper: start detector, run ARP spoof, return (detector, result, elapsed_ms)."""
        detector = ARPDetector(
            interface=network_config["interface"],
            alert_threshold=3,
            trusted_bindings={
                network_config["gateway_ip"]: network_config["gateway_mac"],
            },
        )
        detector.start()

        attack = ARPSpoof(
            target_ip=network_config["victim_ip"],
            gateway_ip=network_config["gateway_ip"],
            target_mac=network_config["victim_mac"],
            interface=network_config["interface"],
        )

        start = time.monotonic()
        result = attack.launch(count=count, interval=interval)
        time.sleep(DETECTION_WINDOW)
        detector.stop()

        elapsed_ms = (time.monotonic() - start) * 1000
        return detector, result, elapsed_ms

    def test_arp_spoof_detected(self, network_config, log_test_result):
        """ARP spoof attack should be detected by the multi-layer engine."""
        detector, result, elapsed_ms = self._run_attack(network_config)
        detected = detector.is_detected()
        alerts = detector.get_alerts()

        log_test_result(
            attack_type="arp_spoof",
            detected=detected,
            response_time_ms=elapsed_ms,
            packets_sent=result.packets_sent,
            severity=alerts[0].severity.value if alerts else "NONE",
            signals_fired=[s.layer_name for a in alerts for s in a.signals],
            total_score=alerts[0].total_score if alerts else 0,
        )

        assert detected, "ARP spoof attack was NOT detected"
        assert len(alerts) > 0

    def test_arp_spoof_multi_layer_convergence(self, network_config, log_test_result):
        """At least 2 distinct detection layers should fire for ARP spoof."""
        detector, result, _ = self._run_attack(network_config)
        alerts = detector.get_alerts()

        assert alerts, "No alerts generated"
        unique_layers = {s.layer_name for s in alerts[0].signals}
        assert len(unique_layers) >= 2, (
            f"Expected ≥2 distinct layers to fire, got: {unique_layers}"
        )

    def test_arp_spoof_response_time(self, network_config, log_test_result):
        """Detection should complete within 5 seconds of attack start."""
        detector, _, elapsed_ms = self._run_attack(network_config)

        assert detector.is_detected(), "ARP spoof not detected"
        assert elapsed_ms < 5000, (
            f"Detection took {elapsed_ms:.0f}ms (limit: 5000ms)"
        )

    def test_arp_spoof_severity(self, network_config, log_test_result):
        """ARP spoof should generate HIGH or CRITICAL severity alerts."""
        detector, _, _ = self._run_attack(network_config)
        alerts = detector.get_alerts()

        assert alerts, "No alerts generated"
        assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL), (
            f"Expected HIGH/CRITICAL, got {alerts[0].severity}"
        )

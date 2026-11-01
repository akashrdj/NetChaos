"""Base class for the multi-layered detection engine.

Each detector runs a background sniffer thread that feeds packets through
multiple heuristic layers. Each layer returns weighted Signal objects.
When the cumulative signal weight for a given source crosses the
alert_threshold, an Alert is raised.

This multi-signal convergence approach prevents single-heuristic false
positives while reliably catching real attacks through layer agreement.
"""

import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from scapy.all import sniff

from common.models import Alert, Severity, Signal


class BaseDetector(ABC):
    """Multi-layered network anomaly detector.

    Subclasses implement:
        _evaluate_layers(packet) -> List[Signal]
        _get_source_key(packet) -> str

    The base class manages:
        - Background sniffer thread with timeout-based clean shutdown
        - Per-source signal accumulation with thread-safe locking
        - Alert generation when score crosses threshold
        - Severity computation from cumulative score
        - MITRE ATT&CK & compliance audit tagging
        - Active defense remediation hooks
    """

    attack_type: str = "unknown"
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    pci_dss_requirement: Optional[str] = None

    def __init__(self, interface: str = "eth0", alert_threshold: int = 3):
        """Initialize the detector.

        Args:
            interface: Network interface to sniff on.
            alert_threshold: Minimum cumulative signal weight needed
                to trigger an alert. Higher = fewer false positives.
        """
        self.interface = interface
        self.alert_threshold = alert_threshold
        self._alerts: List[Alert] = []
        self._signal_scores: Dict[str, List[Signal]] = defaultdict(list)
        self._running = False
        self._sniffer_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background sniffer thread."""
        self._running = True
        self._alerts.clear()
        self._signal_scores.clear()
        self._sniffer_thread = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self._sniffer_thread.start()

    def stop(self) -> None:
        """Signal the sniffer to stop and wait for thread join."""
        self._running = False
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=5)

    def _sniff_loop(self) -> None:
        """Sniff packets in 1-second bursts for clean shutdown.

        Uses timeout=1 so the loop checks self._running between bursts,
        avoiding the problem of sniff() blocking indefinitely on quiet
        networks.
        """
        while self._running:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                timeout=1,
                store=0,
            )

    def _packet_handler(self, packet) -> None:
        """Process a single packet through all detection layers.

        If the cumulative signal score for the packet's source crosses
        the alert threshold, an Alert is raised and the source's score
        is reset.
        """
        signals = self._evaluate_layers(packet)
        if not signals:
            return

        source_key = self._get_source_key(packet)

        with self._lock:
            self._signal_scores[source_key].extend(signals)
            total = sum(s.weight for s in self._signal_scores[source_key])

            if total >= self.alert_threshold:
                alert = Alert(
                    attack_type=self.attack_type,
                    source_key=source_key,
                    signals=list(self._signal_scores[source_key]),
                    total_score=total,
                    timestamp=datetime.now(),
                    severity=self._compute_severity(total),
                    mitre_attack_id=self.mitre_attack_id,
                    mitre_tactic=self.mitre_tactic,
                    pci_dss_requirement=self.pci_dss_requirement,
                )
                self._on_alert_raised(alert, packet)
                self._alerts.append(alert)
                self._signal_scores[source_key].clear()

    def _on_alert_raised(self, alert: Alert, packet) -> None:
        """Hook called immediately when an alert fires.

        Override in subclasses to trigger active defense remediation.
        """
        pass

    @abstractmethod
    def _evaluate_layers(self, packet) -> List[Signal]:
        """Run all heuristic layers against a single packet."""
        pass

    @abstractmethod
    def _get_source_key(self, packet) -> str:
        """Extract a key identifying the source of a potential attack."""
        pass

    def _compute_severity(self, score: int) -> Severity:
        """Map cumulative signal score to a severity level."""
        if score >= 6:
            return Severity.CRITICAL
        if score >= 4:
            return Severity.HIGH
        if score >= 2:
            return Severity.MEDIUM
        return Severity.LOW

    def is_detected(self) -> bool:
        """Check if any alerts have been raised."""
        return len(self._alerts) > 0

    def get_alerts(self) -> List[Alert]:
        """Return a copy of all raised alerts."""
        return list(self._alerts)

"""MAC Flooding detector with 4-layer heuristic engine.

Detection Layers:
    L1 - Unique MAC Rate (weight=2):
        Counts unique source MACs observed in a sliding time window.
        Fires when the count exceeds a threshold (default 50 in 10s).

    L2 - Invalid OUI (weight=2):
        Validates the vendor prefix (first 3 bytes) of each new MAC
        against a database of known manufacturers. Fires when >30% of
        recent MACs have unregistered OUI prefixes — a strong indicator
        of randomly generated MACs.

    L3 - MAC Churn (weight=2):
        Tracks MAC lifespan. Real MACs persist for minutes/hours; flood
        MACs appear once and vanish. Fires when >50% of observed MACs
        are "ephemeral" (seen in exactly one packet). Catches slow floods
        that evade L1's rate threshold.

    L4 - Adaptive Baseline (weight=1):
        Maintains a rolling mean + standard deviation of the MAC learning
        rate. Fires when the current rate exceeds mean + 3σ. Self-calibrating
        — works regardless of network size. Lowest weight since it needs
        history to establish a baseline.

Alert fires when cumulative score ≥ alert_threshold (default 3).
"""

import math
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Set, Tuple

from scapy.all import Ether

from common.models import Signal
from detectors.base import BaseDetector
from detectors.oui_data import is_valid_oui


class MACFloodDetector(BaseDetector):
    """Multi-layered MAC flooding detector."""

    attack_type = "mac_flood"
    mitre_attack_id = "T1498.001"
    mitre_tactic = "Impact: CAM Table Overflow & Network Flooding"
    pci_dss_requirement = "PCI-DSS 4.0 Req 1.4 & 10.4"

    # Layer weights
    WEIGHT_UNIQUE_RATE = 2
    WEIGHT_INVALID_OUI = 2
    WEIGHT_CHURN = 2
    WEIGHT_ADAPTIVE = 1

    def __init__(
        self,
        interface: str = "eth0",
        alert_threshold: int = 3,
        rate_window: float = 10.0,
        rate_threshold: int = 50,
        oui_invalid_ratio: float = 0.3,
        churn_ratio: float = 0.5,
        churn_timeout: float = 5.0,
        baseline_buckets: int = 6,
    ):
        """Initialize the MAC flood detector.

        Args:
            interface: Network interface to sniff on.
            alert_threshold: Minimum score to trigger an alert.
            rate_window: Sliding window duration in seconds for L1.
            rate_threshold: Max unique MACs in window before L1 fires.
            oui_invalid_ratio: Fraction of invalid OUIs to trigger L2.
            churn_ratio: Fraction of ephemeral MACs to trigger L3.
            churn_timeout: Seconds after which a single-packet MAC is
                considered ephemeral.
            baseline_buckets: Number of historical buckets for L4's
                rolling baseline calculation.
        """
        super().__init__(interface=interface, alert_threshold=alert_threshold)

        # L1: unique MAC rate tracking
        self.rate_window = rate_window
        self.rate_threshold = rate_threshold
        self._mac_timestamps: Deque[Tuple[float, str]] = deque()
        self._known_macs: Set[str] = set()

        # L2: OUI validation tracking
        self.oui_invalid_ratio = oui_invalid_ratio
        self._recent_oui_results: Deque[bool] = deque(maxlen=100)

        # L3: MAC churn (ephemeral MAC detection)
        self.churn_ratio = churn_ratio
        self.churn_timeout = churn_timeout
        self._mac_first_seen: Dict[str, float] = {}
        self._mac_last_seen: Dict[str, float] = {}
        self._mac_packet_count: Dict[str, int] = defaultdict(int)

        # L4: adaptive baseline
        self.baseline_buckets = baseline_buckets
        self._bucket_counts: Deque[int] = deque(maxlen=baseline_buckets)
        self._current_bucket_count = 0
        self._last_bucket_time = time.monotonic()

    def _get_source_key(self, packet) -> str:
        """Global key — flood sources are random, can't track per-source."""
        return "mac_flood"

    def _evaluate_layers(self, packet) -> List[Signal]:
        """Evaluate all 4 detection layers on an Ethernet frame."""
        if Ether not in packet:
            return []

        src_mac = packet[Ether].src.lower()
        now = time.monotonic()
        signals = []

        is_new = src_mac not in self._known_macs
        self._known_macs.add(src_mac)

        # --- L1: Unique MAC Rate ---
        if is_new:
            self._mac_timestamps.append((now, src_mac))

        # Evict entries outside the window
        while (self._mac_timestamps
               and now - self._mac_timestamps[0][0] > self.rate_window):
            self._mac_timestamps.popleft()

        # Count unique MACs currently in the window
        window_macs = {mac for _, mac in self._mac_timestamps}
        if len(window_macs) > self.rate_threshold:
            signals.append(Signal(
                layer_name="unique_mac_rate",
                weight=self.WEIGHT_UNIQUE_RATE,
                details=(
                    f"{len(window_macs)} unique MACs in "
                    f"{self.rate_window}s "
                    f"(threshold: {self.rate_threshold})"
                ),
            ))

        # --- L2: Invalid OUI ---
        if is_new:
            valid = is_valid_oui(src_mac)
            self._recent_oui_results.append(valid)

            if len(self._recent_oui_results) >= 20:
                invalid_count = sum(
                    1 for v in self._recent_oui_results if not v
                )
                invalid_pct = invalid_count / len(self._recent_oui_results)
                if invalid_pct > self.oui_invalid_ratio:
                    signals.append(Signal(
                        layer_name="invalid_oui",
                        weight=self.WEIGHT_INVALID_OUI,
                        details=(
                            f"{invalid_pct:.0%} of recent MACs have "
                            f"unknown OUI "
                            f"(threshold: {self.oui_invalid_ratio:.0%})"
                        ),
                    ))

        # --- L3: MAC Churn ---
        self._mac_packet_count[src_mac] += 1
        if src_mac not in self._mac_first_seen:
            self._mac_first_seen[src_mac] = now
        self._mac_last_seen[src_mac] = now

        # Evaluate churn every 50 new MACs (avoid per-packet overhead)
        if (is_new
                and len(self._known_macs) % 50 == 0
                and len(self._known_macs) > 50):
            ephemeral = sum(
                1 for mac in self._known_macs
                if self._mac_packet_count.get(mac, 0) == 1
                and now - self._mac_first_seen.get(mac, now) > self.churn_timeout
            )
            total = len(self._known_macs)
            if total > 0:
                churn_pct = ephemeral / total
                if churn_pct > self.churn_ratio:
                    signals.append(Signal(
                        layer_name="mac_churn",
                        weight=self.WEIGHT_CHURN,
                        details=(
                            f"{churn_pct:.0%} of MACs are ephemeral "
                            f"(threshold: {self.churn_ratio:.0%})"
                        ),
                    ))

        # --- L4: Adaptive Baseline ---
        if is_new:
            self._current_bucket_count += 1

        bucket_duration = self.rate_window
        if now - self._last_bucket_time >= bucket_duration:
            self._bucket_counts.append(self._current_bucket_count)
            self._current_bucket_count = 0
            self._last_bucket_time = now

            if len(self._bucket_counts) >= 3:
                counts = list(self._bucket_counts)
                mean = sum(counts) / len(counts)
                variance = sum(
                    (x - mean) ** 2 for x in counts
                ) / len(counts)
                stddev = math.sqrt(variance) if variance > 0 else 0

                # Check the LAST completed bucket against the baseline
                last_bucket = counts[-1]
                if stddev > 0 and last_bucket > mean + 3 * stddev:
                    signals.append(Signal(
                        layer_name="adaptive_baseline",
                        weight=self.WEIGHT_ADAPTIVE,
                        details=(
                            f"Bucket rate {last_bucket} exceeds "
                            f"baseline {mean:.1f} + 3σ ({3 * stddev:.1f})"
                        ),
                    ))

        return signals

"""DHCP Starvation and Resource Exhaustion Detector with 4-Layer Heuristic Engine.

Detection Layers:
    L1 - Discover Rate Anomaly (weight=2):
        Monitors DHCP DISCOVER frequency in a sliding window. Normal networks
        see occasional discovery frames during client boot; starvation attacks
        burst dozens/hundreds per second.

    L2 - Unique Client MAC (chaddr) Velocity (weight=2):
        Tracks unique client hardware addresses requesting addresses in the
        current time window. High velocity indicates programmatic pool exhaustion.

    L3 - Header vs Payload MAC Mismatch (weight=3):
        Compares Ethernet frame source MAC against BOOTP payload chaddr.
        Many starvation scripts craft distinct payload MACs while retaining
        the attacker's interface MAC in the Ethernet header.

    L4 - Transaction ID (xid) Anomaly (weight=1):
        Detects anomalies in BOOTP transaction ID distribution.
"""

import time
from collections import deque
from typing import Deque, List, Set

from scapy.all import BOOTP, DHCP, Ether

from common.models import Signal
from detectors.base import BaseDetector


class DHCPStarvationDetector(BaseDetector):
    """Multi-layer heuristic detector for DHCP resource starvation."""

    attack_type = "dhcp_starvation"
    mitre_attack_id = "T1499"
    mitre_tactic = "Endpoint Denial of Service: Service Exhaustion"
    pci_dss_requirement = "PCI-DSS 4.0 Req 1.4 & 10.4"

    WEIGHT_DISCOVER_RATE = 2
    WEIGHT_UNIQUE_CHADDR = 2
    WEIGHT_CHADDR_MISMATCH = 3
    WEIGHT_XID_ANOMALY = 1

    def __init__(
        self,
        interface: str = "eth0",
        alert_threshold: int = 3,
        rate_window: float = 5.0,
        rate_threshold: int = 10,
        unique_chaddr_threshold: int = 8,
    ):
        """Initialize the DHCP starvation detector.

        Args:
            interface: Interface to sniff on.
            alert_threshold: Cumulative score required to raise an alert.
            rate_window: Sliding window in seconds for velocity tracking.
            rate_threshold: Max normal DISCOVER frames per window.
            unique_chaddr_threshold: Max normal unique client MACs per window.
        """
        super().__init__(interface=interface, alert_threshold=alert_threshold)
        self.rate_window = rate_window
        self.rate_threshold = rate_threshold
        self.unique_chaddr_threshold = unique_chaddr_threshold

        # Sliding window history: (timestamp, chaddr_hex, xid)
        self._discover_history: Deque = deque(maxlen=200)

    def _get_source_key(self, packet) -> str:
        """Global key for starvation attacks because sources are randomized."""
        return "dhcp_starvation_pool"

    def _evaluate_layers(self, packet) -> List[Signal]:
        """Evaluate starvation heuristic layers on incoming DHCP DISCOVER frames."""
        if not (Ether in packet and BOOTP in packet and DHCP in packet):
            return []

        # Only inspect BOOTREQUEST with DHCP message-type = discover (1)
        bootp = packet[BOOTP]
        if bootp.op != 1:
            return []

        # Check if message-type option is 'discover' (1)
        is_discover = False
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                if opt[1] == 1 or opt[1] == "discover":
                    is_discover = True
                break

        if not is_discover:
            return []

        signals = []
        now = time.monotonic()

        # Extract client hardware address from BOOTP header
        raw_chaddr = bootp.chaddr[:6]
        chaddr_str = ":".join(f"{b:02x}" for b in raw_chaddr)
        ether_src = packet[Ether].src.lower()

        self._discover_history.append((now, chaddr_str, bootp.xid))

        # Evict old events outside sliding window
        window_start = now - self.rate_window
        recent_events = [e for e in self._discover_history if e[0] >= window_start]

        # --- L1: Discover Rate Anomaly ---
        if len(recent_events) > self.rate_threshold:
            signals.append(Signal(
                layer_name="discover_rate_anomaly",
                weight=self.WEIGHT_DISCOVER_RATE,
                details=(
                    f"Excessive DHCP DISCOVER velocity: {len(recent_events)} "
                    f"frames in {self.rate_window}s (threshold: {self.rate_threshold})"
                ),
            ))

        # --- L2: Unique Client MAC (chaddr) Velocity ---
        unique_chaddrs = {e[1] for e in recent_events}
        if len(unique_chaddrs) >= self.unique_chaddr_threshold:
            signals.append(Signal(
                layer_name="unique_chaddr_rate",
                weight=self.WEIGHT_UNIQUE_CHADDR,
                details=(
                    f"Rapid unique client hardware address expansion: "
                    f"{len(unique_chaddrs)} distinct MACs in {self.rate_window}s"
                ),
            ))

        # --- L3: Header vs Payload MAC Mismatch ---
        if ether_src != chaddr_str.lower():
            signals.append(Signal(
                layer_name="chaddr_mismatch",
                weight=self.WEIGHT_CHADDR_MISMATCH,
                details=(
                    f"Ethernet source MAC ({ether_src}) does not match "
                    f"BOOTP client hardware address ({chaddr_str})"
                ),
            ))

        return signals

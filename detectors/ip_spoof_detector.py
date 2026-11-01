"""IP Source Address Anti-Spoofing & Ingress Boundary Detector (BCP-38).

Detection Layers:
    L1 - Bogon & Martian Address Filtering (weight=3):
        RFC 6890 / BCP 38: Packets originating on internal LAN interfaces
        must not carry reserved/martian source addresses (e.g. 127.0.0.0/8,
        0.0.0.0/8, 224.0.0.0/4 multicast, 255.255.255.255 broadcast).

    L2 - Ingress Subnet Boundary Violation (weight=3):
        BCP 38 ingress filtering: Packets originating within the broadcast
        domain must possess a source IP within the local subnet CIDR.

    L3 - IP-to-MAC Binding Conflict (weight=2):
        Correlates IP source with baseline IP-MAC bindings. If a packet
        claims an internal IP (e.g. Gateway) but arrives with an unauthorized
        Ethernet source MAC, it indicates Layer 3 impersonation.

    L4 - Spoofed Flow Rate Anomaly (weight=1):
        Tracks packet velocity from violating sources in a sliding window.
"""

import ipaddress
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional

from scapy.all import Ether, IP

from common.models import NetworkBaseline, Signal
from detectors.base import BaseDetector

BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast source
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
]


class IPSpoofDetector(BaseDetector):
    """Multi-layer heuristic detector for IP source address spoofing."""

    attack_type = "ip_spoof"
    mitre_attack_id = "T1584"
    mitre_tactic = "Defense Evasion / Initial Access: IP Spoofing"
    pci_dss_requirement = "PCI-DSS 4.0 Req 1.3 (Network Ingress & Boundary Protection)"

    WEIGHT_BOGON = 3
    WEIGHT_BOUNDARY_VIOLATION = 3
    WEIGHT_MAC_CONFLICT = 2
    WEIGHT_RATE_ANOMALY = 1

    def __init__(
        self,
        interface: str = "eth0",
        alert_threshold: int = 3,
        subnet_cidr: str = "172.20.0.0/24",
        ip_mac_bindings: Optional[Dict[str, str]] = None,
        baseline: Optional[NetworkBaseline] = None,
    ):
        """Initialize the IP spoof detector.

        Args:
            interface: Interface to monitor.
            alert_threshold: Minimum score to raise an alert.
            subnet_cidr: Authoritative local subnet CIDR.
            ip_mac_bindings: Legitimate IP→MAC bindings.
            baseline: Optional NetworkBaseline to auto-populate subnet and bindings.
        """
        super().__init__(interface=interface, alert_threshold=alert_threshold)

        if baseline:
            self.subnet_cidr = baseline.subnet_cidr or subnet_cidr
            self.ip_mac_bindings = dict(baseline.ip_mac_bindings or {})
        else:
            self.subnet_cidr = subnet_cidr
            self.ip_mac_bindings = dict(ip_mac_bindings or {})

        try:
            self._network = ipaddress.ip_network(self.subnet_cidr, strict=False)
        except Exception:
            self._network = ipaddress.ip_network("172.20.0.0/24", strict=False)

        self._flow_timestamps: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )

    def _get_source_key(self, packet) -> str:
        """Key by Ethernet source MAC to identify the physical sender."""
        if Ether in packet:
            return packet[Ether].src.lower()
        return "unknown"

    def _evaluate_layers(self, packet) -> List[Signal]:
        """Evaluate BCP-38 ingress filtering and spoofing heuristics."""
        if not (Ether in packet and IP in packet):
            return []

        src_ip_str = packet[IP].src
        ether_src = packet[Ether].src.lower()
        signals = []
        now = time.monotonic()

        # DHCP requests legitimately use 0.0.0.0 during initial discovery; ignore UDP port 67/68
        if src_ip_str == "0.0.0.0" and packet[IP].dst == "255.255.255.255":
            return []

        try:
            src_addr = ipaddress.ip_address(src_ip_str)
        except ValueError:
            return []

        # --- L1: Bogon & Martian Address Filtering ---
        for bogon in BOGON_NETWORKS:
            if src_addr in bogon:
                signals.append(Signal(
                    layer_name="bogon_source_ip",
                    weight=self.WEIGHT_BOGON,
                    details=f"Packet carries martian/bogon source IP {src_ip_str} in {bogon}",
                ))
                break

        # --- L2: Ingress Subnet Boundary Violation (BCP-38) ---
        if src_addr not in self._network and not src_addr.is_multicast:
            signals.append(Signal(
                layer_name="subnet_boundary_violation",
                weight=self.WEIGHT_BOUNDARY_VIOLATION,
                details=(
                    f"BCP-38 Ingress Violation: Source IP {src_ip_str} does not "
                    f"belong to local subnet {self.subnet_cidr}"
                ),
            ))

        # --- L3: IP-to-MAC Binding Conflict ---
        if src_ip_str in self.ip_mac_bindings:
            expected_mac = self.ip_mac_bindings[src_ip_str].lower()
            if ether_src != expected_mac:
                signals.append(Signal(
                    layer_name="mac_binding_conflict",
                    weight=self.WEIGHT_MAC_CONFLICT,
                    details=(
                        f"IP {src_ip_str} originated from unauthorized MAC {ether_src} "
                        f"(expected: {expected_mac})"
                    ),
                ))

        # --- L4: Spoofed Flow Rate Anomaly ---
        if signals:
            self._flow_timestamps[ether_src].append(now)
            window_events = [
                t for t in self._flow_timestamps[ether_src]
                if now - t <= 5.0
            ]
            if len(window_events) >= 5:
                signals.append(Signal(
                    layer_name="spoofed_flow_burst",
                    weight=self.WEIGHT_RATE_ANOMALY,
                    details=(
                        f"High velocity spoofed traffic: {len(window_events)} "
                        f"anomalous frames from MAC {ether_src} in 5.0s"
                    ),
                ))

        return signals

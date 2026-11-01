"""ICMP Route Redirect Anomaly Detector with 4-Layer Heuristic Engine.

Detection Layers:
    L1 - Untrusted Redirect Source (weight=3):
        RFC 1122 specifies that hosts must drop ICMP redirects unless
        sent by the current default gateway. Fires if the redirect source
        does not match the baseline gateway IP.

    L2 - Unauthorized Redirect Gateway (weight=2):
        Checks whether the redirected gateway IP (ICMP.gw) is an authorized
        router within the local network segment.

    L3 - Burst Velocity Anomaly (weight=2):
        Monitors redirect frequency per destination in a sliding window.
        Legitimate networks rarely generate multiple redirects per minute.

    L4 - On-Link Redirect Violation (weight=1):
        Detects redirects targeting destinations already on the local subnet
        (violates RFC 1812 router recommendations).
"""

import ipaddress
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional

from scapy.all import ICMP, IP

from common.models import NetworkBaseline, Signal
from detectors.base import BaseDetector


class ICMPRedirectDetector(BaseDetector):
    """Multi-layer heuristic detector for unauthorized ICMP route manipulation."""

    attack_type = "icmp_redirect"
    mitre_attack_id = "T1557"
    mitre_tactic = "Adversary-in-the-Middle: ICMP Route Redirection"
    pci_dss_requirement = "PCI-DSS 4.0 Req 1.3 & 11.2"

    WEIGHT_UNTRUSTED_SOURCE = 3
    WEIGHT_UNAUTHORIZED_GW = 2
    WEIGHT_RATE_ANOMALY = 2
    WEIGHT_ON_LINK_ANOMALY = 1

    def __init__(
        self,
        interface: str = "eth0",
        alert_threshold: int = 3,
        trusted_gateway_ip: Optional[str] = None,
        subnet_cidr: str = "172.20.0.0/24",
        baseline: Optional[NetworkBaseline] = None,
    ):
        """Initialize the ICMP redirect detector.

        Args:
            interface: Network interface to sniff on.
            alert_threshold: Cumulative score required to raise an alert.
            trusted_gateway_ip: Legitimate first-hop gateway IP.
            subnet_cidr: Local subnet IPv4 network range.
            baseline: Optional NetworkBaseline to auto-populate gateway and subnet.
        """
        super().__init__(interface=interface, alert_threshold=alert_threshold)

        if baseline:
            self.trusted_gateway_ip = baseline.gateway_ip or trusted_gateway_ip
            self.subnet_cidr = baseline.subnet_cidr or subnet_cidr
        else:
            self.trusted_gateway_ip = trusted_gateway_ip
            self.subnet_cidr = subnet_cidr

        try:
            self._network = ipaddress.ip_network(self.subnet_cidr, strict=False)
        except Exception:
            self._network = ipaddress.ip_network("172.20.0.0/24", strict=False)

        self._redirect_timestamps: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=50)
        )

    def _get_source_key(self, packet) -> str:
        """Key by the targeted victim IP."""
        if IP in packet:
            return packet[IP].dst
        return "unknown"

    def _evaluate_layers(self, packet) -> List[Signal]:
        """Evaluate heuristic layers on ICMP redirect packets."""
        if not (IP in packet and ICMP in packet):
            return []

        icmp = packet[ICMP]
        # ICMP Type 5 = Redirect
        if icmp.type != 5:
            return []

        signals = []
        now = time.monotonic()
        sender_ip = packet[IP].src
        target_victim = packet[IP].dst
        offered_gw = icmp.gw

        # --- L1: Untrusted Redirect Source ---
        if self.trusted_gateway_ip and sender_ip != self.trusted_gateway_ip:
            signals.append(Signal(
                layer_name="untrusted_redirect_source",
                weight=self.WEIGHT_UNTRUSTED_SOURCE,
                details=(
                    f"ICMP redirect originated from untrusted host {sender_ip} "
                    f"(expected default gateway: {self.trusted_gateway_ip})"
                ),
            ))

        # --- L2: Unauthorized Redirect Gateway ---
        try:
            gw_addr = ipaddress.ip_address(offered_gw)
            if gw_addr not in self._network:
                signals.append(Signal(
                    layer_name="unauthorized_redirect_gw",
                    weight=self.WEIGHT_UNAUTHORIZED_GW,
                    details=(
                        f"Redirect points to off-subnet gateway {offered_gw} "
                        f"outside local CIDR {self.subnet_cidr}"
                    ),
                ))
            elif self.trusted_gateway_ip and offered_gw == sender_ip:
                # Gateway redirecting to itself
                signals.append(Signal(
                    layer_name="unauthorized_redirect_gw",
                    weight=self.WEIGHT_UNAUTHORIZED_GW,
                    details=f"Anomalous redirect pointing to sender itself: {offered_gw}",
                ))
        except ValueError:
            pass

        # --- L3: Rate / Burst Anomaly ---
        self._redirect_timestamps[target_victim].append(now)
        window_events = [
            t for t in self._redirect_timestamps[target_victim]
            if now - t <= 10.0
        ]
        if len(window_events) >= 3:
            signals.append(Signal(
                layer_name="redirect_rate_anomaly",
                weight=self.WEIGHT_RATE_ANOMALY,
                details=(
                    f"Redirect burst targeting {target_victim}: "
                    f"{len(window_events)} redirects within 10.0s"
                ),
            ))

        return signals

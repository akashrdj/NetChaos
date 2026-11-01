"""ARP Spoofing detector with 4-layer heuristic engine and Active Defense.

Detection Layers:
    L1 - Binding Change (weight=2):
        Maintains an IP→MAC mapping table. Fires when an IP's associated
        MAC changes from a previously observed value. Seeds with trusted
        bindings (e.g., gateway) or dynamic NetworkBaseline.

    L2 - Unsolicited Reply (weight=2):
        Tracks recent ARP requests. Fires when an ARP reply arrives
        without a matching prior ARP request — normal ARP follows
        request→reply, so unsolicited replies indicate injection.

    L3 - Header Mismatch (weight=3):
        Compares the Ethernet header source MAC (Ether.src) against the
        ARP payload source MAC (ARP.hwsrc). A mismatch indicates a
        crafted packet. Near-zero false positives — highest weight.

    L4 - Reply Rate Anomaly (weight=1):
        Tracks per-IP ARP reply frequency in a sliding window. Normal
        hosts send ~1 reply/minute; continuous poisoning produces 10+/s.

Active Defense:
    When enabled, triggers ARPCacheHealer to immediately broadcast
    authentic Gratuitous ARP (GARP) bursts restoring legitimate bindings.
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional

from scapy.all import ARP, Ether

from common.models import Alert, NetworkBaseline, Signal
from defense.arp_healer import ARPCacheHealer
from detectors.base import BaseDetector


class ARPDetector(BaseDetector):
    """Multi-layered ARP spoofing detector with Active Healing."""

    attack_type = "arp_spoof"
    mitre_attack_id = "T1557.002"
    mitre_tactic = "Adversary-in-the-Middle: ARP Poisoning"
    pci_dss_requirement = "PCI-DSS 4.0 Req 1.3 & 11.2"

    # Layer weights
    WEIGHT_BINDING_CHANGE = 2
    WEIGHT_UNSOLICITED = 2
    WEIGHT_HEADER_MISMATCH = 3
    WEIGHT_RATE_ANOMALY = 1

    # Rate anomaly configuration
    RATE_WINDOW_SECONDS = 10
    RATE_THRESHOLD = 5  # replies per window

    def __init__(
        self,
        interface: str = "eth0",
        alert_threshold: int = 3,
        trusted_bindings: Optional[Dict[str, str]] = None,
        baseline: Optional[NetworkBaseline] = None,
        active_defense: bool = False,
        healer: Optional[ARPCacheHealer] = None,
    ):
        """Initialize the ARP detector.

        Args:
            interface: Network interface to sniff on.
            alert_threshold: Minimum score to trigger an alert.
            trusted_bindings: Known-good IP→MAC mappings to seed the
                binding table (e.g., {"172.20.0.2": "02:42:ac:14:00:02"}).
            baseline: Optional dynamic NetworkBaseline object to seed bindings.
            active_defense: Whether to execute automated GARP healing on alert.
            healer: Custom ARPCacheHealer instance.
        """
        super().__init__(interface=interface, alert_threshold=alert_threshold)

        # Seed bindings from explicit dict or dynamic baseline
        seed = dict(trusted_bindings or {})
        if baseline and baseline.ip_mac_bindings:
            seed.update(baseline.ip_mac_bindings)

        # L1: known IP→MAC bindings (authoritative reference)
        self.authoritative_bindings = dict(seed)
        self.ip_mac_table: Dict[str, str] = dict(seed)

        # L2: pending ARP requests (target_ip → monotonic timestamp)
        self.pending_requests: Dict[str, float] = {}
        self.request_timeout = 5.0

        # L4: per-IP reply timestamps for rate tracking
        self.reply_timestamps: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )

        # Active Defense configuration
        self.active_defense = active_defense
        self.healer = healer or (
            ARPCacheHealer(
                interface=interface,
                trusted_bindings=self.authoritative_bindings,
                dry_run=False,
            )
            if active_defense
            else None
        )

    def _get_source_key(self, packet) -> str:
        """Key by the claimed source IP in the ARP packet."""
        if ARP in packet:
            return packet[ARP].psrc
        return "unknown"

    def _evaluate_layers(self, packet) -> List[Signal]:
        """Evaluate all 4 detection layers on an ARP packet."""
        if ARP not in packet:
            return []

        signals = []
        arp = packet[ARP]
        now = time.monotonic()

        # Track ARP requests for L2 correlation (don't generate signals)
        if arp.op == 1:  # ARP Request
            self.pending_requests[arp.pdst] = now
            return []

        # Only process ARP replies (op=2) from here
        if arp.op != 2:
            return []

        src_ip = arp.psrc
        src_mac = arp.hwsrc

        # --- L1: Binding Change ---
        if src_ip in self.ip_mac_table:
            if self.ip_mac_table[src_ip] != src_mac:
                signals.append(Signal(
                    layer_name="binding_change",
                    weight=self.WEIGHT_BINDING_CHANGE,
                    details=(
                        f"IP {src_ip} MAC changed: "
                        f"{self.ip_mac_table[src_ip]} → {src_mac}"
                    ),
                ))
        # Update the binding table
        self.ip_mac_table[src_ip] = src_mac

        # --- L2: Unsolicited Reply ---
        stale_ips = [
            ip for ip, ts in self.pending_requests.items()
            if now - ts > self.request_timeout
        ]
        for ip in stale_ips:
            del self.pending_requests[ip]

        if src_ip not in self.pending_requests:
            signals.append(Signal(
                layer_name="unsolicited_reply",
                weight=self.WEIGHT_UNSOLICITED,
                details=f"ARP reply for {src_ip} without matching request",
            ))
        else:
            del self.pending_requests[src_ip]

        # --- L3: Header Mismatch ---
        if Ether in packet:
            ether_src = packet[Ether].src.lower()
            arp_src = src_mac.lower()
            if ether_src != arp_src:
                signals.append(Signal(
                    layer_name="header_mismatch",
                    weight=self.WEIGHT_HEADER_MISMATCH,
                    details=f"Ether.src={ether_src} ≠ ARP.hwsrc={arp_src}",
                ))

        # --- L4: Reply Rate Anomaly ---
        self.reply_timestamps[src_ip].append(now)
        window_start = now - self.RATE_WINDOW_SECONDS
        recent_count = sum(
            1 for ts in self.reply_timestamps[src_ip] if ts >= window_start
        )
        if recent_count > self.RATE_THRESHOLD:
            signals.append(Signal(
                layer_name="reply_rate_anomaly",
                weight=self.WEIGHT_RATE_ANOMALY,
                details=(
                    f"IP {src_ip} sent {recent_count} ARP replies in "
                    f"{self.RATE_WINDOW_SECONDS}s "
                    f"(threshold: {self.RATE_THRESHOLD})"
                ),
            ))

        return signals

    def _on_alert_raised(self, alert: Alert, packet) -> None:
        """Execute active defense when alert threshold is crossed."""
        if self.active_defense and self.healer:
            claimed_ip = alert.source_key
            claimed_mac = packet[ARP].hwsrc if ARP in packet else None
            # If the claimed IP is in our authoritative bindings, restore it
            if claimed_ip in self.authoritative_bindings:
                defense_result = self.healer.remediate(
                    poisoned_ip=claimed_ip,
                    attacker_mac=claimed_mac,
                )
                alert.remediation_action = defense_result.details
                # Re-align local table with authoritative MAC
                self.ip_mac_table[claimed_ip] = self.authoritative_bindings[claimed_ip]

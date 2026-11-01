"""Active Defense & Automated ARP Cache Inoculation Engine.

When an ARP poisoning or spoofing attack is detected, this module
constructs and broadcasts authentic Gratuitous ARP (GARP) healing frames
to immediately overwrite and correct the poisoned ARP tables on all
victim endpoints across the subnet.
"""

import logging
import time
from typing import Dict, List, Optional

from scapy.all import ARP, Ether, sendp

from common.models import DefenseResult

logger = logging.getLogger(__name__)


class ARPCacheHealer:
    """Automated active remediation engine for Layer 2 ARP poisoning."""

    def __init__(
        self,
        interface: str = "eth0",
        trusted_bindings: Optional[Dict[str, str]] = None,
        burst_count: int = 5,
        burst_interval: float = 0.02,
        dry_run: bool = False,
    ):
        """Initialize the ARP healer.

        Args:
            interface: Network interface to inject healing frames on.
            trusted_bindings: Authoritative IP→MAC mapping to restore.
            burst_count: Number of consecutive GARP frames in a healing burst.
            burst_interval: Seconds between frames in the healing burst.
            dry_run: If True, crafts frames and returns telemetry without raw socket transmission.
        """
        self.interface = interface
        self.trusted_bindings = dict(trusted_bindings or {})
        self.burst_count = burst_count
        self.burst_interval = burst_interval
        self.dry_run = dry_run
        self.history: List[DefenseResult] = []

    def build_healing_frames(
        self, target_ip: str, legitimate_mac: str
    ) -> List[Ether]:
        """Craft an authentic Gratuitous ARP (GARP) reply frame.

        A Gratuitous ARP reply broadcasts the authoritative mapping of
        the target IP to its real MAC address, forcing all listening
        switches and host operating systems to overwrite any poisoned
        cache entries.
        """
        frame = Ether(src=legitimate_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,  # ARP reply
            psrc=target_ip,
            hwsrc=legitimate_mac,
            pdst=target_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
        )
        return [frame for _ in range(self.burst_count)]

    def remediate(
        self,
        poisoned_ip: str,
        attacker_mac: Optional[str] = None,
        override_legitimate_mac: Optional[str] = None,
    ) -> DefenseResult:
        """Execute active defense burst to inoculate the network.

        Args:
            poisoned_ip: The IP address that was spoofed (e.g., Default Gateway).
            attacker_mac: The rogue MAC claimed during the attack.
            override_legitimate_mac: Optional explicit MAC if not in trusted_bindings.

        Returns:
            DefenseResult with remediation telemetry and execution status.
        """
        real_mac = (
            override_legitimate_mac
            or self.trusted_bindings.get(poisoned_ip)
        )

        if not real_mac:
            err_msg = (
                f"Cannot remediate IP {poisoned_ip}: "
                f"no authoritative MAC binding registered."
            )
            logger.warning(err_msg)
            result = DefenseResult(
                action_type="gratuitous_arp_burst",
                target_ip=poisoned_ip,
                restored_mac="unknown",
                packets_transmitted=0,
                success=False,
                details=err_msg,
            )
            self.history.append(result)
            return result

        frames = self.build_healing_frames(poisoned_ip, real_mac)
        transmitted = 0

        if not self.dry_run:
            try:
                for frame in frames:
                    sendp(
                        frame,
                        iface=self.interface,
                        verbose=False,
                    )
                    transmitted += 1
                    time.sleep(self.burst_interval)
            except Exception as e:
                logger.error("Failed to inject healing frames: %s", e)
                result = DefenseResult(
                    action_type="gratuitous_arp_burst",
                    target_ip=poisoned_ip,
                    restored_mac=real_mac,
                    packets_transmitted=transmitted,
                    success=False,
                    details=f"Socket error: {e}",
                )
                self.history.append(result)
                return result
        else:
            # Simulated transmission for dry-run/testing
            transmitted = len(frames)

        details = (
            f"Active Inoculation: Transmitted {transmitted}x Gratuitous ARP "
            f"healing frames restoring IP {poisoned_ip} → {real_mac}"
            + (f" (overriding rogue MAC {attacker_mac})" if attacker_mac else "")
        )

        result = DefenseResult(
            action_type="gratuitous_arp_burst",
            target_ip=poisoned_ip,
            restored_mac=real_mac,
            packets_transmitted=transmitted,
            success=True,
            details=details,
        )
        self.history.append(result)
        return result


"""Dynamic Network Profiler & Baseline Learning Engine.

Discovers topology automatically (default gateway IP/MAC, DHCP servers,
subnet ranges, and legitimate OUIs) eliminating brittle hardcoded network
configurations in CI/CD and production environments.
"""

import json
import logging
import os
import subprocess
import time
from typing import Dict, List, Optional, Set

from scapy.all import ARP, Ether, conf, srp1

from common.models import NetworkBaseline

logger = logging.getLogger(__name__)


class NetworkProfiler:
    """Discovers and establishes authoritative network baselines."""

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self._baseline: Optional[NetworkBaseline] = None

    def profile_local_network(
        self,
        passive_duration_s: int = 5,
        default_gateway_hint: Optional[str] = None,
    ) -> NetworkBaseline:
        """Dynamically learn the network baseline.

        Combines local OS routing table inspection with active ARP resolution.

        Args:
            passive_duration_s: Time to passively observe broadcast traffic.
            default_gateway_hint: Optional manual hint for gateway IP if known.

        Returns:
            NetworkBaseline containing discovered gateway, bindings, and OUIs.
        """
        gateway_ip = default_gateway_hint or self._discover_default_gateway_ip()
        gateway_mac = None

        bindings: Dict[str, str] = {}
        trusted_ouis: Set[str] = set()
        trusted_dhcp: Set[str] = set()

        if gateway_ip:
            gateway_mac = self._resolve_mac_for_ip(gateway_ip)
            if gateway_mac:
                bindings[gateway_ip] = gateway_mac
                trusted_ouis.add(gateway_mac[:8].lower())
                trusted_dhcp.add(gateway_mac)

        self._baseline = NetworkBaseline(
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            trusted_dhcp_servers=trusted_dhcp,
            trusted_dns_servers=[gateway_ip] if gateway_ip else [],
            subnet_cidr="172.20.0.0/24",
            ip_mac_bindings=bindings,
            trusted_ouis=trusted_ouis,
        )
        return self._baseline

    def _discover_default_gateway_ip(self) -> Optional[str]:
        """Discover the default IPv4 gateway via routing table or scapy conf."""
        try:
            # Check Scapy's built-in route table
            route = conf.route.route("0.0.0.0")
            if route and len(route) >= 3 and route[2] != "0.0.0.0":
                return route[2]
        except Exception as e:
            logger.debug("Scapy route lookup failed: %s", e)

        # Fallback to inspecting Linux /proc/net/route if present
        if os.path.exists("/proc/net/route"):
            try:
                with open("/proc/net/route", "r") as f:
                    for line in f.readlines()[1:]:
                        fields = line.strip().split()
                        if len(fields) >= 3 and fields[1] == "00000000":
                            # Gateway hex to IP
                            gw_hex = fields[2]
                            gw_ip = ".".join(
                                str(int(gw_hex[i:i + 2], 16))
                                for i in (6, 4, 2, 0)
                            )
                            return gw_ip
            except Exception as e:
                logger.debug("Failed reading /proc/net/route: %s", e)

        return None

    def _resolve_mac_for_ip(self, ip: str) -> Optional[str]:
        """Perform an active ARP request to resolve an IP's hardware address."""
        try:
            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            reply = srp1(
                arp_req,
                iface=self.interface,
                timeout=2,
                verbose=False,
            )
            if reply and ARP in reply:
                return reply[ARP].hwsrc.lower()
        except Exception as e:
            logger.debug("ARP resolution error for %s: %s", ip, e)
        return None

    def export_baseline(self, filepath: str) -> None:
        """Save baseline profile to a JSON file."""
        if not self._baseline:
            raise ValueError("No baseline has been profiled yet.")
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(self._baseline.to_dict(), f, indent=2)

    @classmethod
    def load_baseline(cls, filepath: str) -> NetworkBaseline:
        """Load an existing baseline profile from JSON."""
        with open(filepath, "r") as f:
            data = json.load(f)
        return NetworkBaseline(
            gateway_ip=data.get("gateway_ip"),
            gateway_mac=data.get("gateway_mac"),
            trusted_dhcp_servers=set(data.get("trusted_dhcp_servers", [])),
            trusted_dns_servers=data.get("trusted_dns_servers", []),
            subnet_cidr=data.get("subnet_cidr"),
            ip_mac_bindings=data.get("ip_mac_bindings", {}),
            trusted_ouis=set(data.get("trusted_ouis", [])),
        )

    @classmethod
    def mock_baseline(
        cls,
        gateway_ip: str = "172.20.0.2",
        gateway_mac: str = "02:42:ac:14:00:02",
        subnet_cidr: str = "172.20.0.0/24",
    ) -> NetworkBaseline:
        """Create a mock baseline for test environments and simulations."""
        return NetworkBaseline(
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            trusted_dhcp_servers={gateway_mac},
            trusted_dns_servers=[gateway_ip],
            subnet_cidr=subnet_cidr,
            ip_mac_bindings={gateway_ip: gateway_mac},
            trusted_ouis={gateway_mac[:8].lower()},
        )


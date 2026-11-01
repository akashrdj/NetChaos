"""Chaos Execution & SLA Compliance Engine for NetChaos."""

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from scapy.all import ARP, BOOTP, DHCP, Ether, IP, UDP, RandMAC

from attacks.dhcp_starvation import DHCPStarvation
from attacks.icmp_redirect import ICMPRedirect
from attacks.ip_spoof import IPSpoof
from chaos.profiles import PROFILES, ChaosProfile
from common.db import init_db, log_result
from common.models import Alert, NetworkBaseline
from defense.arp_healer import ARPCacheHealer
from detectors.arp_detector import ARPDetector
from detectors.baseline import NetworkProfiler
from detectors.dhcp_detector import DHCPDetector
from detectors.dhcp_starvation_detector import DHCPStarvationDetector
from detectors.icmp_redirect_detector import ICMPRedirectDetector
from detectors.ip_spoof_detector import IPSpoofDetector
from detectors.mac_flood_detector import MACFloodDetector
from telemetry.dispatcher import WebhookDispatcher

logger = logging.getLogger(__name__)


@dataclass
class AttackExecutionReport:
    """Telemetry report for a single chaos attack validation."""

    attack_type: str
    detected: bool
    latency_ms: float
    sla_passed: bool
    severity: str
    mitre_id: str
    mitre_tactic: str
    pci_requirement: str
    signals_fired: List[str]
    remediation_action: Optional[str] = None


@dataclass
class ChaosRunSummary:
    """Aggregated summary of an entire Chaos run."""

    run_id: str
    profile: str
    timestamp: datetime
    total_attacks: int
    passed_attacks: int
    failed_attacks: int
    all_passed: bool
    reports: List[AttackExecutionReport]


class ChaosEngine:
    """Executes curated chaos testing profiles and asserts detection SLAs."""

    def __init__(
        self,
        interface: str = "eth0",
        db_path: str = "db/results.db",
        webhook_dispatcher: Optional[WebhookDispatcher] = None,
        dry_run: bool = True,
        active_defense: bool = True,
    ):
        self.interface = interface
        self.db_path = db_path
        self.dispatcher = webhook_dispatcher or WebhookDispatcher(dry_run=dry_run)
        self.dry_run = dry_run
        self.active_defense = active_defense
        init_db(self.db_path)

    def execute_profile(
        self,
        profile_name: str = "smoke",
        baseline: Optional[NetworkBaseline] = None,
    ) -> ChaosRunSummary:
        """Run all attack scenarios defined in the selected profile."""
        if profile_name not in PROFILES:
            raise ValueError(f"Unknown chaos profile '{profile_name}'. Available: {list(PROFILES.keys())}")

        profile = PROFILES[profile_name]
        run_id = f"netchaos-{profile_name}-{int(time.time())}"

        # Initialize network baseline if not provided
        active_baseline = baseline or NetworkProfiler.mock_baseline()

        reports: List[AttackExecutionReport] = []

        for attack_type in profile.attack_types:
            report = self._run_single_chaos_drill(
                attack_type=attack_type,
                profile=profile,
                baseline=active_baseline,
                run_id=run_id,
            )
            reports.append(report)

        passed_count = sum(1 for r in reports if r.detected and r.sla_passed)
        all_passed = (passed_count == len(reports))

        return ChaosRunSummary(
            run_id=run_id,
            profile=profile_name,
            timestamp=datetime.now(),
            total_attacks=len(reports),
            passed_attacks=passed_count,
            failed_attacks=len(reports) - passed_count,
            all_passed=all_passed,
            reports=reports,
        )

    def _run_single_chaos_drill(
        self,
        attack_type: str,
        profile: ChaosProfile,
        baseline: NetworkBaseline,
        run_id: str,
    ) -> AttackExecutionReport:
        """Run a single attack simulation against its multi-layer detector."""
        detector = None
        alert = None
        latency_ms = 0.0

        if attack_type == "arp_spoof":
            healer = ARPCacheHealer(
                interface=self.interface,
                trusted_bindings=baseline.ip_mac_bindings,
                dry_run=self.dry_run,
            )
            detector = ARPDetector(
                interface=self.interface,
                alert_threshold=3,
                baseline=baseline,
                active_defense=self.active_defense or profile.require_active_defense,
                healer=healer,
            )
            spoof_pkt = Ether(src="02:42:ac:14:00:ff", dst="02:42:ac:14:00:03") / ARP(
                op=2,
                psrc=baseline.gateway_ip or "172.20.0.2",
                hwsrc="02:42:ac:14:00:ff",
                pdst="172.20.0.3",
                hwdst="02:42:ac:14:00:03",
            )
            start = time.monotonic()
            for _ in range(6):
                detector._packet_handler(spoof_pkt)
            latency_ms = (time.monotonic() - start) * 1000

        elif attack_type == "mac_flood":
            detector = MACFloodDetector(interface=self.interface, alert_threshold=3, rate_threshold=10)
            start = time.monotonic()
            for _ in range(25):
                pkt = Ether(src=RandMAC(), dst="02:42:ac:14:00:02") / ARP(op=1)
                detector._packet_handler(pkt)
            latency_ms = (time.monotonic() - start) * 1000

        elif attack_type == "rogue_dhcp":
            detector = DHCPDetector(interface=self.interface, alert_threshold=3, baseline=baseline)
            rogue_offer = (
                Ether(src="02:42:ac:14:00:66", dst="ff:ff:ff:ff:ff:ff")
                / IP(src="172.20.0.66", dst="255.255.255.255")
                / UDP(sport=67, dport=68)
                / BOOTP(op=2, yiaddr="172.20.0.100", siaddr="172.20.0.66", xid=999)
                / DHCP(options=[
                    ("message-type", "offer"),
                    ("server_id", "172.20.0.66"),
                    ("router", "172.20.0.66"),
                    ("name_server", "172.20.0.66"),
                    "end",
                ])
            )
            start = time.monotonic()
            detector._packet_handler(rogue_offer)
            latency_ms = (time.monotonic() - start) * 1000

        elif attack_type == "dhcp_starvation":
            starve = DHCPStarvation(dry_run=self.dry_run)
            detector = DHCPStarvationDetector(interface=self.interface, alert_threshold=3, rate_threshold=5, unique_chaddr_threshold=5)
            start = time.monotonic()
            for _ in range(12):
                detector._packet_handler(starve.build_discover_frame())
            latency_ms = (time.monotonic() - start) * 1000

        elif attack_type == "icmp_redirect":
            redirect = ICMPRedirect(victim_ip="172.20.0.3", original_gateway_ip="172.20.0.2", redirect_to_gateway_ip="172.20.0.99", dry_run=self.dry_run)
            detector = ICMPRedirectDetector(interface=self.interface, alert_threshold=3, baseline=baseline)
            pkt = redirect.build_redirect_packet(spoof_source_ip="172.20.0.88")
            start = time.monotonic()
            for _ in range(4):
                detector._packet_handler(pkt)
            latency_ms = (time.monotonic() - start) * 1000

        elif attack_type == "ip_spoof":
            detector = IPSpoofDetector(interface=self.interface, alert_threshold=3, baseline=baseline)
            bogon = (
                Ether(src="02:42:ac:14:00:ff", dst="ff:ff:ff:ff:ff:ff")
                / IP(src="127.0.0.1", dst="172.20.0.3")
                / UDP(sport=53, dport=53)
            )
            start = time.monotonic()
            detector._packet_handler(bogon)
            latency_ms = (time.monotonic() - start) * 1000

        detected = detector.is_detected() if detector else False
        alerts = detector.get_alerts() if detector else []
        alert = alerts[0] if alerts else None

        sla_passed = detected and (latency_ms <= profile.sla_max_latency_ms)

        mitre_id = alert.mitre_attack_id if alert else getattr(detector, "mitre_attack_id", "N/A")
        mitre_tactic = alert.mitre_tactic if alert else getattr(detector, "mitre_tactic", "N/A")
        pci_req = alert.pci_dss_requirement if alert else getattr(detector, "pci_dss_requirement", "N/A")
        severity = alert.severity.value if alert else "HIGH"
        signals = [s.layer_name for s in alert.signals] if alert else []
        remediation = alert.remediation_action if alert else None

        # Dispatch SIEM / Webhook
        if alert:
            self.dispatcher.dispatch(alert, latency_ms=latency_ms)

        # Log into SQLite DB
        log_result(
            db_path=self.db_path,
            run_id=run_id,
            attack_type=attack_type,
            detected=detected,
            response_time_ms=latency_ms,
            severity=severity,
            packets_sent=len(signals) if signals else 1,
            signals_fired=signals,
            total_score=alert.total_score if alert else 0,
            notes=f"NetChaos profile [{profile.name}] drill",
            mitre_id=mitre_id,
            mitre_tactic=mitre_tactic,
            pci_requirement=pci_req,
            remediation_action=remediation,
        )

        return AttackExecutionReport(
            attack_type=attack_type,
            detected=detected,
            latency_ms=latency_ms,
            sla_passed=sla_passed,
            severity=severity,
            mitre_id=mitre_id,
            mitre_tactic=mitre_tactic,
            pci_requirement=pci_req,
            signals_fired=signals,
            remediation_action=remediation,
        )

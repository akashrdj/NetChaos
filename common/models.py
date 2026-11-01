"""Data models for the L2 security validation pipeline and NetChaos engine."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set


class Severity(Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Signal:
    """A single detection signal from one heuristic layer.

    Attributes:
        layer_name: Identifier for the detection layer that fired.
        weight: Numeric weight contributing to the alert threshold score.
        details: Human-readable description of what triggered this signal.
        timestamp: When the signal was generated.
    """
    layer_name: str
    weight: int
    details: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Alert:
    """A confirmed detection alert, composed of multiple converging signals.

    An alert fires only when the cumulative weight of signals from a single
    source crosses the detector's alert_threshold. This multi-signal
    convergence prevents single-heuristic false positives.

    Attributes:
        attack_type: Category of attack detected (e.g., 'arp_spoof').
        source_key: Identifier for the attack source (e.g., claimed IP).
        signals: List of Signals that contributed to this alert.
        total_score: Sum of all signal weights at the time of alert.
        timestamp: When the alert was raised.
        severity: Computed severity based on total_score.
        mitre_attack_id: MITRE ATT&CK technique ID (e.g. T1557.002).
        mitre_tactic: MITRE ATT&CK tactical category.
        pci_dss_requirement: PCI-DSS 4.0 requirement mapping.
        remediation_action: Description of automated defense/healing applied.
    """
    attack_type: str
    source_key: str
    signals: List[Signal]
    total_score: int
    timestamp: datetime = field(default_factory=datetime.now)
    severity: Severity = Severity.HIGH
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    pci_dss_requirement: Optional[str] = None
    remediation_action: Optional[str] = None


@dataclass
class AttackResult:
    """Metadata returned after executing an attack simulation.

    Attributes:
        attack_type: Category of attack executed.
        packets_sent: Total number of packets transmitted.
        duration_s: Wall-clock duration of the attack in seconds.
        start_time: When the attack began.
        mitre_attack_id: Associated MITRE ATT&CK technique ID.
    """
    attack_type: str
    packets_sent: int
    duration_s: float
    start_time: datetime
    mitre_attack_id: Optional[str] = None


@dataclass
class DefenseResult:
    """Telemetry from active remediation and defensive healing actions.

    Attributes:
        action_type: Type of defense executed (e.g. 'gratuitous_arp_burst').
        target_ip: IP address inoculated or defended.
        restored_mac: Legitimate MAC address enforced.
        packets_transmitted: Number of healing frames injected.
        timestamp: When the defense was executed.
        success: Whether the remediation dispatched without errors.
    """
    action_type: str
    target_ip: str
    restored_mac: str
    packets_transmitted: int
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    details: str = ""


@dataclass
class NetworkBaseline:
    """Authoritative dynamic baseline learned from network profiling.

    Eliminates hardcoded IP/MAC bindings by discovering topology dynamically.
    """
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    trusted_dhcp_servers: Set[str] = field(default_factory=set)
    trusted_dns_servers: List[str] = field(default_factory=list)
    subnet_cidr: Optional[str] = None
    ip_mac_bindings: Dict[str, str] = field(default_factory=dict)
    trusted_ouis: Set[str] = field(default_factory=set)
    learned_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "trusted_dhcp_servers": list(self.trusted_dhcp_servers),
            "trusted_dns_servers": self.trusted_dns_servers,
            "subnet_cidr": self.subnet_cidr,
            "ip_mac_bindings": self.ip_mac_bindings,
            "trusted_ouis": list(self.trusted_ouis),
            "learned_at": self.learned_at.isoformat(),
        }

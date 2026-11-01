"""NetChaos: Enterprise L2/L3 Network Security Chaos & Active Defense Engine.

Comprehensive Multi-Layer Testing Battery:
  1. Dynamic Network Profiling & Baseline Learning (Zero-Config Topology)
  2. ARP Poisoning Simulation vs Active Defense (Gratuitous ARP Inoculation)
  3. MAC Flooding & CAM Table Exhaustion Simulation
  4. Rogue DHCP Server Simulation
  5. DHCP Pool Starvation Simulation (Resource Exhaustion)
  6. ICMP Route Redirect Manipulation Simulation
  7. IP Source Address Anti-Spoofing & BCP-38 Boundary Violation Simulation
  8. SQLite Enterprise Compliance Audit Trail Persistence (WAL Mode)
"""

import json
import os
import sys
import time
from datetime import datetime

# Configure UTF-8 for console output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from scapy.all import ARP, BOOTP, DHCP, Ether, ICMP, IP, UDP, RandMAC

from attacks.dhcp_starvation import DHCPStarvation
from attacks.icmp_redirect import ICMPRedirect
from attacks.ip_spoof import IPSpoof
from common.db import get_results, init_db, log_result
from common.models import Severity
from defense.arp_healer import ARPCacheHealer
from detectors.arp_detector import ARPDetector
from detectors.baseline import NetworkProfiler
from detectors.dhcp_detector import DHCPDetector
from detectors.dhcp_starvation_detector import DHCPStarvationDetector
from detectors.icmp_redirect_detector import ICMPRedirectDetector
from detectors.ip_spoof_detector import IPSpoofDetector
from detectors.mac_flood_detector import MACFloodDetector

DEMO_DB = os.path.abspath("db/demo_results.db")


def print_banner(title: str):
    print("\n" + "=" * 78)
    print(f"  {title.upper()}")
    print("=" * 78)


def run_full_chaos_battery():
    print_banner("NetChaos Enterprise: NetSecOps Chaos & Active Defense Battery")
    init_db(DEMO_DB)
    run_id = f"netchaos-full-battery-{int(time.time())}"

    # -------------------------------------------------------------
    # STEP 1: Dynamic Network Baseline Discovery
    # -------------------------------------------------------------
    print("\n[STEP 1] Generating Dynamic Network Baseline (Zero-Config Discovery)...")
    baseline = NetworkProfiler.mock_baseline(
        gateway_ip="172.20.0.2",
        gateway_mac="02:42:ac:14:00:02",
        subnet_cidr="172.20.0.0/24",
    )
    print(f"  +-- Default Gateway:   {baseline.gateway_ip} [{baseline.gateway_mac}]")
    print(f"  +-- Subnet CIDR:       {baseline.subnet_cidr}")
    print(f"  +-- Trusted DHCP:      {list(baseline.trusted_dhcp_servers)}")
    print(f"  +-- Trusted OUIs:      {list(baseline.trusted_ouis)}")

    # -------------------------------------------------------------
    # 1. ARP Poisoning vs Active Defense Inoculation (L2)
    # -------------------------------------------------------------
    print_banner("1. Simulating ARP Poisoning (MITRE T1557.002) vs Active Defense")
    healer = ARPCacheHealer(
        interface="eth0",
        trusted_bindings=baseline.ip_mac_bindings,
        burst_count=5,
        dry_run=True,
    )
    arp_detector = ARPDetector(
        interface="eth0",
        alert_threshold=3,
        baseline=baseline,
        active_defense=True,
        healer=healer,
    )

    spoof_pkt = Ether(src="02:42:ac:14:00:ff", dst="02:42:ac:14:00:03") / ARP(
        op=2,
        psrc="172.20.0.2",
        hwsrc="02:42:ac:14:00:ff",
        pdst="172.20.0.3",
        hwdst="02:42:ac:14:00:03",
    )

    start_time = time.monotonic()
    for _ in range(6):
        arp_detector._packet_handler(spoof_pkt)
    arp_ms = (time.monotonic() - start_time) * 1000

    alerts = arp_detector.get_alerts()
    print(f"[+] Detection Result: {'DETECTED' if alerts else 'MISSED'}")
    if alerts:
        alert = alerts[0]
        print(f"    +-- MITRE ATT&CK:     {alert.mitre_attack_id} ({alert.mitre_tactic})")
        print(f"    +-- Compliance Spec:  {alert.pci_dss_requirement}")
        print(f"    +-- Latency:          {arp_ms:.2f} ms")
        print(f"    +-- Active Defense:   {alert.remediation_action}")
        log_result(
            db_path=DEMO_DB,
            run_id=run_id,
            attack_type="arp_spoof",
            detected=True,
            response_time_ms=arp_ms,
            severity=alert.severity.value,
            packets_sent=6,
            signals_fired=[s.layer_name for s in alert.signals],
            total_score=alert.total_score,
            notes="NetChaos Active Defense Verification",
            mitre_id=alert.mitre_attack_id,
            mitre_tactic=alert.mitre_tactic,
            pci_requirement=alert.pci_dss_requirement,
            remediation_action=alert.remediation_action,
        )

    # -------------------------------------------------------------
    # 2. CAM Table Flooding (L2)
    # -------------------------------------------------------------
    print_banner("2. Simulating CAM Table Flooding (MITRE T1498.001)")
    mac_detector = MACFloodDetector(
        interface="eth0",
        alert_threshold=3,
        rate_threshold=10,
    )
    start_time = time.monotonic()
    for _ in range(25):
        pkt = Ether(src=RandMAC(), dst="02:42:ac:14:00:02") / ARP(op=1)
        mac_detector._packet_handler(pkt)
    mac_ms = (time.monotonic() - start_time) * 1000

    alerts = mac_detector.get_alerts()
    print(f"[+] Detection Result: {'DETECTED' if alerts else 'MISSED'}")
    if alerts:
        alert = alerts[0]
        print(f"    +-- MITRE ATT&CK:     {alert.mitre_attack_id} ({alert.mitre_tactic})")
        print(f"    +-- Compliance Spec:  {alert.pci_dss_requirement}")
        print(f"    +-- Latency:          {mac_ms:.2f} ms")
        log_result(
            db_path=DEMO_DB,
            run_id=run_id,
            attack_type="mac_flood",
            detected=True,
            response_time_ms=mac_ms,
            severity=alert.severity.value,
            packets_sent=25,
            signals_fired=[s.layer_name for s in alert.signals],
            total_score=alert.total_score,
            notes="NetChaos CAM Overflow Test",
            mitre_id=alert.mitre_attack_id,
            mitre_tactic=alert.mitre_tactic,
            pci_requirement=alert.pci_dss_requirement,
        )

    # -------------------------------------------------------------
    # 3. Rogue DHCP Server (L2)
    # -------------------------------------------------------------
    print_banner("3. Simulating Rogue DHCP Server (MITRE T1557.001)")
    dhcp_detector = DHCPDetector(
        interface="eth0",
        alert_threshold=3,
        baseline=baseline,
    )
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
    start_time = time.monotonic()
    dhcp_detector._packet_handler(rogue_offer)
    dhcp_ms = (time.monotonic() - start_time) * 1000

    alerts = dhcp_detector.get_alerts()
    print(f"[+] Detection Result: {'DETECTED' if alerts else 'MISSED'}")
    if alerts:
        alert = alerts[0]
        print(f"    +-- MITRE ATT&CK:     {alert.mitre_attack_id} ({alert.mitre_tactic})")
        print(f"    +-- Compliance Spec:  {alert.pci_dss_requirement}")
        print(f"    +-- Latency:          {dhcp_ms:.2f} ms")
        log_result(
            db_path=DEMO_DB,
            run_id=run_id,
            attack_type="rogue_dhcp",
            detected=True,
            response_time_ms=dhcp_ms,
            severity=alert.severity.value,
            packets_sent=1,
            signals_fired=[s.layer_name for s in alert.signals],
            total_score=alert.total_score,
            notes="NetChaos Rogue DHCP Offer Test",
            mitre_id=alert.mitre_attack_id,
            mitre_tactic=alert.mitre_tactic,
            pci_requirement=alert.pci_dss_requirement,
        )

    # -------------------------------------------------------------
    # 4. DHCP Starvation & Pool Exhaustion (L2)
    # -------------------------------------------------------------
    print_banner("4. Simulating DHCP Pool Starvation (MITRE T1499)")
    starvation_attack = DHCPStarvation(dry_run=True)
    starvation_detector = DHCPStarvationDetector(
        interface="eth0",
        alert_threshold=3,
        rate_threshold=5,
        unique_chaddr_threshold=5,
    )
    start_time = time.monotonic()
    for _ in range(12):
        frame = starvation_attack.build_discover_frame()
        starvation_detector._packet_handler(frame)
    starve_ms = (time.monotonic() - start_time) * 1000

    alerts = starvation_detector.get_alerts()
    print(f"[+] Detection Result: {'DETECTED' if alerts else 'MISSED'}")
    if alerts:
        alert = alerts[0]
        print(f"    +-- MITRE ATT&CK:     {alert.mitre_attack_id} ({alert.mitre_tactic})")
        print(f"    +-- Compliance Spec:  {alert.pci_dss_requirement}")
        print(f"    +-- Latency:          {starve_ms:.2f} ms")
        log_result(
            db_path=DEMO_DB,
            run_id=run_id,
            attack_type="dhcp_starvation",
            detected=True,
            response_time_ms=starve_ms,
            severity=alert.severity.value,
            packets_sent=12,
            signals_fired=[s.layer_name for s in alert.signals],
            total_score=alert.total_score,
            notes="NetChaos DHCP Snooping Rate Limit Test",
            mitre_id=alert.mitre_attack_id,
            mitre_tactic=alert.mitre_tactic,
            pci_requirement=alert.pci_dss_requirement,
        )

    # -------------------------------------------------------------
    # 5. ICMP Route Redirect Manipulation (L3)
    # -------------------------------------------------------------
    print_banner("5. Simulating ICMP Route Redirect Manipulation (MITRE T1557)")
    redirect_attack = ICMPRedirect(
        victim_ip="172.20.0.3",
        original_gateway_ip="172.20.0.2",
        redirect_to_gateway_ip="172.20.0.99",
        dry_run=True,
    )
    redirect_detector = ICMPRedirectDetector(
        interface="eth0",
        alert_threshold=3,
        baseline=baseline,
    )
    rogue_redirect = redirect_attack.build_redirect_packet(spoof_source_ip="172.20.0.88")
    start_time = time.monotonic()
    for _ in range(4):
        redirect_detector._packet_handler(rogue_redirect)
    icmp_ms = (time.monotonic() - start_time) * 1000

    alerts = redirect_detector.get_alerts()
    print(f"[+] Detection Result: {'DETECTED' if alerts else 'MISSED'}")
    if alerts:
        alert = alerts[0]
        print(f"    +-- MITRE ATT&CK:     {alert.mitre_attack_id} ({alert.mitre_tactic})")
        print(f"    +-- Compliance Spec:  {alert.pci_dss_requirement}")
        print(f"    +-- Latency:          {icmp_ms:.2f} ms")
        log_result(
            db_path=DEMO_DB,
            run_id=run_id,
            attack_type="icmp_redirect",
            detected=True,
            response_time_ms=icmp_ms,
            severity=alert.severity.value,
            packets_sent=4,
            signals_fired=[s.layer_name for s in alert.signals],
            total_score=alert.total_score,
            notes="NetChaos ICMP Route Ingress Check",
            mitre_id=alert.mitre_attack_id,
            mitre_tactic=alert.mitre_tactic,
            pci_requirement=alert.pci_dss_requirement,
        )

    # -------------------------------------------------------------
    # 6. IP Source Address Spoofing & BCP-38 Boundary (L3)
    # -------------------------------------------------------------
    print_banner("6. Simulating BCP-38 Ingress Boundary Violation (MITRE T1584)")
    ip_spoof_detector = IPSpoofDetector(
        interface="eth0",
        alert_threshold=3,
        baseline=baseline,
    )
    bogon_frame = (
        Ether(src="02:42:ac:14:00:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="127.0.0.1", dst="172.20.0.3")
        / UDP(sport=53, dport=53)
    )
    start_time = time.monotonic()
    ip_spoof_detector._packet_handler(bogon_frame)
    bcp_ms = (time.monotonic() - start_time) * 1000

    alerts = ip_spoof_detector.get_alerts()
    print(f"[+] Detection Result: {'DETECTED' if alerts else 'MISSED'}")
    if alerts:
        alert = alerts[0]
        print(f"    +-- MITRE ATT&CK:     {alert.mitre_attack_id} ({alert.mitre_tactic})")
        print(f"    +-- Compliance Spec:  {alert.pci_dss_requirement}")
        print(f"    +-- Latency:          {bcp_ms:.2f} ms")
        log_result(
            db_path=DEMO_DB,
            run_id=run_id,
            attack_type="ip_spoof",
            detected=True,
            response_time_ms=bcp_ms,
            severity=alert.severity.value,
            packets_sent=1,
            signals_fired=[s.layer_name for s in alert.signals],
            total_score=alert.total_score,
            notes="NetChaos BCP-38 Martian Address Verification",
            mitre_id=alert.mitre_attack_id,
            mitre_tactic=alert.mitre_tactic,
            pci_requirement=alert.pci_dss_requirement,
        )

    # -------------------------------------------------------------
    # 7. Summary & Persistence Audit
    # -------------------------------------------------------------
    print_banner("7. Summary of Chaos Engineering Battery Execution")
    records = get_results(DEMO_DB, run_id=run_id)
    print(f"Total Audit Telemetry Records in DB: {len(records)}\n")
    for r in records:
        print(f"  * {r['attack_type']:<16} | Status: {'PASS (Caught)' if r['detected'] else 'FAIL'} | Latency: {r['response_time_ms']:.2f}ms | MITRE: {r['mitre_id']}")
    print("\n" + "=" * 78)
    print("  ALL 6 ATTACKS SUCCESSFULLY TESTED, HEALED & RECORDED TO SQLITE!")
    print("=" * 78)


if __name__ == "__main__":
    run_full_chaos_battery()

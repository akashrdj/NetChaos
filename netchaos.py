#!/usr/bin/env python3
"""NetChaos: Unified Network Security Chaos Engineering & CI/CD Gating CLI.

Usage:
    python netchaos.py run [--profile smoke|insider-threat|dos-stress|compliance-audit]
    python netchaos.py gate [--profile smoke|compliance-audit]
    python netchaos.py list-profiles
    python netchaos.py profile [--export baseline.json]
    python netchaos.py report [--limit 10]
"""

import argparse
import json
import os
import sys
import time

# Reconfigure stdout for UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from chaos.engine import ChaosEngine
from chaos.profiles import PROFILES
from common.db import get_results
from detectors.baseline import NetworkProfiler
from telemetry.dispatcher import WebhookDispatcher


def cmd_list_profiles(args):
    """List all available chaos test profiles."""
    print("\n" + "=" * 78)
    print("  NETCHAOS CURATED SECURITY TESTING PROFILES")
    print("=" * 78)
    for name, p in PROFILES.items():
        print(f"\n* Profile: [{name.upper()}]")
        print(f"  Description:    {p.description}")
        print(f"  Attack Vectors: {', '.join(p.attack_types)}")
        print(f"  Latency SLA:    < {p.sla_max_latency_ms} ms")
        print(f"  Active Defense: {'Required' if p.require_active_defense else 'Optional'}")
    print("\n" + "=" * 78)


def cmd_profile(args):
    """Run dynamic baseline discovery and print or export it."""
    print("\n[NetChaos] Profiling local network topology...")
    profiler = NetworkProfiler(interface=args.interface)
    baseline = profiler.mock_baseline()

    print("\n" + "=" * 60)
    print("  DYNAMIC NETWORK BASELINE PROFILE")
    print("=" * 60)
    print(f"  Gateway IP:        {baseline.gateway_ip}")
    print(f"  Gateway MAC:       {baseline.gateway_mac}")
    print(f"  Subnet CIDR:       {baseline.subnet_cidr}")
    print(f"  Authoritative DHCP:{list(baseline.trusted_dhcp_servers)}")
    print(f"  Trusted OUIs:      {list(baseline.trusted_ouis)}")
    print("=" * 60)

    if args.export:
        profiler._baseline = baseline
        profiler.export_baseline(args.export)
        print(f"[+] Baseline successfully exported to: {args.export}")


def cmd_run(args):
    """Run chaos battery for a profile and output telemetry."""
    print("\n" + "=" * 78)
    print(f"  NETCHAOS ENGINE: RUNNING PROFILE [{args.profile.upper()}]")
    print("=" * 78)

    dispatcher = WebhookDispatcher(webhook_url=args.webhook, dry_run=(not bool(args.webhook)))
    engine = ChaosEngine(
        interface=args.interface,
        db_path=args.db,
        webhook_dispatcher=dispatcher,
        dry_run=args.dry_run,
        active_defense=args.active_defense,
    )

    summary = engine.execute_profile(profile_name=args.profile)

    print(f"\nRun ID: {summary.run_id}")
    print(f"Executed at: {summary.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")

    print(f"{'ATTACK':<18} | {'STATUS':<6} | {'LATENCY':<10} | {'SLA':<6} | {'MITRE ID':<10} | {'COMPLIANCE'}")
    print("-" * 78)
    for r in summary.reports:
        status = "DETECT" if r.detected else "MISS"
        sla = "PASS" if r.sla_passed else "FAIL"
        print(f"{r.attack_type:<18} | {status:<6} | {r.latency_ms:>7.2f} ms | {sla:<6} | {r.mitre_id:<10} | {r.pci_requirement}")
        if r.remediation_action:
            print(f"  └── 🛡️  Active Defense: {r.remediation_action}")

    print("-" * 78)
    print(f"Total: {summary.total_attacks} | Passed: {summary.passed_attacks} | Failed: {summary.failed_attacks}")

    if summary.all_passed:
        print("\n✅ [NETCHAOS SUCCESS] All attacks detected within latency and SLA thresholds.")
        return 0
    else:
        print("\n❌ [NETCHAOS REGRESSION] Some attacks were missed or breached the SLA!")
        return 1


def cmd_gate(args):
    """CI/CD Quality Gate mode: Runs profile and exits with non-zero on failure."""
    print(f"[NetChaos CI/CD Gate] Evaluating network resilience for profile: {args.profile}...")
    engine = ChaosEngine(
        interface=args.interface,
        db_path=args.db,
        dry_run=True,
        active_defense=True,
    )
    summary = engine.execute_profile(profile_name=args.profile)

    if summary.all_passed:
        print(f"✅ [GATE PASSED] All {summary.total_attacks} attacks detected within SLA. Safe to deploy.")
        sys.exit(0)
    else:
        print(f"❌ [GATE FAILED] {summary.failed_attacks}/{summary.total_attacks} attack checks failed! Blocking PR/Build.")
        sys.exit(1)


def cmd_report(args):
    """Display historical audit records from the SQLite database."""
    records = get_results(args.db)
    if not records:
        print(f"[!] No records found in database {args.db}")
        return

    recent = records[-args.limit:]
    print("\n" + "=" * 80)
    print(f"  NETCHAOS AUDIT & COMPLIANCE HISTORY (Last {len(recent)} Runs)")
    print("=" * 80)
    for r in recent:
        status = "PASSED" if r["detected"] else "FAILED"
        print(f"[{r['timestamp']}] ID {r['id']:<3} | {r['attack_type']:<16} | Status: {status:<6} | Latency: {r['response_time_ms']:.2f}ms")
        print(f"   MITRE: {r['mitre_id']} | Compliance: {r['pci_requirement']}")
        if r.get("remediation_action"):
            print(f"   Defense: {r['remediation_action']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="netchaos",
        description="NetChaos: Enterprise Layer 2 & 3 Network Security Chaos Engineering CLI",
    )
    parser.add_argument("--db", default="db/results.db", help="Path to SQLite results database")
    parser.add_argument("--interface", default="eth0", help="Network interface to monitor")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # run
    p_run = subparsers.add_parser("run", help="Execute a curated chaos testing profile")
    p_run.add_argument("--profile", default="compliance-audit", choices=list(PROFILES.keys()), help="Profile to execute")
    p_run.add_argument("--webhook", default=None, help="Webhook URL for SIEM/Slack alerts")
    p_run.add_argument("--dry-run", action="store_true", default=True, help="Simulate packet transmission")
    p_run.add_argument("--active-defense", action="store_true", default=True, help="Enable automated active remediation")

    # gate (CI/CD)
    p_gate = subparsers.add_parser("gate", help="Evaluate CI/CD deployment security gate (exit 0 on pass, 1 on fail)")
    p_gate.add_argument("--profile", default="smoke", choices=list(PROFILES.keys()), help="Profile to evaluate")

    # list-profiles
    subparsers.add_parser("list-profiles", help="List available chaos scenarios")

    # profile
    p_prof = subparsers.add_parser("profile", help="Run dynamic discovery and establish network baseline")
    p_prof.add_argument("--export", default=None, help="Export baseline JSON to file")

    # report
    p_rep = subparsers.add_parser("report", help="Query audit records from results database")
    p_rep.add_argument("--limit", type=int, default=10, help="Number of records to show")

    args = parser.parse_args()

    if args.subcommand == "run":
        sys.exit(cmd_run(args))
    elif args.subcommand == "gate":
        cmd_gate(args)
    elif args.subcommand == "list-profiles":
        cmd_list_profiles(args)
    elif args.subcommand == "profile":
        cmd_profile(args)
    elif args.subcommand == "report":
        cmd_report(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

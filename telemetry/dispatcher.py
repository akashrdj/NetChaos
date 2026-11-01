"""SIEM & Webhook Alert Dispatcher for NetChaos.

Formats and transmits real-time detection telemetry, MITRE ATT&CK mappings,
and active defense actions to SIEMs (Splunk, Elastic, Datadog) or ChatOps
webhooks (Slack, Discord, Microsoft Teams).
"""

import json
import logging
import os
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional

from common.models import Alert

logger = logging.getLogger(__name__)


class WebhookDispatcher:
    """Dispatches structured security alert notifications to webhooks and SIEMs."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        dry_run: bool = False,
    ):
        """Initialize the dispatcher.

        Args:
            webhook_url: Target HTTP/HTTPS endpoint for webhook notifications.
                Defaults to NETCHAOS_WEBHOOK_URL environment variable if set.
            dry_run: If True, formats payloads and logs them without sending HTTP requests.
        """
        self.webhook_url = webhook_url or os.getenv("NETCHAOS_WEBHOOK_URL")
        self.dry_run = dry_run
        self.dispatched_payloads: List[Dict[str, Any]] = []

    def format_siem_event(self, alert: Alert, latency_ms: float = 0.0) -> Dict[str, Any]:
        """Format an alert as a standardized Common Event Format / JSON payload for SIEM ingestion."""
        return {
            "@timestamp": alert.timestamp.isoformat(),
            "event": {
                "kind": "alert",
                "category": ["network", "intrusion_detection"],
                "type": ["indicator", "anomaly"],
                "outcome": "detected",
                "duration_ms": round(latency_ms, 2),
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": alert.mitre_attack_id or "UNKNOWN",
                    "name": alert.mitre_tactic or "Network Attack",
                },
            },
            "compliance": {
                "standard": "PCI-DSS 4.0",
                "requirement": alert.pci_dss_requirement or "Unmapped",
            },
            "alert": {
                "attack_type": alert.attack_type,
                "severity": alert.severity.value,
                "score": alert.total_score,
                "source_key": alert.source_key,
                "signals": [
                    {
                        "layer": s.layer_name,
                        "weight": s.weight,
                        "details": s.details,
                    }
                    for s in alert.signals
                ],
                "remediation": alert.remediation_action or "None (Detection Only)",
            },
        }

    def format_slack_payload(self, alert: Alert, latency_ms: float = 0.0) -> Dict[str, Any]:
        """Format an alert into a rich Slack/Discord Block Kit notification."""
        color = "#e01e5a" if alert.severity.value == "CRITICAL" else "#ecb22e"

        fields = [
            {"title": "Attack Type", "value": f"`{alert.attack_type}`", "short": True},
            {"title": "Severity", "value": f"*{alert.severity.value}* (Score: {alert.total_score})", "short": True},
            {"title": "MITRE ATT&CK", "value": f"{alert.mitre_attack_id or 'N/A'}", "short": True},
            {"title": "Detection Latency", "value": f"{latency_ms:.2f} ms", "short": True},
            {"title": "Compliance", "value": f"{alert.pci_dss_requirement or 'N/A'}", "short": False},
        ]

        if alert.remediation_action:
            fields.append({
                "title": "Active Defense Inoculation",
                "value": f"✅ {alert.remediation_action}",
                "short": False,
            })

        signals_text = "\n".join(f"• *[{s.layer_name}]* (+{s.weight}): {s.details}" for s in alert.signals[:4])

        return {
            "attachments": [
                {
                    "color": color,
                    "title": f"🚨 [NetChaos Alert] {alert.attack_type.upper()} Detected",
                    "fields": fields,
                    "text": f"*Triggered Heuristics:*\n{signals_text}",
                    "footer": "NetChaos Autonomous Network Defense Engine",
                    "ts": int(alert.timestamp.timestamp()),
                }
            ]
        }

    def dispatch(self, alert: Alert, latency_ms: float = 0.0) -> bool:
        """Transmit alert payload to configured webhook endpoint or record locally."""
        payload = self.format_siem_event(alert, latency_ms)
        self.dispatched_payloads.append(payload)

        if self.dry_run or not self.webhook_url:
            logger.info("[NetChaos Telemetry Dry-Run] Alert payload generated for %s", alert.attack_type)
            return True

        try:
            slack_payload = self.format_slack_payload(alert, latency_ms)
            data = json.dumps(slack_payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 204)
        except Exception as e:
            logger.error("Failed to dispatch alert to webhook %s: %s", self.webhook_url, e)
            return False

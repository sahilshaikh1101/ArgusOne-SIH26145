"""
ArgusOne — Correlation Engine (Kill-Chain Fusion Layer)

Groups alerts by source IP and maps them to MITRE ATT&CK kill-chain stages.
When multiple stages are observed for the same actor, severity is escalated.
"""

import uuid
import logging
from collections import defaultdict
from argusone.config import CORRELATION_WINDOW, KILL_CHAIN_STAGES, CORRELATION_ESCALATION_THRESHOLD

logger = logging.getLogger("argusone.detectors")


# Map threat classes to kill-chain stages
THREAT_TO_STAGE = {}
for stage, threats in KILL_CHAIN_STAGES.items():
    for threat in threats:
        THREAT_TO_STAGE[threat] = stage


class CorrelationEngine:
    """
    Groups related alerts and maps them onto a kill-chain.
    Escalates severity when multi-stage attacks are detected.
    """

    def __init__(self, window=CORRELATION_WINDOW):
        self.window = window
        # src_ip → list of (timestamp, alert) 
        self.alert_buffer = defaultdict(list)
        # Active correlations
        self.correlations = {}
        self.correlation_count = 0

    def add_alert(self, alert):
        """
        Add an alert to the correlation engine.
        
        Returns the alert (potentially with updated severity and correlation_id).
        """
        src_ip = alert.get('src_ip', '')
        timestamp = alert.get('timestamp', 0)
        threat_class = alert.get('threat_class', '')

        # Add to buffer
        self.alert_buffer[src_ip].append({
            'timestamp': timestamp,
            'threat_class': threat_class,
            'alert': alert,
        })

        # Clean old entries
        self._clean_buffer(src_ip, timestamp)

        # Check for kill-chain correlation
        correlated = self._check_correlation(src_ip, timestamp)

        if correlated:
            alert['correlation_id'] = correlated['correlation_id']
            alert['kill_chain_stages'] = correlated['stages']
            
            # Escalate severity
            if len(correlated['stages']) >= CORRELATION_ESCALATION_THRESHOLD:
                alert['severity'] = 'critical'
                alert['confidence'] = min(alert.get('confidence', 0.5) + 0.15, 0.99)
                alert['correlation_note'] = (
                    f"Multi-stage attack detected: {' → '.join(correlated['stages'])} "
                    f"({len(correlated['related_alerts'])} related alerts)"
                )
                logger.warning(
                    f"KILL-CHAIN ESCALATION: {src_ip} — "
                    f"stages: {correlated['stages']}"
                )

        return alert

    def _clean_buffer(self, src_ip, current_time):
        """Remove alerts outside the correlation window."""
        self.alert_buffer[src_ip] = [
            entry for entry in self.alert_buffer[src_ip]
            if current_time - entry['timestamp'] <= self.window
        ]

    def _check_correlation(self, src_ip, current_time):
        """Check if alerts from this source form a kill-chain pattern."""
        entries = self.alert_buffer[src_ip]

        if len(entries) < 2:
            return None

        # Map alerts to kill-chain stages
        observed_stages = set()
        related_alerts = []

        for entry in entries:
            threat = entry['threat_class']
            stage = THREAT_TO_STAGE.get(threat)
            if stage:
                observed_stages.add(stage)
                related_alerts.append(entry['alert'])

        # Check if multiple stages observed
        if len(observed_stages) >= CORRELATION_ESCALATION_THRESHOLD:
            # Order stages by kill-chain progression
            stage_order = ['recon', 'initial_access', 'c2', 'exfiltration']
            ordered_stages = [s for s in stage_order if s in observed_stages]

            correlation_id = self._get_or_create_correlation(src_ip)

            return {
                'correlation_id': correlation_id,
                'stages': ordered_stages,
                'related_alerts': related_alerts,
                'src_ip': src_ip,
            }

        return None

    def _get_or_create_correlation(self, src_ip):
        """Get existing correlation ID or create a new one."""
        if src_ip in self.correlations:
            return self.correlations[src_ip]

        self.correlation_count += 1
        corr_id = f"kc-{self.correlation_count:04d}"
        self.correlations[src_ip] = corr_id
        return corr_id

    def get_active_correlations(self):
        """Get all active kill-chain correlations with details."""
        result = []
        for src_ip, entries in self.alert_buffer.items():
            if len(entries) < 2:
                continue

            stages = set()
            for entry in entries:
                stage = THREAT_TO_STAGE.get(entry['threat_class'])
                if stage:
                    stages.add(stage)

            if len(stages) >= 2:
                result.append({
                    'src_ip': src_ip,
                    'stages': list(stages),
                    'alert_count': len(entries),
                    'correlation_id': self.correlations.get(src_ip, 'pending'),
                })

        return result

    def get_stats(self):
        return {
            'total_correlations': self.correlation_count,
            'active_sources': len(self.alert_buffer),
            'active_kill_chains': len([
                src for src, entries in self.alert_buffer.items()
                if len(entries) >= 2
            ]),
        }

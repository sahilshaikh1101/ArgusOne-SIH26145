"""
ArgusOne — Detector (f): Data Exfiltration Detection

Detects data exfiltration via outbound:inbound byte ratio anomalies,
destination rarity, and protocol-misuse volume (DNS/ICMP tunnelling).
"""

import numpy as np
import logging
from collections import defaultdict
from argusone.config import (
    EXFIL_OUT_IN_RATIO_THRESHOLD, EXFIL_RARE_DEST_THRESHOLD,
    EXFIL_DNS_BYTES_THRESHOLD, EXFIL_SIGMA_THRESHOLD
)

logger = logging.getLogger("argusone.detectors")


class ExfilDetector:
    """
    Detects data exfiltration patterns:
    1. Outbound:inbound byte ratio anomaly (EWMA baseline)
    2. Destination rarity scoring (new/rare external destinations)
    3. Protocol misuse detection (DNS/ICMP carrying unusual data volumes)
    """

    def __init__(self):
        # Per-host behavioural baselines (EWMA)
        self.host_out_in_ratio = defaultdict(lambda: {'ewma': 1.0, 'var': 1.0, 'count': 0})
        self.host_byte_rate = defaultdict(lambda: {'ewma': 0.0, 'var': 0.0, 'count': 0})

        # Destination popularity (how many internal hosts talk to each external dest)
        self.dest_popularity = defaultdict(set)  # dst_ip → set of src_ips
        self.total_internal_hosts = set()

        # DNS byte tracking per source
        self.src_dns_bytes = defaultdict(int)

        # EWMA parameters
        self.alpha = 0.2

        self.alerts_generated = set()

    def analyze_flow(self, flow_record):
        """
        Analyze a completed flow for exfiltration indicators.
        
        Returns alert dict or None.
        """
        src = flow_record.src_ip
        dst = flow_record.dst_ip

        # Track destination popularity
        self.total_internal_hosts.add(src)
        self.dest_popularity[dst].add(src)

        # Track DNS bytes
        if flow_record.dns_queries:
            self.src_dns_bytes[src] += flow_record.fwd_bytes

        # Update host baseline
        out_in = flow_record.out_in_ratio
        baseline = self.host_out_in_ratio[src]
        baseline['count'] += 1

        if baseline['count'] < 5:
            # Learning phase
            baseline['ewma'] = self.alpha * out_in + (1 - self.alpha) * baseline['ewma']
            baseline['var'] = self.alpha * abs(out_in - baseline['ewma']) + (1 - self.alpha) * baseline['var']
            return None

        # Update EWMA
        old_ewma = baseline['ewma']
        baseline['ewma'] = self.alpha * out_in + (1 - self.alpha) * old_ewma
        deviation = abs(out_in - old_ewma)
        baseline['var'] = self.alpha * deviation + (1 - self.alpha) * baseline['var']

        confidence = 0.0
        evidence = {}
        alert_key = f"{src}->{dst}"

        if alert_key in self.alerts_generated:
            return None

        # ── 1. Outbound:Inbound Ratio Anomaly ──
        if baseline['var'] > 0:
            z_score = (out_in - old_ewma) / max(baseline['var'], 0.01)
            if z_score > EXFIL_SIGMA_THRESHOLD and out_in > EXFIL_OUT_IN_RATIO_THRESHOLD:
                ratio_conf = min(z_score / 10 + 0.3, 0.85)
                confidence = max(confidence, ratio_conf)
                evidence['out_in_ratio'] = round(out_in, 2)
                evidence['baseline_ratio'] = round(old_ewma, 2)
                evidence['z_score'] = round(z_score, 2)
                evidence['fwd_bytes'] = flow_record.fwd_bytes

        # ── 2. Destination Rarity ──
        total_hosts = max(len(self.total_internal_hosts), 1)
        dest_hosts = len(self.dest_popularity.get(dst, set()))
        dest_rarity = 1.0 - (dest_hosts / total_hosts)

        if dest_rarity > (1.0 - EXFIL_RARE_DEST_THRESHOLD):
            # This destination is rare — few internal hosts communicate with it
            rarity_conf = dest_rarity * 0.5
            confidence = max(confidence, rarity_conf)
            evidence['dest_rarity'] = round(dest_rarity, 3)
            evidence['dest_seen_by_hosts'] = dest_hosts

        # ── 3. Large Volume to Rare Destination ──
        if flow_record.fwd_bytes > 50000 and dest_rarity > 0.9:
            volume_conf = min(flow_record.fwd_bytes / 500000 + 0.4, 0.9)
            confidence = max(confidence, volume_conf)
            evidence['large_transfer_bytes'] = flow_record.fwd_bytes
            evidence['duration_sec'] = round(flow_record.duration, 2)

        # ── 4. DNS/Protocol Misuse ──
        if self.src_dns_bytes.get(src, 0) > EXFIL_DNS_BYTES_THRESHOLD:
            dns_conf = min(self.src_dns_bytes[src] / (EXFIL_DNS_BYTES_THRESHOLD * 5) + 0.3, 0.85)
            confidence = max(confidence, dns_conf)
            evidence['dns_bytes_total'] = self.src_dns_bytes[src]
            evidence['protocol_misuse'] = 'dns_exfil'

        if confidence > 0.4:
            self.alerts_generated.add(alert_key)
            severity = 'critical' if confidence > 0.8 else 'high' if confidence > 0.6 else 'medium'
            return {
                'threat_class': 'data_exfiltration',
                'src_ip': src,
                'dst_ip': dst,
                'confidence': round(confidence, 3),
                'severity': severity,
                'evidence': evidence,
            }

        return None

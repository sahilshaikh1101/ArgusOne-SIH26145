"""
ArgusOne — Detector (e): Reconnaissance / Port Scanning Detection

Detects vertical (single host, many ports) and horizontal (many hosts, few ports)
scanning using z-score thresholding and fan-out analysis.
"""

import numpy as np
import logging
from collections import defaultdict
from argusone.config import (
    SCAN_UNIQUE_PORTS_THRESHOLD, SCAN_UNIQUE_HOSTS_THRESHOLD,
    SCAN_SYN_NO_ACK_RATIO, SCAN_Z_SCORE_THRESHOLD
)

logger = logging.getLogger("argusone.detectors")


class ScanDetector:
    """
    Detects port scanning and network reconnaissance:
    1. Vertical scan: one source → many ports on one host
    2. Horizontal scan: one source → one port on many hosts  
    3. Mixed/distributed scans via fan-out graph analysis
    """

    def __init__(self):
        # Per-source tracking
        self.src_dst_ports = defaultdict(lambda: defaultdict(set))  # src → dst → {ports}
        self.src_dst_hosts = defaultdict(set)     # src → {dst hosts}
        self.src_syn_count = defaultdict(int)
        self.src_ack_count = defaultdict(int)
        self.src_total_count = defaultdict(int)
        self.src_packet_sizes = defaultdict(list)

        # Baseline statistics
        self.baseline_port_counts = []
        self.baseline_host_counts = []
        self.baseline_mean_ports = 0
        self.baseline_std_ports = 1
        self.baseline_mean_hosts = 0
        self.baseline_std_hosts = 1
        self.baseline_established = False
        self.baseline_threshold = 20

        self.alerts_generated = set()

    def add_packet(self, pkt_info):
        """Track packet for scan analysis."""
        src = pkt_info.src_ip
        dst = pkt_info.dst_ip

        self.src_dst_ports[src][dst].add(pkt_info.dst_port)
        self.src_dst_hosts[src].add(dst)
        self.src_total_count[src] += 1
        self.src_packet_sizes[src].append(pkt_info.size)

        if pkt_info.flags:
            flags = pkt_info.flags.upper()
            if 'S' in flags and 'A' not in flags:
                self.src_syn_count[src] += 1
            if 'A' in flags:
                self.src_ack_count[src] += 1

    def analyze_window(self, window_stats):
        """
        Analyze window for scanning patterns.
        
        Returns list of alert dicts.
        """
        alerts = []

        for src_ip in window_stats.src_packet_count:
            if src_ip in self.alerts_generated:
                continue

            # Unique destination ports from this source
            unique_ports = len(window_stats.src_dst_ports.get(src_ip, set()))
            unique_hosts = len(window_stats.src_dst_hosts.get(src_ip, set()))

            # Update baseline
            if not self.baseline_established:
                self.baseline_port_counts.append(unique_ports)
                self.baseline_host_counts.append(unique_hosts)
                if len(self.baseline_port_counts) >= self.baseline_threshold:
                    self._establish_baseline()
                continue

            # SYN-without-ACK ratio for this source
            syn_count = window_stats.src_syn_count.get(src_ip, 0)
            ack_count = window_stats.src_ack_count.get(src_ip, 0)
            total = window_stats.src_packet_count.get(src_ip, 1)
            syn_no_ack_ratio = syn_count / max(total, 1)

            # ── Vertical Scan: many ports on single/few hosts ──
            if unique_ports > SCAN_UNIQUE_PORTS_THRESHOLD:
                z_score_ports = (unique_ports - self.baseline_mean_ports) / max(self.baseline_std_ports, 1)

                if z_score_ports > SCAN_Z_SCORE_THRESHOLD:
                    confidence = min(0.5 + (z_score_ports - 3) * 0.1 + syn_no_ack_ratio * 0.3, 0.95)
                    alerts.append({
                        'threat_class': 'port_scan',
                        'threat_subtype': 'vertical_scan',
                        'src_ip': src_ip,
                        'confidence': round(confidence, 3),
                        'severity': 'high' if confidence > 0.7 else 'medium',
                        'evidence': {
                            'unique_dst_ports': unique_ports,
                            'z_score': round(z_score_ports, 2),
                            'syn_no_ack_ratio': round(syn_no_ack_ratio, 3),
                            'target_hosts': unique_hosts,
                        }
                    })
                    self.alerts_generated.add(src_ip)

            # ── Horizontal Scan: many hosts on single/few ports ──
            if unique_hosts > SCAN_UNIQUE_HOSTS_THRESHOLD:
                z_score_hosts = (unique_hosts - self.baseline_mean_hosts) / max(self.baseline_std_hosts, 1)

                if z_score_hosts > SCAN_Z_SCORE_THRESHOLD:
                    confidence = min(0.5 + (z_score_hosts - 3) * 0.1 + syn_no_ack_ratio * 0.3, 0.95)
                    alerts.append({
                        'threat_class': 'port_scan',
                        'threat_subtype': 'horizontal_scan',
                        'src_ip': src_ip,
                        'confidence': round(confidence, 3),
                        'severity': 'high' if confidence > 0.7 else 'medium',
                        'evidence': {
                            'unique_dst_hosts': unique_hosts,
                            'z_score': round(z_score_hosts, 2),
                            'syn_no_ack_ratio': round(syn_no_ack_ratio, 3),
                            'unique_ports': unique_ports,
                        }
                    })
                    self.alerts_generated.add(src_ip)

        return alerts

    def _establish_baseline(self):
        """Establish baseline statistics from initial traffic."""
        self.baseline_mean_ports = np.mean(self.baseline_port_counts)
        self.baseline_std_ports = max(np.std(self.baseline_port_counts), 1)
        self.baseline_mean_hosts = np.mean(self.baseline_host_counts)
        self.baseline_std_hosts = max(np.std(self.baseline_host_counts), 1)
        self.baseline_established = True
        logger.info(f"Scan baseline established: ports μ={self.baseline_mean_ports:.1f} σ={self.baseline_std_ports:.1f}")

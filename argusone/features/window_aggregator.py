"""
ArgusOne — Layer 2: Window Aggregator

Computes windowed statistics (1s/5s/30s/5min) over incoming traffic.
Provides per-source, per-destination, and global aggregate features
for all six detectors.
"""

import time
import math
import logging
from collections import defaultdict
from argusone.config import WINDOW_SIZES

logger = logging.getLogger("argusone.features")


class WindowStats:
    """Statistics for a single time window."""

    def __init__(self, window_size, start_time):
        self.window_size = window_size
        self.start_time = start_time
        self.end_time = start_time + window_size

        # Global counters
        self.packet_count = 0
        self.byte_count = 0
        self.syn_count = 0
        self.ack_count = 0

        # Per-source tracking
        self.src_ips = set()
        self.src_packet_count = defaultdict(int)
        self.src_byte_count = defaultdict(int)
        self.src_dst_ports = defaultdict(set)   # for scan detection
        self.src_dst_hosts = defaultdict(set)   # for scan detection
        self.src_syn_count = defaultdict(int)
        self.src_ack_count = defaultdict(int)

        # Per-destination tracking
        self.dst_ips = set()

        # DNS tracking
        self.dns_queries = []
        self.dns_query_count = 0
        self.dns_nxdomain_count = 0
        self.src_dns_count = defaultdict(int)

        # Protocol mix
        self.proto_counts = defaultdict(int)

        # TTL values (for spoofing detection)
        self.ttl_values = []

        # Per-pair tracking (src→dst) for beaconing
        self.pair_timestamps = defaultdict(list)

    def add_packet(self, pkt_info):
        """Add a packet to this window."""
        self.packet_count += 1
        self.byte_count += pkt_info.size
        self.src_ips.add(pkt_info.src_ip)
        self.dst_ips.add(pkt_info.dst_ip)
        self.proto_counts[pkt_info.proto] += 1
        self.ttl_values.append(pkt_info.ttl)

        # Per-source stats
        src = pkt_info.src_ip
        self.src_packet_count[src] += 1
        self.src_byte_count[src] += pkt_info.size
        self.src_dst_ports[src].add(pkt_info.dst_port)
        self.src_dst_hosts[src].add(pkt_info.dst_ip)

        # Flags
        if pkt_info.flags:
            flags = pkt_info.flags.upper()
            if 'S' in flags and 'A' not in flags:
                self.syn_count += 1
                self.src_syn_count[src] += 1
            if 'A' in flags:
                self.ack_count += 1
                self.src_ack_count[src] += 1

        # DNS
        if pkt_info.is_dns:
            self.dns_query_count += 1
            self.src_dns_count[src] += 1
            if pkt_info.dns_query:
                self.dns_queries.append(pkt_info.dns_query)
            if pkt_info.dns_rcode == 3:
                self.dns_nxdomain_count += 1

        # Pair tracking for beaconing
        pair_key = (pkt_info.src_ip, pkt_info.dst_ip)
        self.pair_timestamps[pair_key].append(pkt_info.timestamp)

    @property
    def packets_per_sec(self):
        return self.packet_count / max(self.window_size, 1)

    @property
    def bytes_per_sec(self):
        return self.byte_count / max(self.window_size, 1)

    @property
    def unique_src_count(self):
        return len(self.src_ips)

    @property
    def unique_dst_count(self):
        return len(self.dst_ips)

    @property
    def src_ip_entropy(self):
        """Shannon entropy of source IP distribution."""
        total = sum(self.src_packet_count.values())
        if total == 0:
            return 0
        entropy = 0
        for count in self.src_packet_count.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @property
    def syn_ratio(self):
        return self.syn_count / max(self.packet_count, 1)

    @property
    def ttl_variance(self):
        if len(self.ttl_values) < 2:
            return 0
        mean = sum(self.ttl_values) / len(self.ttl_values)
        return sum((t - mean) ** 2 for t in self.ttl_values) / len(self.ttl_values)

    def to_dict(self):
        return {
            'window_size': self.window_size,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'pps': self.packets_per_sec,
            'bps': self.bytes_per_sec,
            'unique_srcs': self.unique_src_count,
            'unique_dsts': self.unique_dst_count,
            'src_entropy': self.src_ip_entropy,
            'syn_ratio': self.syn_ratio,
            'syn_count': self.syn_count,
            'ttl_variance': self.ttl_variance,
            'dns_query_count': self.dns_query_count,
            'dns_nxdomain_count': self.dns_nxdomain_count,
        }


class WindowAggregator:
    """
    Manages multiple tumbling windows at different granularities.
    Emits completed window stats for detector consumption.
    """

    def __init__(self, window_sizes=None):
        self.window_sizes = window_sizes or WINDOW_SIZES
        self.current_windows = {}  # window_size -> WindowStats
        self.completed_windows = []
        self._initialized = False

    def add_packet(self, pkt_info):
        """Add packet to all active windows."""
        ts = pkt_info.timestamp

        if not self._initialized:
            # Initialize windows starting from first packet time
            for ws in self.window_sizes:
                window_start = int(ts / ws) * ws
                self.current_windows[ws] = WindowStats(ws, window_start)
            self._initialized = True

        # Check and rotate windows
        for ws in self.window_sizes:
            window = self.current_windows[ws]
            if ts >= window.end_time:
                # Emit completed window
                self.completed_windows.append(window)
                # Start new window
                window_start = int(ts / ws) * ws
                self.current_windows[ws] = WindowStats(ws, window_start)

            self.current_windows[ws].add_packet(pkt_info)

    def get_completed_windows(self, clear=True):
        """Get completed windows for processing."""
        windows = self.completed_windows.copy()
        if clear:
            self.completed_windows = []
        return windows

    def get_current_window(self, window_size):
        """Get the current (in-progress) window for a given size."""
        return self.current_windows.get(window_size)

    def get_all_current(self):
        """Get all current windows."""
        return dict(self.current_windows)

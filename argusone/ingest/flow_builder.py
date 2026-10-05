"""
ArgusOne — Layer 1: Flow Builder

Groups packets into bidirectional flows by 5-tuple.
Tracks per-flow statistics and exports completed/active flows.
"""

import time
import logging
from collections import defaultdict
from argusone.config import FLOW_TIMEOUT, FLOW_MAX_DURATION

logger = logging.getLogger("argusone.ingest")


class FlowRecord:
    """Represents a single network flow with statistics."""

    def __init__(self, flow_key, first_packet):
        self.flow_key = flow_key
        self.flow_id = f"{flow_key[0]}:{flow_key[2]}->{flow_key[1]}:{flow_key[3]}/{flow_key[4]}"
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto = flow_key
        self.start_time = first_packet.timestamp
        self.last_time = first_packet.timestamp

        # Packet counts
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.total_packets = 0

        # Byte counts
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.total_bytes = 0

        # Flag counts
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0

        # TTL tracking
        self.ttl_values = []

        # Packet sizes for shape analysis
        self.packet_sizes = []
        self.packet_timestamps = []

        # Inter-arrival times
        self.iats = []
        self._last_pkt_time = first_packet.timestamp

        # DNS tracking
        self.dns_queries = []
        self.dns_nxdomain_count = 0

        # TLS tracking
        self.tls_client_hellos = []
        self.has_tls = False

        # State
        self.is_active = True

        # Add first packet
        self._add_packet(first_packet)

    def _add_packet(self, pkt):
        """Add packet statistics to this flow."""
        self.last_time = pkt.timestamp
        self.total_packets += 1
        self.total_bytes += pkt.size
        self.packet_sizes.append(pkt.size)
        self.packet_timestamps.append(pkt.timestamp)

        # Direction
        if pkt.src_ip == self.src_ip:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.size
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.size

        # Flags
        if pkt.flags:
            flags = pkt.flags.upper()
            if 'S' in flags and 'A' not in flags:
                self.syn_count += 1
            if 'A' in flags:
                self.ack_count += 1
            if 'F' in flags:
                self.fin_count += 1
            if 'R' in flags:
                self.rst_count += 1
            if 'P' in flags:
                self.psh_count += 1

        # TTL
        self.ttl_values.append(pkt.ttl)

        # Inter-arrival time
        iat = pkt.timestamp - self._last_pkt_time
        if iat > 0:
            self.iats.append(iat)
        self._last_pkt_time = pkt.timestamp

        # DNS
        if pkt.is_dns and pkt.dns_query:
            self.dns_queries.append(pkt.dns_query)
            if pkt.dns_rcode == 3:  # NXDOMAIN
                self.dns_nxdomain_count += 1

        # TLS
        if pkt.is_tls:
            self.has_tls = True
            self.tls_client_hellos.append(pkt.tls_data)

    @property
    def duration(self):
        return max(self.last_time - self.start_time, 0.001)

    @property
    def packets_per_sec(self):
        return self.total_packets / self.duration

    @property
    def bytes_per_sec(self):
        return self.total_bytes / self.duration

    @property
    def avg_packet_size(self):
        return self.total_bytes / max(self.total_packets, 1)

    @property
    def syn_ratio(self):
        return self.syn_count / max(self.total_packets, 1)

    @property
    def out_in_ratio(self):
        return self.fwd_bytes / max(self.bwd_bytes, 1)

    def to_dict(self):
        import numpy as np
        ttl_arr = self.ttl_values if self.ttl_values else [0]
        iat_arr = self.iats if self.iats else [0]
        return {
            'flow_key': str(self.flow_key),
            'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
            'src_port': self.src_port, 'dst_port': self.dst_port,
            'proto': self.proto,
            'start_time': self.start_time, 'last_time': self.last_time,
            'duration': self.duration,
            'total_packets': self.total_packets,
            'fwd_packets': self.fwd_packets, 'bwd_packets': self.bwd_packets,
            'total_bytes': self.total_bytes,
            'fwd_bytes': self.fwd_bytes, 'bwd_bytes': self.bwd_bytes,
            'packets_per_sec': self.packets_per_sec,
            'bytes_per_sec': self.bytes_per_sec,
            'avg_packet_size': self.avg_packet_size,
            'syn_count': self.syn_count, 'ack_count': self.ack_count,
            'fin_count': self.fin_count, 'rst_count': self.rst_count,
            'syn_ratio': self.syn_ratio,
            'out_in_ratio': self.out_in_ratio,
            'ttl_mean': float(np.mean(ttl_arr)),
            'ttl_std': float(np.std(ttl_arr)),
            'iat_mean': float(np.mean(iat_arr)),
            'iat_std': float(np.std(iat_arr)),
            'iat_cv': float(np.std(iat_arr) / max(np.mean(iat_arr), 1e-9)),
            'dns_query_count': len(self.dns_queries),
            'dns_nxdomain_count': self.dns_nxdomain_count,
            'has_tls': self.has_tls,
            'packet_sizes': self.packet_sizes[:20],  # first 20 for shape
        }


class FlowBuilder:
    """
    Groups incoming packets into bidirectional flows.
    Exports flows when they timeout or reach max duration.
    """

    def __init__(self, flow_timeout=FLOW_TIMEOUT, max_duration=FLOW_MAX_DURATION):
        self.flows = {}            # flow_key -> FlowRecord
        self.completed_flows = []  # exported flows
        self.flow_timeout = flow_timeout
        self.max_duration = max_duration
        self.total_flows_created = 0
        self.total_flows_exported = 0

    def add_packet(self, pkt_info):
        """Add a packet to its flow (create if new)."""
        key = pkt_info.flow_key_bidir

        if key in self.flows:
            self.flows[key]._add_packet(pkt_info)
        else:
            self.flows[key] = FlowRecord(pkt_info.flow_key, pkt_info)
            self.total_flows_created += 1

        # Check for flow exports
        self._check_exports(pkt_info.timestamp)

        return self.flows[key]

    def _check_exports(self, current_time):
        """Export flows that have timed out or exceeded max duration."""
        expired_keys = []
        for key, flow in self.flows.items():
            if (current_time - flow.last_time > self.flow_timeout or
                    flow.duration > self.max_duration):
                flow.is_active = False
                self.completed_flows.append(flow)
                self.total_flows_exported += 1
                expired_keys.append(key)

        for key in expired_keys:
            del self.flows[key]

    def get_active_flows(self):
        """Get all currently active flows."""
        return list(self.flows.values())

    def get_completed_flows(self, clear=True):
        """Get and optionally clear completed flows."""
        flows = self.completed_flows.copy()
        if clear:
            self.completed_flows = []
        return flows

    def flush_all(self):
        """Export all remaining flows (at end of PCAP)."""
        for flow in self.flows.values():
            flow.is_active = False
            self.completed_flows.append(flow)
            self.total_flows_exported += 1
        self.flows.clear()
        return self.get_completed_flows()

    def get_stats(self):
        return {
            'active_flows': len(self.flows),
            'total_created': self.total_flows_created,
            'total_exported': self.total_flows_exported,
        }

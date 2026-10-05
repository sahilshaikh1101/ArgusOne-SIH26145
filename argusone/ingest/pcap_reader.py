"""
ArgusOne — Layer 0+1: PCAP Packet Reader (Read-Only Ingest)

Reads packets from PCAP files using Scapy in a strictly read-only manner.
Simulates the data-diode constraint: we only observe, never send.
Supports streaming (packet-by-packet) or batch modes.
"""

import time
import logging
from collections import defaultdict
from scapy.all import rdpcap, PcapReader as ScapyPcapReader, IP, TCP, UDP, DNS, Raw

logger = logging.getLogger("argusone.ingest")


class PacketInfo:
    """Normalized packet metadata extracted from raw packet."""
    __slots__ = [
        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'proto', 'size', 'ttl', 'flags', 'payload_size',
        'is_dns', 'dns_query', 'dns_response', 'dns_rcode',
        'is_tls', 'tls_data',
        'raw_packet'
    ]

    def __init__(self):
        self.timestamp = 0.0
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.proto = ""
        self.size = 0
        self.ttl = 0
        self.flags = ""
        self.payload_size = 0
        self.is_dns = False
        self.dns_query = ""
        self.dns_response = ""
        self.dns_rcode = 0
        self.is_tls = False
        self.tls_data = None
        self.raw_packet = None

    @property
    def flow_key(self):
        """5-tuple flow identifier."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)

    @property
    def flow_key_bidir(self):
        """Bidirectional flow key (sorted so both directions match)."""
        forward = (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)
        reverse = (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.proto)
        return min(forward, reverse)

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'proto': self.proto,
            'size': self.size,
            'ttl': self.ttl,
            'flags': self.flags,
            'payload_size': self.payload_size,
            'is_dns': self.is_dns,
            'dns_query': self.dns_query,
            'is_tls': self.is_tls,
        }


def parse_packet(pkt):
    """Extract normalized PacketInfo from a Scapy packet."""
    info = PacketInfo()
    info.raw_packet = pkt
    info.timestamp = float(pkt.time)
    info.size = len(pkt)

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    info.src_ip = ip.src
    info.dst_ip = ip.dst
    info.ttl = ip.ttl

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.proto = "tcp"
        info.src_port = tcp.sport
        info.dst_port = tcp.dport
        info.flags = str(tcp.flags)
        info.payload_size = len(tcp.payload) if tcp.payload else 0

        # Check for TLS (Client Hello starts with 0x16 0x03)
        if tcp.payload and len(tcp.payload) > 5:
            payload_bytes = bytes(tcp.payload)
            if payload_bytes[0] == 0x16 and payload_bytes[1] == 0x03:
                info.is_tls = True
                info.tls_data = payload_bytes

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info.proto = "udp"
        info.src_port = udp.sport
        info.dst_port = udp.dport
        info.payload_size = len(udp.payload) if udp.payload else 0

        # Check for DNS
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            info.is_dns = True
            info.dns_rcode = dns.rcode
            if dns.qd:
                try:
                    qname = dns.qd.qname.decode('utf-8', errors='ignore')
                    info.dns_query = qname.rstrip('.')
                except Exception:
                    info.dns_query = ""
            if dns.an:
                try:
                    info.dns_response = str(dns.an)
                except Exception:
                    info.dns_response = ""
    else:
        info.proto = str(ip.proto)
        info.payload_size = len(ip.payload) if ip.payload else 0

    return info


def read_pcap_streaming(pcap_path, speed=1.0, callback=None):
    """
    Read packets from PCAP file in streaming mode.
    
    Args:
        pcap_path: Path to PCAP file
        speed: Replay speed (1.0 = real-time, 0.0 = fast-forward)
        callback: Function called with each PacketInfo
        
    Yields:
        PacketInfo objects one at a time
    """
    logger.info(f"Opening PCAP: {pcap_path} (speed={speed}x)")
    packet_count = 0
    start_time = None
    first_pkt_time = None

    try:
        with ScapyPcapReader(pcap_path) as reader:
            for pkt in reader:
                info = parse_packet(pkt)
                if info is None:
                    continue

                packet_count += 1

                # Simulate real-time replay timing
                if speed > 0:
                    if first_pkt_time is None:
                        first_pkt_time = info.timestamp
                        start_time = time.time()
                    else:
                        elapsed_pcap = info.timestamp - first_pkt_time
                        elapsed_real = time.time() - start_time
                        sleep_time = (elapsed_pcap / speed) - elapsed_real
                        if sleep_time > 0:
                            time.sleep(min(sleep_time, 0.5))  # cap at 0.5s

                if callback:
                    callback(info)

                yield info

                if packet_count % 1000 == 0:
                    logger.info(f"Processed {packet_count} packets")

    except Exception as e:
        logger.error(f"Error reading PCAP: {e}")
        raise

    logger.info(f"PCAP complete: {packet_count} packets processed")


def read_pcap_batch(pcap_path, max_packets=None):
    """Read all packets from PCAP at once (for training/analysis)."""
    logger.info(f"Loading PCAP batch: {pcap_path}")
    packets = []
    try:
        raw_packets = rdpcap(pcap_path)
        for i, pkt in enumerate(raw_packets):
            if max_packets and i >= max_packets:
                break
            info = parse_packet(pkt)
            if info:
                packets.append(info)
    except Exception as e:
        logger.error(f"Error loading PCAP: {e}")
        raise

    logger.info(f"Loaded {len(packets)} packets")
    return packets

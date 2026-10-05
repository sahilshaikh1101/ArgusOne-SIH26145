"""
ArgusOne — Synthetic Traffic Generator

Generates labelled PCAP files with both benign and attack traffic
for demo and validation purposes. Each attack type is clearly labelled
so we can verify detection accuracy.
"""

import random
import string
import struct
import time
import os
import logging
from scapy.all import (
    IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, Ether,
    wrpcap, RandShort, RandIP
)
from argusone.config import DATA_DIR

logger = logging.getLogger("argusone.traffic_gen")


class TrafficGenerator:
    """Generates synthetic network traffic with labelled attacks."""

    def __init__(self, seed=42):
        random.seed(seed)
        self.packets = []
        self.labels = []
        self.base_time = time.time()
        self.current_time = self.base_time

        # Internal network
        self.internal_ips = [f"10.0.1.{i}" for i in range(10, 50)]
        # External servers (benign)
        self.benign_external = ["8.8.8.8", "1.1.1.1", "93.184.216.34",
                                "142.250.190.46", "151.101.1.140"]
        # Malicious external
        self.malicious_c2 = ["185.220.101.42", "45.33.32.156", "203.0.113.50"]
        self.malicious_exfil = ["198.51.100.77", "192.0.2.88"]

    def generate_all(self, duration_sec=120):
        """Generate a complete demo traffic capture."""
        logger.info(f"Generating {duration_sec}s of synthetic traffic...")

        # Generate benign baseline throughout
        self._generate_benign_traffic(duration_sec)

        # Inject attacks at specific time offsets
        # Phase 1 (10-20s): Port scanning
        self._generate_port_scan(offset=10)

        # Phase 2 (25-35s): DGA domain queries
        self._generate_dga_traffic(offset=25)

        # Phase 3 (40-60s): SYN flood DDoS
        self._generate_ddos_syn_flood(offset=40, duration=15)

        # Phase 4 (50-80s): C2 beaconing
        self._generate_beacon_traffic(offset=50, duration=30)

        # Phase 5 (70-90s): Encrypted malware (TLS on unusual port)
        self._generate_encrypted_malware(offset=70)

        # Phase 6 (85-100s): Data exfiltration
        self._generate_exfiltration(offset=85)

        # Sort by timestamp
        combined = list(zip(self.packets, self.labels))
        combined.sort(key=lambda x: float(x[0].time))
        self.packets, self.labels = zip(*combined) if combined else ([], [])

        logger.info(f"Generated {len(self.packets)} packets")
        return self.packets, self.labels

    def save_pcap(self, filename="demo_traffic.pcap"):
        """Save generated traffic to PCAP file."""
        os.makedirs(DATA_DIR, exist_ok=True)
        filepath = os.path.join(DATA_DIR, filename)
        wrpcap(filepath, list(self.packets))
        logger.info(f"PCAP saved: {filepath} ({len(self.packets)} packets)")

        # Save labels
        label_path = os.path.join(DATA_DIR, filename.replace('.pcap', '_labels.txt'))
        with open(label_path, 'w') as f:
            for label in self.labels:
                f.write(f"{label}\n")
        logger.info(f"Labels saved: {label_path}")

        return filepath

    def _add_packet(self, pkt, label, time_offset=0):
        """Add a packet with timestamp and label."""
        pkt.time = self.base_time + time_offset + random.uniform(0, 0.01)
        self.packets.append(pkt)
        self.labels.append(label)

    # ─── Benign Traffic ───

    def _generate_benign_traffic(self, duration_sec):
        """Generate normal browsing, DNS, and HTTPS traffic."""
        for t in range(0, duration_sec, 1):
            # Random benign flows each second
            num_flows = random.randint(3, 8)
            for _ in range(num_flows):
                src = random.choice(self.internal_ips)
                dst = random.choice(self.benign_external)
                sport = random.randint(49152, 65535)

                # DNS lookup
                domain = random.choice([
                    "google.com", "github.com", "stackoverflow.com",
                    "python.org", "wikipedia.org", "amazon.com",
                    "microsoft.com", "apple.com", "reddit.com",
                    "youtube.com", "linkedin.com", "cloudflare.com",
                ])
                dns_pkt = (IP(src=src, dst="8.8.8.8", ttl=64) /
                          UDP(sport=sport, dport=53) /
                          DNS(rd=1, qd=DNSQR(qname=domain)))
                self._add_packet(dns_pkt, "benign", t)

                # TCP SYN + SYN-ACK + ACK (3-way handshake)
                syn = IP(src=src, dst=dst, ttl=64) / TCP(sport=sport, dport=443, flags="S")
                self._add_packet(syn, "benign", t + 0.01)

                syn_ack = IP(src=dst, dst=src, ttl=128) / TCP(sport=443, dport=sport, flags="SA")
                self._add_packet(syn_ack, "benign", t + 0.05)

                ack = IP(src=src, dst=dst, ttl=64) / TCP(sport=sport, dport=443, flags="A")
                self._add_packet(ack, "benign", t + 0.06)

                # TLS Client Hello (simplified)
                tls_hello = self._make_tls_client_hello()
                data_pkt = (IP(src=src, dst=dst, ttl=64) /
                           TCP(sport=sport, dport=443, flags="PA") /
                           Raw(load=tls_hello))
                self._add_packet(data_pkt, "benign", t + 0.1)

                # Data exchange
                for i in range(random.randint(2, 5)):
                    size = random.randint(100, 1400)
                    data = IP(src=src, dst=dst, ttl=64) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=b'\x00' * size)
                    self._add_packet(data, "benign", t + 0.2 + i * 0.1)

    # ─── Attack: DDoS SYN Flood ───

    def _generate_ddos_syn_flood(self, offset=40, duration=15):
        """Generate SYN flood from many spoofed sources."""
        target = "10.0.1.10"
        for t_offset in range(duration):
            t = offset + t_offset
            # 200+ SYN packets per second from random sources
            for _ in range(200):
                src = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 8080])
                ttl = random.choice([32, 64, 128, 255])  # varied TTL = spoofed

                syn = (IP(src=src, dst=target, ttl=ttl) /
                      TCP(sport=sport, dport=dport, flags="S"))
                self._add_packet(syn, "ddos_syn_flood", t + random.uniform(0, 0.99))

    # ─── Attack: C2 Beaconing ───

    def _generate_beacon_traffic(self, offset=50, duration=30):
        """Generate regular-interval C2 beacon connections."""
        infected_host = "10.0.1.15"
        c2_server = self.malicious_c2[0]
        beacon_interval = 5.0  # seconds (very regular)
        jitter = 0.2  # small jitter

        for i in range(int(duration / beacon_interval)):
            t = offset + i * beacon_interval + random.uniform(-jitter, jitter)
            sport = random.randint(49152, 65535)

            # SYN
            syn = IP(src=infected_host, dst=c2_server, ttl=64) / TCP(sport=sport, dport=443, flags="S")
            self._add_packet(syn, "c2_beaconing", t)

            # Small data exchange (C2 command)
            cmd = IP(src=infected_host, dst=c2_server, ttl=64) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=b'\x00' * 128)
            self._add_packet(cmd, "c2_beaconing", t + 0.1)

            # Response
            resp = IP(src=c2_server, dst=infected_host, ttl=128) / TCP(sport=443, dport=sport, flags="PA") / Raw(load=b'\x00' * 256)
            self._add_packet(resp, "c2_beaconing", t + 0.2)

    # ─── Attack: DGA Domains ───

    def _generate_dga_traffic(self, offset=25):
        """Generate DNS queries for algorithmically generated domains."""
        infected_host = "10.0.1.20"

        for i in range(60):
            t = offset + i * 0.3

            # Generate DGA domain (high entropy, random-looking)
            dga_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(12, 25)))
            tld = random.choice([".com", ".net", ".org", ".info", ".xyz"])
            domain = dga_name + tld

            sport = random.randint(49152, 65535)
            
            # Most DGA queries return NXDOMAIN
            rcode = 3 if random.random() < 0.85 else 0

            dns_pkt = (IP(src=infected_host, dst="8.8.8.8", ttl=64) /
                      UDP(sport=sport, dport=53) /
                      DNS(rd=1, qd=DNSQR(qname=domain)))
            self._add_packet(dns_pkt, "dga_domain", t)

    # ─── Attack: Port Scanning ───

    def _generate_port_scan(self, offset=10):
        """Generate vertical port scan (one host, many ports)."""
        scanner = "10.0.1.30"
        target = "10.0.1.10"

        # Scan 100 ports
        ports = list(range(1, 1024))
        random.shuffle(ports)

        for i, port in enumerate(ports[:100]):
            t = offset + i * 0.05
            sport = random.randint(49152, 65535)

            # SYN only (no ACK response = typical scan)
            syn = IP(src=scanner, dst=target, ttl=64) / TCP(sport=sport, dport=port, flags="S")
            self._add_packet(syn, "port_scan", t)

    # ─── Attack: Encrypted Malware ───

    def _generate_encrypted_malware(self, offset=70):
        """Generate TLS connections on unusual ports with suspicious JA3."""
        infected = "10.0.1.25"
        c2 = self.malicious_c2[1]

        for i in range(10):
            t = offset + i * 2
            sport = random.randint(49152, 65535)
            dport = random.choice([4443, 8443, 9999, 1337])  # non-standard TLS ports

            # TLS Client Hello with known-malicious-like pattern
            tls_data = self._make_malicious_tls_hello()

            syn = IP(src=infected, dst=c2, ttl=64) / TCP(sport=sport, dport=dport, flags="S")
            self._add_packet(syn, "encrypted_malware", t)

            hello = (IP(src=infected, dst=c2, ttl=64) /
                    TCP(sport=sport, dport=dport, flags="PA") /
                    Raw(load=tls_data))
            self._add_packet(hello, "encrypted_malware", t + 0.1)

            # Small fixed-size exchanges (C2 pattern)
            for j in range(3):
                data = (IP(src=infected, dst=c2, ttl=64) /
                       TCP(sport=sport, dport=dport, flags="PA") /
                       Raw(load=b'\x00' * 128))
                self._add_packet(data, "encrypted_malware", t + 0.5 + j * 0.3)

    # ─── Attack: Data Exfiltration ───

    def _generate_exfiltration(self, offset=85):
        """Generate large outbound data transfers to rare destinations."""
        compromised = "10.0.1.35"
        exfil_dest = self.malicious_exfil[0]

        for i in range(15):
            t = offset + i * 0.8
            sport = random.randint(49152, 65535)

            # Large outbound packets (exfiltrating data)
            for j in range(5):
                size = random.randint(1200, 1460)  # near-MTU = bulk transfer
                data = (IP(src=compromised, dst=exfil_dest, ttl=64) /
                       TCP(sport=sport, dport=443, flags="PA") /
                       Raw(load=b'\x00' * size))
                self._add_packet(data, "data_exfiltration", t + j * 0.05)

            # Tiny ACK responses (very asymmetric)
            ack = (IP(src=exfil_dest, dst=compromised, ttl=128) /
                  TCP(sport=443, dport=sport, flags="A"))
            self._add_packet(ack, "data_exfiltration", t + 0.3)

        # DNS exfiltration variant
        for i in range(20):
            t = offset + 12 + i * 0.2
            # Encode data in long subdomain labels
            encoded_data = ''.join(random.choices(string.ascii_lowercase + string.digits, k=50))
            domain = f"{encoded_data}.exfil.evil-server.xyz"
            sport = random.randint(49152, 65535)

            dns_pkt = (IP(src=compromised, dst="8.8.8.8", ttl=64) /
                      UDP(sport=sport, dport=53) /
                      DNS(rd=1, qd=DNSQR(qname=domain, qtype="TXT")))
            self._add_packet(dns_pkt, "data_exfiltration", t)

    # ─── TLS Hello Helpers ───

    def _make_tls_client_hello(self):
        """Create a benign-looking TLS Client Hello."""
        # Simplified TLS 1.2 Client Hello
        hello = bytearray()
        hello.append(0x16)  # Handshake
        hello.extend(b'\x03\x01')  # TLS 1.0 record version
        hello.extend(b'\x00\x00')  # Length placeholder
        hello.append(0x01)  # Client Hello
        hello.extend(b'\x00\x00\x00')  # Handshake length placeholder
        hello.extend(b'\x03\x03')  # TLS 1.2
        hello.extend(os.urandom(32))  # Random
        hello.append(0x00)  # Session ID length
        # Cipher suites (standard browser set)
        ciphers = [0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009e, 0x009c, 0x00ff]
        hello.extend(struct.pack('!H', len(ciphers) * 2))
        for c in ciphers:
            hello.extend(struct.pack('!H', c))
        hello.append(0x01)  # Compression methods
        hello.append(0x00)  # null
        # Update lengths
        total_len = len(hello) - 5
        struct.pack_into('!H', hello, 3, total_len)
        handshake_len = total_len - 4
        hello[6] = (handshake_len >> 16) & 0xFF
        hello[7] = (handshake_len >> 8) & 0xFF
        hello[8] = handshake_len & 0xFF
        return bytes(hello)

    def _make_malicious_tls_hello(self):
        """Create a suspicious TLS Client Hello (few ciphers, unusual pattern)."""
        hello = bytearray()
        hello.append(0x16)
        hello.extend(b'\x03\x01')
        hello.extend(b'\x00\x00')
        hello.append(0x01)
        hello.extend(b'\x00\x00\x00')
        hello.extend(b'\x03\x03')
        hello.extend(os.urandom(32))
        hello.append(0x00)
        # Only 2 cipher suites (suspicious — real browsers offer many)
        ciphers = [0x002f, 0x0035]
        hello.extend(struct.pack('!H', len(ciphers) * 2))
        for c in ciphers:
            hello.extend(struct.pack('!H', c))
        hello.append(0x01)
        hello.append(0x00)
        total_len = len(hello) - 5
        struct.pack_into('!H', hello, 3, total_len)
        handshake_len = total_len - 4
        hello[6] = (handshake_len >> 16) & 0xFF
        hello[7] = (handshake_len >> 8) & 0xFF
        hello[8] = handshake_len & 0xFF
        return bytes(hello)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    gen = TrafficGenerator()
    gen.generate_all(duration_sec=120)
    gen.save_pcap("demo_traffic.pcap")
    print(f"Generated {len(gen.packets)} packets")

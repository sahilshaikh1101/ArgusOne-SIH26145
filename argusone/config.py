"""
ArgusOne — Global Configuration
All thresholds, window sizes, and model parameters in one place.
"""

import os

# ─── Paths ───
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")
DB_PATH = os.path.join(DATA_DIR, "alerts.db")

# ─── Load .env if present ───
env_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()

# ─── Database Configuration (PostgreSQL / SQLite Dual Engine) ───
DB_ENGINE = os.environ.get("DB_ENGINE", "sqlite")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.environ.get("POSTGRES_DB", "postgres")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")

# ─── Ingest ───
PCAP_REPLAY_SPEED = 1.0        # 1.0 = real-time, 0.0 = as-fast-as-possible
FLOW_TIMEOUT = 30               # seconds of inactivity to close a flow
FLOW_MAX_DURATION = 300         # max flow duration before forced export (5 min)

# ─── Windowing ───
WINDOW_SIZES = [1, 5, 30, 300]  # seconds: 1s, 5s, 30s, 5min

# ─── Detector Thresholds ───

# (a) DDoS
DDOS_PPS_THRESHOLD = 5000       # packets/sec spike threshold
DDOS_ENTROPY_LOW = 1.0          # low source-IP entropy → spoofed
DDOS_SYN_RATIO_THRESHOLD = 0.85 # SYN:total ratio
DDOS_ISOLATION_CONTAMINATION = 0.05

# (b) C2 Beaconing
BEACON_MIN_CONNECTIONS = 5      # minimum connections to analyze
BEACON_CV_THRESHOLD = 0.3       # coefficient of variation (lower = more periodic)
BEACON_MIN_PERIOD = 10          # seconds
BEACON_MAX_PERIOD = 3600        # seconds
BEACON_FFT_PEAK_THRESHOLD = 0.7 # FFT peak strength

# (c) DGA / DNS Tunnelling
DGA_ENTROPY_THRESHOLD = 3.5     # Shannon entropy of domain name
DGA_LENGTH_THRESHOLD = 15       # suspicious domain length
DGA_DIGIT_RATIO_THRESHOLD = 0.3 # high digit ratio
DNS_TUNNEL_QUERY_RATE = 10      # queries/sec to same domain
DNS_TUNNEL_TXT_RATIO = 0.3      # unusual TXT record ratio

# (d) Encrypted Malware
ENCRYPTED_SHAPE_ANOMALY_THRESHOLD = 0.7
ENCRYPTED_CERT_VALIDITY_MIN_DAYS = 30  # suspicious if cert valid < 30 days
JA3_PACKET_SEQ_LENGTH = 10     # first N packets for shape analysis

# (e) Port Scanning
SCAN_UNIQUE_PORTS_THRESHOLD = 15   # unique dst ports from single source
SCAN_UNIQUE_HOSTS_THRESHOLD = 10   # unique dst hosts from single source
SCAN_SYN_NO_ACK_RATIO = 0.8       # mostly SYN without ACK response
SCAN_Z_SCORE_THRESHOLD = 3.0      # standard deviations above baseline

# (f) Data Exfiltration
EXFIL_OUT_IN_RATIO_THRESHOLD = 5.0    # outbound:inbound byte ratio
EXFIL_RARE_DEST_THRESHOLD = 0.1       # destination seen by < 10% of hosts
EXFIL_DNS_BYTES_THRESHOLD = 10000     # unusual bytes over DNS
EXFIL_SIGMA_THRESHOLD = 2.0           # std devs above baseline

# ─── Correlation ───
CORRELATION_WINDOW = 300        # 5 minute correlation window
KILL_CHAIN_STAGES = {
    "recon": ["port_scan", "reconnaissance"],
    "initial_access": ["encrypted_malware"],
    "c2": ["c2_beaconing", "dga_domain", "dns_tunnelling"],
    "exfiltration": ["data_exfiltration"],
}
CORRELATION_ESCALATION_THRESHOLD = 2  # min stages for escalation

# ─── Alert ───
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]
CONFIDENCE_BINS = {
    "low": (0.0, 0.4),
    "medium": (0.4, 0.7),
    "high": (0.7, 0.9),
    "critical": (0.9, 1.0),
}

# ─── API / Dashboard ───
API_HOST = "0.0.0.0"
API_PORT = 5000
WEBSOCKET_NAMESPACE = "/ws"

# ─── Known-malicious JA3 fingerprints (subset for demo) ───
KNOWN_MALICIOUS_JA3 = {
    "a0e9f5d64349fb13191bc781f81f42e1",  # Trickbot
    "e7d705a3286e19ea42f587b344ee6865",  # AsyncRAT
    "51c64c77e60f3980eea90869b68c58a8",  # Cobalt Strike
    "72a589da586844d7f0818ce684948eea",  # Metasploit
    "3b5074b1b5d032e5620f69f9f700ff0e",  # IcedID
    "6734f37431670b3ab4292b8f60f29984",  # Dridex
    "b32309a26951912be7dba376398abc3b",  # Emotet
}

# ─── English bigram frequencies (for DGA scoring) ───
ENGLISH_BIGRAMS = {
    'th': 3.56, 'he': 3.07, 'in': 2.43, 'er': 2.05, 'an': 1.99,
    'en': 1.45, 'on': 1.45, 'at': 1.33, 'es': 1.34, 'ed': 1.28,
    'or': 1.28, 'ti': 1.27, 're': 1.27, 'is': 1.13, 'it': 1.13,
    'al': 1.09, 'ar': 1.07, 'st': 1.05, 'nd': 1.02, 'to': 1.04,
    'nt': 1.04, 'ng': 0.95, 'se': 0.93, 'ha': 0.93, 'as': 0.87,
    'ou': 0.87, 'io': 0.83, 'le': 0.83, 've': 0.83, 'co': 0.79,
    'me': 0.79, 'de': 0.76, 'hi': 0.76, 'ri': 0.73, 'ro': 0.73,
    'ic': 0.70, 'ne': 0.69, 'ea': 0.69, 'ra': 0.69, 'ce': 0.65,
}

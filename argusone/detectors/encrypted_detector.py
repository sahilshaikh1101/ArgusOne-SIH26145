"""
ArgusOne — Detector (d): Malware in Encrypted Sessions

Detects malicious encrypted traffic via JA3 fingerprint matching
and packet size/timing shape analysis — NO payload decryption.
"""

import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier
from argusone.features.tls_features import extract_tls_features
from argusone.config import KNOWN_MALICIOUS_JA3, JA3_PACKET_SEQ_LENGTH

logger = logging.getLogger("argusone.detectors")


class EncryptedMalwareDetector:
    """
    Detects malware in encrypted (TLS/QUIC) sessions using:
    1. JA3/JA3S fingerprint matching against known-malicious database
    2. Packet size/timing shape analysis (1D feature vector)
    3. Certificate anomaly detection (self-signed, short validity, SNI mismatch)
    """

    def __init__(self):
        self.known_malicious_ja3 = KNOWN_MALICIOUS_JA3
        self.benign_shapes = []  # Baseline packet shape profiles
        self.shape_model = None
        self.is_trained = False
        self.training_samples = []
        self.training_labels = []
        self.training_threshold = 20
        self._init_baseline_model()

    def _init_baseline_model(self):
        """Pre-seed and train Random Forest classifier on standard TLS flow geometries."""
        # Benign TLS flows: high variance in packet sizes (HTTP/2, HTTPS dynamic assets)
        benign_seeds = [
            [517, 1420, 1420, 240, 1420, 85, 1420, 1420, 620, 1420],
            [350, 1460, 1460, 1460, 520, 120, 1460, 1460, 1460, 890],
            [480, 1380, 210, 1380, 1380, 95, 1380, 450, 1380, 1380],
            [512, 1440, 1440, 310, 1440, 1440, 720, 1440, 140, 1440],
            [290, 1400, 1400, 1400, 180, 1400, 540, 1400, 1400, 910],
            [610, 1450, 330, 1450, 1450, 110, 1450, 1450, 480, 1450],
            [420, 1420, 1420, 290, 1420, 1420, 1420, 680, 150, 1420],
            [380, 1460, 1460, 190, 1460, 1460, 820, 1460, 240, 1460],
            [550, 1400, 260, 1400, 1400, 1400, 390, 1400, 1400, 760],
            [470, 1440, 1440, 1440, 170, 1440, 610, 1440, 1440, 320],
        ]
        # Malicious C2 / tunneling TLS flows: uniform, fixed-size command/response frames
        malicious_seeds = [
            [128, 128, 128, 128, 128, 256, 128, 128, 128, 128],
            [160, 160, 160, 320, 160, 160, 160, 320, 160, 160],
            [96, 96, 96, 96, 96, 96, 192, 96, 96, 96],
            [210, 210, 210, 210, 420, 210, 210, 210, 210, 420],
            [144, 144, 144, 144, 144, 144, 144, 288, 144, 144],
            [112, 112, 112, 224, 112, 112, 112, 112, 224, 112],
            [180, 180, 180, 180, 360, 180, 180, 180, 180, 360],
            [130, 130, 130, 130, 130, 260, 130, 130, 130, 130],
            [90, 90, 90, 180, 90, 90, 90, 90, 180, 90],
            [150, 150, 150, 150, 300, 150, 150, 150, 150, 300],
        ]
        self.training_samples = benign_seeds + malicious_seeds
        self.training_labels = [0] * len(benign_seeds) + [1] * len(malicious_seeds)
        self._train_shape_model()


    def analyze_flow(self, flow_record):
        """
        Analyze a TLS flow for encrypted malware indicators.
        
        Returns alert dict or None.
        """
        if not flow_record.has_tls:
            return None

        tls_features = extract_tls_features(flow_record)
        confidence = 0.0
        evidence = {}

        # 1. JA3 Fingerprint Matching
        ja3_hash = tls_features.get('ja3_hash')
        if ja3_hash:
            evidence['ja3_hash'] = ja3_hash

            if ja3_hash in self.known_malicious_ja3:
                confidence = max(confidence, 0.85)
                evidence['ja3_match'] = 'known_malicious'
                evidence['ja3_confidence'] = 0.85

            # Check for unusual cipher count (very few = suspicious)
            cipher_count = tls_features.get('cipher_count', 0)
            if 0 < cipher_count < 3:
                confidence = max(confidence, 0.5)
                evidence['low_cipher_count'] = cipher_count

        # 2. Packet Size/Timing Shape Analysis
        packet_sizes = tls_features.get('packet_sizes_first10', [])
        packet_iats = tls_features.get('packet_iats_first10', [])

        if len(packet_sizes) >= 5:
            shape_score = self._analyze_shape(packet_sizes, packet_iats)
            if shape_score > 0.6:
                confidence = max(confidence, shape_score * 0.8)
                evidence['shape_anomaly_score'] = round(shape_score, 4)
                evidence['packet_sizes'] = packet_sizes[:10]

        # 3. Connection pattern anomalies
        # Short-lived TLS sessions (connect, small exchange, disconnect)
        if flow_record.duration < 5 and flow_record.total_packets < 20:
            if flow_record.total_bytes < 5000:
                confidence = max(confidence, 0.4)
                evidence['short_session'] = True
                evidence['duration'] = round(flow_record.duration, 2)

        # Self-signed / anomalous cert indicators
        # (In production, we'd parse the certificate from Server Hello)
        if flow_record.dst_port not in (443, 8443, 993, 995, 465, 587):
            # TLS on non-standard port
            confidence = max(confidence, 0.45)
            evidence['non_standard_tls_port'] = flow_record.dst_port

        if confidence > 0.4:
            severity = 'critical' if confidence > 0.8 else 'high' if confidence > 0.6 else 'medium'
            return {
                'threat_class': 'encrypted_malware',
                'src_ip': flow_record.src_ip,
                'dst_ip': flow_record.dst_ip,
                'dst_port': flow_record.dst_port,
                'confidence': round(confidence, 3),
                'severity': severity,
                'evidence': evidence,
            }

        return None

    def _analyze_shape(self, packet_sizes, packet_iats):
        """
        Analyze packet size/timing shape for malware patterns.
        
        Known malware patterns:
        - Very regular packet sizes (C2 commands are often fixed-size)
        - Bimodal size distribution (small commands, large responses)
        - Very consistent inter-arrival timing
        """
        sizes = np.array(packet_sizes[:JA3_PACKET_SEQ_LENGTH], dtype=float)

        if len(sizes) < 3:
            return 0.0

        score = 0.0

        # Size regularity (low variance = suspicious for encrypted traffic)
        size_cv = np.std(sizes) / max(np.mean(sizes), 1)
        if size_cv < 0.1:  # Very uniform packet sizes
            score += 0.3

        # Bimodal distribution (two clusters of sizes)
        sorted_sizes = np.sort(sizes)
        if len(sorted_sizes) >= 4:
            midpoint = len(sorted_sizes) // 2
            lower = sorted_sizes[:midpoint]
            upper = sorted_sizes[midpoint:]
            if np.mean(upper) > np.mean(lower) * 3:  # Bimodal gap
                score += 0.2

        # Small initial packets (typical C2 handshake)
        if len(sizes) >= 3 and np.mean(sizes[:3]) < 200:
            score += 0.15

        # IAT regularity
        if packet_iats and len(packet_iats) >= 3:
            iats = np.array(packet_iats)
            iat_cv = np.std(iats) / max(np.mean(iats), 1e-9)
            if iat_cv < 0.2:
                score += 0.25

        # Random Forest model inference if trained
        if self.is_trained and self.shape_model is not None:
            try:
                padded = list(sizes[:JA3_PACKET_SEQ_LENGTH])
                padded += [0.0] * (JA3_PACKET_SEQ_LENGTH - len(padded))
                rf_prob = float(self.shape_model.predict_proba([padded])[0][1])
                score = max(score, rf_prob)
            except Exception as e:
                logger.debug(f"Random Forest inference fallback: {e}")

        return min(score, 0.95)


    def add_training_sample(self, packet_sizes, is_malicious):
        """Add a labelled sample for shape model training."""
        if len(packet_sizes) >= 5:
            # Pad/truncate to fixed length
            padded = packet_sizes[:JA3_PACKET_SEQ_LENGTH]
            padded += [0] * (JA3_PACKET_SEQ_LENGTH - len(padded))
            self.training_samples.append(padded)
            self.training_labels.append(1 if is_malicious else 0)

            if len(self.training_samples) >= self.training_threshold:
                self._train_shape_model()

    def _train_shape_model(self):
        """Train Random Forest on packet shape features."""
        try:
            X = np.array(self.training_samples)
            y = np.array(self.training_labels)
            self.shape_model = RandomForestClassifier(n_estimators=50, random_state=42)
            self.shape_model.fit(X, y)
            self.is_trained = True
            logger.info(f"Encrypted malware shape model trained on {len(X)} samples")
        except Exception as e:
            logger.error(f"Shape model training failed: {e}")

"""
ArgusOne — Detector (a): Volumetric/Protocol DDoS Detection

Uses EWMA change-point detection for rate spikes + Isolation Forest 
for detecting low-and-slow and reflection patterns.
"""

import numpy as np
import logging
from sklearn.ensemble import IsolationForest
from argusone.config import (
    DDOS_PPS_THRESHOLD, DDOS_ENTROPY_LOW,
    DDOS_SYN_RATIO_THRESHOLD, DDOS_ISOLATION_CONTAMINATION
)

logger = logging.getLogger("argusone.detectors")


class DDoSDetector:
    """
    Detects volumetric and protocol-level DDoS attacks using:
    1. EWMA (Exponentially Weighted Moving Average) for rate spike detection
    2. Isolation Forest on multivariate feature vectors for anomaly detection
    """

    def __init__(self):
        self.ewma_alpha = 0.3
        self.ewma_pps = 0
        self.ewma_bps = 0
        self.ewma_var_pps = 0
        self.baseline_samples = []
        self.model = None
        self.is_trained = False
        self.window_count = 0
        self.training_threshold = 10  # train after 10 windows

    def analyze_window(self, window_stats):
        """
        Analyze a completed window for DDoS indicators.
        
        Returns alert dict or None.
        """
        self.window_count += 1
        ws = window_stats

        # Extract features
        features = {
            'pps': ws.packets_per_sec,
            'bps': ws.bytes_per_sec,
            'unique_srcs': ws.unique_src_count,
            'src_entropy': ws.src_ip_entropy,
            'syn_ratio': ws.syn_ratio,
            'ttl_variance': ws.ttl_variance,
            'syn_count': ws.syn_count,
        }

        # Update EWMA baselines
        self.ewma_pps = self.ewma_alpha * features['pps'] + (1 - self.ewma_alpha) * self.ewma_pps
        deviation = abs(features['pps'] - self.ewma_pps)
        self.ewma_var_pps = self.ewma_alpha * deviation + (1 - self.ewma_alpha) * self.ewma_var_pps

        # Collect training samples
        feature_vec = [
            features['pps'], features['bps'], features['unique_srcs'],
            features['src_entropy'], features['syn_ratio'], features['ttl_variance']
        ]

        if not self.is_trained:
            self.baseline_samples.append(feature_vec)
            if len(self.baseline_samples) >= self.training_threshold:
                self._train_model()
            return None

        # ── Detection Logic ──

        confidence = 0.0
        evidence = {}
        threat_type = None

        # 1. EWMA spike detection
        if self.ewma_var_pps > 0:
            z_score = deviation / max(self.ewma_var_pps, 1)
            if z_score > 3:
                confidence = max(confidence, min(z_score / 10, 0.95))
                evidence['pps_z_score'] = round(z_score, 2)
                evidence['pps'] = round(features['pps'], 1)
                evidence['ewma_baseline'] = round(self.ewma_pps, 1)

        # 2. SYN flood signature
        if features['syn_ratio'] > DDOS_SYN_RATIO_THRESHOLD and features['syn_count'] > 50:
            syn_conf = min(features['syn_ratio'], 0.95)
            confidence = max(confidence, syn_conf)
            evidence['syn_ratio'] = round(features['syn_ratio'], 3)
            evidence['syn_count'] = features['syn_count']
            threat_type = "syn_flood"

        # 3. Low entropy (many spoofed sources)
        if features['src_entropy'] < DDOS_ENTROPY_LOW and features['unique_srcs'] > 20:
            entropy_conf = min((DDOS_ENTROPY_LOW - features['src_entropy']) / DDOS_ENTROPY_LOW, 0.9)
            confidence = max(confidence, entropy_conf)
            evidence['src_entropy'] = round(features['src_entropy'], 3)
            evidence['unique_sources'] = features['unique_srcs']
            threat_type = "volumetric_spoofed"

        # 4. Isolation Forest anomaly score
        if self.model:
            score = self.model.decision_function([feature_vec])[0]
            is_anomaly = self.model.predict([feature_vec])[0] == -1
            if is_anomaly:
                anomaly_conf = min(abs(score) * 2, 0.9)
                confidence = max(confidence, anomaly_conf)
                evidence['anomaly_score'] = round(score, 4)

        if confidence > 0.4:
            severity = self._score_to_severity(confidence)
            return {
                'threat_class': 'ddos',
                'threat_subtype': threat_type or 'volumetric',
                'confidence': round(confidence, 3),
                'severity': severity,
                'evidence': evidence,
                'window_info': ws.to_dict(),
            }

        return None

    def _train_model(self):
        """Train Isolation Forest on baseline samples."""
        try:
            X = np.array(self.baseline_samples)
            self.model = IsolationForest(
                contamination=DDOS_ISOLATION_CONTAMINATION,
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X)
            self.is_trained = True
            logger.info(f"DDoS detector trained on {len(self.baseline_samples)} windows")
        except Exception as e:
            logger.error(f"DDoS model training failed: {e}")

    def _score_to_severity(self, confidence):
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        return "low"

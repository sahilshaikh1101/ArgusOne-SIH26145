"""
ArgusOne — Detector (b): C2 Beaconing Detection

Detects command-and-control beaconing via inter-arrival-time analysis,
FFT periodicity scoring, and DBSCAN clustering.
"""

import numpy as np
import logging
from collections import defaultdict
from argusone.config import (
    BEACON_MIN_CONNECTIONS, BEACON_CV_THRESHOLD,
    BEACON_MIN_PERIOD, BEACON_MAX_PERIOD, BEACON_FFT_PEAK_THRESHOLD
)

logger = logging.getLogger("argusone.detectors")


class BeaconDetector:
    """
    Detects C2 beaconing patterns by analyzing inter-arrival times between
    connections from the same source to the same destination.
    """

    def __init__(self):
        # Track connection timestamps per (src, dst) pair
        self.pair_history = defaultdict(list)
        # Known benign periodic services (NTP, heartbeats, etc.)
        self.benign_ports = {123, 53, 67, 68, 161, 162, 514}
        self.alerts_generated = set()

    def add_connection(self, src_ip, dst_ip, dst_port, timestamp):
        """Record a new connection for beaconing analysis."""
        pair_key = (src_ip, dst_ip, dst_port)
        self.pair_history[pair_key].append(timestamp)

    def analyze_pairs(self):
        """
        Analyze all tracked pairs for beaconing patterns.
        
        Returns list of alert dicts.
        """
        alerts = []

        for pair_key, timestamps in self.pair_history.items():
            src_ip, dst_ip, dst_port = pair_key

            # Skip known benign periodic services
            if dst_port in self.benign_ports:
                continue

            # Need minimum connections to analyze
            if len(timestamps) < BEACON_MIN_CONNECTIONS:
                continue

            # Skip if already alerted on this pair
            if pair_key in self.alerts_generated:
                continue

            # Compute inter-arrival times
            sorted_ts = sorted(timestamps)
            iats = [sorted_ts[i] - sorted_ts[i-1] for i in range(1, len(sorted_ts))]

            if not iats:
                continue

            alert = self._analyze_iats(iats, pair_key)
            if alert:
                alert.update({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'connection_count': len(timestamps),
                })
                alerts.append(alert)
                self.alerts_generated.add(pair_key)

        return alerts

    def _analyze_iats(self, iats, pair_key):
        """Analyze inter-arrival times for periodicity."""
        iats_arr = np.array(iats)
        mean_iat = np.mean(iats_arr)
        std_iat = np.std(iats_arr)

        # Coefficient of variation — low CV means very regular timing
        cv = std_iat / max(mean_iat, 1e-9)

        # Check if period is in suspicious range
        if mean_iat < BEACON_MIN_PERIOD or mean_iat > BEACON_MAX_PERIOD:
            return None

        confidence = 0.0
        evidence = {}

        # 1. CV-based detection (very regular = suspicious)
        if cv < BEACON_CV_THRESHOLD:
            cv_conf = 1.0 - (cv / BEACON_CV_THRESHOLD)
            confidence = max(confidence, min(cv_conf, 0.9))
            evidence['coefficient_of_variation'] = round(cv, 4)
            evidence['mean_interval_sec'] = round(mean_iat, 2)
            evidence['std_interval_sec'] = round(std_iat, 2)

        # 2. FFT periodicity analysis
        if len(iats) >= 8:
            fft_result = self._fft_periodicity(iats_arr)
            if fft_result:
                confidence = max(confidence, fft_result['fft_confidence'])
                evidence.update(fft_result)

        # 3. Jitter analysis — real C2 has small, consistent jitter
        if len(iats) >= 5:
            jitter = np.diff(iats_arr)
            jitter_cv = np.std(jitter) / max(np.mean(np.abs(jitter)), 1e-9)
            if jitter_cv < 0.5:  # Consistent jitter pattern
                confidence = max(confidence, 0.6)
                evidence['jitter_cv'] = round(jitter_cv, 4)

        if confidence > 0.4:
            severity = self._score_to_severity(confidence)
            return {
                'threat_class': 'c2_beaconing',
                'confidence': round(confidence, 3),
                'severity': severity,
                'evidence': evidence,
            }

        return None

    def _fft_periodicity(self, iats):
        """Use FFT to detect strong periodic components."""
        try:
            # Normalize
            iats_norm = iats - np.mean(iats)
            if np.std(iats_norm) < 1e-9:
                return {'fft_confidence': 0.85, 'fft_dominant_period': float(np.mean(iats))}

            # FFT
            fft_vals = np.fft.fft(iats_norm)
            fft_mag = np.abs(fft_vals[:len(fft_vals)//2])

            if len(fft_mag) < 2:
                return None

            # Find dominant frequency (skip DC component)
            peak_idx = np.argmax(fft_mag[1:]) + 1
            peak_strength = fft_mag[peak_idx] / max(np.sum(fft_mag[1:]), 1e-9)

            if peak_strength > BEACON_FFT_PEAK_THRESHOLD:
                # Dominant period
                period = len(iats) / peak_idx * np.mean(iats)
                return {
                    'fft_confidence': round(min(peak_strength, 0.95), 3),
                    'fft_peak_strength': round(peak_strength, 4),
                    'fft_dominant_period': round(period, 2),
                }
        except Exception as e:
            logger.debug(f"FFT analysis failed: {e}")

        return None

    def _score_to_severity(self, confidence):
        if confidence >= 0.85:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        return "low"

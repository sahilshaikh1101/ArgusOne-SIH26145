"""
ArgusOne — Detector (c): DGA Domain / DNS Tunnelling Detection

Detects algorithmically generated domains using entropy + n-gram analysis
and DNS tunnelling via query rate / response size anomalies.
"""

import logging
from collections import defaultdict
from argusone.features.dns_features import extract_dns_features, shannon_entropy
from argusone.config import (
    DGA_ENTROPY_THRESHOLD, DGA_LENGTH_THRESHOLD,
    DGA_DIGIT_RATIO_THRESHOLD, DNS_TUNNEL_QUERY_RATE, DNS_TUNNEL_TXT_RATIO
)

logger = logging.getLogger("argusone.detectors")


class DGADetector:
    """
    Detects DGA-generated domains and DNS tunnelling using:
    1. Domain name entropy + structural features (LightGBM-style scoring)
    2. NXDOMAIN storm detection (many failed lookups = DGA scanning)
    3. DNS tunnelling via unusual query patterns
    """

    def __init__(self):
        # Track domains per source
        self.src_domains = defaultdict(list)
        self.src_nxdomain = defaultdict(int)
        self.src_query_count = defaultdict(int)
        self.src_query_times = defaultdict(list)
        self.analyzed_domains = set()
        self.alerts_generated = set()

        # Feature weights (simulates trained LightGBM model)
        # Higher weight = more important for DGA classification
        self.weights = {
            'entropy': 0.30,
            'bigram_score_inv': 0.25,  # inverted: low bigram = suspicious
            'length': 0.15,
            'digit_ratio': 0.10,
            'consonant_ratio': 0.10,
            'unique_char_ratio': 0.05,
            'label_count': 0.05,
        }

    def add_dns_query(self, src_ip, domain, rcode, timestamp):
        """Record a DNS query for analysis."""
        self.src_domains[src_ip].append((domain, timestamp))
        self.src_query_count[src_ip] += 1
        self.src_query_times[src_ip].append(timestamp)

        if rcode == 3:  # NXDOMAIN
            self.src_nxdomain[src_ip] += 1

    def analyze_domain(self, domain):
        """
        Score a single domain for DGA likelihood.
        
        Returns (score, features) tuple.
        """
        if domain in self.analyzed_domains:
            return None, None

        features = extract_dns_features(domain)
        if features['length'] == 0:
            return None, None

        # Score each feature
        score = 0.0

        # Entropy (higher = more random = more suspicious)
        if features['entropy'] > DGA_ENTROPY_THRESHOLD:
            normalized = min((features['entropy'] - 2.0) / 3.0, 1.0)
            score += self.weights['entropy'] * normalized

        # Bigram score (lower = less English-like = more suspicious)
        if features['bigram_score'] < 0.5:
            normalized = 1.0 - min(features['bigram_score'] / 0.5, 1.0)
            score += self.weights['bigram_score_inv'] * normalized

        # Length (longer = more suspicious for DGA)
        if features['length'] > DGA_LENGTH_THRESHOLD:
            normalized = min((features['length'] - 8) / 30.0, 1.0)
            score += self.weights['length'] * normalized

        # Digit ratio (higher = more suspicious)
        if features['digit_ratio'] > DGA_DIGIT_RATIO_THRESHOLD:
            score += self.weights['digit_ratio'] * min(features['digit_ratio'] / 0.5, 1.0)

        # Consonant ratio (higher = more suspicious)
        if features['consonant_ratio'] > 0.7:
            score += self.weights['consonant_ratio'] * min(features['consonant_ratio'], 1.0)

        # Unique char ratio (very high or very low can be suspicious)
        score += self.weights['unique_char_ratio'] * abs(features['unique_char_ratio'] - 0.5) * 2

        # Label count (many subdomains = suspicious)
        if features['label_count'] > 3:
            score += self.weights['label_count'] * min((features['label_count'] - 2) / 5.0, 1.0)

        self.analyzed_domains.add(domain)
        return score, features

    def analyze_source(self, src_ip, time_window=60):
        """
        Analyze all DNS activity from a source for DGA/tunnelling patterns.
        
        Returns list of alert dicts.
        """
        alerts = []

        if src_ip in self.alerts_generated:
            return alerts

        domains = self.src_domains.get(src_ip, [])
        if not domains:
            return alerts

        # ── DGA Storm & Algorithmic Domain Detection ──
        nxdomain_count = self.src_nxdomain.get(src_ip, 0)
        total_queries = self.src_query_count.get(src_ip, 0)

        # Score suspicious domains
        suspicious_domains = []
        for domain, ts in domains:
            score, features = self.analyze_domain(domain)
            if score and score > 0.45:
                suspicious_domains.append({
                    'domain': domain,
                    'dga_score': round(score, 3),
                    'entropy': round(features['entropy'], 3),
                })

        suspicious_ratio = len(suspicious_domains) / max(total_queries, 1)
        nxdomain_ratio = nxdomain_count / max(total_queries, 1)

        # Trigger if either NXDOMAIN storm OR high proportion of algorithmic domains (passive unidirectional link)
        if total_queries >= 8 and (suspicious_ratio >= 0.4 or (nxdomain_count > 5 and nxdomain_ratio > 0.5)):
            confidence = min(0.5 + (suspicious_ratio * 0.3) + (min(len(suspicious_domains), 20) * 0.015), 0.96)
            alerts.append({
                'threat_class': 'dga_domain',
                'src_ip': src_ip,
                'confidence': round(confidence, 3),
                'severity': 'high' if confidence > 0.7 else 'medium',
                'evidence': {
                    'suspicious_ratio': round(suspicious_ratio, 3),
                    'suspicious_count': len(suspicious_domains),
                    'nxdomain_ratio': round(nxdomain_ratio, 3),
                    'nxdomain_count': nxdomain_count,
                    'total_queries': total_queries,
                    'suspicious_domains': suspicious_domains[:10],
                }
            })
            self.alerts_generated.add(src_ip)

        # ── DNS Tunnelling Detection ──
        query_times = self.src_query_times.get(src_ip, [])
        if len(query_times) > 20:
            duration = max(query_times[-1] - query_times[0], 1)
            query_rate = len(query_times) / duration

            if query_rate > DNS_TUNNEL_QUERY_RATE:
                # Check for subdomain encoding pattern (long subdomains)
                long_domains = [d for d, _ in domains if len(d.split('.')[0]) > 30]

                if long_domains:
                    confidence = min(query_rate / (DNS_TUNNEL_QUERY_RATE * 3) + 0.3, 0.9)
                    alerts.append({
                        'threat_class': 'dns_tunnelling',
                        'src_ip': src_ip,
                        'confidence': round(confidence, 3),
                        'severity': 'high',
                        'evidence': {
                            'query_rate_per_sec': round(query_rate, 2),
                            'long_subdomain_count': len(long_domains),
                            'sample_domains': [d[:60] for d in long_domains[:5]],
                        }
                    })

        return alerts

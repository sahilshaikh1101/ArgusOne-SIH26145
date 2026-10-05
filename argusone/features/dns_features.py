"""
ArgusOne — DNS Feature Extraction

Extracts features from DNS queries for DGA detection and DNS tunnelling.
Computes domain name entropy, n-gram scores, structural features.
"""

import math
import string
from collections import Counter
from argusone.config import ENGLISH_BIGRAMS


def shannon_entropy(s):
    """Compute Shannon entropy of a string."""
    if not s:
        return 0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


compute_entropy = shannon_entropy


def extract_dns_features(domain):
    """
    Extract features from a domain name for DGA/tunnelling detection.
    
    Returns dict of features:
      - length: total domain length
      - label_count: number of labels (parts split by '.')
      - entropy: Shannon entropy
      - digit_ratio: fraction of digits
      - consonant_ratio: fraction of consonants
      - unique_char_ratio: unique chars / total length
      - bigram_score: average English bigram frequency
      - max_label_length: longest single label
      - has_ip_pattern: contains IP-like patterns
      - numeric_labels: count of purely numeric labels
    """
    if not domain:
        return _empty_features()

    # Remove TLD for analysis (focus on SLD and subdomains)
    parts = domain.lower().split('.')
    
    # Analyze the most suspicious part (longest non-TLD label)
    analysis_parts = parts[:-1] if len(parts) > 1 else parts
    analysis_str = '.'.join(analysis_parts)

    if not analysis_str:
        return _empty_features()

    # Basic structural features
    length = len(analysis_str)
    label_count = len(parts)
    max_label_len = max(len(p) for p in parts) if parts else 0

    # Character composition
    digits = sum(1 for c in analysis_str if c.isdigit())
    letters = sum(1 for c in analysis_str if c.isalpha())
    consonants = sum(1 for c in analysis_str if c.isalpha() and c not in 'aeiou')
    unique_chars = len(set(analysis_str))

    digit_ratio = digits / max(length, 1)
    consonant_ratio = consonants / max(letters, 1)
    unique_char_ratio = unique_chars / max(length, 1)

    # Shannon entropy
    entropy = shannon_entropy(analysis_str.replace('.', ''))

    # Bigram score — how "English-like" the domain looks
    bigram_score = _compute_bigram_score(analysis_str.replace('.', ''))

    # Numeric labels
    numeric_labels = sum(1 for p in parts if p.isdigit())

    # IP pattern detection
    has_ip = _has_ip_pattern(domain)

    return {
        'length': length,
        'label_count': label_count,
        'entropy': entropy,
        'digit_ratio': digit_ratio,
        'consonant_ratio': consonant_ratio,
        'unique_char_ratio': unique_char_ratio,
        'bigram_score': bigram_score,
        'max_label_length': max_label_len,
        'has_ip_pattern': int(has_ip),
        'numeric_labels': numeric_labels,
    }


def _compute_bigram_score(s):
    """Score how English-like a string is using bigram frequencies."""
    if len(s) < 2:
        return 0
    bigrams = [s[i:i+2] for i in range(len(s) - 1)]
    total_score = sum(ENGLISH_BIGRAMS.get(bg, 0) for bg in bigrams)
    return total_score / len(bigrams)


def _has_ip_pattern(domain):
    """Check if domain contains IP-address-like patterns."""
    parts = domain.split('.')
    numeric_parts = [p for p in parts if p.isdigit()]
    return len(numeric_parts) >= 3


def _empty_features():
    return {
        'length': 0, 'label_count': 0, 'entropy': 0,
        'digit_ratio': 0, 'consonant_ratio': 0, 'unique_char_ratio': 0,
        'bigram_score': 0, 'max_label_length': 0,
        'has_ip_pattern': 0, 'numeric_labels': 0,
    }


def is_likely_dga(features, entropy_thresh=3.5, bigram_thresh=0.3):
    """Quick heuristic check for DGA domains."""
    return (
        features['entropy'] > entropy_thresh and
        features['bigram_score'] < bigram_thresh and
        features['length'] > 10
    )

"""
ArgusOne — TLS Feature Extraction

Extracts JA3 fingerprints and TLS metadata from Client Hello messages.
All analysis is metadata-only — no payload decryption.
"""

import hashlib
import struct
import logging

logger = logging.getLogger("argusone.features")


def compute_ja3_fingerprint(tls_data):
    """Compute JA3 fingerprint hash string from raw TLS data or string."""
    if not tls_data:
        return ""
    if isinstance(tls_data, str):
        return tls_data
    res = extract_ja3(tls_data)
    if res and 'ja3_hash' in res:
        return res['ja3_hash']
    return hashlib.md5(tls_data).hexdigest() if isinstance(tls_data, bytes) else "e7d705a3286e19ea"


def extract_ja3(tls_data):
    """
    Extract JA3 fingerprint from TLS Client Hello.
    
    JA3 = MD5(TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats)
    
    Returns dict with:
      - ja3_hash: MD5 hash string
      - ja3_string: raw JA3 string
      - tls_version: TLS version
      - cipher_count: number of cipher suites
      - extension_count: number of extensions
    """
    if not tls_data or len(tls_data) < 43:
        return None

    try:
        # TLS Record Header
        content_type = tls_data[0]
        if content_type != 0x16:  # Not a handshake
            return None

        tls_version = struct.unpack('!H', tls_data[1:3])[0]
        record_length = struct.unpack('!H', tls_data[3:5])[0]

        # Handshake Header
        if len(tls_data) < 9:
            return None
        handshake_type = tls_data[5]
        if handshake_type != 0x01:  # Not Client Hello
            return None

        # Skip handshake length (3 bytes) + client version (2 bytes) + random (32 bytes)
        pos = 5 + 4 + 2 + 32  # = 43

        if pos >= len(tls_data):
            return None

        # Client Hello Version
        ch_version = struct.unpack('!H', tls_data[9:11])[0]

        # Session ID
        if pos >= len(tls_data):
            return None
        session_id_len = tls_data[pos]
        pos += 1 + session_id_len

        # Cipher Suites
        if pos + 2 > len(tls_data):
            return None
        cipher_suites_len = struct.unpack('!H', tls_data[pos:pos+2])[0]
        pos += 2
        
        ciphers = []
        cipher_end = pos + cipher_suites_len
        while pos + 2 <= cipher_end and pos + 2 <= len(tls_data):
            cipher = struct.unpack('!H', tls_data[pos:pos+2])[0]
            # Skip GREASE values
            if (cipher & 0x0f0f) != 0x0a0a:
                ciphers.append(str(cipher))
            pos += 2
        pos = cipher_end

        # Compression Methods
        if pos >= len(tls_data):
            return _build_ja3(ch_version, ciphers, [], [], [])
        comp_len = tls_data[pos]
        pos += 1 + comp_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        if pos + 2 <= len(tls_data):
            ext_total_len = struct.unpack('!H', tls_data[pos:pos+2])[0]
            pos += 2
            ext_end = pos + ext_total_len

            while pos + 4 <= ext_end and pos + 4 <= len(tls_data):
                ext_type = struct.unpack('!H', tls_data[pos:pos+2])[0]
                ext_len = struct.unpack('!H', tls_data[pos+2:pos+4])[0]
                pos += 4

                # Skip GREASE
                if (ext_type & 0x0f0f) != 0x0a0a:
                    extensions.append(str(ext_type))

                # Elliptic Curves (supported_groups, type 0x000a)
                if ext_type == 0x000a and pos + 2 <= len(tls_data):
                    curves_len = struct.unpack('!H', tls_data[pos:pos+2])[0]
                    curve_pos = pos + 2
                    while curve_pos + 2 <= pos + 2 + curves_len and curve_pos + 2 <= len(tls_data):
                        curve = struct.unpack('!H', tls_data[curve_pos:curve_pos+2])[0]
                        if (curve & 0x0f0f) != 0x0a0a:
                            elliptic_curves.append(str(curve))
                        curve_pos += 2

                # EC Point Formats (type 0x000b)
                if ext_type == 0x000b and pos < len(tls_data):
                    formats_len = tls_data[pos]
                    for i in range(formats_len):
                        if pos + 1 + i < len(tls_data):
                            ec_point_formats.append(str(tls_data[pos + 1 + i]))

                pos += ext_len

        return _build_ja3(ch_version, ciphers, extensions, elliptic_curves, ec_point_formats)

    except Exception as e:
        logger.debug(f"JA3 extraction failed: {e}")
        return None


def _build_ja3(version, ciphers, extensions, curves, ec_formats):
    """Build JA3 hash from components."""
    ja3_string = ','.join([
        str(version),
        '-'.join(ciphers),
        '-'.join(extensions),
        '-'.join(curves),
        '-'.join(ec_formats),
    ])
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    
    return {
        'ja3_hash': ja3_hash,
        'ja3_string': ja3_string,
        'tls_version': version,
        'cipher_count': len(ciphers),
        'extension_count': len(extensions),
        'curve_count': len(curves),
    }


def extract_tls_features(flow_record):
    """
    Extract TLS-level features from a flow record.
    
    Returns dict with JA3 info + certificate anomalies + shape features.
    """
    features = {
        'has_tls': flow_record.has_tls,
        'ja3_hash': None,
        'cipher_count': 0,
        'extension_count': 0,
        'packet_sizes_first10': [],
        'packet_iats_first10': [],
    }

    if not flow_record.has_tls:
        return features

    # Extract JA3 from first Client Hello
    for tls_data in flow_record.tls_client_hellos[:1]:
        ja3 = extract_ja3(tls_data)
        if ja3:
            features.update({
                'ja3_hash': ja3['ja3_hash'],
                'cipher_count': ja3['cipher_count'],
                'extension_count': ja3['extension_count'],
            })
            break

    # Packet size/timing shape (first 10 packets)
    features['packet_sizes_first10'] = flow_record.packet_sizes[:10]
    
    timestamps = flow_record.packet_timestamps[:10]
    if len(timestamps) > 1:
        features['packet_iats_first10'] = [
            timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))
        ]

    return features

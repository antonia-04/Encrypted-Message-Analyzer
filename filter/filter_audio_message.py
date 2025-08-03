# Re-importăm după reset
import pyshark
from datetime import datetime
import ipaddress
import os


# Load IP ranges from file
def load_whatsapp_ips():
    file_path = os.path.join("filter", "ip_whatsapp.txt")
    ips = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                ips.append(ipaddress.ip_network(line))
    return ips


# Check if IP is in WhatsApp ranges
def is_whatsapp_ip(ip_input, whatsapp_ips):
    ip = ipaddress.ip_address(ip_input)
    return any(ip in net for net in whatsapp_ips)


# Format timestamp
def format_ts_pyshark(ts):
    return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')


# Detect WhatsApp voice messages
def detect_audio_messages(pcap_path, min_total_len=3500, min_packets=4):
    print("\nDetecting WhatsApp audio messages...")

    whatsapp_ips = load_whatsapp_ips()
    capture = pyshark.FileCapture(pcap_path, display_filter='tcp.port == 443')

    audio_streams = {}

    for pkt in capture:
        try:
            ip_layer = pkt.ip
            tcp_layer = pkt.tcp
            tls_layer = getattr(pkt, 'tls', None)

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = int(pkt.length)
            stream_id = tcp_layer.stream
            timestamp = pkt.sniff_timestamp

            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            if tls_layer and 'Application Data' not in str(tls_layer):
                continue

            if stream_id not in audio_streams:
                audio_streams[stream_id] = {
                    'packets': [],
                    'total_len': 0,
                    'src': src_ip,
                    'dst': dst_ip,
                    'timestamp': format_ts_pyshark(timestamp)
                }

            audio_streams[stream_id]['packets'].append(pkt)
            audio_streams[stream_id]['total_len'] += length

        except AttributeError:
            continue

    capture.close()

    audio_messages = []
    for stream_id, info in audio_streams.items():
        if len(info['packets']) >= min_packets and info['total_len'] >= min_total_len:
            audio_messages.append({
                'timestamp': info['timestamp'],
                'src': info['src'],
                'dst': info['dst'],
                'stream_id': stream_id,
                'packet_count': len(info['packets']),
                'total_length': info['total_len'],
                'type': 'audio_message'
            })

    if not audio_messages:
        print("No audio messages detected.")
    else:
        print(f"\n=== Detected {len(audio_messages)} WhatsApp audio message(s) ===")
        for msg in audio_messages:
            print(
                f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | stream {msg['stream_id']} | {msg['packet_count']} pkts | {msg['total_length']} bytes")

    return audio_messages

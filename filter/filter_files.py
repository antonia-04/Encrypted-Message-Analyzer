import pyshark
import ipaddress
import os
from datetime import datetime

# Load WhatsApp IPs from file
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

# Relaxed file detection
def detect_file_messages(pcap_path, min_total_len=15000, min_packets=5):
    print("\n[INFO] Detecting WhatsApp file transfers (relaxed mode)...")

    whatsapp_ips = load_whatsapp_ips()
    capture = pyshark.FileCapture(pcap_path, use_json=True, include_raw=False)

    file_streams = {}

    for pkt in capture:
        try:
            if 'TCP' not in pkt or 'IP' not in pkt:
                continue

            ip_layer = pkt.ip
            tcp_layer = pkt.tcp
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = int(pkt.length)
            stream_id = tcp_layer.stream
            timestamp = pkt.sniff_timestamp

            # Check if one of the IPs is WhatsApp
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            if stream_id not in file_streams:
                file_streams[stream_id] = {
                    'packets': [],
                    'total_len': 0,
                    'src': src_ip,
                    'dst': dst_ip,
                    'timestamp': format_ts_pyshark(timestamp)
                }

            file_streams[stream_id]['packets'].append(pkt)
            file_streams[stream_id]['total_len'] += length

        except AttributeError:
            continue

    capture.close()

    file_messages = []
    for stream_id, info in file_streams.items():
        if len(info['packets']) >= min_packets and info['total_len'] >= min_total_len:
            avg_packet_size = info['total_len'] / len(info['packets'])
            print(f"[DEBUG] Stream {stream_id} | {info['src']} → {info['dst']} | {len(info['packets'])} pkts | {info['total_len']} bytes")

            file_messages.append({
                'timestamp': info['timestamp'],
                'src': info['src'],
                'dst': info['dst'],
                'stream_id': stream_id,
                'packet_count': len(info['packets']),
                'total_length': info['total_len'],
                'avg_packet_size': round(avg_packet_size, 1),
                'type': 'file_transfer'
            })

    return file_messages

# Display output
def print_detected_files(file_messages):
    if not file_messages:
        print("No WhatsApp file transfers detected.")
        return

    print(f"\n=== Detected {len(file_messages)} WhatsApp file transfer(s) ===")
    for msg in file_messages:
        print(f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | stream {msg['stream_id']} | {msg['packet_count']} pkts | {msg['total_length']} bytes | avg size {msg['avg_packet_size']} bytes")

import os
import ipaddress
import pyshark
from datetime import datetime

# === Încarcă IP-urile WhatsApp din fișier ===
def load_whatsapp_ips():
    file_path = os.path.join("filter", "ip_whatsapp.txt")
    ips = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                ips.append(ipaddress.ip_network(line))
    return ips

# === Verifică dacă un IP aparține rețelelor WhatsApp ===
def is_whatsapp_ip(ip_input, whatsapp_ips):
    try:
        ip = ipaddress.ip_address(ip_input)
        return any(ip in net for net in whatsapp_ips)
    except ValueError:
        return False

# === Formatează timestamp-ul din pachet ===
def format_ts_pyshark(ts):
    return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')

# === Detectează fluxuri TCP scurte către IP-uri WhatsApp (candidați pt. locație) ===
def detect_location_messages(pcap_path, min_pkt=2, max_pkt=100, max_bytes=30000):
    print("\n[INFO] Detecting WhatsApp location messages (short TCP streams to WhatsApp IPs)...")

    whatsapp_ips = load_whatsapp_ips()
    capture = pyshark.FileCapture(pcap_path, use_json=True, include_raw=False)

    stream_data = {}

    for pkt in capture:
        try:
            if 'TCP' not in pkt or 'IP' not in pkt:
                continue

            ip_layer = pkt.ip
            tcp_layer = pkt.tcp
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            stream_id = tcp_layer.stream
            pkt_len = int(pkt.length)
            timestamp = pkt.sniff_timestamp

            # Filtrăm doar ce merge spre/spre WhatsApp
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            if stream_id not in stream_data:
                stream_data[stream_id] = {
                    'src': src_ip,
                    'dst': dst_ip,
                    'packets': 0,
                    'bytes': 0,
                    'timestamp': format_ts_pyshark(timestamp)
                }

            stream_data[stream_id]['packets'] += 1
            stream_data[stream_id]['bytes'] += pkt_len

        except AttributeError:
            continue

    capture.close()

    # Heuristici pentru mesaj de tip locație: flux scurt, dimensiune mică
    detected = []
    for stream_id, info in stream_data.items():
        if min_pkt <= info['packets'] <= max_pkt and info['bytes'] <= max_bytes:
            detected.append({
                'timestamp': info['timestamp'],
                'src': info['src'],
                'dst': info['dst'],
                'stream_id': stream_id,
                'packet_count': info['packets'],
                'total_bytes': info['bytes'],
                'type': 'location_message'
            })

    return detected

# === Afișare rezultate ===
def print_detected_locations(locations):
    if not locations:
        print("No WhatsApp location messages detected.")
    else:
        print(f"\n=== Detected {len(locations)} WhatsApp location message(s) ===")
        for loc in locations:
            print(f"[{loc['timestamp']}] {loc['src']} → {loc['dst']} | "
                  f"stream {loc['stream_id']} | {loc['packet_count']} pkts | "
                  f"{loc['total_bytes']} bytes")

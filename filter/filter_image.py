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

# Check if IP is from WhatsApp
def is_whatsapp_ip(ip_input, whatsapp_ips):
    ip = ipaddress.ip_address(ip_input)
    return any(ip in net for net in whatsapp_ips)

# Format timestamp
def format_ts_pyshark(ts):
    return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')

# Detect possible images using SNI + heuristics
def detect_images_by_sni(pcap_path, min_packets=10, min_total_len=4000):
    print("\n[INFO] Detecting WhatsApp images (based on SNI domains and flow size)...")

    whatsapp_ips = load_whatsapp_ips()
    capture = pyshark.FileCapture(pcap_path, use_json=True, include_raw=False)

    image_streams = {}

    for pkt in capture:
        try:
            if 'IP' not in pkt or 'TCP' not in pkt:
                continue
            if not hasattr(pkt.tcp, 'stream'):
                continue

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            stream_id = pkt.tcp.stream
            timestamp = pkt.sniff_timestamp
            length = int(pkt.length)

            # must involve a WhatsApp IP
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            # SNI detection from TLS handshake (optional but useful)
            sni = ""
            if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                sni = pkt.tls.handshake_extensions_server_name.lower()

            if stream_id not in image_streams:
                image_streams[stream_id] = {
                    "packets": 0,
                    "total_len": 0,
                    "src": src_ip,
                    "dst": dst_ip,
                    "timestamp": format_ts_pyshark(timestamp),
                    "sni": sni
                }

            image_streams[stream_id]["packets"] += 1
            image_streams[stream_id]["total_len"] += length
            if sni:
                image_streams[stream_id]["sni"] = sni

        except AttributeError:
            continue

    capture.close()

    # Filter by heuristic
    detected = []
    for stream_id, info in image_streams.items():
        if info["packets"] >= min_packets and info["total_len"] >= min_total_len:
            avg_len = round(info["total_len"] / info["packets"])
            detected.append({
                "stream": stream_id,
                "src": info["src"],
                "dst": info["dst"],
                "timestamp": info["timestamp"],
                "packet_count": info["packets"],
                "total_len": info["total_len"],
                "avg_len": avg_len,
                "sni": info["sni"]
            })

    return detected

# Display results
def print_detected_images(image_streams):
    if not image_streams:
        print("No image transfers detected.")
        return

    print(f"\n=== Detected {len(image_streams)} image/media streams ===")
    for img in image_streams:
        print(f"  [{img['timestamp']}] {img['src']} → {img['dst']} | stream {img['stream']} | "
              f"{img['packet_count']} pkts | {img['total_len']} bytes | avg {img['avg_len']} B"
              + (f" | SNI: {img['sni']}" if img['sni'] else ""))


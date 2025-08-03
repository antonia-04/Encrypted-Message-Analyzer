import pyshark
import ipaddress
import os
from datetime import datetime
from filter.whatsapp_ips import is_whatsapp_ip
from filter.formatter import format_ts_pyshark


def detect_images_by_sni(pcap_path, whatsapp_ips, min_packets=10, min_total_len=4000):
    print("\n[INFO] Detecting WhatsApp images (based on SNI domains and flow size)...")

    capture = pyshark.FileCapture(pcap_path, use_json=True, include_raw=False)
    image_streams = {}

    for pkt in capture:
        try:
            if 'IP' not in pkt or 'TCP' not in pkt or not hasattr(pkt.tcp, 'stream'):
                continue

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            stream_id = pkt.tcp.stream
            timestamp = pkt.sniff_timestamp
            length = int(pkt.length)

            # must involve a whatsapp IP
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            # optional: extract SNI if available
            sni = ""
            if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                sni = pkt.tls.handshake_extensions_server_name.lower()

            if stream_id not in image_streams:
                image_streams[stream_id] = {
                    "packet_count": 0,
                    "total_len": 0,
                    "src": src_ip,
                    "dst": dst_ip,
                    "timestamp": format_ts_pyshark(timestamp),
                    "sni": sni
                }

            image_streams[stream_id]["packet_count"] += 1
            image_streams[stream_id]["total_len"] += length
            if sni:
                image_streams[stream_id]["sni"] = sni

        except AttributeError:
            continue

    capture.close()

    # filter by flow size and packet count
    detected = []
    for stream_id, info in image_streams.items():
        if info["packet_count"] >= min_packets and info["total_len"] >= min_total_len:
            avg_len = round(info["total_len"] / info["packet_count"])
            detected.append({
                "timestamp": info["timestamp"],
                "src": info["src"],
                "dst": info["dst"],
                "stream": stream_id,
                "packet_count": info["packet_count"],
                "total_len": info["total_len"],
                "avg_len": avg_len,
                "sni": info["sni"],
                "type": "image"
            })

    return detected


def print_detected_images(image_streams):
    if not image_streams:
        print("No image transfers detected.")
        return

    print(f"\n=== Detected {len(image_streams)} image/media streams ===")
    for img in image_streams:
        print(f"  [{img['timestamp']}] {img['src']} → {img['dst']} | stream {img['stream']} | "
              f"{img['packet_count']} pkts | {img['total_len']} bytes | avg {img['avg_len']} B"
              + (f" | SNI: {img['sni']}" if img['sni'] else ""))

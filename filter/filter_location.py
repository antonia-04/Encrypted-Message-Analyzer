import pyshark
from filter.whatsapp_ips import is_whatsapp_ip
from filter.formatter import format_ts_pyshark


def detect_location_messages(pcap_path, whatsapp_ips, min_pkt=2, max_pkt=100, max_bytes=30000):
    print("\n[INFO] Detecting WhatsApp location messages (short TCP streams)...")

    capture = pyshark.FileCapture(pcap_path, use_json=True, include_raw=False)
    stream_data = {}

    for pkt in capture:
        try:
            if 'TCP' not in pkt or 'IP' not in pkt or not hasattr(pkt.tcp, 'stream'):
                continue

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            stream_id = pkt.tcp.stream
            pkt_len = int(pkt.length)
            timestamp = pkt.sniff_timestamp

            # must involve a whatsapp ip
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            if stream_id not in stream_data:
                stream_data[stream_id] = {
                    "src": src_ip,
                    "dst": dst_ip,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "timestamp": format_ts_pyshark(timestamp)
                }

            stream_data[stream_id]["packet_count"] += 1
            stream_data[stream_id]["total_bytes"] += pkt_len

        except AttributeError:
            continue

    capture.close()

    # short stream, low total size
    location_messages = []

    for stream_id, info in stream_data.items():
        if min_pkt <= info["packet_count"] <= max_pkt and info["total_bytes"] <= max_bytes:
            location_messages.append({
                "timestamp": info["timestamp"],
                "src": info["src"],
                "dst": info["dst"],
                "stream_id": stream_id,
                "packet_count": info["packet_count"],
                "total_bytes": info["total_bytes"],
                "type": "location_message"
            })

    return location_messages


def print_detected_locations(locations):
    if not locations:
        print("No WhatsApp location messages detected.")
        return

    print(f"\n=== Detected {len(locations)} WhatsApp location message(s) ===")
    for msg in locations:
        print(f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | "
              f"stream {msg['stream_id']} | {msg['packet_count']} pkts | "
              f"{msg['total_bytes']} bytes")

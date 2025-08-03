import pyshark
from filter.whatsapp_ips import is_whatsapp_ip
from filter.formatter import format_ts_pyshark

def detect_video_messages(pcap_path, whatsapp_ips, min_packets=100, min_total_bytes=500_000):
    print("\n[INFO] Detecting WhatsApp video messages (large TCP streams)...")

    capture = pyshark.FileCapture(pcap_path, use_json=True, include_raw=False)
    video_streams = {}

    for pkt in capture:
        try:
            if 'TCP' not in pkt or 'IP' not in pkt or not hasattr(pkt.tcp, 'stream'):
                continue

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            stream_id = pkt.tcp.stream
            length = int(pkt.length)
            timestamp = pkt.sniff_timestamp

            # must involve a whatsapp ip
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            if stream_id not in video_streams:
                video_streams[stream_id] = {
                    "packets": 0,
                    "total_len": 0,
                    "src": src_ip,
                    "dst": dst_ip,
                    "timestamp": format_ts_pyshark(timestamp)
                }

            video_streams[stream_id]["packets"] += 1
            video_streams[stream_id]["total_len"] += length

        except AttributeError:
            continue

    capture.close()

    detected = []
    for stream_id, info in video_streams.items():
        if info["packets"] >= min_packets and info["total_len"] >= min_total_bytes:
            avg_size = info["total_len"] / info["packets"]
            detected.append({
                "timestamp": info["timestamp"],
                "src": info["src"],
                "dst": info["dst"],
                "stream_id": stream_id,
                "packet_count": info["packets"],
                "total_length": info["total_len"],
                "avg_packet_size": round(avg_size, 1),
                "type": "video_message"
            })

    return detected

def print_detected_videos(video_messages):
    if not video_messages:
        print("No WhatsApp video messages detected.")
        return

    print(f"\n=== Detected {len(video_messages)} WhatsApp video message(s) ===")
    for msg in video_messages:
        print(f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | "
              f"stream {msg['stream_id']} | {msg['packet_count']} pkts | "
              f"{msg['total_length']} bytes | avg {msg['avg_packet_size']} bytes")

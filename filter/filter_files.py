import pyshark
from filter.whatsapp_ips import load_whatsapp_ips, is_whatsapp_ip
from filter.formatter import format_ts_pyshark


def detect_file_messages(pcap_path, whatsapp_ips, min_total_len=15000, min_packets=5):
    print("\n[INFO] Detecting whatsapp file transfers...")

    # capture all TCP packets
    capture = pyshark.FileCapture(pcap_path, display_filter="tcp.port == 443")

    file_streams = {}

    for pkt in capture:
        try:
            # skip packets without IP/TCP
            if not hasattr(pkt, "ip") or not hasattr(pkt, "tcp"):
                continue

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            length = int(pkt.length)
            stream_id = pkt.tcp.stream
            timestamp = pkt.sniff_timestamp

            # must involve a whatsapp IP
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            # initialize new stream entry
            if stream_id not in file_streams:
                file_streams[stream_id] = {
                    "packet_count": 0,
                    "total_len": 0,
                    "src": src_ip,
                    "dst": dst_ip,
                    "timestamp": format_ts_pyshark(timestamp)
                }

            # update stream stats
            file_streams[stream_id]["packet_count"] += 1
            file_streams[stream_id]["total_len"] += length

        except AttributeError:
            continue

    capture.close()

    # build results
    file_messages = []
    for stream_id, info in file_streams.items():
        if info["packet_count"] >= min_packets and info["total_len"] >= min_total_len:
            avg_packet_size = info["total_len"] / info["packet_count"]
            file_messages.append({
                "timestamp": info["timestamp"],
                "src": info["src"],
                "dst": info["dst"],
                "stream_id": stream_id,
                "packet_count": info["packet_count"],
                "total_length": info["total_len"],
                "avg_packet_size": round(avg_packet_size, 1),
                "type": "file_transfer"
            })

    return file_messages


def print_detected_files(file_messages):
    if not file_messages:
        print("No whatsapp file transfers detected.")
        return

    print(f"\n=== Detected {len(file_messages)} whatsapp file transfer(s) ===")
    for msg in file_messages:
        print(f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | stream {msg['stream_id']} | "
              f"{msg['packet_count']} pkts | {msg['total_length']} bytes | avg size {msg['avg_packet_size']} bytes")

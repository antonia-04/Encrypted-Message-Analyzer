import pyshark
from filter.whatsapp_ips import is_whatsapp_ip
from filter.formatter import format_ts_pyshark

def detect_audio_messages(pcap_path, whatsapp_ips, min_total_len=3500, min_packets=4):
    print("\n[INFO] Detecting whatsapp audio messages...")

    # capture only TCP traffic on port 443 (TLS)
    capture = pyshark.FileCapture(pcap_path, display_filter="tcp.port == 443")

    audio_streams = {}

    for pkt in capture:
        try:
            # skip packets without ip/tcp
            if not hasattr(pkt, "ip") or not hasattr(pkt, "tcp"):
                continue

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            length = int(pkt.length)
            stream_id = pkt.tcp.stream
            timestamp = pkt.sniff_timestamp
            tls_layer = getattr(pkt, "tls", None)

            # must involve a whatsapp IP
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            # must be TLS application data
            if tls_layer and "Application Data" not in str(tls_layer):
                continue

            # initialize stream if not yet seen
            if stream_id not in audio_streams:
                audio_streams[stream_id] = {
                    "packet_count": 0,
                    "total_len": 0,
                    "src": src_ip,
                    "dst": dst_ip,
                    "timestamp": format_ts_pyshark(timestamp)
                }

            audio_streams[stream_id]["packet_count"] += 1
            audio_streams[stream_id]["total_len"] += length

        except AttributeError:
            continue  # skip incomplete packets

    capture.close()

    # build result list based on thresholds
    audio_messages = []
    # stream, details for stream
    for stream_id, info in audio_streams.items():
        if info["packet_count"] >= min_packets and info["total_len"] >= min_total_len:
            audio_messages.append({
                "timestamp": info["timestamp"],
                "src": info["src"],
                "dst": info["dst"],
                "stream_id": stream_id,
                "packet_count": info["packet_count"],
                "total_length": info["total_len"],
                "type": "audio_message"
            })

    # print summary
    if not audio_messages:
        print("No audio messages detected.")
    else:
        print(f"\n=== Detected {len(audio_messages)} whatsapp audio message(s) ===")
        for msg in audio_messages:
            print(f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | "
                  f"stream {msg['stream_id']} | {msg['packet_count']} pkts | {msg['total_length']} bytes")

    return audio_messages

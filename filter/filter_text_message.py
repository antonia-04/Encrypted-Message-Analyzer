import pyshark
from filter.formatter import format_ts_pyshark
from filter.whatsapp_ips import load_whatsapp_ips, is_whatsapp_ip

def detect_text_messages(pcap_path, whatsapp_ips, min_len=80, max_len=600):
    print("\n[INFO] Detecting whatsapp text messages...")

    # load whatsapp IPs from file
    ## whatsapp_ips = load_whatsapp_ips()

    # capture only TCP traffic on port 443 (TLS)
    # pyshark to not lose data!
    capture = pyshark.FileCapture(pcap_path, display_filter="tcp.port == 443")

    text_messages = []
    seen_streams = set()

    for pkt in capture:
        try:
            # skip if packet doesn't have ip and tcp layers
            # hasattr -> has ATTRIBUTE
            if not hasattr(pkt, "ip") or not hasattr(pkt, "tcp"):
                continue

            # extract basic info
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            length = int(pkt.length)
            stream_id = pkt.tcp.stream
            timestamp = pkt.sniff_timestamp
            tls_layer = getattr(pkt, "tls", None)

            # check if packet size is within expected text message bounds
            if not (min_len <= length <= max_len):
                continue

            # ensure this is application data (not handshake)
            if tls_layer and "Application Data" not in str(tls_layer):
                continue

            # one of the endpoints must be a whatsapp IP
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            # skip duplicate streams (each stream = 1 message)
            # duplicates -> seen/delivered etc
            if stream_id in seen_streams:
                continue
            seen_streams.add(stream_id)

            # append detected message metadata
            text_messages.append({
                "timestamp": format_ts_pyshark(timestamp),
                "src": src_ip,
                "dst": dst_ip,
                "length": length,
                "stream": stream_id,
                "type": "text_message"
            })

        except AttributeError:
            continue  # skip packets with missing fields

    capture.close()

    # print results
    if not text_messages:
        print("No text messages detected.")
    else:
        print(f"\n=== Detected {len(text_messages)} WhatsApp text message(s) ===")
        for msg in text_messages:
            print(f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | "
                  f"{msg['length']} bytes | stream {msg['stream']}")

    return text_messages

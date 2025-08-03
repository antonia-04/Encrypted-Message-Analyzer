import pyshark
from datetime import datetime
from filter.whatsapp_ips import load_whatsapp_ips, is_whatsapp_ip  # ajustează calea dacă e diferit

def format_ts_pyshark(ts):
    return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')

def detect_text_messages(pcap_path, min_len=80, max_len=600):
    print("\nDetecting WhatsApp text messages...")

    # Încarcă IP-urile WhatsApp (CIDR) din fișierul ip_whatsapp.txt
    whatsapp_ips = load_whatsapp_ips()

    # Deschide captura doar cu traficul TCP port 443
    capture = pyshark.FileCapture(pcap_path, display_filter='tcp.port == 443')

    messages = []
    seen_streams = set()

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

            # 1. Dimensiune specifică mesajelor text
            if not (min_len <= length <= max_len):
                continue

            # 2. Trebuie să fie Application Data în TLS
            if tls_layer and 'Application Data' not in str(tls_layer):
                continue

            # 3. IP sursă sau destinație trebuie să fie din rețelele WhatsApp
            if not (is_whatsapp_ip(src_ip, whatsapp_ips) or is_whatsapp_ip(dst_ip, whatsapp_ips)):
                continue

            # 4. Evită duplicatele pe același flux TCP
            if stream_id in seen_streams:
                continue
            seen_streams.add(stream_id)

            messages.append({
                'timestamp': format_ts_pyshark(timestamp),
                'src': src_ip,
                'dst': dst_ip,
                'length': length,
                'stream': stream_id,
                'type': 'text_message'
            })

        except AttributeError:
            continue

    capture.close()

    if not messages:
        print("No text messages detected.")
    else:
        print(f"\n=== Detected {len(messages)} WhatsApp text message(s) ===")
        for msg in messages:
            print(f"  [{msg['timestamp']}] {msg['src']} → {msg['dst']} | {msg['length']} bytes | stream {msg['stream']}")

    return messages

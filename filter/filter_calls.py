from scapy.all import rdpcap, IP, UDP
from filter.formatter import format_ts_pyshark


def is_voip_udp(pkt):
    return IP in pkt and UDP in pkt and (
            20000 <= pkt[UDP].sport <= 65535 or 20000 <= pkt[UDP].dport <= 65535
    )

# 192.168 comum
def detect_call_messages(pcap_path, min_packets=20, min_avg_len=300, local_prefix="192.168."):
    print("\n[INFO] Detecting WhatsApp calls...")

    # load and filter packets
    packets = rdpcap(pcap_path)
    relevant = [pkt for pkt in packets if is_voip_udp(pkt)]

    if not relevant:
        print("No VoIP-like UDP packets found.")
        return []

    # group by (src, dst) where src is local
    flows = {}
    for pkt in relevant:
        src, dst, time = pkt[IP].src, pkt[IP].dst, pkt.time
        if not src.startswith(local_prefix):
            continue
        flows.setdefault((src, dst), []).append({'time': time, 'length': len(pkt)})

    # find flow with longest duration and enough packets
    main_call = None
    for (src, dst), pkts in flows.items():
        if len(pkts) < min_packets:
            continue
        times = [p['time'] for p in pkts]
        duration = max(times) - min(times)
        if main_call is None or duration > main_call['duration']:
            main_call = {
                'src': src,
                'dst': [dst],
                'start': min(times),
                'end': max(times),
                'duration': duration,
                'packets': pkts
            }

    if not main_call:
        print("No call matched thresholds.")
        return []

    # include related packets in ±5s window
    # margin bcs loses connection
    margin = 5
    t0 = main_call['start'] - margin
    t1 = main_call['end'] + margin
    related = []
    for pkt in relevant:
        if t0 <= pkt.time <= t1 and (pkt[IP].src == main_call['src'] or pkt[IP].dst == main_call['src']):
            related.append({'length': len(pkt)})
            main_call['dst'].append(pkt[IP].dst)

    avg_len = sum(p['length'] for p in related) / len(related)
    call_type = "video_call" if avg_len > min_avg_len and main_call['duration'] > 20 else "audio_call"

    summary = {
        "src_ip": main_call['src'],
        "dst_ips": list(set(main_call['dst'])),
        "start_time": format_ts_pyshark(main_call['start']),
        "end_time": format_ts_pyshark(main_call['end']),
        "duration_sec": round(main_call['end'] - main_call['start'], 2),
        "packet_count": len(related),
        "avg_packet_size": round(avg_len, 1),
        "type": call_type
    }

    print("\n=== Detected WhatsApp Call ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    return [summary]

from scapy.all import rdpcap, IP, UDP
from datetime import datetime
from collections import defaultdict


def format_timestamp(ts):
    """Convert UNIX timestamp to readable string."""
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def is_possible_call_packet(pkt):
    """Check if packet is UDP and uses high ports (likely for VoIP)."""
    if IP in pkt and UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        return 20000 <= sport <= 65535 or 20000 <= dport <= 65535
    return False


def extract_relevant_udp_packets(pcap_path):
    """Load packets from file and return only relevant UDP packets."""
    packets = rdpcap(pcap_path)
    filtered = []

    for pkt in packets:
        if is_possible_call_packet(pkt):
            filtered.append({
                'src': pkt[IP].src,
                'dst': pkt[IP].dst,
                'time': pkt.time,
                'length': len(pkt)
            })

    print(f"[DEBUG] Extracted {len(filtered)} possible call packets")
    return filtered


def find_local_initiated_flows(packets, local_prefix="192.168."):
    """Group packets by (src, dst) if src starts with local_prefix."""
    grouped = defaultdict(list)

    for pkt in packets:
        if pkt['src'].startswith(local_prefix):
            grouped[(pkt['src'], pkt['dst'])].append(pkt)

    return grouped


def select_main_call_flow(grouped_flows, min_packets=20):
    """From grouped flows, select the one with longest duration and enough packets."""
    best_flow = None

    for (src, dst), pkts in grouped_flows.items():
        if len(pkts) < min_packets:
            continue

        times = [p['time'] for p in pkts]
        duration = max(times) - min(times)

        if best_flow is None or duration > best_flow['duration']:
            best_flow = {
                'src_ip': src,
                'dst_ips': {dst},
                'start': min(times),
                'end': max(times),
                'duration': duration,
                'packets': pkts
            }

    return best_flow


def collect_all_related_packets(main_call, all_packets, margin_sec=5):
    """Find all packets within ±margin_sec of main call involving same src_ip."""
    t_start = main_call['start'] - margin_sec
    t_end = main_call['end'] + margin_sec
    local_ip = main_call['src_ip']
    dst_ips = set(main_call['dst_ips'])
    related = []

    for pkt in all_packets:
        if t_start <= pkt['time'] <= t_end and (pkt['src'] == local_ip or pkt['dst'] == local_ip):
            related.append(pkt)
            dst_ips.add(pkt['dst'])

    return related, dst_ips


def build_call_summary(main_call, related_packets, dst_ips):
    """Return a dictionary summarizing the full call."""
    lengths = [p['length'] for p in related_packets]
    avg_len = sum(lengths) / len(lengths) if lengths else 0

    return {
        'src_ip': main_call['src_ip'],
        'dst_ips': list(dst_ips),
        'start_time': format_timestamp(main_call['start']),
        'end_time': format_timestamp(main_call['end']),
        'duration_sec': round(main_call['end'] - main_call['start'], 2),
        'packet_count': len(related_packets),
        'avg_packet_size': round(avg_len, 1),
        'type': 'video_call' if avg_len > 300 and (main_call['end'] - main_call['start']) > 20 else 'audio_call'
    }


def detect_full_call_merged(pcap_path):
    """Main detection pipeline for WhatsApp call."""
    print("\nDetecting WhatsApp calls...")
    all_packets = extract_relevant_udp_packets(pcap_path)
    grouped_flows = find_local_initiated_flows(all_packets)
    main_call = select_main_call_flow(grouped_flows)

    if not main_call:
        print("No call found from local IP.")
        return []

    related_packets, dst_ips = collect_all_related_packets(main_call, all_packets)
    summary = build_call_summary(main_call, related_packets, dst_ips)

    print("\n=== Detected WhatsApp Call ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    return [summary]

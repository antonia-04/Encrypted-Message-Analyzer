# filter the file given from wireshark
from scapy.utils import rdpcap
from scapy.all import IP, TCP, UDP

from filter.whatsapp_ips import load_whatsapp_ips, is_whatsapp_ip
import datetime


# primul nivel de filtrare: luam doar pachetele trimise/primite de la adrese de whatsapp
# all packages that go/come from whatsapp servers
# e scapy, mai util pyshark
def filter_whatsapp(pcap_path):
    whatsapp_ips = load_whatsapp_ips()
    # loads all the packets from wireshark file
    packets = rdpcap(pcap_path)

    filtered_packets = []

    for pkt in packets:
        # verify that the packets has IP layer, else ignores
        if IP in pkt:
            source_ip = pkt[IP].src
            dest_ip = pkt[IP].dst

            if is_whatsapp_ip(source_ip, whatsapp_ips) or is_whatsapp_ip(dest_ip, whatsapp_ips):
                filtered_packets.append(pkt)

    return filtered_packets


# results filtered in html file
def generate_html_filtered(packets, output_file="filtered.html"):
    rows = []

    for pkt in packets:
        if IP in pkt:
            timestamp = datetime.datetime.fromtimestamp(pkt.time)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            length = len(pkt)

            if TCP in pkt:
                protocol = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                protocol = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                protocol = "N/A"
                sport = dport = "N/A"
            rows.append((timestamp, src_ip, dst_ip, sport, dport, protocol, length))

    with open(output_file, "w") as f:
        f.write("<html><head><title>WhatsApp Traffic Report</title></head><body>")
        f.write("<h2>WhatsApp Traffic Report – Metadata</h2>")
        f.write("<table border='1' cellpadding='5'>")
        f.write("<tr><th>#</th><th>Timestamp</th><th>Src IP</th><th>Dst IP</th>"
                "<th>Src Port</th><th>Dst Port</th><th>Protocol</th><th>Length (bytes)</th></tr>")

        for idx, (ts, src, dst, sport, dport, proto, length) in enumerate(rows, 1):
            f.write(f"<tr><td>{idx}</td><td>{ts}</td><td>{src}</td><td>{dst}</td>"
                    f"<td>{sport}</td><td>{dport}</td><td>{proto}</td><td>{length}</td></tr>")

        f.write("</table></body></html>")

    print("HTML File generated!")

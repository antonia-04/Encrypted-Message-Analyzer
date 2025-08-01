# filter the file given from wireshark
from scapy.utils import rdpcap
from scapy.all import IP

from filter.whatsapp_ips import load_whatsapp_ips, is_whatsapp_ip


# primul nivel de filtrare: luam doar pachetele trimise/primite de la adrese de whatsapp
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

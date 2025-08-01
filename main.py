from capture.loader import load_wireshark_file
from filter.filter import filter_whatsapp

if __name__ == "__main__":
    pcap_file = "capture1.pcapng"
    filtered = filter_whatsapp(pcap_file)
    print(f"Pachete WhatsApp detectate: {len(filtered)}")

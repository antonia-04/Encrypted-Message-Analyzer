# main.py
from capture.loader import load_wireshark_file
from filter.filter import filter_whatsapp


# === 4. Exemplu de utilizare ===
if __name__ == "__main__":
    pcap_file = "capture1.pcapng"  # sau "filter/captura.pcap" dacă e și el acolo
    filtered = filter_whatsapp(pcap_file)
    print(f"Pachete WhatsApp detectate: {len(filtered)}")


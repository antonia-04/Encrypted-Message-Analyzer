# filter the file given from wireshark
import ipaddress
import os.path


# load from ip_whatsapp.txt all ip addresses that belong to whatsapp
def load_whatsapp_ips():
    file_path = os.path.join("filter", "ip_whatsapp.txt")
    ips = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                # ip address in CIDR format!
                ips.append(ipaddress.ip_network(line))
    return ips

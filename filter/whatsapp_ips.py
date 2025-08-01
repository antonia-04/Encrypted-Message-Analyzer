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


# ip_input is string
# returns True if the ip is in any whatsapp ips
def is_whatsapp_ip(ip_input, whatsapp_ips):
    ip = ipaddress.ip_address(ip_input)
    return any(ip in net for net in whatsapp_ips)

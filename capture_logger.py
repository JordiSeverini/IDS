from scapy.all import sniff, IP, conf
from datetime import datetime, timezone 

# for iface in conf.ifaces.values():
#     print(iface.index, iface.name, iface.ips)

# !!IMPLEMENT A WAY TO ASK USER FOR THE INTERFACE !!

def iso_ts(): 
    return datetime.now(timezone.utc).isoformat()

def handle_packet (pkt):
    if IP not in pkt:
        return
    

    print({
        "ts": iso_ts(),
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "proto": pkt[IP].proto
    })

sniff(iface = "Ethernet 3", prn = handle_packet, store = False, count = 5)
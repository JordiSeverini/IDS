# April 10, 2026: Implemented Rule 1 – Tracks packet frequency per source IP and triggers an alert when activity exceeds 50 packets within a 10-second window.
    # Next: Potentially add flagged src IPs to a list ??


# sniff -> starts capturing live network packets
# IP -> lets you check/ extract IPv4 lyer info from packets
# conf -> Scapy configuration object (used to access network interfaces)
# collections : defaultdict -> special dictionary that auto-initializes missing keys to
from scapy.all import sniff, IP, conf
from datetime import datetime, timezone 
from collections import defaultdict


# conf.ifaces -> scapys interface manager 
    # Stores information such as Ethernet adapters, Wi-fi adapters, etc
    # .values() -> returns interface objects 
 
for iface in conf.ifaces.values():
    print(iface.index, iface.name, iface.ips)

# !!IMPLEMENT A WAY TO ASK USER FOR THE INTERFACE !!

# Timeframe to keep timestamps
WINDOW_SECONDS = 10
# Packets per IP before alert 
THRESHOLD = 50 

# dict holding IP address 
ip_counter = defaultdict(list)


# datetime.now() -> gets current time
# timezone.utc -> forces utc timezone
# isoformat() -> converts to standard readable string
def iso_ts(): 
    return datetime.now(timezone.utc).isoformat()

# Runs everytime a pkt is captured (sniff calls this)
def handle_packet (pkt):
    
    # If the pkt does not contain IP address ignore it (uses import IP)
    if IP not in pkt:
        return
    

    src = pkt[IP].src # Go to the IP layer of this packet then give me the source field
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    now = datetime.now(timezone.utc)

    
    # Rule 1: Packet rate capturing

    # Add the current timestamp to the list 
    ip_counter[src].append(now)

    # Modifies the ip_counter[src] list
        # removes timestamps from outside the WINDOW_SECONDS 
    ip_counter[src] = [
       t for t in ip_counter[src] 
        if(now - t).total_seconds() <= WINDOW_SECONDS
    ]

    # Count how many timestamps in the listpacket
    count = len(ip_counter[src])


    # Checks if the length of the ip_counter[src] list is equal to the threshold
        # Prints an alert if it is 
    if count == THRESHOLD:
        print("ALERT : High packet rate detected from: ", src)



    print({
        "ts": iso_ts(),
        "src": src, 
        "dst": dst,
        "proto":proto,
        "count_last-10s": count
    })

# Packet capturing starts here
# iface -> Listen only on this interface 
# prn = handle_packet -> for every packet captured call handle_packet
# store = False -> dont save packets in memory
# count = 5 -> stop after five packets 

sniff(
    iface = "Ethernet 3", 
    prn = handle_packet, 
    store = False, 
    count = 5)
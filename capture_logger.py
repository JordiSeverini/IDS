"""
Network Packet Sniffer - Rule Engine
Rule 1: High-frequency packet rate detection per source IP.
"""

from scapy.all import sniff, IP, conf
from datetime import datetime, timezone
from collections import defaultdict


# ---------------------------------------------------------------------------
# Interface Discovery
# ---------------------------------------------------------------------------

for iface in conf.ifaces.values():
    print(iface.index, iface.name, iface.ips)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WINDOW_SECONDS = 10
"""Rolling time window (in seconds) used to evaluate packet rate per source IP."""

THRESHOLD = 50
"""Maximum number of packets allowed from a single source IP within WINDOW_SECONDS
before an alert is triggered."""

ip_counter = defaultdict(list)
"""Maps each source IP address to a list of UTC timestamps for recent packets."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def iso_ts() -> str:
    """Return the current UTC time as an ISO 8601 formatted string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Packet Handler
# ---------------------------------------------------------------------------

def handle_packet(pkt) -> None:
    """
    Process a single captured packet.

    Extracts the source IP, destination IP, and protocol. Applies Rule 1:
    tracks packet frequency per source IP over a rolling window and triggers
    an alert if the packet count reaches THRESHOLD.

    Args:
        pkt: A Scapy packet object passed in by the sniff callback.
    """
    if IP not in pkt:
        return

    src   = pkt[IP].src
    dst   = pkt[IP].dst
    proto = pkt[IP].proto
    now   = datetime.now(timezone.utc)

    # --- Rule 1: High packet-rate detection ---
    ip_counter[src].append(now)

    ip_counter[src] = [
        t for t in ip_counter[src]
        if (now - t).total_seconds() <= WINDOW_SECONDS
    ]

    count = len(ip_counter[src])

    if count == THRESHOLD:
        print(f"ALERT: High packet rate detected from {src} "
              f"({count} packets in {WINDOW_SECONDS}s)")

    print({
        "ts":            iso_ts(),
        "src":           src,
        "dst":           dst,
        "proto":         proto,
        "count_last_10s": count,
    })


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

sniff(
    iface="Ethernet 3",
    prn=handle_packet,
    store=False,
    count=5,
)
# Real-Time Network Intrusion Detection System (Prototype)

A Python-based network intrusion detection prototype that monitors live packet traffic and detects abnormal activity using rule-based analysis.

---

## Overview

This project implements a lightweight Intrusion Detection System (IDS) using Scapy. It captures live network packets and analyzes traffic patterns in real time to identify potential anomalies based on packet frequency per source IP.

---

## Features

- Live packet capture using Scapy
- Extraction of packet metadata (source IP, destination IP, protocol, timestamp)
- Sliding time-window analysis (10-second window)
- Rule-based anomaly detection for high-frequency traffic
- Real-time console alerts for suspicious activity

---

## Detection Logic

The system triggers an alert when:

- A single source IP sends **50 or more packets within a 10-second window**

This helps simulate detection of:
- Potential DDoS-like behavior
- Abnormal traffic spikes
- High-frequency scanning activity

---

## Tech Stack

- Python
- Scapy
- Collections (defaultdict)
- Datetime

---

## How It Works

1. Captures live network packets on a selected interface
2. Extracts IP-layer information from each packet
3. Stores timestamps per source IP
4. Maintains a rolling 10-second window
5. Counts packet frequency per IP
6. Triggers an alert if threshold is exceeded

---

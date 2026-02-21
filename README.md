# Network Traffic Threat Hunting using Wireshark

## 📌 Project Overview
This project demonstrates practical network traffic analysis using Wireshark to identify potential malicious communication patterns such as command-and-control (C2) beaconing, abnormal DNS activity, and data exfiltration indicators.

The analysis was conducted on live captured WiFi traffic in a controlled environment.

---

## 🎯 Objective
To establish a baseline of normal network behavior and detect potential indicators of compromise through packet-level inspection and behavioral analysis.

---

## 🛠 Tools & Environment
- Wireshark
- Ubuntu Linux
- WiFi Network Capture
- Protocol Filters (DNS, IPv4, IPv6, IP-based filtering)
- I/O Graph Analysis

---

## 🔎 Investigation Methodology
- Captured ~20 minutes of live network traffic
- Analyzed IPv4 & IPv6 conversations sorted by byte count
- Investigated high-volume internal and external IPs
- Filtered DNS queries for suspicious domains
- Reviewed multicast traffic behavior (mDNS)
- Evaluated I/O Graph for periodic beaconing patterns

---

## 📊 Key Findings (Session 1 – Baseline Analysis)
- High internal traffic between private IP addresses (10.0.0.0/8 range)
- DNS queries directed to Google Public DNS (8.8.4.4)
- Domains such as googlevideo.com observed (legitimate CDN traffic)
- IPv6 multicast traffic identified as mDNS (normal service discovery)
- No periodic beaconing patterns detected
- No suspicious domain generation behavior observed

This session establishes a clean baseline of normal network activity.

---

## 🚨 Suspicious Traffic Indicators Monitored
- Periodic outbound communication to a single external IP
- Large outbound data transfer without corresponding inbound traffic
- Randomized domain names (DGA behavior)
- Unusual encrypted traffic on uncommon ports
- Repeated failed DNS lookups

None of the above indicators were detected during this session.

---

## 📂 Project Structure

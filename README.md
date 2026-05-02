# 🔍 Wireshark Threat Hunting

![Tool](https://img.shields.io/badge/Tool-Wireshark_4.4.6-1679A7?logo=wireshark&logoColor=white)
![OS](https://img.shields.io/badge/OS-Kali_Linux-557C94?logo=kalilinux&logoColor=white)
![Framework](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-E31337?logoColor=white)
![Type](https://img.shields.io/badge/Type-Threat_Hunting-red)
![Sessions](https://img.shields.io/badge/Sessions-2-blue)
![Status](https://img.shields.io/badge/Status-Complete-success)

> A two-session network forensics investigation using Wireshark on Kali Linux.  
> Session 1 establishes a clean baseline. Session 2 analyses real malware traffic from a training PCAP, identifying C2 communication, malicious domains, and adversary techniques mapped to MITRE ATT&CK.

---

## 📁 Repository Structure

```
Wireshark-Threat-Hunting/
├── screenshots/
│   ├── session1-baseline-conversations.png
│   ├── session1-io-graph-clean.png
│   ├── session2-protocol-hierarchy.png
│   ├── session2-http-request-c2.png
│   ├── session2-dns-angrypoutine.png
│   ├── session2-tcp-stream-payload.png
│   ├── session2-virustotal-malicious.png
│   └── session2-virustotal-clean.png
├── Session1_Baseline_Report.pdf
├── SOC_ThreatHunting_Session2_Report.pdf
├── iocs-session2.txt
└── README.md
```

---

## 🧪 Session 1 — Baseline Traffic Analysis

**Objective:** Capture and analyse normal home/lab network traffic to establish a clean baseline for comparison.

**Environment:**
- OS: Kali Linux
- Tool: Wireshark 4.4.6
- Interface: Live capture on local network

**Findings:** Traffic was clean — predominantly DNS, ARP, and HTTPS to known services (Google, Microsoft). No suspicious external connections detected. This baseline is used as a reference point to identify anomalies in Session 2.

---

## 🚨 Session 2 — Malware PCAP Analysis

**PCAP Source:** [malware-traffic-analysis.net](https://malware-traffic-analysis.net/training-exercises.html) — Training Exercise "Angry Poutine" (2021-09-10)  
**Severity:** 🔴 HIGH  
**Malware Family:** Suspected Emotet/Trickbot variant  
**Infected Host:** `10.9.10.102` (DESKTOP-KKITB6Q)

### 🎯 Summary of Findings

| # | Finding | Technique | MITRE ID | Severity |
|---|---------|-----------|----------|----------|
| 1 | C2 beaconing to `194.62.42.206` | Web Protocols C2 | T1071.001 | 🔴 Critical |
| 2 | DNS queries to `angrypoutine.com` | DNS C2 | T1071.004 | 🔴 High |
| 3 | Fake Windows Update downloads | Masquerading | T1036 | 🟠 High |
| 4 | SSDP network scanning | Network Service Discovery | T1046 | 🟡 Medium |
| 5 | 285KB PE executable downloaded | Command & Scripting | T1059 | 🔴 Critical |
| 6 | SMB lateral movement attempt | SMB/Windows Admin Shares | T1021.002 | 🟠 High |

---

### 📸 Evidence

#### Protocol Hierarchy — Traffic Breakdown
![Protocol Hierarchy](screenshots/session2-protocol-hierarchy.png)
*HTTP carries 5.1% of bytes (307,754 bytes) — anomalous for a workstation. SMB and Kerberos confirm Active Directory environment.*

---

#### Finding 1 — C2 Beaconing (HTTP GET to malicious IP)
![HTTP C2 Request](screenshots/session2-http-request-c2.png)
*Infected host sends HTTP GET to `194.62.42.206` with random-path URL `/bmdff/BhoHsCtZ/MLdmpfjaX/` — classic algorithmically-generated C2 path. Also shows masqueraded Windows Update requests to `23.1.237.200`.*

---

#### Finding 2 — TCP Stream: 285KB Executable Downloaded
![TCP Stream Payload](screenshots/session2-tcp-stream-payload.png)
*TCP stream reveals server responded HTTP 200 OK with `Content-Type: application/octet-stream`. MZ header (Windows PE executable) visible in payload — 285KB second-stage malware downloaded.*

---

#### Finding 3 — DNS Queries to angrypoutine.com
![DNS Filter](screenshots/session2-dns-angrypoutine.png)
*50+ DNS queries to subdomains of `angrypoutine.com` including `ANGRYPOUTINE-DC` (Domain Controller) and `wpad.angrypoutine.com` (WPAD proxy abuse).*

---

#### Finding 4 — Threat Intelligence: Confirmed Malicious IP
![VirusTotal Malicious](screenshots/session2-virustotal-malicious.png)
*`194.62.42.206` flagged as Malware by ESET on VirusTotal (1/91). ASN: WorkTitans B.V. — known bulletproof hosting provider used by threat actors.*

---

### 🔍 Wireshark Filters Used

```wireshark
# Identify all HTTP requests
http.request

# Find C2 beaconing traffic
http.request && ip.dst == 194.62.42.206

# DNS queries to malicious domain
dns.qry.name contains "angrypoutine"

# Follow C2 TCP stream (packet 1189)
tcp.stream eq 50

# Remove internal traffic — show only external
!(ip.addr == 10.0.0.0/8) && !(ip.addr == 169.254.0.0/16)

# Detect network scanning
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Find large data transfers (possible exfiltration)
frame.len > 1400 && ip.dst != 10.0.0.0/8
```

---

### 🧾 Indicators of Compromise (IOCs)

| Type | Value | Confidence | Notes |
|------|-------|------------|-------|
| IP | `194.62.42.206` | HIGH | C2 server — ESET flagged Malware |
| IP | `23.1.237.200` | MEDIUM | Akamai CDN abused for fake Windows Updates |
| Domain | `angrypoutine.com` | HIGH | Malicious AD domain — 50+ DNS queries |
| Domain | `wpad.angrypoutine.com` | HIGH | WPAD proxy hijacking attempt |
| Domain | `simpsonsavingss.com` | HIGH | C2 Host header — fake domain |
| URL | `/bmdff/BhoHsCtZ/MLdmpfjaX/` | HIGH | Random C2 URI path |
| File | `date6` (285KB .exe) | HIGH | MZ PE executable — second-stage payload |
| Host | `DESKTOP-KKITB6Q` | HIGH | Infected Windows 10 workstation |
| IP | `10.9.10.102` | HIGH | Victim IP address |

Full IOC list: [iocs-session2.txt](iocs-session2.txt)

---

### 🗺️ MITRE ATT&CK Mapping

```
Tactic              Technique ID    Technique Name                  Evidence
──────────────────────────────────────────────────────────────────────────────
Command & Control   T1071.001       Web Protocols                   HTTP GET /bmdff/BhoHsCtZ/
Command & Control   T1071.004       DNS                             50+ angrypoutine.com queries
Defense Evasion     T1036           Masquerading                    Fake /msdownload/ paths
Discovery           T1046           Network Service Discovery        SSDP M-SEARCH flood
Execution           T1059           Command & Scripting Interpreter  285KB .exe downloaded
Lateral Movement    T1021.002       SMB/Windows Admin Shares        SMB2 to ANGRYPOUTINE-DC
```

---

### 🔁 How to Reproduce

1. Download the training PCAP from [malware-traffic-analysis.net](https://malware-traffic-analysis.net/training-exercises.html) — search for "2021-09-10 Angry Poutine"
2. Extract using password format: `infected_YYYYMMDD`
3. Open in Wireshark: `wireshark 2021-09-10-traffic-analysis-exercise.pcap`
4. Apply the filters listed above in order
5. Verify IPs at [virustotal.com](https://virustotal.com) and [abuseipdb.com](https://abuseipdb.com)

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark 4.4.6 | Packet capture and analysis |
| Kali Linux | Analysis environment |
| VirusTotal | Threat intelligence verification |
| AbuseIPDB | IP reputation lookup |
| MITRE ATT&CK | Adversary technique mapping |
| malware-traffic-analysis.net | PCAP source for Session 2 |

---

## 📄 Reports

- 📘 [Session 1 — Baseline Traffic Analysis Report](Session1_Baseline_Report.pdf)
- 📕 [Session 2 — Malware Traffic Analysis Report](SOC_ThreatHunting_Session2_Report.pdf)

---

## 👩‍💻 About

**Nazneen** | 3rd Year B.Tech CSE  
RGUKT Srikakulam | Web Technologies (20CS2203)  
🔗 [GitHub](https://github.com/nazneen0304) | 📧 Connect on [LinkedIn](https://linkedin.com/in/nazneen0304)

> *"You don't find the threat by luck — you find it by knowing what normal looks like."*


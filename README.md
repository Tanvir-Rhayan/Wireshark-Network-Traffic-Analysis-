# Penetration Testing Project: Network Traffic Analysis & Protocol Inspection Using Wireshark
## Student & Institutional Details
* **Student Name:** Tanvir Rahyan Shayem
* **Student ID:** 2024000000035
* **Academic Batch:** CADS 004
* **Institution:** Southeast University
* **Project Mentor:** Hasibul L Hasan
* **Date of Assessment:** May 16, 2026
* **Project Status:** Approved / Portfolio Ready
---
## 1. Executive Summary
[span_2](start_span)[span_3](start_span)Wireshark serves as an essential open-source network protocol analyzer used by security professionals to capture and inspect packet-level data in real time[span_2](end_span)[span_3](end_span). [span_4](start_span)In a formal penetration testing architecture, Wireshark fulfills the role of a passive reconnaissance and evidence-gathering utility[span_4](end_span). [span_5](start_span)It can uncover cleartext credentials, exposed session tokens, plain DNS queries, and anomalous traffic indicators that pinpoint misconfigured or structurally vulnerable network services[span_5](end_span).
[span_6](start_span)This repository documents the systematic capture, parsing, and analysis of network traffic within an isolated virtual lab sandbox[span_6](end_span). The objective is to demonstrate the real-world operational risks associated with legacy, unencrypted transport daemons and map out structural remediation workflows.
---
## 2. Technical Lab Objectives
* **[span_7](start_span)[span_8](start_span)Live Traffic Capture:** Monitoring and logging active network frame transmission across a localized network interface[span_7](end_span)[span_8](end_span).
* **[span_9](start_span)Protocol Segmentation:** Utilizing targeted display filters to isolate FTP, Telnet, HTTP, SMB, and DNS protocols[span_9](end_span).
* **[span_10](start_span)[span_11](start_span)Credential Harvesting:** Extracting unencrypted text passwords and authentication tokens transmitted across insecure channels[span_10](end_span)[span_11](end_span).
* **[span_12](start_span)Layer-2 Security Auditing:** Analyzing Address Resolution Protocol (ARP) tables to detect patterns indicative of spoofing or Man-in-the-Middle (MITM) positioning[span_12](end_span).
* **[span_13](start_span)Forensic Documentation:** Compiling high-fidelity packet evidence into a formal, industry-ready penetration testing portfolio[span_13](end_span).
---
## 3. Laboratory Environment & Architecture
[span_14](start_span)[span_15](start_span)To guarantee complete safety and eliminate defensive out-of-scope risks, all sniffing operations were strictly restricted to an isolated, non-routing private virtual environment[span_14](end_span)[span_15](end_span).

| Asset / Component | Operational IP Address | Software Version | Sandbox Infrastructure Role |
| :--- | :--- | :--- | :--- |
| **Kali Linux Host** | `192.168.1.42` | v2023.4 | [span_16](start_span)Primary security auditing platform and packet capture node[span_16](end_span). |
| **Wireshark Engine** | Local Interface | v4.2.0 | [span_17](start_span)Graphical user interface utilized for deep packet dissection[span_17](end_span). |
| **tshark Engine** | Command Line | v4.2.0 CLI | [span_18](start_span)Terminal-based wrapper used for headless/automated scripting[span_18](end_span). |
| **Metasploitable 2** | `192.168.1.105` | Linux Base | [span_19](start_span)Linux-centric vulnerable node containing legacy daemons[span_19](end_span). |
| **Windows XP VM** | `192.168.1.110` | Service Pack 3 | [span_20](start_span)Legacy client endpoint used for multi-vector tracking[span_20](end_span). |
| **Hypervisor Core** | Subnet Native | VMware Pro 17 | [span_21](start_span)Virtualization platform hosting the sandboxed local network[span_21](end_span). |

---
## 4. Operational Methodology & Capture Filters
### 4.1 Interface Initialization
[span_22](start_span)The primary hardware interface (`eth0`) bridged to the sandboxed private subnet was selected for monitoring[span_22](end_span). [span_23](start_span)[span_24](start_span)To reduce administrative overhead and discard out-of-scope traffic, a strict capture filter was enforced immediately[span_23](end_span)[span_24](end_span):
```bash
host 192.168.1.0/24
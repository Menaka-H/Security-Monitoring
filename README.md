# Security-Monitoring
Project Overview

This project implements an automated network security monitoring system using Suricata, an open-source Intrusion Detection and Prevention System (IDS/IPS).
The system continuously monitors network traffic in real time, detects suspicious activities and intrusions, and generates actionable alerts and logs for security analysis.

The solution is designed to help organizations identify threats early, improve incident response, and gain deep visibility into network behavior.

<img width="1899" height="1083" alt="image" src="https://github.com/user-attachments/assets/d0ab55a3-aeea-4d99-ab92-7c72c33b3646" />


🎯 Objectives

1.Monitor live network traffic for malicious activity

2.Detect unauthorized access attempts and abnormal traffic patterns

3.Generate real-time alerts for security incidents

4.Maintain detailed logs for forensic analysis and compliance


Key Features
1.Real-Time Network Traffic Monitoring

* Captures and inspects live packets

* Analyzes Layer 3–7 protocols

* Detects suspicious inbound and outbound traffic


2.Intrusion Detection & Alerting

** Identifies attacks such as:

* Port scanning

* Brute-force login attempts

* Malware communication

* Policy violations

** Generates real-time alerts in structured formats (JSON / EVE logs)


3.Custom Rule Implementation

** Developed custom Suricata rules to:

* Detect unauthorized access attempts

* Identify abnormal traffic behavior

* Monitor specific IPs, ports, and protocols

** Enhanced detection accuracy beyond default rule sets


4.Logging & Incident Analysis

** Detailed logs for:

* Alerts

* DNS queries

* HTTP requests

* TLS traffic

** Supports forensic investigation and post-incident analysis

How Suricata Works 

1.Network packets are captured from the monitored interface

2.Suricata decodes protocols and inspects payloads

3.Rules are applied to detect malicious patterns

4.Alerts are generated for suspicious activity

5.Logs are stored for analysis and reporting


Tools & Technologies Used :

1.Suricata

2.Linux (Ubuntu / Kali Linux)

3.YAML & Rule-based Detection

4.PCAP & Live Traffic Analysis

5.JSON / EVE Logging

6.Bash & Python (for automation)


Project Structure
Security-Monitoring-Suricata/
│
├── rules/
│   ├── custom.rules
│
├── configs/
│   ├── suricata.yaml
│
├── logs/
│   ├── eve.json
│   ├── fast.log
│
├── scripts/
│   ├── alert_monitor.py
│
├── pcaps/
│   ├── test_traffic.pcap
│
└── README.md


Testing & Validation

1.Simulated attacks using:

* Port scanning tools

* Brute-force attempts

* Malicious traffic PCAP files

* Verified alert accuracy and log generation

* Tuned rules to reduce false positives


Real-World Use Cases

* Enterprise network monitoring

* SOC (Security Operations Center) environments

* Incident detection and response

* Threat hunting and forensic analysis

* Compliance and security auditing

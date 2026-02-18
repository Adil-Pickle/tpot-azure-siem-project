# Tpot Azure SIEM Project

## Overview

Deployed a **TPOT multi-honeypot** on an **Azure VM running Ubuntu** to attract real-world cyber attacks. Integrated **Microsoft Sentinel** as my SIEM, ingested live Syslog data, and built custom **KQL detection rules** to catch SSH brute-force patterns. The project captured **360,000+ attacks**, generated **295 security alerts**, and gave me hands-on experience in **cloud security, threat detection, and log analysis**.

---

## Environment Setup

### Azure VM
Set up an **Ubuntu VM** on Azure with a public IP and open NSG rules to allow attacker traffic.

![VM Overview](screenshots/Screenshot%20(62).png)

### NSG Configuration
Configured the Network Security Group to allow **SSH (port 22)** for admin access and **all TCP ports (0-65535)** to maximize attack surface.

![NSG Rules](screenshots/Screenshot%202025-12-27%20000434.png)

### System Verification
Connected via SSH to confirm the system was ready before installing TPOT.

![System Info](screenshots/Screenshot%20(63).png)

### TPOT Installation
Installed the **TPOT framework**, which includes honeypots like **Cowrie**, **Dionaea**, and **Honeytrap**. SSH was automatically moved to port **64295** to avoid conflicts.

![TPOT Setup](screenshots/Screenshot%20(64).png)

---

## Attack Traffic Collection

### Accessing TPOT Dashboard
The TPOT web interface was accessible via **HTTP** rather than HTTPS because the self-signed certificate was blocked by the browser. Once inside, I analyzed real-time attack data using the built-in tools.

![TPOT Dashboard Access](screenshots/Screenshot%20(68).png)

### Elastic Kibana Dashboard
The **Kibana dashboard** provided a detailed breakdown of attacks across all honeypot services. At this point, I was at 126k total attacks, and it had only been a few days. **Cowrie** (SSH) saw the most activity with **99k attacks**, followed by **Honeytrap** with **21k**. The dashboard also visualizes attack rates, destination ports, and geographic distribution.

![Kibana Dashboard](screenshots/Screenshot%20(70).png)

### Attack Patterns & Statistics
The Kibana dashboards broke down attacks by **destination port, honeypot type, and country of origin**. Port **22** (SSH) saw the most traffic, with **Cowrie** being the most targeted honeypot. The **United States, Hong Kong, and the Netherlands** were top source countries.

![Attack Statistics](screenshots/Screenshot%202025-12-26%20235534.png)

### Top Attackers by ASN & IP
The data revealed **HKT Limited (AS4760)** as the top autonomous system with over **69k attacks**, followed by **Google Cloud** and **DigitalOcean**. The most active single source IP was **220.241.56.171**, responsible for **69,510 attacks**.

![Top Attackers ASN IP](screenshots/Screenshot%202025-12-26%20235630.png)

### Attack Map & Live Feed
The **TPOT attack map** displayed real-time attacker locations and service targeting. Each attack includes details like protocol used (SSH, FTP, Telnet) and timestamp.

![Attack Map](screenshots/Screenshot%20(72).png)

The live feed breaks down **top attacking IPs** and **top countries** — the United States, Germany, and the UK were among the most frequent sources. Many IPs in the top 10 were flagged as known attackers.

![Top Attackers Dashboard](screenshots/Screenshot%20(80).png)

The dashboard tracks total hits, source IP reputation, country of origin, and last seen protocol. The **24-hour attack count** reached **21,479** at the time of this screenshot.

![Top Attackers Detail](screenshots/Screenshot%20(81).png)

## Sentinel & KQL Detection Rules

### Data Ingestion Verification
Before building detection rules, I confirmed that logs were flowing properly into Sentinel by running a **Heartbeat query**. This verified the Azure Monitor Agent was actively connected and sending data from the honeypot VM.

<img width="1867" height="650" alt="Screenshot 2025-12-26 053110" src="https://github.com/user-attachments/assets/fe2c46fe-6a79-432f-8d32-d543bda29f97" />

### Custom SSH Brute Force Detection Rule
I created a custom **KQL detection rule** in Microsoft Sentinel to identify SSH brute-force attempts targeting the Cowrie honeypot. The rule runs every **10 minutes**, looking back **20 minutes** of data, and triggers an alert when it finds more than **10 login attempts** in a 10-minute window from the same source.

<img width="604" height="674" alt="Screenshot 2025-12-26 233229" src="https://github.com/user-attachments/assets/ad4b5c8e-2bb1-41ed-9c13-0f43dd569cc2" />

```kql
Syslog
| where SyslogMessage contains "cowrie" and SyslogMessage contains "login attempt"
| summarize Count = count() by bin(TimeGenerated, 10m)
| where Count > 10
```

### Attack Timeline Query
This query tracks SSH brute-force attempts over time, revealing peak attack volumes. The results show **169 attacks in a single 10-minute window** — the highest observed at this point in the project.

<img width="926" height="561" alt="Screenshot 2025-12-26 233336" src="https://github.com/user-attachments/assets/5e749c15-81a5-49b7-93e2-7244bcc2ec90" />

```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage contains "cowrie" and SyslogMessage contains "login attempt"
| summarize Count = count() by bin(TimeGenerated, 10m), Computer
| where Count > 10
| order by TimeGenerated desc



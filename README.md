# Tpot Azure SIEM Project

## Overview

Deployed a **TPOT multi-honeypot** on an **Azure VM running Ubuntu** to attract real-world cyber attacks. By integrating **Microsoft Sentinel** as my SIEM, I ingested live Syslog data and built custom **KQL detection rules** to identify SSH brute-force patterns. The project resulted in **360,000+ captured attacks**, **295 automated security alerts**, and key insights into attacker behavior — all while demonstrating hands-on skills in **cloud security, threat detection, and log analysis**.

## Environment Setup

### Azure Virtual Machine
A publicly exposed **Ubuntu 24.04 LTS VM** was deployed on Azure to serve as the honeypot host. The VM was configured with a public IP and intentionally open network security groups to attract internet-wide attack traffic.

![VM Overview](screenshots/Screenshot%20(62).png)
*Figure 1: Azure VM overview showing tpot-honeypot, Ubuntu 24.04, Standard D4s v3 (4 vCPU, 16GB RAM), and public IP configuration.*

---

### System Verification
After deployment, SSH access was confirmed and system resources were verified to ensure the VM was ready for TPOT installation.

![System Info](screenshots/Screenshot%20(63).png)
*Figure 2: Ubuntu system information showing OS version, resource usage (5.6% disk, 1% memory), and network interface details.*

---

### TPOT Installation
The **TPOT (The Pot) multi-honeypot framework** was installed, which includes several honeypot services like **Cowrie** (SSH), **Dionaea** (malware), and **Honeytrap** (multi-protocol). During installation, the system displayed running services and confirmed SSH was configured on a non-standard port (**64295**) to avoid conflicts.

![TPOT Setup](screenshots/Screenshot%20(64).png)
*Figure 3: TPOT installation output showing active services and SSH configuration on port 64295.*

---

### Network Security Group Configuration
To ensure the honeypot was reachable by attackers, the **Network Security Group (NSG)** was configured with permissive inbound rules:

- **SSH (port 22):** Allowed for administrative access
- **All ports (0-65535):** Open TCP traffic to maximize attack surface
- Default Azure rules for load balancer and virtual network traffic

![NSG Rules](screenshots/Screenshot%202025-12-27%20000434.png)
*Figure 4: Network Security Group inbound rules showing open ports for SSH and all TCP traffic to attract maximum attack volume.*

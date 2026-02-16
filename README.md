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


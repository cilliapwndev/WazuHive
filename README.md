
# 🐝 WazuHive

**WazuHive.sh** is a semi-automated, interactive Bash script designed to deploy and configure the [Wazuh agent](https://wazuh.com/) on Linux systems. It goes beyond installation by offering additional hardening, detection, and prevention features for enhanced endpoint visibility and security.

> ✨ Future updates will bring support for **Windows** and **macOS** agents, with even more security features and customization options.

---

## 🧠 What is WazuHive?

WazuHive is more than just an installer. It’s a toolkit that transforms your machine into a monitored and hardened endpoint under the Wazuh SIEM. Built with blue teamers in mind, WazuHive assists in detecting:

* Brute-force attempts (SSH/FTP)
* Mimikatz-style memory access
* Crypto mining binaries and file locations
* High/odd port usage
* Torrent client behavior
* Weak SSH configurations

---

## 🔐 Features

| Feature                            | Description                                                                 |
| ---------------------------------- | --------------------------------------------------------------------------- |
| 📦 Wazuh Agent Installation        | Installs the Wazuh agent via APT or YUM.                                    |
| 🔧 Agent Configuration             | Set agent name and Wazuh Manager IP.                                        |
| 🛡️ System Hardening Detection     | Detects weak SSH settings like root login or password authentication.       |
| 🚫 Brute Force Protection          | Detects SSH and FTP login failures and supports active response.            |
| 📡 High Port Monitoring            | Flags traffic to ports above 10000.                                         |
| 🧭 First-Time Port Usage Detection | Notifies when a new destination port is seen for the first time.            |
| ⛏️ Crypto Mining Detection         | Flags binaries like `xmrig`, `minerd`, etc. and scans typical hiding paths. |
| 🌊 Torrent Detection               | Alerts on known torrent clients via log matching.                           |
| 🧠 Mimikatz-Like Behavior Alerts   | Uses `auditd` to monitor credential memory access.                          |

---

## 📦 Installation

```bash
chmod +x WazuHive.sh
sudo ./WazuHive.sh
```

You will be prompted to enter:

* Agent name
* Wazuh manager IP
* Mode: Detection or Detection + Prevention

Then select features individually or run all.

---

## 📌 Prerequisites

* Root privileges
* Linux (Debian/Ubuntu/CentOS/Fedora/Red Hat)
* Internet access for repository and package downloads

---

## 🛠️ Planned Features

* ✅ Cross-platform support (Windows & macOS)
* ✅ Interactive CLI improvements
* ✅ Log forwarding to ELK stack
* ✅ Hardened default configurations
* ✅ Scheduled hardening scans
* ✅ Auto-enrollment with manager

---

## ✍️ Author

**Cillia 🐝**
Focused on blue team automation and endpoint hardening.


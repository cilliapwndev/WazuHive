# 🐝 WazuHive – Wazuh Agent Installer

> A semi-automated, interactive installer for setting up and securing a **Wazuh agent** on Linux systems with advanced detection capabilities.

## 🔒 Features

WazuHive helps automate the deployment of the **Wazuh agent** with hardened configurations and active threat detection rules:

| Feature | Description |
|--------|-------------|
| 🛡️ Detection / Prevention Mode | Choose between alert-only or automatic blocking |
| 🚪 High Port (>10000) Detection | Detect unusual service ports |
| 🧱 System Hardening Checks | Alerts on weak SSH settings |
| 🦠 Crypto Miner Detection | Monitors common miner paths and names |
| 🌐 Tor Network Detection | Watches for use of known Tor ports |
| 🐛 Mimikatz / Credential Dumping | Uses auditd to detect credential dumping |
| 🧟 Suspicious Process Detection | Detects suspicious process execution |
| 🕳️ Hidden Process Detection | Scans `/proc` for hidden processes (rootkit indicators) |

---

## 🐝 What is WazuHive?

**WazuHive** is a **modular, menu-driven Bash script** that helps system admins and security teams quickly deploy Wazuh agents with hardened configurations and active threat detection rules.

It currently supports:
- ✅ **Debian/Ubuntu**
- ✅ **CentOS/RHEL**

Support for **Windows PowerShell**, **macOS shell scripts**, and **containerized deployments** will be added in future versions.

---

## 📋 Requirements

- Root access or `sudo` privileges
- Internet connectivity to install Wazuh agent and dependencies
- Wazuh Manager IP address

---

## 🚀 Installation

1. Clone the repo:
```bash
git clone https://github.com/cilliapwndev/WazuHive.git
cd WazuHive
```

2. Make the script executable:
```bash
chmod +x wazuhive.sh
```

3. Run it:
```bash
sudo ./wazuhive.sh
```

---

## 🧩 Interactive Menu Options

The script provides an easy-to-use interactive menu where you can enable/disable modules:

| Option | Feature |
|--------|---------|
| 1 | Install Wazuh Agent |
| 2 | Configure Manager IP & Agent Name |
| 3 | System Hardening Checks |
| 4 | Brute Force Protection (SSH/FTP) |
| 5 | High Port (>10000) Detection |
| 6 | First-Time Port Usage Detection |
| 7 | Crypto Mining Detection |
| 8 | Torrent Network Detection |
| 9 | Mimikatz / Credential Dumping Detection |
| 10 | Detect Tor Network Connection |
| 11 | Detect Hidden Processes via `/proc` |
| 12 | Run All Tasks |
| 13 | Exit |

---

## 📊 Wazuh Dashboard Integration

After running this script, monitor events in your **Wazuh dashboard** by filtering:

| Rule ID | Group             | Description                             |
|--------|-------------------|------------------------------------------|
| 100001 | crypto_mining     | Crypto miner binary detected             |
| 100003 | torrent           | BitTorrent client detected               |
| 100006 | brute_force       | Multiple SSH login attempts              |
| 100008 | high_port_usage   | Connection to port >10000                |
| 100010 | suspicious_process| Suspicious process executed              |
| 100011 | tor_detection     | Tor network port used                    |
| 100012 | hidden_process    | Possible hidden process/rootkit detected |

---

## 📜 License – GPL-3.0

This project is licensed under the **GNU General Public License v3.0**.

### You may:
- ✅ Use the software freely
- ✅ Study and modify the source code
- ✅ Redistribute copies
- ✅ Improve the program and release your improvements to the public

### You must:
- 📄 Include the same license and copyright notice if redistributing
- 📁 Share any modifications you make under the same license

For more details, see [LICENSE](LICENSE).

---

## 💙 Contributing

Contributions are welcome! Whether you want to improve documentation, add new features, or fix bugs — feel free to submit pull requests or open issues.

---

## 🔄 Future Plans & Roadmap

This current version of **WazuHive** is focused on **Linux-based systems**, but we're planning to expand support to include:

- ✅ **Windows PowerShell / Batch scripts** for Windows endpoints  
- ✅ **macOS shell scripts** for Apple devices  
- ✅ **Containerized deployment** (e.g., Docker, Kubernetes)

We're also planning to add more detection and prevention features such as:

- 🔍 **YARA-based memory scanning**
- 🧠 **Threat intelligence integration**
- 🛡️ **System integrity checks**
- 🧱 **Hardening recommendations**
- 📢 **Alert forwarding to Slack/Discord/Telegram**
- 🤖 **AI/ML anomaly detection modules**

Stay tuned — **WazuHive will evolve into a full cross-platform security toolset** for Wazuh users!

---

## 🐝 Thank You!

Thanks for using **WazuHive** – your friendly neighborhood **Wazuh agent installer**, powered by 🐝🐝🐝

Let me know how far you'd like to take this project!

---

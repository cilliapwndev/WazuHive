#!/bin/bash

# Script Name: WazuHive.sh
# Description: A semi-automated Wazuh agent installer with interactive menu,
#              support for detection/prevention modes, system hardening,
#              crypto mining, Mimikatz, high-port detection, Tor detection,
#              and hidden process monitoring.
# Author: Cillia🐝
# Date: 2025-04-05

# ASCII Art - WazuHive Logo 🐝
clear
echo -e "
"
cat << "BEE"
              \     /
          \    o ^ o    /
            \ (     ) /
 ____________(%%%%%%%)____________
(     /   /  )%%%%%%%(  \   \     )
(___/___/__/           \__\___\___)
   (     /  /(%%%%%%%)\  \     )
    (__/___/ (%%%%%%%) \___\__)
            /(       )\
          /   (%%%%%)   \
               (%%%)
                 !
 __      __                             __  __                        
/\ \  __/\ \                           /\ \/\ \  __                   
\ \ \/\ \ \ \     __     ____    __  __\ \ \_\ \/\_\  __  __     __   
 \ \ \ \ \ \ \  /'__`\  /\_ ,`\ /\ \/\ \\ \  _  \/\ \/\ \/\ \  /'__`\ 
  \ \ \_/ \_\ \/\ \L\.\_\/_/  /_\ \ \_\ \\ \ \ \ \ \ \ \ \_/ |/\  __/ 
   \ `\___x___/\ \__/.\_\ /\____\\ \____/ \ \_\ \_\ \_\ \___/ \ \____\
    '\/__//__/  \/__/\/_/ \/____/ \/___/   \/_/\/_/\/_/\/__/   \/____/
                                                                      
                                                                      

BEE
echo -e "
🐝 Welcome to WazuHive - Wazuh Agent Installer for Linux
"
sleep 2

# Colors
GREEN='\e[32m'
YELLOW='\e[33m'
NC='\e[0m'

AGENT_NAME=""
WAZUH_MANAGER_IP=""
MODE="detection"  # Default mode
HIGH_PORT_REGEX="1[0-9]{4}|[2-9][0-9]{4,}"

log() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

pause() {
  read -p "Press Enter to continue..."
}

ask_input() {
  read -p "$1: " input
  echo "$input"
}

confirm() {
  while true; do
    read -p "$1 [y/n]: " yn
    case $yn in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer yes or no.";;
    esac
  done
}

detect_os() {
  if grep -qEi 'debian|ubuntu' /etc/os-release; then
    PKG_MGR="apt"
  elif grep -qEi 'centos|fedora|red hat' /etc/os-release; then
    PKG_MGR="yum"
  else
    echo "Unsupported OS detected."
    exit 1
  fi
}

# Create local_rules.xml if it doesn't exist
create_local_rules_file() {
  LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
  if [ ! -f "$LOCAL_RULES" ]; then
    log "Creating $LOCAL_RULES..."
    mkdir -p "$(dirname "$LOCAL_RULES")"
    echo '<?xml version="1.0" encoding="UTF-8"?>' > "$LOCAL_RULES"
    echo '<group name="local,syslog">' >> "$LOCAL_RULES"
    echo '</group>' >> "$LOCAL_RULES"
  else
    log "$LOCAL_RULES already exists."
  fi
}

# Create ossec directories if missing
create_ossec_dirs() {
  mkdir -p /var/ossec/etc/ossec.conf.d/
}

# Ensure curl is installed
ensure_curl_installed() {
  if ! command -v curl &>/dev/null; then
    log "curl is not installed. Installing curl..."
    if [ "$PKG_MGR" = "apt" ]; then
      apt update -qq && apt install -y curl
    else
      yum install -y curl
    fi
    if ! command -v curl &>/dev/null; then
      warn "Failed to install curl. Exiting."
      exit 1
    fi
    log "curl installed successfully."
  else
    log "curl is already installed."
  fi
}

# Restart Wazuh only if running
safe_restart_wazuh() {
  if systemctl is-active --quiet wazuh-agent; then
    systemctl restart wazuh-agent
  else
    warn "Wazuh agent is not running. Skipping restart."
  fi
}

# Install Wazuh agent
install_wazuh_agent() {
  detect_os
  ensure_curl_installed
  log "Installing Wazuh agent..."

  if [ "$PKG_MGR" = "apt" ]; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH  | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/  stable main" > /etc/apt/sources.list.d/wazuh.list
    apt update -qq && apt install -y wazuh-agent
  else
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 
    cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH 
enabled=1
baseurl=https://packages.wazuh.com/4.x/yum/ 
pkg_gpgcheck=1
EOF
    yum makecache -q && yum install -y wazuh-agent
  fi

  systemctl enable wazuh-agent --now

  create_ossec_dirs
  create_local_rules_file
}

configure_wazuh_agent() {
  log "Configuring Wazuh agent with manager IP and agent name..."
  sed -i "s:<server_ip>.*</server_ip>:<server_ip>$WAZUH_MANAGER_IP</server_ip>:" /var/ossec/etc/ossec.conf
  sed -i "s:<node_name>.*</node_name>:<node_name>$AGENT_NAME</node_name>:" /var/ossec/etc/ossec.conf
}

enable_system_hardening_checks() {
  log "Enabling system hardening rules..."
  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="system_hardening,">
  <rule id="100004" level="7">
    <if_sid>5402</if_sid>
    <match>PermitRootLogin yes</match>
    <description>SSH PermitRootLogin is enabled.</description>
  </rule>
  <rule id="100005" level="7">
    <if_sid>5402</if_sid>
    <match>PasswordAuthentication yes</match>
    <description>SSH PasswordAuthentication is enabled.</description>
  </rule>
</group>
EOF
  safe_restart_wazuh
}

enable_brute_force_protection() {
  log "Setting up brute force protection..."
  cat >> /var/ossec/etc/ossec.conf << EOF
<active-response>
  <command>host-deny</command>
  <location>local</location>
  <level>8</level>
  <timeout>600</timeout>
</active-response>
EOF

  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="brute_force,">
  <rule id="100006" level="8">
    <if_sid>5710,5715</if_sid>
    <match>sshd.*Failed password for</match>
    <description>Multiple SSH login failures detected.</description>
  </rule>

  <rule id="100007" level="8">
    <if_sid>5710,5725</if_sid>
    <match>vsftpd.*Login failure</match>
    <description>Multiple FTP login failures detected.</description>
  </rule>
</group>
EOF

  safe_restart_wazuh
}

enable_high_port_detection() {
  log "Setting up high port (>10000) detection..."
  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="high_port_usage,">
  <rule id="100008" level="7">
    <if_sid>5400</if_sid>
    <field name="dstport">$HIGH_PORT_REGEX</field>
    <description>Connection attempt to high port (>10000).</description>
  </rule>
</group>
EOF

  safe_restart_wazuh
}

enable_first_time_port_usage() {
  log "Setting up first-time port usage detection..."
  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="first_time_port,">
  <rule id="100009" level="5">
    <if_sid>5400</if_sid>
    <match>new port opened</match>
    <description>New destination port was observed for the first time.</description>
  </rule>
</group>
EOF

  safe_restart_wazuh
}

setup_auditd() {
  log "Setting up auditd rules for Mimikatz-like behavior..."

  if ! command -v auditd &>/dev/null; then
    if [ "$PKG_MGR" = "apt" ]; then
      apt install -y auditd audispd-plugins
    else
      yum install -y audit audit-libs
    fi
  fi

  cat > /etc/audit/rules.d/99-wazuh-crypto.rules << EOF
-a always,exit -F arch=b64 -S process_vm_readv -k mem_access
-a always,exit -F arch=b32 -S process_vm_readv -k mem_access
-w /etc/shadow -p war -k shadow_access
-w /tmp/minerd -k miner_detected
-w /dev/shm/xmrig -k miner_detected
EOF

  augenrules --load
  systemctl enable auditd --now
}

enable_crypto_mining_detection() {
  log "Enabling crypto mining detection..."
  cat >> /var/ossec/etc/ossec.conf << EOF
<syscheck>
  <directories check_all="yes">/tmp,/dev/shm,/home/*/.ssh,/home/*/.minerd</directories>
</syscheck>
EOF

  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="crypto_mining,">
  <rule id="100001" level="10">
    <if_sid>530</if_sid>
    <match>minerd|xmr-stak|xmrig|cpuminer</match>
    <description>Crypto miner binary detected.</description>
    <group>malware,</group>
  </rule>
</group>
EOF

  safe_restart_wazuh
}

enable_torrent_detection() {
  log "Setting up torrent detection..."
  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="torrent,">
  <rule id="100003" level="7">
    <if_sid>5400</if_sid>
    <match>BitTorrent|bittorrent|utorrent|Transmission|Deluge|qBittorrent</match>
    <description>Torrent client activity detected.</description>
    <group>network,</group>
  </rule>
</group>
EOF

  safe_restart_wazuh
}

detect_tor_connections() {
  log "Setting up Tor network connection detection..."
  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="tor_detection,">
  <rule id="100011" level="7">
    <if_sid>5400</if_sid>
    <match>:(9001|9030|9050|9051|9070|9071|9080|9090|9150|9151)</match>
    <description>Tor network port used (likely Tor traffic).</description>
    <group>network,</group>
  </rule>
</group>
EOF

  safe_restart_wazuh
}

setup_hidden_process_detection() {
  log "Setting up hidden process detection..."

  cat > /usr/local/bin/check-hidden-processes.sh << 'EOF'
#!/bin/bash
LOGFILE="/var/log/hidden_processes.log"

log_event() {
  echo "$(date '+%Y-%m-%d %T') $1" >> "$LOGFILE"
}
touch "$LOGFILE"

for pid in /proc/[0-9]*; do
  pid=$(basename "$pid")
  if [ ! -r "/proc/$pid/exe" ]; then
    desc="Hidden process detected with PID: $pid"
    log_event "$desc"
    echo "1|$0|$desc"  # Send to Wazuh FIFO
  fi
done
EOF

  chmod +x /usr/local/bin/check-hidden-processes.sh

  cat > /var/ossec/etc/shared/hidden-process.conf << EOF
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/hidden_processes.log</location>
</localfile>
EOF

  ln -sf /var/ossec/etc/shared/hidden-process.conf /var/ossec/etc/ossec.conf.d/

  cat >> /var/ossec/etc/rules/local_rules.xml << EOF
<group name="hidden_process,">
  <rule id="100012" level="10">
    <match>Hidden process detected</match>
    <description>Possible hidden process/rootkit detected.</description>
    <group>malware,</group>
  </rule>
</group>
EOF

  (crontab -l 2>/dev/null; echo "* * * * * root /usr/local/bin/check-hidden-processes.sh") | crontab -

  safe_restart_wazuh
}

full_setup() {
  install_wazuh_agent
  configure_wazuh_agent
  enable_system_hardening_checks
  enable_brute_force_protection
  enable_high_port_detection
  enable_first_time_port_usage
  enable_crypto_mining_detection
  enable_torrent_detection
  setup_auditd
  detect_tor_connections
  setup_hidden_process_detection
}

main_menu() {
  clear
  echo "==============================="
  echo " 🔐 WazuHive - Wazuh Installer"
  echo "==============================="
  echo "Agent Name: $AGENT_NAME"
  echo "Manager IP: $WAZUH_MANAGER_IP"
  echo "Mode: $MODE"
  echo ""
  echo "Select features to enable:"
  echo "1. Install Wazuh Agent"
  echo "2. Configure Manager IP & Agent Name"
  echo "3. System Hardening Checks"
  echo "4. Brute Force Protection (SSH/FTP)"
  echo "5. High Port (>10000) Detection"
  echo "6. First-Time Port Usage Detection"
  echo "7. Crypto Mining Detection"
  echo "8. Torrent Network Detection"
  echo "9. Mimikatz / Credential Dumping Detection"
  echo "10. Detect Tor Network Connection"
  echo "11. Detect Hidden Processes via /proc"
  echo "12. Run All Tasks"
  echo "13. Exit"
  echo ""
}

run_selected_tasks() {
  if confirm "Install Wazuh Agent?"; then install_wazuh_agent; fi
  if confirm "Configure Manager IP and Agent Name?"; then configure_wazuh_agent; fi
  if confirm "Enable System Hardening Rules?"; then enable_system_hardening_checks; fi
  if confirm "Enable Brute Force Protection?"; then enable_brute_force_protection; fi
  if confirm "Enable High Port (>10000) Detection?"; then enable_high_port_detection; fi
  if confirm "Enable First-Time Port Detection?"; then enable_first_time_port_usage; fi
  if confirm "Enable Crypto Mining Detection?"; then enable_crypto_mining_detection; fi
  if confirm "Enable Torrent Detection?"; then enable_torrent_detection; fi
  if confirm "Setup Audit Rules for Mimikatz Detection?"; then setup_auditd; fi
  if confirm "Detect Tor Network Connection?"; then detect_tor_connections; fi
  if confirm "Detect Hidden Processes via /proc?"; then setup_hidden_process_detection; fi
}

main() {
  detect_os
  clear
  log "Welcome to WazuHive - Wazuh Agent Installer!"
  pause

  AGENT_NAME=$(ask_input "Enter agent name")
  WAZUH_MANAGER_IP=$(ask_input "Enter Wazuh manager IP")

  echo ""
  echo "Choose mode:"
  echo "1. Detection Only"
  echo "2. Detection + Prevention (Active Response)"
  read -p "Option [1/2]: " mode_choice
  case $mode_choice in
    1) MODE="detection" ;;
    2) MODE="detection+prevention" ;;
    *) warn "Invalid option. Defaulting to detection only."; MODE="detection" ;;
  esac

  while true; do
    main_menu
    read -p "Choose an option [1-13]: " choice
    case $choice in
      1) install_wazuh_agent ;;
      2) configure_wazuh_agent ;;
      3) enable_system_hardening_checks ;;
      4) enable_brute_force_protection ;;
      5) enable_high_port_detection ;;
      6) enable_first_time_port_usage ;;
      7) enable_crypto_mining_detection ;;
      8) enable_torrent_detection ;;
      9) setup_auditd ;;
      10) detect_tor_connections ;;
      11) setup_hidden_process_detection ;;
      12) full_setup ;;
      13) echo -e "\n🐝 Goodbye from WazuHive!\n"; exit 0 ;;
      *) warn "Invalid option. Try again." ;;
    esac
    pause
  done
}

main

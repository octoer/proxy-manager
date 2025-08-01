#!/usr/bin/env bash
#
# proxy_manager.sh - Unified proxy management utility
#
# This script provides a simple text‑based menu for installing, removing
# and configuring several popular proxy protocols.  It wraps existing
# community‑maintained install scripts for Snell, Hysteria 2 and
# Shadowsocks‑Rust/ShadowTLS and adds some convenience helpers for
# editing configuration files and viewing service status.
#
# Features inspired by open source projects:
#   * The Snell manager script by jinqians offers one‑click installation
#     and removal of Snell v4/v5 as well as ShadowTLS integration and
#     additional tools such as BBR optimisation and multi‑user support【790071861813661†L68-L169】.
#   * The ss‑2022.sh project wraps Shadowsocks‑Rust and ShadowTLS and
#     provides installation, update, removal and configuration helpers【626787053643720†L20-L54】.
#   * The Hysteria 2 shell installer provides a menu for installation,
#     removal and controlling the server, with sensible defaults for
#     ports and passwords【148586898745330†L13-L27】.
#
# This unified script does not attempt to duplicate every feature of the
# upstream projects.  Instead it calls their official install scripts
# where appropriate, then offers simple helpers to adjust ports and
# passwords and to restart the services.  Advanced features such as
# multi‑user configuration, BBR tuning or subscription link generation
# should still be performed via the upstream menus.

# Colours for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
PLAIN="\033[0m"

# Ensure the script is run as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error:${PLAIN} This script must be run as root. Use sudo or login as root."
        exit 1
    fi
}

# Detect operating system for dependency installation
detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        OS_FAMILY="centos"
    elif grep -qi debian /etc/issue; then
        OS_FAMILY="debian"
    elif grep -qi ubuntu /etc/issue; then
        OS_FAMILY="ubuntu"
    elif grep -qi -E "centos|red hat|redhat|rocky" /etc/issue; then
        OS_FAMILY="centos"
    elif [[ -f /etc/debian_version ]]; then
        OS_FAMILY="debian"
    else
        OS_FAMILY="unknown"
    fi
}

# Install common tools if missing.  These are needed for the
# configuration helpers (sed, curl, systemctl, etc.).  The upstream
# install scripts will install additional dependencies as required.
install_dependencies() {
    local pkgs=(curl wget jq)
    case "$OS_FAMILY" in
        centos)
            yum install -y epel-release >/dev/null 2>&1
            yum install -y "${pkgs[@]}" >/dev/null 2>&1
            ;;
        debian|ubuntu)
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y "${pkgs[@]}" >/dev/null 2>&1
            ;;
        *)
            # Fallback: try with apt
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y "${pkgs[@]}" >/dev/null 2>&1
            ;;
    esac
}

###
# Snell management
###

# Call the upstream Snell installer.  This function runs the
# recommended installation script provided by jinqians.  It will
# prompt for version (v4 or v5), generate a random port and password
# and configure systemd.  See the upstream documentation for full
# functionality【790071861813661†L137-L178】.
snell_install() {
    echo -e "${GREEN}Running the Snell installer...${PLAIN}"
    # Install Snell via upstream script (interactive).  Users will
    # be prompted to choose a version and configure options.  We
    # preserve stdin/out to allow interaction.
    bash <(curl -fsSL https://install.jinqians.com)
    echo -e "${GREEN}Snell installation complete.${PLAIN}"
}

# Remove Snell and its service files.  This function stops the
# service, disables it and removes all associated files.  It does not
# remove ShadowTLS; if you installed ShadowTLS via the Snell menu
# please remove it separately using the menu or via snell_uninstall_shadowtls.
snell_uninstall() {
    if systemctl is-active --quiet snell-server.service; then
        echo -e "Stopping Snell service..."
        systemctl stop snell-server.service
    fi
    echo -e "Disabling Snell service..."
    systemctl disable snell-server.service >/dev/null 2>&1 || true
    echo -e "Removing Snell files..."
    rm -rf /usr/local/bin/snell-server /etc/snell /etc/systemd/system/snell-server.service
    systemctl daemon-reload
    echo -e "${GREEN}Snell has been removed.${PLAIN}"
}

# Edit Snell configuration.  The default configuration file is
# /etc/snell/config.conf.  We prompt the user for a new port and
# pre‑shared key (PSK) and write a minimal configuration.  If you
# require obfs or ShadowTLS options please edit the file manually.
snell_config() {
    local conf="/etc/snell/config.conf"
    if [[ ! -f "$conf" ]]; then
        echo -e "${RED}Error:${PLAIN} Snell does not appear to be installed."
        return
    fi
    read -rp "Enter listening port for Snell (e.g. 57891): " port
    read -rp "Enter PSK (password) for Snell: " psk
    # Basic validation
    if [[ -z "$port" || -z "$psk" ]]; then
        echo -e "${RED}Invalid input.  Port and PSK cannot be empty.${PLAIN}"
        return
    fi
    cat > "$conf" <<EOF
listen = 0.0.0.0:${port}
psk = ${psk}
# Additional optional fields (uncomment as needed)
# obfs = tls
# obfs-host = bing.com
EOF
    echo -e "${GREEN}Updated Snell configuration.${PLAIN}"
    systemctl restart snell-server.service && echo -e "${GREEN}Snell service restarted.${PLAIN}" || echo -e "${YELLOW}Warning:${PLAIN} failed to restart Snell service."
}

# Display Snell service status using systemctl.  This will show
# whether the service is active and any recent logs.
snell_status() {
    systemctl status snell-server.service
}

###
# Hysteria 2 management
###

# Install Hysteria 2.  We call the official installer and then
# populate /etc/hysteria/config.yaml with basic settings.  The
# installer will create a hysteria user and systemd unit.
hysteria_install() {
    echo -e "${GREEN}Running the Hysteria 2 installer...${PLAIN}"
    bash <(curl -fsSL https://get.hy2.sh/)
    # Prompt for basic configuration
    read -rp "Enter Hysteria port (default 8443): " hy_port
    read -rp "Enter domain for ACME certificate (leave blank to skip): " hy_domain
    read -rp "Enter password (default random): " hy_password
    hy_port=${hy_port:-8443}
    hy_password=${hy_password:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c16)}
    mkdir -p /etc/hysteria
    # Write YAML configuration.  ACME section included only if domain provided.
    {
        echo "listen: :${hy_port}"
        if [[ -n "$hy_domain" ]]; then
            cat <<ACME
acme:
  domains:
    - ${hy_domain}
  email: admin@${hy_domain}
ACME
        fi
        cat <<AUTH
auth:
  type: password
  password: ${hy_password}
masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true
AUTH
    } > /etc/hysteria/config.yaml
    echo -e "${GREEN}Hysteria 2 configuration written to /etc/hysteria/config.yaml.${PLAIN}"
    systemctl restart hysteria-server.service && echo -e "${GREEN}Hysteria 2 service restarted.${PLAIN}" || echo -e "${YELLOW}Warning:${PLAIN} failed to restart Hysteria 2 service."
    echo -e "Domain: ${hy_domain:-<none>}\nPort: ${hy_port}\nPassword: ${hy_password}"
}

# Uninstall Hysteria 2.  Use the official removal flag and clean up.
hysteria_uninstall() {
    echo -e "${GREEN}Removing Hysteria 2...${PLAIN}"
    bash <(curl -fsSL https://get.hy2.sh/) --remove
    rm -rf /etc/hysteria
    userdel -r hysteria >/dev/null 2>&1 || true
    # Clean up leftover units
    rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service 2>/dev/null
    rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@*.service 2>/dev/null
    systemctl daemon-reload
    echo -e "${GREEN}Hysteria 2 has been removed.${PLAIN}"
}

# Edit Hysteria configuration.  This helper rewrites
# /etc/hysteria/config.yaml with new port/domain/password.  It
# preserves the existing masquerade settings.
hysteria_config() {
    local conf="/etc/hysteria/config.yaml"
    if [[ ! -f "$conf" ]]; then
        echo -e "${RED}Error:${PLAIN} Hysteria 2 does not appear to be installed."
        return
    fi
    read -rp "Enter new port (leave blank to keep current): " hy_port
    read -rp "Enter new domain (blank for none): " hy_domain
    read -rp "Enter new password (leave blank to keep current): " hy_password
    # Read existing masquerade section
    local masquerade
    masquerade=$(awk '/masquerade:/,0' "$conf")
    # Extract existing password if not provided
    if [[ -z "$hy_password" ]]; then
        hy_password=$(grep -A1 '^auth:' "$conf" | grep 'password:' | awk '{print $2}')
    fi
    # Extract existing port if not provided
    if [[ -z "$hy_port" ]]; then
        hy_port=$(grep '^listen:' "$conf" | sed 's/listen: ://')
    fi
    # Write new configuration
    {
        echo "listen: :${hy_port}"
        if [[ -n "$hy_domain" ]]; then
            cat <<ACME
acme:
  domains:
    - ${hy_domain}
  email: admin@${hy_domain}
ACME
        fi
        cat <<AUTH
auth:
  type: password
  password: ${hy_password}
${masquerade}
AUTH
    } > "$conf"
    echo -e "${GREEN}Updated Hysteria 2 configuration.${PLAIN}"
    systemctl restart hysteria-server.service && echo -e "${GREEN}Hysteria 2 service restarted.${PLAIN}" || echo -e "${YELLOW}Warning:${PLAIN} failed to restart Hysteria 2 service."
}

# Display Hysteria 2 status
hysteria_status() {
    systemctl status hysteria-server.service
}

###
# Shadowsocks‑Rust (2022) and ShadowTLS management
###

# Install Shadowsocks‑Rust and ShadowTLS via upstream script.  The
# upstream menu supports installation, update, removal and many other
# features for Shadowsocks Rust and ShadowTLS【626787053643720†L40-L54】.  We
# delegate installation to it but provide a simple wrapper so the
# unified script remains consistent.
ss_install() {
    echo -e "${GREEN}Running the Shadowsocks‑Rust + ShadowTLS installer...${PLAIN}"
    bash <(curl -fsSL ss.jinqians.com)
    echo -e "${GREEN}Installation finished.  Use the SS menu above for advanced options.${PLAIN}"
}

# Uninstall Shadowsocks‑Rust and ShadowTLS.  Stop services and remove
# files.  Note: the upstream script also provides an uninstall
# option in its menu; you can use that instead.
ss_uninstall() {
    echo -e "${GREEN}Stopping ss-rust and shadowtls services...${PLAIN}"
    systemctl stop ss-rust.service 2>/dev/null || true
    systemctl stop shadowtls.service 2>/dev/null || true
    systemctl disable ss-rust.service 2>/dev/null || true
    systemctl disable shadowtls.service 2>/dev/null || true
    echo -e "Removing binaries and configuration..."
    rm -rf /usr/local/bin/ss-* /usr/local/bin/ssserver /etc/ss-rust
    rm -rf /usr/local/bin/shadowtls* /etc/shadowtls
    rm -f /etc/systemd/system/ss-rust.service /etc/systemd/system/shadowtls.service
    systemctl daemon-reload
    echo -e "${GREEN}Shadowsocks‑Rust and ShadowTLS removed.${PLAIN}"
}

# Edit Shadowsocks configuration.  The config file is assumed to be
# /etc/ss-rust/config.json as used by the upstream script.  We prompt
# for port, password and encryption method and regenerate a minimal
# JSON.  Supported methods include aes-128-gcm, aes-256-gcm,
# chacha20-ietf-poly1305 and several 2022 variants【626787053643720†L56-L65】.
ss_config() {
    local conf="/etc/ss-rust/config.json"
    if [[ ! -f "$conf" ]]; then
        echo -e "${RED}Error:${PLAIN} Shadowsocks‑Rust does not appear to be installed."
        return
    fi
    read -rp "Enter listening port for Shadowsocks (e.g. 9000): " ss_port
    read -rp "Enter password: " ss_password
    echo "Select encryption method:" 
    local methods=("aes-128-gcm" "aes-256-gcm" "chacha20-ietf-poly1305" "2022-blake3-aes-128-gcm" "2022-blake3-aes-256-gcm" "2022-blake3-chacha20-poly1305")
    local i=1
    for m in "${methods[@]}"; do
        echo "$i) $m"
        ((i++))
    done
    read -rp "Choice [1-${#methods[@]}]: " choice
    local method="${methods[$((choice-1))]}"
    if [[ -z "$ss_port" || -z "$ss_password" || -z "$method" ]]; then
        echo -e "${RED}Invalid input.${PLAIN}"
        return
    fi
    mkdir -p /etc/ss-rust
    cat > "$conf" <<EOF
{
  "server": "0.0.0.0",
  "server_port": ${ss_port},
  "password": "${ss_password}",
  "method": "${method}",
  "mode": "tcp_and_udp"
}
EOF
    echo -e "${GREEN}Updated Shadowsocks configuration.${PLAIN}"
    systemctl restart ss-rust.service && echo -e "${GREEN}Shadowsocks‑Rust service restarted.${PLAIN}" || echo -e "${YELLOW}Warning:${PLAIN} failed to restart ss-rust service."
}

# Show Shadowsocks and ShadowTLS service status
ss_status() {
    systemctl status ss-rust.service
    systemctl status shadowtls.service 2>/dev/null || true
}

###
# Interactive menus
###

snell_menu() {
    while true; do
        echo ""
        echo "===== Snell Management ====="
        echo "1) Install Snell"
        echo "2) Uninstall Snell"
        echo "3) Edit Snell configuration"
        echo "4) Show Snell status"
        echo "0) Back to main menu"
        read -rp "Choose an option: " sn_choice
        case "$sn_choice" in
            1) snell_install ;;
            2) snell_uninstall ;;
            3) snell_config ;;
            4) snell_status ;;
            0) break ;;
            *) echo "Invalid choice" ;;
        esac
    done
}

hysteria_menu() {
    while true; do
        echo ""
        echo "===== Hysteria 2 Management ====="
        echo "1) Install Hysteria 2"
        echo "2) Uninstall Hysteria 2"
        echo "3) Edit Hysteria configuration"
        echo "4) Show Hysteria status"
        echo "0) Back to main menu"
        read -rp "Choose an option: " hy_choice
        case "$hy_choice" in
            1) hysteria_install ;;
            2) hysteria_uninstall ;;
            3) hysteria_config ;;
            4) hysteria_status ;;
            0) break ;;
            *) echo "Invalid choice" ;;
        esac
    done
}

ss_menu() {
    while true; do
        echo ""
        echo "===== Shadowsocks‑Rust & ShadowTLS Management ====="
        echo "1) Install Shadowsocks‑Rust + ShadowTLS"
        echo "2) Uninstall Shadowsocks‑Rust + ShadowTLS"
        echo "3) Edit Shadowsocks configuration"
        echo "4) Show service status"
        echo "0) Back to main menu"
        read -rp "Choose an option: " ss_choice
        case "$ss_choice" in
            1) ss_install ;;
            2) ss_uninstall ;;
            3) ss_config ;;
            4) ss_status ;;
            0) break ;;
            *) echo "Invalid choice" ;;
        esac
    done
}

#
# V2Ray management functions
#

# Install V2Ray using the official V2Fly install script and generate a basic
# configuration.  V2Ray is a platform for multiple proxy protocols such as
# VMess and VLess.  According to official documentation, V2Ray supports
# multiple proxy protocols (HTTP, HTTPS, SOCKS, VMess, Shadowsocks and
# others) and provides encryption and obfuscation features to enhance
# privacy【490479597040404†L89-L112】.
v2ray_install() {
    echo -e "${GREEN}Installing V2Ray...${PLAIN}"
    # Use official script to install v2ray.  This will install binaries and
    # systemd service.  The script may be re‑run to update or remove the
    # software; we use it here for fresh installation.
    bash <(curl -fsSL https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    # Prompt for configuration
    read -rp "Enter listening port for V2Ray (e.g. 443): " v2_port
    echo "Select protocol:"
    echo "1) VMess"
    echo "2) VLess"
    read -rp "Protocol [1-2]: " proto_choice
    local proto="vmess"
    case "$proto_choice" in
        2) proto="vless" ;;
        *) proto="vmess" ;;
    esac
    # Generate a UUID for client ID
    local uuid
    uuid=$(uuidgen)
    mkdir -p /usr/local/etc/v2ray
    if [[ "$proto" == "vmess" ]]; then
        cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "inbounds": [{
    "port": ${v2_port},
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "${uuid}",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "tcp"
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    else
        cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "inbounds": [{
    "port": ${v2_port},
    "protocol": "vless",
    "settings": {
      "clients": [{
        "id": "${uuid}",
        "flow": ""
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp"
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    fi
    # Restart service; try different unit names for compatibility
    systemctl restart v2ray.service 2>/dev/null || systemctl restart v2ray 2>/dev/null || true
    systemctl enable v2ray.service 2>/dev/null || systemctl enable v2ray 2>/dev/null || true
    echo -e "${GREEN}V2Ray installed with ${proto} on port ${v2_port}. UUID: ${uuid}${PLAIN}"
}

# Remove V2Ray installation.  This calls the official install script with
# --remove flag to clean up binaries, systemd units and configs.  It then
# deletes any remaining configuration files.
v2ray_uninstall() {
    echo -e "${GREEN}Removing V2Ray...${PLAIN}"
    bash <(curl -fsSL https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --remove
    rm -rf /usr/local/etc/v2ray
    systemctl daemon-reload
    echo -e "${GREEN}V2Ray has been removed.${PLAIN}"
}

# Edit existing V2Ray configuration.  We attempt to parse the current
# configuration to preserve the UUID.  Users can modify the listening
# port and protocol.
v2ray_config() {
    local conf="/usr/local/etc/v2ray/config.json"
    if [[ ! -f "$conf" ]]; then
        echo -e "${RED}Error:${PLAIN} V2Ray does not appear to be installed."
        return
    fi
    local current_port current_uuid current_proto
    current_proto=$(jq -r '.inbounds[0].protocol' "$conf" 2>/dev/null || echo "vmess")
    current_port=$(jq -r '.inbounds[0].port' "$conf" 2>/dev/null || echo "")
    current_uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$conf" 2>/dev/null || uuidgen)
    read -rp "Enter new listening port (current ${current_port}): " new_port
    echo "Select protocol:"
    echo "1) VMess"
    echo "2) VLess"
    read -rp "Protocol [1-2] (current ${current_proto}): " new_proto_choice
    local new_proto="$current_proto"
    case "$new_proto_choice" in
        1) new_proto="vmess" ;;
        2) new_proto="vless" ;;
        *) : ;;
    esac
    [[ -z "$new_port" ]] && new_port="$current_port"
    mkdir -p /usr/local/etc/v2ray
    if [[ "$new_proto" == "vmess" ]]; then
        cat > "$conf" <<EOF
{
  "inbounds": [{
    "port": ${new_port},
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "${current_uuid}",
        "alterId": 0
      }]
    },
    "streamSettings": {
      "network": "tcp"
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    else
        cat > "$conf" <<EOF
{
  "inbounds": [{
    "port": ${new_port},
    "protocol": "vless",
    "settings": {
      "clients": [{
        "id": "${current_uuid}",
        "flow": ""
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp"
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    fi
    systemctl restart v2ray.service 2>/dev/null || systemctl restart v2ray 2>/dev/null || true
    echo -e "${GREEN}Updated V2Ray configuration.${PLAIN}"
}

# Show V2Ray service status
v2ray_status() {
    systemctl status v2ray.service 2>/dev/null || systemctl status v2ray 2>/dev/null || true
}

# Interactive menu for V2Ray
v2ray_menu() {
    while true; do
        echo ""
        echo "===== V2Ray Management ====="
        echo "1) Install V2Ray"
        echo "2) Uninstall V2Ray"
        echo "3) Edit V2Ray configuration"
        echo "4) Show V2Ray status"
        echo "0) Back to main menu"
        read -rp "Choose an option: " v2_choice
        case "$v2_choice" in
            1) v2ray_install ;;
            2) v2ray_uninstall ;;
            3) v2ray_config ;;
            4) v2ray_status ;;
            0) break ;;
            *) echo "Invalid choice" ;;
        esac
    done
}

#
# Trojan management functions
#

# Install Trojan via the trojan-quickstart script.  Trojan-Go is a proxy
# protocol that disguises itself as normal HTTPS traffic by performing a real
# TLS handshake and serving a decoy website, making it hard for censors to
# distinguish from legitimate HTTPS【972719891332728†L250-L274】.
trojan_install() {
    echo -e "${GREEN}Installing Trojan...${PLAIN}"
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
    echo -e "${GREEN}Trojan installation complete.${PLAIN}"
    # Prompt to configure immediately
    echo -e "You should now configure your Trojan server."
    trojan_config
}

# Uninstall Trojan by removing binary, configuration and service
trojan_uninstall() {
    echo -e "${GREEN}Removing Trojan...${PLAIN}"
    systemctl stop trojan.service 2>/dev/null || true
    systemctl disable trojan.service 2>/dev/null || true
    rm -f /usr/local/bin/trojan
    rm -rf /usr/local/etc/trojan
    rm -f /etc/systemd/system/trojan.service
    systemctl daemon-reload
    echo -e "${GREEN}Trojan has been removed.${PLAIN}"
}

# Configure Trojan server.  Requires a valid certificate and key for TLS.
trojan_config() {
    local conf="/usr/local/etc/trojan/config.json"
    if [[ ! -f "$conf" ]]; then
        echo -e "${RED}Error:${PLAIN} Trojan does not appear to be installed."
        return
    fi
    read -rp "Enter listening port for Trojan (default 443): " tr_port
    read -rp "Enter password: " tr_pass
    read -rp "Enter full path to TLS certificate (e.g. /etc/ssl/certs/fullchain.pem): " tr_cert
    read -rp "Enter full path to TLS key (e.g. /etc/ssl/private/privkey.pem): " tr_key
    tr_port=${tr_port:-443}
    # Generate configuration
    mkdir -p /usr/local/etc/trojan
    cat > "$conf" <<EOF
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": ${tr_port},
  "remote_addr": "127.0.0.1",
  "remote_port": 80,
  "password": [ "${tr_pass}" ],
  "ssl": {
    "cert": "${tr_cert}",
    "key": "${tr_key}",
    "sni": ""
  }
}
EOF
    systemctl restart trojan.service 2>/dev/null || true
    systemctl enable trojan.service 2>/dev/null || true
    echo -e "${GREEN}Trojan configuration updated and service restarted.${PLAIN}"
}

# Show Trojan service status
trojan_status() {
    systemctl status trojan.service 2>/dev/null || true
}

# Menu for Trojan
trojan_menu() {
    while true; do
        echo ""
        echo "===== Trojan Management ====="
        echo "1) Install Trojan"
        echo "2) Uninstall Trojan"
        echo "3) Edit Trojan configuration"
        echo "4) Show Trojan status"
        echo "0) Back to main menu"
        read -rp "Choose an option: " tr_choice
        case "$tr_choice" in
            1) trojan_install ;;
            2) trojan_uninstall ;;
            3) trojan_config ;;
            4) trojan_status ;;
            0) break ;;
            *) echo "Invalid choice" ;;
        esac
    done
}

#
# TUIC management functions
#

# Install TUIC server using the tuic-setup script.  TUIC is a modern
# congestion‑controlled transport that supports QUIC‑based connections and
# automatically generates certificates and prints server credentials.  The
# script prompts for port, password and congestion control and sets up
# systemd【213372400254652†L223-L240】.
tuic_install() {
    echo -e "${GREEN}Installing TUIC...${PLAIN}"
    local tmp_script="/tmp/tuic-setup.sh"
    curl -fsSL https://raw.githubusercontent.com/hrostami/tuic-setup/master/setup.sh -o "$tmp_script"
    chmod +x "$tmp_script"
    bash "$tmp_script"
    rm -f "$tmp_script"
    echo -e "${GREEN}TUIC installation complete.${PLAIN}"
}

# Uninstall TUIC by stopping service and removing installation directory
tuic_uninstall() {
    echo -e "${GREEN}Removing TUIC...${PLAIN}"
    # Stop and disable service
    systemctl stop tuic 2>/dev/null || true
    systemctl disable tuic 2>/dev/null || true
    # Remove possible installation directories
    rm -rf /root/tuic "$HOME/tuic"
    rm -f /etc/systemd/system/tuic.service
    systemctl daemon-reload
    echo -e "${GREEN}TUIC has been removed.${PLAIN}"
}

# Configure TUIC server by modifying its config.json.  We attempt to detect
# the config file location (/root/tuic or $HOME/tuic) and preserve the UUID
# and certificate paths.  Users can change port, password and congestion
# control algorithm.
tuic_config() {
    local conf
    local folder
    if [[ -f /root/tuic/config.json ]]; then
        conf="/root/tuic/config.json"
        folder="/root/tuic"
    elif [[ -f "$HOME/tuic/config.json" ]]; then
        conf="$HOME/tuic/config.json"
        folder="$HOME/tuic"
    else
        echo -e "${RED}Error:${PLAIN} TUIC configuration file not found."
        return
    fi
    # Extract current values
    local uuid password port cong
    uuid=$(jq -r '.users | keys[0]' "$conf")
    password=$(jq -r ".users[\"$uuid\"]" "$conf")
    port=$(jq -r '.server' "$conf" | awk -F ':' '{print $NF}')
    cong=$(jq -r '.congestion_control' "$conf")
    read -rp "Enter new port (current ${port}): " new_port
    read -rp "Enter new password (current ${password}): " new_pass
    echo "Select congestion control algorithm:"
    local options=("cubic" "new_reno" "bbr")
    local i=1
    for opt in "${options[@]}"; do
        echo "$i) $opt"
        ((i++))
    done
    read -rp "Choice [1-${#options[@]}] (current ${cong}): " cong_choice
    local new_cong
    if [[ -n "$cong_choice" && "$cong_choice" =~ ^[0-9]+$ && "$cong_choice" -ge 1 && "$cong_choice" -le ${#options[@]} ]]; then
        new_cong="${options[$((cong_choice-1))]}"
    else
        new_cong="$cong"
    fi
    [[ -z "$new_port" ]] && new_port="$port"
    [[ -z "$new_pass" ]] && new_pass="$password"
    # Write updated configuration
    cat > "$conf" <<EOF
{
  "server": "[::]:${new_port}",
  "users": {
    "${uuid}": "${new_pass}"
  },
  "certificate": "${folder}/ca.crt",
  "private_key": "${folder}/ca.key",
  "congestion_control": "${new_cong}",
  "alpn": ["h3", "spdy/3.1"],
  "udp_relay_ipv6": true,
  "zero_rtt_handshake": false,
  "dual_stack": true,
  "auth_timeout": "3s",
  "task_negotiation_timeout": "3s",
  "max_idle_time": "10s",
  "max_external_packet_size": 1500,
  "send_window": 16777216,
  "receive_window": 8388608,
  "gc_interval": "3s",
  "gc_lifetime": "15s",
  "log_level": "warn"
}
EOF
    systemctl restart tuic 2>/dev/null || true
    systemctl enable tuic 2>/dev/null || true
    echo -e "${GREEN}Updated TUIC configuration and restarted service.${PLAIN}"
}

# Show TUIC service status
tuic_status() {
    systemctl status tuic 2>/dev/null || true
}

# Menu for TUIC
tuic_menu() {
    while true; do
        echo ""
        echo "===== TUIC Management ====="
        echo "1) Install TUIC"
        echo "2) Uninstall TUIC"
        echo "3) Edit TUIC configuration"
        echo "4) Show TUIC status"
        echo "0) Back to main menu"
        read -rp "Choose an option: " tuic_choice
        case "$tuic_choice" in
            1) tuic_install ;;
            2) tuic_uninstall ;;
            3) tuic_config ;;
            4) tuic_status ;;
            0) break ;;
            *) echo "Invalid choice" ;;
        esac
    done
}

uninstall_script() {
  echo ""
  echo "==== Uninstall Proxy Manager ===="
  # Remove symlink if exists
  if [ -L "/usr/local/bin/pm" ]; then
    rm -f /usr/local/bin/pm
    echo "Removed symlink /usr/local/bin/pm"
  fi
  # Remove script itself
  script_path="$(readlink -f "$0")"
  rm -f "$script_path"
  echo "Removed script file $script_path"
  echo "Proxy Manager has been uninstalled."
  exit 0
}

main_menu() {
  while true; do
    echo ""
    echo "==== Proxy Manager ===="
    echo "1) Snell"
    echo "2) Hysteria 2"
    echo "3) Shadowsocks-Rust + ShadowTLS"
    echo "4) V2Ray (VMess/VLess)"
    echo "5) Trojan"
    echo "6) TUIC"
    echo "7) Uninstall Proxy Manager script"
    echo "0) Exit"
    read -rp "Select a protocol to manage: " main_choice
    case "$main_choice" in
      1) snell_menu ;;
      2) hysteria_menu ;;
      3) ss_menu ;;
      4) v2ray_menu ;;
      5) trojan_menu ;;
      6) tuic_menu ;;
      7) uninstall_script ;;
      0) echo "Exiting."; exit 0 ;;
      *) echo "Invalid selection" ;;
    esac
  done
}


# Entry point
require_root
detect_os
install_dependencies

# Ensure a convenient alias 'pm' is available system-wide by creating a symlink
setup_quick_command() {
    local target="/usr/local/bin/pm"
    local script_path
    script_path="$(readlink -f "$0")"
    if [[ "$script_path" != "$target" ]]; then
        ln -sf "$script_path" "$target"
        chmod +x "$target"
    fi
}
# ===== Entry point (keep this at the VERY END of the file) =====
require_root
detect_os

# Only install dependencies on first run to speed up subsequent starts
STATE_FILE="/usr/local/share/proxy_manager_setup_done"
if [[ ! -f "$STATE_FILE" ]]; then
  install_dependencies
  touch "$STATE_FILE"
fi

# Ensure quick command symlink
setup_quick_command

# Start menu
main_menu


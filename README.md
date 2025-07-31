# proxy-manager

This repository contains a unified one-click proxy management script that supports several mainstream proxy protocols: **Snell**, **Hysteria2**, **Shadowsocks Rust** (with **ShadowTLS**), **V2Ray** (VMess/VLess), **Trojan-Go**, and **TUIC**. It provides interactive menus for installing, configuring, and managing each protocol on a Linux server.

## Features

- Automated installation and uninstallation of each supported proxy.
- Interactive configuration editing (port, password, protocol selection, etc.).
- Start, stop, restart and status checking for each service.
- Supports Snell v4/v5 (with optional ShadowTLS integration), Hysteria2, Shadowsocks Rust & ShadowTLS (including 2022-blake3 ciphers), V2Ray (VMess/VLess), Trojan-Go, and TUIC.
- User-friendly menu-based interface.

## Quick installation

To download and run the script on your server, use either **wget** or **curl**:

```bash
# Using wget
wget -O proxy_manager.sh https://raw.githubusercontent.com/octoer/proxy-manager/main/proxy_manager.sh
# Make it executable
chmod +x proxy_manager.sh
# Run it with sudo (root privileges)
sudo bash proxy_manager.sh

# Using curl
curl -fsSL https://raw.githubusercontent.com/octoer/proxy-manager/main/proxy_manager.sh -o proxy_manager.sh
chmod +x proxy_manager.sh
sudo bash proxy_manager.sh
```

The script will detect your operating system, install necessary dependencies, and present a menu where you can choose which proxy protocol to manage.

## Usage

Run the script and follow the on‑screen prompts to install, configure, or remove any of the supported proxies. After installation, configuration files are stored in standard locations (for example, `/etc/snell/config.conf`, `/etc/hysteria/config.yaml`, `/usr/local/etc/v2ray/config.json`), and services are managed via `systemd`.

## Disclaimer

This script is provided as‑is. Use it at your own risk and ensure you comply with the laws and regulations in your region regarding proxy software.

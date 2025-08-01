proxy-manager
This repository contains a unified one‑click proxy management script that supports several mainstream proxy protocols: Snell, Hysteria2, Shadowsocks Rust (with ShadowTLS), V2Ray (VMess/VLess), Trojan-Go, and TUIC. It provides interactive menus for installing, configuring, and managing each protocol on a Linux server.

Features
Automated installation and uninstallation of each supported proxy.

Interactive configuration editing (port, password, protocol selection, etc.).

Start, stop, restart and status checking for each service.

Supports Snell v4/v5 (with optional ShadowTLS integration), Hysteria2, Shadowsocks Rust & ShadowTLS (including 2022‑blake3 ciphers), V2Ray (VMess/VLess), Trojan‑Go, and TUIC.

User‑friendly menu‑based interface.

Quick installation
To download and run the script on your server, use one of the following two‑step methods:

bash
复制
编辑
# 使用 wget 下载脚本
wget -O proxy_manager.sh https://raw.githubusercontent.com/octoer/proxy-manager/main/proxy_manager.sh
# 直接运行脚本（无需额外赋权，脚本会自动安装依赖并打开菜单）
sudo bash proxy_manager.sh
Alternatively, using curl:

bash
复制
编辑
# 使用 curl 下载脚本
curl -fsSL https://raw.githubusercontent.com/octoer/proxy-manager/main/proxy_manager.sh -o proxy_manager.sh
# 直接运行脚本
sudo bash proxy_manager.sh
运行脚本后，它会自动检测您的系统、安装必要的依赖，然后进入交互式菜单供您选择要管理的代理协议。

Usage
Run the script and follow the on‑screen prompts to install, configure, or remove any of the supported proxies. After installation, configuration files are stored in standard locations (for example, /etc/snell/config.conf, /etc/hysteria/config.yaml, /usr/local/etc/v2ray/config.json), and services are managed via systemd.

Disclaimer
This script is provided as‑is. Use it at your own risk and ensure you comply with the laws and regulations in your region regarding proxy software.

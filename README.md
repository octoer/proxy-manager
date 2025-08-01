# proxy-manager

This repository contains a unified one‑click proxy management script that supports several mainstream proxy protocols: **Snell**, **Hysteria2**, **Shadowsocks Rust** (with **ShadowTLS**), **V2Ray** (VMess/VLess), **Trojan‑Go**, and **TUIC**. It provides interactive menus for installing, configuring and managing each protocol on a Linux server.

## Features

- Automated installation and uninstallation of each supported proxy.
- Interactive configuration editing (port, password, protocol selection, etc.).
- Start, stop, restart and status checking for each service.
- Supports Snell v4/v5 (with optional ShadowTLS integration), Hysteria2, Shadowsocks Rust & ShadowTLS (including 2022‑blake3 ciphers), V2Ray (VMess/VLess), Trojan‑Go, and TUIC.
- User‑friendly menu‑based interface.

## Quick installation

To download and run the script on your server, use one of the following two‑step methods:

```bash
# 使用 wget 下载脚本
wget -O proxy_manager.sh https://raw.githubusercontent.com/octoer/proxy-manager/main/proxy_manager.sh
# 直接运行脚本（无需额外赋权，脚本会自动安装依赖并打开菜单）
sudo bash proxy_manager.sh

# 使用 curl 下载脚本
curl -fsSL https://raw.githubusercontent.com/octoer/proxy-manager/main/proxy_manager.sh -o proxy_manager.sh

# 直接运行脚本
sudo bash proxy_manager.sh

运行脚本后，它会自动检测您的系统、安装必要的依赖，然后进入交互式菜单供您选择要管理的代理协议。首次运行脚本会在 /usr/local/bin/pm 创建一个系统范围的符号链接，随后可以通过 pm 快捷命令再次启动管理脚本。

用法
运行脚本并按照屏幕提示进行操作，以安装、配置或删除任何支持的代理。安装后，配置文件将存储在标准位置（例如 /etc/snell/config.conf、/etc/hysteria/config.yaml、/usr/local/etc/v2ray/config.json），并且服务通过 systemd进行管理。

免责声明
本脚本按“原样”提供。使用风险自负，并请确保您遵守所在地区有关代理软件的法律法规。

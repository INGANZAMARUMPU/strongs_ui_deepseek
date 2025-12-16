# strongswan-manager

Lightweight manager for StrongSwan IPsec installations. Provides a minimal, extensible UI and CLI helpers for composing connection profiles, managing certificates, controlling tunnels, and viewing runtime status and logs.

## Features
- Create, edit, enable/disable StrongSwan connection profiles
- Apply configuration via VICI (strongswan vici socket) or by writing ipsec.conf/ipsec.secrets
- Certificate and key management (import, view, revoke)
- Start/stop/reload tunnels and view connection status
- Live logs and diagnostics (ipsec status, syslog tail)
- Import/export connection sets and backup/restore configs
- Role-based access for safe remote administration (when fronted by an API)

## Prerequisites
- StrongSwan installed and configured on host(s)
- Access to StrongSwan control interface:
    - VICI socket (recommended) OR
    - permission to modify /etc/ipsec.conf and run ipsec commands (requires root)
- Optional: systemd service for running the manager with elevated privileges


## /etc/systemd/system/ipsec_ui.service   
[Unit]
Description=StrongSwan UI
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/home/ubuntu/strongs_ui_deepseek
ExecStart=/home/ubuntu/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target

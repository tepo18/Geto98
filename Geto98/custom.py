#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import json
import shutil
import subprocess


# ============================================================
# COLORS
# ============================================================

CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
NC = "\033[0m"


# ============================================================
# CLEAR SCREEN
# ============================================================

os.system("clear")


# ============================================================
# HEADER
# ============================================================

print(f"{CYAN}=== CUSTOM CONFIG GENERATOR ==={NC}")
print()


# ============================================================
# INPUTS
# ============================================================

REMARKS = input("NAME (remarks): ")

IP = input("IP / ADDRESS: ")

PORT = input("PORT (default 443): ")
PORT = PORT if PORT else "443"

PASSWORD = input("PASSWORD: ")

HOST = input("HOST: ")

SNI = input("SNI: ")

PATHWS = input("PATH: ")


# ============================================================
# PORT VALIDATION
# ============================================================

try:
    PORT = int(PORT)
except ValueError:
    print()
    print("Invalid PORT.")
    raise SystemExit(1)


# ============================================================
# CONFIG
# ============================================================

config = {
    "remarks": REMARKS,

    "log": {
        "access": "",
        "error": "",
        "loglevel": "info",
        "dnsLog": False
    },

    "inbounds": [
        {
            "tag": "in_proxy",
            "port": 1080,
            "protocol": "socks",
            "listen": "0.0.0.0",
            "settings": {
                "auth": "noauth",
                "udp": True,
                "userLevel": 8
            },
            "sniffing": {
                "enabled": False
            }
        },
        {
            "tag": "http-in",
            "port": 10808,
            "listen": "::",
            "protocol": "http"
        }
    ],

    "outbounds": [
        {
            "tag": "proxy",
            "protocol": "trojan",

            "settings": {
                "servers": [
                    {
                        "address": IP,
                        "port": PORT,
                        "password": PASSWORD,
                        "level": 8
                    }
                ]
            },

            "streamSettings": {
                "network": "ws",
                "security": "tls",

                "wsSettings": {
                    "path": PATHWS,
                    "headers": {
                        "Host": HOST
                    }
                },

                "tlsSettings": {
                    "allowInsecure": True,
                    "serverName": SNI,
                    "alpn": [
                        "http/1.1"
                    ],
                    "fingerprint": "ios"
                }
            },

            "mux": {
                "enabled": False,
                "concurrency": 8
            }
        }
    ],

    "dns": {
        "servers": [
            "8.8.8.8"
        ]
    },

    "routing": {
        "domainStrategy": "UseIp",
        "rules": []
    }
}


# ============================================================
# JSON OUTPUT
# ============================================================

output = json.dumps(
    config,
    ensure_ascii=False,
    indent=2
)


# ============================================================
# DISPLAY
# ============================================================

print()
print(f"{GREEN}=== GENERATED CONFIG ==={NC}")
print()

print(output)


# ============================================================
# COPY TO TERMUX CLIPBOARD
# Equivalent to:
# tee >(termux-clipboard-set)
# ============================================================

clipboard_ok = False

try:
    if shutil.which("termux-clipboard-set"):
        process = subprocess.run(
            ["termux-clipboard-set"],
            input=output,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if process.returncode == 0:
            clipboard_ok = True

except Exception:
    clipboard_ok = False


# ============================================================
# RESULT
# ============================================================

print()

if clipboard_ok:
    print(f"{GREEN}✔ CONFIG GENERATED + COPIED TO CLIPBOARD{NC}")
else:
    print(f"{GREEN}✔ CONFIG GENERATED{NC}")
    print("⚠ Clipboard copy failed: termux-api / termux-clipboard-set is unavailable.")

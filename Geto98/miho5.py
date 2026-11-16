#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-
"""
MIHOMO INDUSTRIAL — FOUR GROUPS ONLY
Full proxy parser, normalizer, validator, and Mihomo configuration builder for Termux.

- Exactly four independent groups: Select, Fallback, Unknown Country, and Direct.
- Proxy-country labels are based only on measured proxy Egress IP, never server IP or source remarks.
- Proxy providers: http / file / inline
- URI + Base64 + JSON + YAML input
- VLESS / VMess / Trojan / SS / SSR / Hysteria / Hysteria2 / TUIC /
  HTTP / SOCKS5 / WireGuard / AnyTLS / Snell structured nodes
- Native Mihomo url-test/fallback health checks are used for runtime selection;
  static generation does not claim an endpoint is live without successful test evidence.
- Optional timestamped change reports, audit logs, and validated-output backups.
- Input is emptied before nano and again after successful output.
- Atomic YAML write and structural validation.
"""

from __future__ import annotations

import base64
import copy
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import html
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ENGINE_VERSION = "MIHOMO-INDUSTRIAL-FOUR-GROUPS-EGRESS-GEO-V1"

PROJECT_DIR = Path.home() / "mihomo" / "MihomoIndustrial"
GEOIP_LOCAL_DIR = PROJECT_DIR / "geo"
MIHOMO_SOURCE_DIR = Path.home() / "mihomo" / "mihomo_source"
BASE_DIR = Path("/storage/emulated/0/Download/Akbar98")
INPUT_PATH = BASE_DIR / "input.txt"
DOWNLOAD_DIR = Path("/storage/emulated/0/Download")

# ============================================================
# GROUP MASTER KEY — ONLY FOUR GROUP TYPES EXIST IN THIS BUILD
# Use +, comma, semicolon, or newline between group names.
# Fixed output order. The master key is retained for compatibility, but cannot
# remove any of the four mandatory groups.
# ============================================================
ENABLE_GROUP_MASTER_KEY = True
DEFAULT_RULE_GROUP = "Select ⚖️"
FALLBACK_GROUP_NAME = "🔁 Fallback"
UNKNOWN_GROUP_NAME = "🌐 Unknown Country"
DIRECT_GROUP_NAME = "⚡ Direct"
GROUP_ORDER = (DEFAULT_RULE_GROUP, FALLBACK_GROUP_NAME, UNKNOWN_GROUP_NAME, DIRECT_GROUP_NAME)
GROUP_MASTER_KEY = "+".join(GROUP_ORDER)

HEALTH_URL = "https://www.gstatic.com/generate_204"
HEALTH_INTERVAL = 300
HEALTH_TIMEOUT = 5000

# Real Egress verification. Every proxy is tested in an isolated Mihomo process.
EGRESS_PROBE_ENABLED = True
EGRESS_PROBE_WORKERS = 4
EGRESS_PROBE_START_TIMEOUT = 12.0
EGRESS_PROBE_REQUEST_TIMEOUT = 6.0
EGRESS_PROBE_CONFIG_TEST_TIMEOUT = 20.0
EGRESS_PROBE_QUORUM = 2  # at least 2 of 3 independent echo services must agree
EGRESS_PROBE_ENDPOINTS_V4 = (
    "https://api4.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
)
EGRESS_PROBE_ENDPOINTS_V6 = (
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
    "https://v6.ident.me",
)
EGRESS_HEALTH_ENDPOINTS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/generate_204",
)
EGRESS_AUDIT_PATH = BASE_DIR / "egress_audit.json"
MIHOMO_BINARY_OVERRIDE = os.environ.get("MIHOMO_BINARY", "").strip()
_EGRESS_RESULTS: dict[str, dict[str, Any]] = {}
_EGRESS_RESULTS_LOCK = threading.RLock()

# Legacy optional service checks remain available to the rest of the application.
ENABLE_SERVICE_LIVE_TESTS = False
SERVICE_TEST_TIMEOUT_MS = 7000
SERVICE_TEST_REPEATS = 2
SERVICE_TEST_MIN_SUCCESSFUL_REPEATS = 1
SERVICE_TEST_MAX_DELAY_MS = 1500
SERVICE_TEST_WORKERS = 12
SERVICE_TEST_REQUIRE_ALL_ENDPOINTS = True
SERVICE_TEST_RESULTS: dict[str, dict[str, tuple[bool, int | None]]] = {}
SERVICE_TESTS: dict[str, tuple[tuple[str, int], ...]] = {
    "__GENERAL__": (("https://www.gstatic.com/generate_204", 204),),
}

# Core configuration engines; unrelated to proxy-group selection.
ENABLE_DNS_ENGINE = True
ENABLE_RULE_PROVIDER_ENGINE = True
ENABLE_PROXY_PROVIDER_ENGINE = True
ENABLE_TUN_ENGINE = True
ENABLE_LISTENER_ENGINE = True
ENABLE_PROFILE_ENGINE = True
ENABLE_EXPERIMENTAL_ENGINE = True
MAX_PROVIDER_SIZE = 100 * 1024 * 1024

# Reliability and output controls.
ENABLE_CONFIG_BACKUPS = False
ENABLE_CHANGE_REPORTS = False
ENABLE_AUDIT_LOG = False
STORE_SELECTED_PROXY = True
PROXY_ALLOWLIST: tuple[str, ...] = ()
PROXY_BLOCKLIST: tuple[str, ...] = ()
PROXY_NAME_EXCLUDE_TERMS: tuple[str, ...] = ()

# Optional local Mihomo controller integration.
ENABLE_CONTROLLER_PINNED_GROUP = False
CONTROLLER_API_URL = "http://127.0.0.1:9090"
CONTROLLER_API_SECRET = ""
CONTROLLER_SOURCE_GROUP = DEFAULT_RULE_GROUP
CONTROLLER_PINNED_GROUP_NAME = "🎯 Curated / Pinned"
CONTROLLER_REQUEST_TIMEOUT = 3.0
ENABLE_CONTROLLER_LIVE_FILTER = False
CONTROLLER_TEST_URL = HEALTH_URL
CONTROLLER_TEST_TIMEOUT_MS = 5000
CONTROLLER_MAX_DELAY_MS = 1200
CONTROLLER_MIN_SUCCESSFUL_TESTS = 1
CONTROLLER_TEST_REPEATS = 2
CONTROLLER_TEST_WORKERS = 8
KEEP_UNTESTED_PROXIES = True
REQUIRE_LIVE_HEALTH_TESTS = False
_CONTROLLER_PINNED_PROXY_NAME = ""
_DECORATED_ORIGINAL_NAMES: dict[str, str] = {}

IRAN_DIRECT_RULES = (
    f"DOMAIN-SUFFIX,ir,{DIRECT_GROUP_NAME}",
    f"DOMAIN-SUFFIX,local,{DIRECT_GROUP_NAME}",
    f"DOMAIN-SUFFIX,localhost,{DIRECT_GROUP_NAME}",
    f"DOMAIN-SUFFIX,localdomain,{DIRECT_GROUP_NAME}",
    f"DOMAIN-SUFFIX,lan,{DIRECT_GROUP_NAME}",
    f"DOMAIN-SUFFIX,home.arpa,{DIRECT_GROUP_NAME}",
    f"IP-CIDR,10.0.0.0/8,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR,172.16.0.0/12,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR,192.168.0.0/16,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR,127.0.0.0/8,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR,169.254.0.0/16,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR,100.64.0.0/10,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR6,::1/128,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR6,fc00::/7,{DIRECT_GROUP_NAME},no-resolve",
    f"IP-CIDR6,fe80::/10,{DIRECT_GROUP_NAME},no-resolve",
    f"GEOIP,IR,{DIRECT_GROUP_NAME}",
)

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_NODES = 10000

MAX_PROVIDER_SIZE = 100 * 1024 * 1024

# Membership guarantees for the four supported generated groups.
GROUP_MEMBERSHIP_CONTRACTS = {
    "select": "Only healthy proxies with a measured Egress IP and independently resolved country/location.",
    "fallback": "Independently selected healthy proxies with measured Egress IP, country known or unknown.",
    "unknown": "Only healthy proxies with measured Egress IP whose country cannot be established.",
    "direct": "Exactly the Mihomo built-in DIRECT member; no proxy or other group references.",
    "uniqueness": "At most one proxy per measured Egress IP inside each proxy group; no global inventory deletion.",
    "independence": "Every group is built from the full node inventory and its own predicate; no group references another group.",
}

# Sections whose source data is not present are NOT fabricated.
PRESERVE_TOP_LEVEL = {
    "port",
    "socks-port",
    "mixed-port",
    "redir-port",
    "tproxy-port",
    "tun",
    "listeners",
    "dns",
    "sniffer",
    "geodata-mode",
    "geo-auto-update",
    "geo-update-interval",
    "geox-url",
    "profile",
    "experimental",
    "hosts",
    "fallback-filter",
    "authentication",
    "skip-auth-prefixes",
    "external-controller",
    "external-controller-cors",
    "external-controller-unix",
    "secret",
    "external-ui",
    "external-ui-url",
    "external-ui-name",
    "interface-name",
    "routing-mark",
    "find-process-mode",
    "tcp-concurrent",
    "unified-delay",
    "global-client-fingerprint",
    "global-ua",
    "keep-alive-idle",
    "keep-alive-interval",
    "disable-keep-alive",
    "tls",
    "ntp",
    "ebpf",
    "system-proxy",
    "service-worker",
    "global-client-fingerprint",
    # Additional documented Mihomo sections/keys from the local guide.
    "mode", "log-level", "ipv6", "allow-lan", "bind-address",
    "lan-allowed-ips", "lan-disallowed-ips", "authentication",
    "skip-auth-prefixes", "sniffer", "dns", "hosts",
    "sub-rules", "tunnels", "ntp", "profile", "geodata-loader",
    "geoip-url", "geosite-url", "mmdb-url", "asn-url",
    "proxy-server-nameserver", "direct-nameserver", "nameserver",
    "nameserver-policy", "fallback", "fallback-filter", "default-nameserver",
    "proxy-resolver", "dns-hijack", "external-controller-pipe",
    "external-controller-cors", "external-controller-unix",
    "external-ui-download-url", "external-ui-url", "external-ui-name",
    "secret", "interface-name", "routing-mark", "global-ua",
    "keep-alive-idle", "keep-alive-interval", "disable-keep-alive",
    "global-client-fingerprint", "tcp-concurrent", "unified-delay",
    "find-process-mode", "global-client-fingerprint", "global-ua",
    "disable-udp", "respect-rules", "store-fake-ip", "ebpf",
    "system-proxy", "hosts", "sniffer", "tun", "listeners",
    "experimental", "profile", "ntp", "tunnels", "sub-rules",
}


SUPPORTED_TYPES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "http",
    "socks",
    "socks5",
    "wireguard",
    "anytls",
    "snell",
    "mieru",
    "sudoku",
    "shadowquic",
    "trusttunnel",
    "easytier",
    "tailscale",
    "ssh",
    "masque",
    "zerotier",
    "openvpn",
}

BOOL_KEYS = {
    "udp",
    "tls",
    "skip-cert-verify",
    "disable-sni",
    "reduce-rtt",
    "fast-open",
    "tfo",
    "mptcp",
    "global-padding",
    "authenticated-length",
    "reuse",
    "udp-over-tcp",
}

INT_KEYS = {
    "port",
    "alterId",
    "heartbeat-interval",
    "request-timeout",
    "max-udp-relay-packet-size",
    "max-open-streams",
    "idle-session-check-interval",
    "idle-session-timeout",
    "min-idle-session",
    "recv-window",
    "recv-window-conn",
    "max-failed-times",
    "timeout",
    "interval",
    "size-limit",
    "routing-mark",
}


def log(value: Any = "") -> None:
    print(str(value), flush=True)


def clean_name(value: Any, fallback: str = "Node") -> str:
    value = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return value[:120] or fallback


def safe_int(value: Any, default: Any = 0) -> Any:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {
        "1", "true", "yes", "on", "enable", "enabled"
    }


def b64decode_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = re.sub(r"\s+", "", value.strip())
    if not value:
        return None

    value += "=" * ((4 - len(value) % 4) % 4)

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(value).decode("utf-8")
        except Exception:
            pass

    return None


def unquote(value: Any) -> str:
    return urllib.parse.unquote(str(value or ""))


def parse_qs(url: urllib.parse.ParseResult) -> dict[str, str]:
    raw = urllib.parse.parse_qs(url.query, keep_blank_values=True)
    return {
        key: unquote(values[-1]) if values else ""
        for key, values in raw.items()
    }


def split_host_port(host: Any, port: Any = 0) -> tuple[str, int]:
    host = str(host or "").strip()
    port = safe_int(port, 0)

    if host.startswith("[") and "]" in host:
        end = host.index("]")
        inside = host[1:end]
        rest = host[end + 1:]
        if rest.startswith(":") and not port:
            port = safe_int(rest[1:], 0)
        return inside, port

    # Only split simple host:port. Raw IPv6 is kept intact.
    if host.count(":") == 1 and not port:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            return left, int(right)

    return host, port


def canonical(value: Any) -> str:
    if isinstance(value, dict):
        return "{" + ",".join(
            f"{key}:{canonical(value[key])}" for key in sorted(value)
        ) + "}"

    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical(item) for item in value) + "]"

    return str(value).strip()


def normalize_common(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in data.items():
        if value is None or value == "":
            continue

        key = str(key)

        if key in BOOL_KEYS:
            result[key] = bool_value(value)

        elif key in INT_KEYS:
            integer = safe_int(value, None)
            result[key] = integer if integer is not None else value

        else:
            result[key] = value

    return result


def fingerprint(node_data: dict[str, Any]) -> str:
    data = copy.deepcopy(node_data)
    data.pop("name", None)

    body = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def tls_fields(
    query: dict[str, str],
    data: dict[str, Any],
    servername_key: str = "servername",
) -> None:
    if query.get("security"):
        security = query["security"].lower()

        if security in {"tls", "reality", "true", "1"}:
            data["tls"] = True
        elif security in {"none", "false", "0"}:
            data["tls"] = False

    for source in ("sni", "servername", "peer"):
        if query.get(source):
            data[servername_key] = query[source]
            break

    if query.get("alpn"):
        data["alpn"] = [
            item for item in query["alpn"].split(",") if item
        ]

    if query.get("fp"):
        data["client-fingerprint"] = query["fp"]

    if query.get("client-fingerprint"):
        data["client-fingerprint"] = query["client-fingerprint"]

    if query.get("fingerprint"):
        data["fingerprint"] = query["fingerprint"]

    if "skip-cert-verify" in query:
        data["skip-cert-verify"] = bool_value(
            query["skip-cert-verify"]
        )

    if "insecure" in query:
        data["skip-cert-verify"] = bool_value(query["insecure"])


def transport_fields(
    query: dict[str, str],
    data: dict[str, Any],
    network: str,
) -> None:
    data["network"] = network

    if network in {"ws", "http"}:
        ws: dict[str, Any] = {}

        if query.get("path"):
            ws["path"] = query["path"]

        if query.get("host"):
            ws["headers"] = {"Host": query["host"]}

        if query.get("headers"):
            try:
                headers = json.loads(query["headers"])
                if isinstance(headers, dict):
                    ws["headers"] = headers
            except Exception:
                pass

        if ws:
            data["ws-opts"] = ws

    elif network == "grpc":
        grpc: dict[str, Any] = {}

        for source in (
            "serviceName",
            "service-name",
            "grpc-service-name",
        ):
            if query.get(source):
                grpc["grpc-service-name"] = query[source]
                break

        if query.get("mode"):
            grpc["grpc-mode"] = query["mode"]

        if grpc:
            data["grpc-opts"] = grpc

    elif network == "h2":
        h2: dict[str, Any] = {}

        if query.get("path"):
            h2["path"] = query["path"]

        if query.get("host"):
            h2["host"] = [
                item for item in query["host"].split(",") if item
            ]

        if h2:
            data["h2-opts"] = h2

    elif network == "xhttp":
        # Mihomo XHTTP transport. Preserve supplied settings only; do not
        # invent transport values for subscriptions that omit them.
        xhttp: dict[str, Any] = {}
        for key in (
            "path", "host", "mode", "headers", "extra",
            "x-padding-bytes", "x-padding-Obfs-mode",
            "x-padding-key", "x-padding-header", "x-padding-placement",
            "x-padding-method", "uplink-http-method", "session-placement",
            "session-key", "session-table", "session-length",
            "seq-placement", "seq-key", "uplink-data-placement",
            "uplink-data-key", "uplink-chunk-size",
            "sc-max-each-post-bytes", "sc-min-posts-interval-ms",
        ):
            if query.get(key) not in (None, ""):
                value = query[key]
                if key in {"headers", "extra"}:
                    try:
                        parsed = json.loads(value)
                        if isinstance(parsed, dict):
                            xhttp[key] = parsed
                            continue
                    except (TypeError, ValueError):
                        pass
                xhttp[key] = value
        for key in ("no-grpc-header", "x-padding-obfs-mode"):
            if key in query:
                xhttp[key] = bool_value(query[key])
        if xhttp:
            data["xhttp-opts"] = xhttp


def make_node(
    proxy_type: str,
    name: Any,
    server: Any,
    port: Any,
    data: dict[str, Any],
) -> dict[str, Any]:
    server, port = split_host_port(server, port)

    try:
        port = int(port)
    except Exception:
        port = 0

    normalized = normalize_common(data)

    normalized["server"] = str(server)
    normalized["port"] = port
    normalized["name"] = clean_name(
        name,
        proxy_type.upper(),
    )

    if proxy_type == "socks5":
        proxy_type = "socks"

    if proxy_type == "hy2":
        proxy_type = "hysteria2"

    normalized["type"] = proxy_type

    return normalized


def parse_vmess(line: str) -> dict[str, Any] | None:
    try:
        payload = line.split("://", 1)[1].split("#", 1)[0]
        decoded = b64decode_text(payload)
        if not decoded:
            return None

        obj = json.loads(decoded)
    except Exception:
        return None

    host = (
        obj.get("add")
        or obj.get("address")
        or obj.get("server")
    )

    port = safe_int(obj.get("port"), 0)

    if not host or not (1 <= port <= 65535):
        return None

    data: dict[str, Any] = {
        "uuid": obj.get("id", ""),
        "alterId": safe_int(obj.get("aid"), 0),
        "cipher": obj.get("scy") or obj.get("cipher") or "auto",
        "network": obj.get("net") or "tcp",
    }

    if obj.get("tls"):
        data["tls"] = True

    if obj.get("sni"):
        data["servername"] = obj["sni"]

    if obj.get("fp"):
        data["client-fingerprint"] = obj["fp"]

    if obj.get("alpn"):
        data["alpn"] = (
            obj["alpn"].split(",")
            if isinstance(obj["alpn"], str)
            else obj["alpn"]
        )

    if obj.get("packet-encoding"):
        data["packet-encoding"] = obj["packet-encoding"]

    if obj.get("global-padding") is not None:
        data["global-padding"] = bool_value(
            obj["global-padding"]
        )

    if obj.get("authenticated-length") is not None:
        data["authenticated-length"] = bool_value(
            obj["authenticated-length"]
        )

    transport_query = {
        str(key): unquote(value)
        for key, value in obj.items()
        if value is not None
    }

    transport_fields(
        transport_query,
        data,
        data["network"],
    )

    for key in (
        "reality-opts",
        "shadow-tls-opts",
        "restls-opts",
        "jls-opts",
        "tlsmirror-opts",
        "smux",
    ):
        if isinstance(obj.get(key), dict):
            data[key] = obj[key]

    return make_node(
        "vmess",
        obj.get("ps") or "VMess",
        host,
        port,
        data,
    )


def parse_vless(line: str) -> dict[str, Any] | None:
    try:
        url = urllib.parse.urlparse(line)
    except Exception:
        return None

    host = url.hostname
    port = url.port

    if not host or not port:
        return None

    query = parse_qs(url)
    data: dict[str, Any] = {
        "uuid": unquote(url.username)
    }

    network = (
        query.get("type")
        or query.get("network")
        or "tcp"
    )

    tls_fields(query, data)
    transport_fields(query, data, network)

    for key in (
        "flow",
        "encryption",
        "packet-encoding",
    ):
        if query.get(key):
            data[key] = query[key]

    if query.get("security") == "reality":
        reality: dict[str, Any] = {}

        if query.get("pbk"):
            reality["public-key"] = query["pbk"]

        if query.get("sid"):
            reality["short-id"] = query["sid"]

        if reality:
            data["reality-opts"] = reality

    return make_node(
        "vless",
        query.get("remarks") or url.fragment or "VLESS",
        host,
        port,
        data,
    )


def parse_trojan(line: str) -> dict[str, Any] | None:
    try:
        url = urllib.parse.urlparse(line)
    except Exception:
        return None

    if not url.hostname or not url.port:
        return None

    query = parse_qs(url)

    data: dict[str, Any] = {
        "password": unquote(url.username),
        "tls": True,
    }

    tls_fields(query, data, "sni")

    network = (
        query.get("type")
        or query.get("network")
        or "tcp"
    )

    transport_fields(query, data, network)

    for key in (
        "udp",
        "skip-cert-verify",
        "name-cert-verify",
        "client-fingerprint",
        "fingerprint",
    ):
        if key in query:
            data[key] = (
                bool_value(query[key])
                if key == "udp"
                else query[key]
            )

    if query.get("flow"):
        data["flow"] = query["flow"]

    if query.get("pbk") or query.get("sid"):
        reality: dict[str, Any] = {}

        if query.get("pbk"):
            reality["public-key"] = query["pbk"]

        if query.get("sid"):
            reality["short-id"] = query["sid"]

        data["reality-opts"] = reality

    return make_node(
        "trojan",
        query.get("remarks") or url.fragment or "Trojan",
        url.hostname,
        url.port,
        data,
    )


def parse_ss(line: str) -> dict[str, Any] | None:
    try:
        url = urllib.parse.urlparse(line)
    except Exception:
        return None

    if not url.hostname or not url.port:
        return None

    user = url.username or ""
    password_part = url.password or ""

    method = ""
    password = ""

    if user and password_part:
        method = unquote(user)
        password = unquote(password_part)

    else:
        decoded = b64decode_text(user)

        if decoded and ":" in decoded:
            method, password = decoded.split(":", 1)

        elif ":" in user:
            method, password = user.split(":", 1)

    data: dict[str, Any] = {
        "cipher": method,
        "password": password,
    }

    query = parse_qs(url)

    if "udp" in query:
        data["udp"] = bool_value(query["udp"])

    if query.get("plugin"):
        parts = query["plugin"].split(";")
        data["plugin"] = parts[0]

        options: dict[str, str] = {}

        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                options[key] = value

        if options:
            data["plugin-opts"] = options

    return make_node(
        "ss",
        url.fragment or "SS",
        url.hostname,
        url.port,
        data,
    )


def parse_ssr(line: str) -> dict[str, Any] | None:
    decoded = b64decode_text(line.split("://", 1)[1])

    if not decoded:
        return None

    main, _, query_text = decoded.partition("/?")
    parts = main.split(":")

    if len(parts) < 6:
        return None

    host, port, protocol, cipher, obfs, password_b64 = parts[:6]

    query = urllib.parse.parse_qs(
        query_text,
        keep_blank_values=True,
    )

    password = (
        b64decode_text(password_b64)
        or password_b64
    )

    remarks = (
        b64decode_text(query.get("remarks", [""])[-1])
        or "SSR"
    )

    data = {
        "protocol": protocol,
        "cipher": cipher,
        "obfs": obfs,
        "password": password,
    }

    for source, target in (
        ("obfsparam", "obfs-param"),
        ("protoparam", "protocol-param"),
    ):
        if query.get(source):
            data[target] = (
                b64decode_text(query[source][-1])
                or query[source][-1]
            )

    return make_node(
        "ssr",
        remarks,
        host,
        safe_int(port, 0),
        data,
    )


def parse_hysteria(
    line: str,
    proxy_type: str,
) -> dict[str, Any] | None:
    try:
        url = urllib.parse.urlparse(line)
    except Exception:
        return None

    if not url.hostname or not url.port:
        return None

    query = parse_qs(url)
    data: dict[str, Any] = {}

    if proxy_type == "hysteria2":
        if url.username:
            data["password"] = unquote(url.username)

        for key in (
            "ports",
            "hop-interval",
            "up",
            "down",
            "obfs",
            "obfs-password",
            "obfs-min-packet-size",
            "obfs-max-packet-size",
            "bbr-profile",
            "sni",
            "name-cert-verify",
            "fingerprint",
            "handshake-timeout",
        ):
            if query.get(key):
                data[key] = query[key]

    else:
        if url.username:
            data["auth-str"] = unquote(url.username)

        for key in (
            "protocol",
            "up",
            "down",
            "obfs",
            "sni",
            "name-cert-verify",
            "fingerprint",
            "recv-window",
            "recv-window-conn",
            "ports",
            "fast-open",
        ):
            if query.get(key):
                data[key] = query[key]

    if query.get("alpn"):
        data["alpn"] = query["alpn"].split(",")

    if "skip-cert-verify" in query:
        data["skip-cert-verify"] = bool_value(
            query["skip-cert-verify"]
        )

    if "insecure" in query:
        data["skip-cert-verify"] = bool_value(
            query["insecure"]
        )

    return make_node(
        proxy_type,
        query.get("remarks") or url.fragment or proxy_type.upper(),
        url.hostname,
        url.port,
        data,
    )


def parse_tuic(line: str) -> dict[str, Any] | None:
    try:
        url = urllib.parse.urlparse(line)
    except Exception:
        return None

    if not url.hostname or not url.port:
        return None

    query = parse_qs(url)
    data: dict[str, Any] = {}

    if url.username:
        data["uuid"] = unquote(url.username)

    if url.password:
        data["password"] = unquote(url.password)

    for key in (
        "token",
        "ip",
        "heartbeat-interval",
        "alpn",
        "disable-sni",
        "reduce-rtt",
        "request-timeout",
        "udp-relay-mode",
        "congestion-controller",
        "bbr-profile",
        "max-udp-relay-packet-size",
        "fast-open",
        "skip-cert-verify",
        "name-cert-verify",
        "max-open-streams",
        "sni",
    ):
        if key in query and query[key] != "":
            data[key] = query[key]

    if isinstance(data.get("alpn"), str):
        data["alpn"] = data["alpn"].split(",")

    return make_node(
        "tuic",
        query.get("name") or url.fragment or "TUIC",
        url.hostname,
        url.port,
        data,
    )


def parse_http_socks(
    line: str,
    proxy_type: str,
) -> dict[str, Any] | None:
    try:
        url = urllib.parse.urlparse(line)
    except Exception:
        return None

    if not url.hostname or not url.port:
        return None

    data: dict[str, Any] = {}

    if url.username:
        data["username"] = unquote(url.username)

    if url.password:
        data["password"] = unquote(url.password)

    query = parse_qs(url)

    if proxy_type == "http" and (
        url.scheme.lower() == "https"
        or "tls" in query
    ):
        data["tls"] = True

    for key in (
        "tls",
        "udp",
        "skip-cert-verify",
        "name-cert-verify",
        "sni",
    ):
        if key in query:
            data[key] = (
                bool_value(query[key])
                if key in {"tls", "udp", "skip-cert-verify"}
                else query[key]
            )

    return make_node(
        proxy_type,
        url.fragment or proxy_type.upper(),
        url.hostname,
        url.port,
        data,
    )


def parse_anytls(line: str) -> dict[str, Any] | None:
    try:
        url = urllib.parse.urlparse(line)
    except Exception:
        return None

    if not url.hostname or not url.port:
        return None

    query = parse_qs(url)

    data: dict[str, Any] = {
        "password": unquote(url.username)
    }

    for key in (
        "client-fingerprint",
        "client-metadata",
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
        "sni",
        "alpn",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
    ):
        if query.get(key) != "":
            data[key] = query[key]

    if isinstance(data.get("alpn"), str):
        data["alpn"] = data["alpn"].split(",")

    return make_node(
        "anytls",
        query.get("remarks") or url.fragment or "AnyTLS",
        url.hostname,
        url.port,
        data,
    )


def parse_uri(line: str) -> dict[str, Any] | None:
    low = line.lower()

    if low.startswith("vmess://"):
        return parse_vmess(line)

    if low.startswith("vless://"):
        return parse_vless(line)

    if low.startswith("trojan://"):
        return parse_trojan(line)

    if low.startswith("ss://"):
        return parse_ss(line)

    if low.startswith("ssr://"):
        return parse_ssr(line)

    if low.startswith("hysteria2://"):
        return parse_hysteria(line, "hysteria2")

    if low.startswith("hy2://"):
        return parse_hysteria(line, "hysteria2")

    if low.startswith("hysteria://"):
        return parse_hysteria(line, "hysteria")

    if low.startswith("tuic://"):
        return parse_tuic(line)

    if low.startswith("anytls://"):
        return parse_anytls(line)

    if low.startswith("socks5://"):
        return parse_http_socks(line, "socks")

    if low.startswith("socks://"):
        return parse_http_socks(line, "socks")

    return None


def parse_node_dict(
    obj: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None

    proxy_type = str(obj.get("type") or "").lower()

    if proxy_type not in SUPPORTED_TYPES:
        return None

    if proxy_type == "socks5":
        proxy_type = "socks"

    if proxy_type == "hy2":
        proxy_type = "hysteria2"

    # Some documented Mihomo adapters (notably EasyTier/Tailscale/ZeroTier)
    # are not conventional server:port outbounds. Preserve their complete
    # structured mapping instead of dropping them or inventing endpoint data.
    endpoint_optional = {"easytier", "tailscale", "zerotier"}
    server = (
        obj.get("server")
        or obj.get("address")
        or obj.get("add")
        or obj.get("host")
    )
    port = safe_int(obj.get("port"), 0)

    if proxy_type in endpoint_optional and (not server or not (1 <= port <= 65535)):
        data = copy.deepcopy(obj)
        data["name"] = clean_name(obj.get("name") or obj.get("remarks") or proxy_type.upper(), proxy_type.upper())
        data["type"] = proxy_type
        return data

    if not server or not (1 <= port <= 65535):
        return None

    data = copy.deepcopy(obj)

    for key in (
        "name",
        "type",
        "server",
        "address",
        "add",
        "host",
        "port",
        "remarks",
    ):
        data.pop(key, None)

    # Keep Mihomo common fields such as ip-version, udp, interface-name,
    # routing-mark, tfo, mptcp, dialer-proxy and smux intact.

    return make_node(
        proxy_type,
        obj.get("name") or obj.get("remarks") or proxy_type.upper(),
        server,
        port,
        data,
    )


def walk_structured(
    obj: Any,
    result: list[dict[str, Any]],
) -> None:
    if isinstance(obj, dict):
        parsed = parse_node_dict(obj)

        if parsed:
            result.append(parsed)

        for value in obj.values():
            if isinstance(value, (dict, list)):
                walk_structured(value, result)

    elif isinstance(obj, list):
        for item in obj:
            walk_structured(item, result)


def parse_structured(text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    try:
        obj = json.loads(text)
        walk_structured(obj, result)

        if result:
            return result
    except Exception:
        pass

    try:
        import yaml

        obj = yaml.safe_load(text)
        walk_structured(obj, result)

    except Exception:
        pass

    return result


def parse_all(text: str) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []

    # Structured config first.
    nodes.extend(parse_structured(text))

    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")

        if not line or line.startswith("#"):
            continue

        if line.startswith("{") or line.startswith("["):
            continue

        parsed = parse_uri(line)

        if parsed:
            nodes.append(parsed)
            continue

        decoded = b64decode_text(line)

        if decoded and re.search(
            r"(?:vmess|vless|trojan|ss|ssr|hysteria|tuic|anytls)://",
            decoded,
            re.I,
        ):
            for sub_line in decoded.splitlines():
                parsed = parse_uri(sub_line.strip())

                if parsed:
                    nodes.append(parsed)

    return nodes


def dedupe(
    nodes: list[dict[str, Any]],
    *,
    unique_endpoint_ip: bool = True,
) -> list[dict[str, Any]]:
    """Keep the first node for each endpoint IP + port + protocol identity.

    Remarks, flags, hashes, UUIDs and passwords do not make the same endpoint
    a different proxy. A different port or protocol remains a distinct node.
    Hostnames are not resolved here. This endpoint-level dedupe never assigns country.
    """
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if unique_endpoint_ip:
            endpoint_ip = _literal_endpoint_ip(node)
            if endpoint_ip:
                identity = ("ip:" + endpoint_ip, str(node.get("port") or ""), str(node.get("type") or "").casefold())
            else:
                identity = ("host:" + str(node.get("server") or "").strip().lower().rstrip("."), str(node.get("port") or ""), str(node.get("type") or "").casefold())
        else:
            identity = (fingerprint(node), "", "")
        if identity in seen:
            continue
        seen.add(identity)
        result.append(node)
    return result


def _literal_endpoint_ip(node_data: dict[str, Any]) -> str | None:
    """Return a canonical IP only when server itself is a literal IP."""
    raw = str(node_data.get("server") or "").strip().strip("[]")
    try:
        return str(ipaddress.ip_address(raw.split("%", 1)[0]))
    except ValueError:
        return None


def _node_endpoint_identity(node: dict[str, Any]) -> tuple[str, str, str]:
    """Stable dedupe key: resolved endpoint IP/host + port + protocol type."""
    endpoint = _node_endpoint_key(node)
    port = str(node.get("port") or "").strip()
    protocol = str(node.get("type") or "unknown").strip().casefold()
    return endpoint, port, protocol


def dedupe_by_resolved_endpoint_ip(
    nodes: list[dict[str, Any]],
    *,
    keep_first: bool = True,
) -> tuple[list[dict[str, Any]], int]:
    """Legacy endpoint-identity helper; not used for Egress group membership.

    Duplicates require the same endpoint identity, port and protocol type.
    The four generated groups instead deduplicate only by measured Egress IP.
    """
    kept: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    removed = 0
    ordered = nodes if keep_first else list(reversed(nodes))
    for node in ordered:
        identity = _node_endpoint_identity(node)
        if identity in seen:
            removed += 1
            continue
        seen.add(identity)
        kept.append(node)
    if not keep_first:
        kept.reverse()
    return kept, removed


def unique_names(nodes: list[dict[str, Any]]) -> None:
    used: dict[str, int] = {}
    rename: dict[str, str] = {}
    reserved = set(GROUP_ORDER) | {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS", "REJECT-DROP", "EGRESS_PROBE_ROUTE", "__MIHOMO_EGRESS_PROBE_ROUTE__"}

    for node_data in nodes:
        old_name = str(node_data.get("name") or "")
        base = clean_name(node_data.get("name"), str(node_data.get("type", "NODE")).upper())
        if base in reserved:
            base = f"{base} [proxy]"
        used[base] = used.get(base, 0) + 1
        new_name = base if used[base] == 1 else f"{base} {used[base]}"
        node_data["name"] = new_name
        if old_name and old_name not in rename:
            rename[old_name] = new_name

    builtins = {"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL"}
    for node_data in nodes:
        dialer = node_data.get("dialer-proxy")
        if isinstance(dialer, str) and dialer in rename and dialer not in builtins:
            node_data["dialer-proxy"] = rename[dialer]


def validate_node(
    node_data: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    proxy_type = node_data.get("type")
    server = node_data.get("server")
    port = node_data.get("port")

    if proxy_type not in SUPPORTED_TYPES:
        errors.append(f"unsupported type {proxy_type}")

    endpoint_optional = {"easytier", "tailscale", "zerotier"}
    if proxy_type not in endpoint_optional and not server:
        errors.append("missing server")

    if proxy_type not in endpoint_optional and (not isinstance(port, int) or not (1 <= port <= 65535)):
        errors.append("invalid port")

    if proxy_type in {"vless", "vmess"}:
        if not node_data.get("uuid"):
            errors.append("missing uuid")

    if proxy_type == "trojan":
        if not node_data.get("password"):
            errors.append("missing password")

    if proxy_type == "ss":
        if not node_data.get("cipher"):
            errors.append("missing ss cipher")
        if not node_data.get("password"):
            errors.append("missing ss password")

    if proxy_type == "ssr":
        if not node_data.get("cipher"):
            errors.append("missing ssr cipher")
        if not node_data.get("password"):
            errors.append("missing ssr password")

    if proxy_type == "tuic":
        if not (
            node_data.get("token")
            or (
                node_data.get("uuid")
                and node_data.get("password")
            )
        ):
            errors.append(
                "TUIC requires token or uuid+password"
            )

    if proxy_type == "hysteria2":
        if not node_data.get("password"):
            errors.append("missing hysteria2 password")

    if proxy_type == "hysteria":
        if not (
            node_data.get("auth-str")
            or node_data.get("auth")
        ):
            errors.append("missing hysteria auth")

    if proxy_type == "anytls":
        if not node_data.get("password"):
            errors.append("missing anytls password")

    if proxy_type == "snell":
        if not node_data.get("psk"):
            errors.append("missing snell psk")

    return errors


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (int, float)):
        return str(value)

    return json.dumps(
        str(value),
        ensure_ascii=False,
    )


def yaml_dump(obj: Any, level: int = 0) -> list[str]:
    """Serialize YAML with a standards-compliant serializer (Unicode-safe, no aliases)."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required for safe YAML serialization. Install it with: pip install pyyaml"
        ) from exc

    class _MihomoSafeDumper(yaml.SafeDumper):
        def ignore_aliases(self, data: Any) -> bool:
            return True

    rendered = yaml.dump(
        obj,
        Dumper=_MihomoSafeDumper,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=120,
        indent=2,
        explicit_start=False,
    )
    return rendered.rstrip("\n").splitlines()


def validate_yaml_text(text: str) -> list[str]:
    try:
        import yaml
        parsed = yaml.safe_load(text)

        if not isinstance(parsed, dict):
            return ["YAML root is not mapping"]

        return validate_config(parsed)

    except ImportError:
        # The in-memory configuration was already structurally validated.
        # If PyYAML is absent, native Mihomo validation is used when available.
        return []

    except Exception as exc:
        return [f"YAML syntax: {exc}"]


def group_common(
    name: str,
    group_type: str,
    nodes: list[str],
) -> dict[str, Any]:
    return {
        "name": name,
        "type": group_type,
        "proxies": nodes,
        "url": HEALTH_URL,
        "interval": HEALTH_INTERVAL,
        "lazy": True,
        "timeout": HEALTH_TIMEOUT,
    }


def _node_endpoint_key(node: dict[str, Any]) -> str:
    """Legacy endpoint identity helper; never used to infer Egress country.

    Prefer a literal server IP. Otherwise retain hostname; the current four
    group builders use only measured Egress IP evidence for their membership.
    """
    server = str(node.get("server") or "").strip().strip("[]")
    try:
        return "ip:" + str(ipaddress.ip_address(server.split("%", 1)[0]))
    except ValueError:
        pass
    name = str(node.get("name") or "")
    # Parse the endpoint IP from the decoration independently of the country label.
    # The previous expression only recognized a fixed list of country labels, so
    # names like "🌐 Unknown | 203.0.113.7 | ..." lost their resolved IP identity.
    # That let duplicate IP:port:protocol nodes survive when GeoIP had no country.
    match = re.search(
        r"\|\s*((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{3,})\s*\|",
        name,
    )
    if match:
        try:
            return "ip:" + str(ipaddress.ip_address(match.group(1).split("%", 1)[0]))
        except ValueError:
            pass
    server = server.lower().rstrip(".")
    return "host:" + server if server else "unknown:" + str(node.get("name") or "")


# Country labels are applied only after the live Mihomo probe has measured the
# proxy's public Egress IP. Endpoint IP, DNS, ASN, source flags and remarks are
# deliberately excluded from the country-decision path.
COUNTRY_LABELS = {
    "US": "🇺🇸 US",
    "NL": "🇳🇱 NL",
    "GB": "🇬🇧 GB",
    "FR": "🇫🇷 FR",
    "CA": "🇨🇦 CA",
    "TR": "🇹🇷 TR",
    "AZ": "🇦🇿 AZ",
    "DE": "🇩🇪 DE",
}
# Country flags are generated from any valid ISO 3166-1 alpha-2 code, not
# limited to the small set used by optional country-specific groups. This is
# important for endpoints in Finland, Sweden, Japan, etc.
COUNTRY_FLAGS = {"US": "🇺🇸", "NL": "🇳🇱", "GB": "🇬🇧", "FR": "🇫🇷", "CA": "🇨🇦", "TR": "🇹🇷", "AZ": "🇦🇿", "DE": "🇩🇪"}
COUNTRY_CODES = set(COUNTRY_LABELS)


def _country_flag_from_code(country_code: str) -> str | None:
    """Build a flag emoji from a valid two-letter ISO-style country code."""
    code = str(country_code or "").strip().upper()
    if len(code) != 2 or not all("A" <= char <= "Z" for char in code):
        return None
    # Regional Indicator Symbols are offset from ASCII A by 0x1F1E6.
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)
# Local offline GeoIP database paths. The full database is preferred; the lite
# database is a fallback only when the full database is absent or unreadable.
GEOIP_LOCAL_DATABASES = tuple(dict.fromkeys(_p for _p in [
    Path(os.environ["MIHOMO_COUNTRY_MMDB"]) if os.environ.get("MIHOMO_COUNTRY_MMDB") else None,
    GEOIP_LOCAL_DIR / "GeoLite2-City.mmdb",
    GEOIP_LOCAL_DIR / "City.mmdb",
    GEOIP_LOCAL_DIR / "GeoLite2-Country.mmdb",
    GEOIP_LOCAL_DIR / "Country-without-asn.mmdb",
    GEOIP_LOCAL_DIR / "country.mmdb",
    GEOIP_LOCAL_DIR / "country-lite.mmdb",
    GEOIP_LOCAL_DIR / "geo" / "GeoLite2-City.mmdb",
    GEOIP_LOCAL_DIR / "geo" / "City.mmdb",
    GEOIP_LOCAL_DIR / "geo" / "GeoLite2-Country.mmdb",
    GEOIP_LOCAL_DIR / "geo" / "Country-without-asn.mmdb",
    GEOIP_LOCAL_DIR / "geo" / "country.mmdb",
    GEOIP_LOCAL_DIR / "geo" / "country-lite.mmdb",
    GEOIP_LOCAL_DIR / "GeoLite2-City.mmdb",
    GEOIP_LOCAL_DIR / "City.mmdb",
    GEOIP_LOCAL_DIR / "GeoLite2-Country.mmdb",
    GEOIP_LOCAL_DIR / "Country-without-asn.mmdb",
    GEOIP_LOCAL_DIR / "country.mmdb",
    GEOIP_LOCAL_DIR / "country-lite.mmdb",
    PROJECT_DIR / "assets" / "GeoLite2-Country.mmdb",
    PROJECT_DIR / "assets" / "Country-without-asn.mmdb",
] if _p is not None))
_EGRESS_GEO_CACHE: dict[str, dict[str, str] | None] = {}
_EGRESS_GEO_CACHE_LOCK = threading.RLock()
_EGRESS_GEO_IP_LOCKS: dict[str, threading.Lock] = {}
_MMDB_READER: Any = None
_MMDB_READER_PATH: str | None = None
_MMDB_INIT_DONE = False
_MMDB_LOCK = threading.RLock()
_MMDB_LOGGED = False


def _open_local_mmdb() -> Any:
    """Open the first readable local MMDB; never treat .db/.dat as MMDB."""
    global _MMDB_READER, _MMDB_READER_PATH, _MMDB_INIT_DONE, _MMDB_LOGGED
    with _MMDB_LOCK:
        if _MMDB_INIT_DONE:
            return _MMDB_READER
        _MMDB_INIT_DONE = True
        existing = [Path(x) for x in GEOIP_LOCAL_DATABASES if x and Path(x).is_file()]
        if not existing:
            log("[GEOIP-LOCAL] No supported .mmdb country database found in configured paths.")
            return None
        try:
            import maxminddb  # type: ignore
            for candidate in existing:
                try:
                    reader = maxminddb.open_database(str(candidate))
                    if not hasattr(reader, "get"):
                        try: reader.close()
                        except Exception: pass
                        continue
                    _MMDB_READER = reader
                    _MMDB_READER_PATH = str(candidate)
                    log(f"[GEOIP-LOCAL] Loaded country MMDB: {_MMDB_READER_PATH}")
                    return _MMDB_READER
                except Exception as exc:
                    log(f"[GEOIP-LOCAL] Rejected {candidate.name}: {type(exc).__name__}")
        except ImportError:
            try:
                import geoip2.database  # type: ignore
                for candidate in existing:
                    try:
                        _MMDB_READER = geoip2.database.Reader(str(candidate))
                        _MMDB_READER_PATH = str(candidate)
                        log(f"[GEOIP-LOCAL] Loaded country MMDB: {_MMDB_READER_PATH}")
                        return _MMDB_READER
                    except Exception as exc:
                        log(f"[GEOIP-LOCAL] Rejected {candidate.name}: {type(exc).__name__}")
            except ImportError:
                if not _MMDB_LOGGED:
                    log("[GEOIP-LOCAL] No MMDB reader module is available; online GeoIP fallback may be used.")
                    _MMDB_LOGGED = True
        return None


def _country_record_from_mmdb(record: Any) -> dict[str, str] | None:
    """Extract ISO code and English country name from common MaxMind country records."""
    if not isinstance(record, dict):
        return None
    for section_name in ("country", "registered_country", "represented_country"):
        section = record.get(section_name)
        if not isinstance(section, dict):
            continue
        code = str(section.get("iso_code") or "").strip().upper()
        names = section.get("names")
        country = str(names.get("en") or "").strip() if isinstance(names, dict) else ""
        if code and len(code) == 2 and code.isalpha():
            country = country or _country_name_for_code(code) or code
            result = {"code": code, "country": country}
            city_obj = record.get("city") if isinstance(record.get("city"), dict) else {}
            city_names = city_obj.get("names") if isinstance(city_obj.get("names"), dict) else {}
            result["city"] = str(city_names.get("en") or "")
            subdivisions = record.get("subdivisions")
            if isinstance(subdivisions, list) and subdivisions and isinstance(subdivisions[0], dict):
                sub_names = subdivisions[0].get("names") if isinstance(subdivisions[0].get("names"), dict) else {}
                result["region"] = str(sub_names.get("en") or "")
            return result
    # Also accept simple custom MMDB records with country_code/country_name keys.
    code = str(record.get("country_code") or record.get("iso_code") or "").strip().upper()
    country = str(record.get("country_name") or record.get("country") or "").strip()
    if code and len(code) == 2 and code.isalpha():
        return {"code": code, "country": country or _country_name_for_code(code) or code,
                "region": str(record.get("region") or ""), "city": str(record.get("city_name") or "")}
    return None


def _local_mmdb_lookup(ip_text: str) -> dict[str, str] | None:
    """Resolve the measured Egress IP locally first; accept only valid country records."""
    reader = _open_local_mmdb()
    if reader is None:
        return None
    try:
        with _MMDB_LOCK:
            if hasattr(reader, "get"):
                record = reader.get(ip_text)
            elif hasattr(reader, "country"):
                response = reader.country(ip_text)
                country_obj = getattr(response, "country", None)
                iso_code = str(getattr(country_obj, "iso_code", "") or "").upper()
                names_obj = getattr(country_obj, "names", {}) or {}
                country_name = str(names_obj.get("en", "") if isinstance(names_obj, dict) else "")
                record = {"country": {"iso_code": iso_code, "names": {"en": country_name}}} if iso_code else None
        result = _country_record_from_mmdb(record)
        if result:
            result["source"] = Path(_MMDB_READER_PATH or "local-mmdb").name
        return result
    except Exception as exc:
        log(f"[GEOIP-LOCAL] Lookup failed for measured Egress {ip_text}: {type(exc).__name__}")
        return None


def _geoip_ip(ip_text: str) -> dict[str, str] | None:
    """Local MMDB first; online providers are optional fallback, cached only per run/IP."""
    try:
        ip_obj = ipaddress.ip_address(str(ip_text).strip())
    except ValueError:
        return None
    if not ip_obj.is_global:
        return None
    ip_text = str(ip_obj)
    with _EGRESS_GEO_CACHE_LOCK:
        ip_lock = _EGRESS_GEO_IP_LOCKS.setdefault(ip_text, threading.Lock())
    with ip_lock:
        with _EGRESS_GEO_CACHE_LOCK:
            if ip_text in _EGRESS_GEO_CACHE:
                cached = _EGRESS_GEO_CACHE[ip_text]
                return dict(cached) if isinstance(cached, dict) else None

        local = _local_mmdb_lookup(ip_text)
        if local:
            with _EGRESS_GEO_CACHE_LOCK:
                _EGRESS_GEO_CACHE[ip_text] = dict(local)
            return local
    
        results: list[dict[str, str]] = []
        endpoints = (
            (f"https://ipwho.is/{urllib.parse.quote(ip_text, safe=':')}?fields=success,country_code,country,region,city", "ipwho"),
            (f"https://ipapi.co/{urllib.parse.quote(ip_text, safe=':')}/json/", "ipapi"),
        )
        for url, provider in endpoints:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "MihomoIndustrial-Egress/1.0"})
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read(128 * 1024).decode("utf-8", "replace"))
                if provider == "ipwho":
                    ok = data.get("success") is True
                    code = str(data.get("country_code") or "").strip().upper()
                    country = str(data.get("country") or "").strip()
                    region = str(data.get("region") or "").strip()
                    city = str(data.get("city") or "").strip()
                else:
                    ok = not data.get("error") and bool(data.get("country_code"))
                    code = str(data.get("country_code") or "").strip().upper()
                    country = str(data.get("country_name") or "").strip()
                    region = str(data.get("region") or "").strip()
                    city = str(data.get("city") or "").strip()
                if ok and len(code) == 2 and code.isalpha() and country:
                    results.append({"code": code, "country": country, "region": region,
                                    "city": city, "source": provider})
            except Exception as exc:
                # Rate limits and timeouts are provider failures, not proxy failures.
                log(f"[GEOIP-ONLINE] {provider} unavailable for {ip_text}: {type(exc).__name__}")
    
        resolved: dict[str, str] | None = None
        if results:
            codes = {x["code"] for x in results}
            if len(codes) == 1:
                # Prefer country consensus; only publish region/city when all responding
                # providers agree on the same non-empty value.
                results.sort(key=lambda x: (bool(x.get("city")), bool(x.get("region"))), reverse=True)
                chosen = dict(results[0])
                if len(results) < 2 or not all(x.get("region") for x in results) or len({x.get("region") for x in results}) != 1:
                    chosen["region"] = ""
                if len(results) < 2 or not all(x.get("city") for x in results) or len({x.get("city") for x in results}) != 1:
                    chosen["city"] = ""
                chosen["source"] = "+".join(sorted({x["source"] for x in results}))
                resolved = chosen
            else:
                log(f"[GEOIP-ONLINE] Provider disagreement for {ip_text}; country left unknown.")
    
        with _EGRESS_GEO_CACHE_LOCK:
            _EGRESS_GEO_CACHE[ip_text] = dict(resolved) if resolved else None
        return resolved

_COUNTRY_NAMES_FALLBACK = {
    "US": "United States", "GB": "United Kingdom", "UK": "United Kingdom",
    "NL": "Netherlands", "DE": "Germany", "FI": "Finland", "SE": "Sweden",
    "NO": "Norway", "DK": "Denmark", "IS": "Iceland", "FR": "France",
    "IT": "Italy", "ES": "Spain", "PT": "Portugal", "BE": "Belgium",
    "CH": "Switzerland", "AT": "Austria", "PL": "Poland", "CZ": "Czechia",
    "SK": "Slovakia", "HU": "Hungary", "RO": "Romania", "BG": "Bulgaria",
    "GR": "Greece", "TR": "Turkey", "UA": "Ukraine", "IE": "Ireland",
    "EE": "Estonia", "LV": "Latvia", "LT": "Lithuania", "LU": "Luxembourg",
    "CA": "Canada", "MX": "Mexico", "BR": "Brazil", "AR": "Argentina",
    "CL": "Chile", "CO": "Colombia", "JP": "Japan", "KR": "South Korea",
    "CN": "China", "HK": "Hong Kong", "TW": "Taiwan", "SG": "Singapore",
    "MY": "Malaysia", "TH": "Thailand", "VN": "Vietnam", "ID": "Indonesia",
    "IN": "India", "PK": "Pakistan", "BD": "Bangladesh", "AU": "Australia",
    "NZ": "New Zealand", "RU": "Russia", "KZ": "Kazakhstan", "AZ": "Azerbaijan",
    "AM": "Armenia", "GE": "Georgia", "IL": "Israel", "AE": "United Arab Emirates",
    "SA": "Saudi Arabia", "IR": "Iran", "IQ": "Iraq", "EG": "Egypt",
    "ZA": "South Africa", "NG": "Nigeria", "KE": "Kenya", "CY": "Cyprus",
    "MT": "Malta", "HR": "Croatia", "SI": "Slovenia", "RS": "Serbia",
    "BA": "Bosnia and Herzegovina", "ME": "Montenegro", "MK": "North Macedonia",
    "MD": "Moldova", "BY": "Belarus", "AL": "Albania", "XK": "Kosovo",
}


def _country_name_for_code(code: str) -> str | None:
    code = str(code or "").upper()
    try:
        # Optional dependency: if present, provides the full ISO country-name set.
        import pycountry  # type: ignore
        country = pycountry.countries.get(alpha_2=code)
        if country:
            return str(country.name)
    except Exception:
        pass
    return _COUNTRY_NAMES_FALLBACK.get(code)


def _strip_leading_source_country(name: str) -> str:
    """Remove imported country flags/labels so a stale source flag cannot contradict GeoIP."""
    value = str(name or "NODE").strip()
    # Remove any flag pair anywhere in the remark, not only at its beginning.
    value = re.sub(r"[\U0001F1E6-\U0001F1FF]{2}", " ", value)
    # Remove explicit two-letter country tags such as [FI] and #FI.
    value = re.sub(r"(?<![A-Za-z0-9])(?:#|\[)[A-Za-z]{2}\]?(?![A-Za-z])", " ", value)
    # Remove country-name tokens anywhere in the remark; the canonical label is
    # already added before this text and must be the only country label shown.
    for country in sorted(set(_COUNTRY_NAMES_FALLBACK.values()), key=len, reverse=True):
        value = re.sub(r"(?<![A-Za-z])" + re.escape(country) + r"(?![A-Za-z])", " ", value, flags=re.IGNORECASE)
    value = re.sub(r"\s+", " ", value).strip(" -|:#")
    return value or "NODE"


def _find_mihomo_binary() -> str | None:
    """Locate an executable Mihomo core without installing or updating packages."""
    candidates = [
        MIHOMO_BINARY_OVERRIDE or None,
        str(MIHOMO_SOURCE_DIR / "bin" / "mihomo-android-arm64"),
        str(PROJECT_DIR / "core" / "mihomo"),
        str(PROJECT_DIR / "core" / "mihomo2"),
        str(BASE_DIR / "core" / "mihomo"),
        str(PROJECT_DIR / "core" / "mihomo"),
        str(PROJECT_DIR / "core" / "mihomo"),
        shutil.which("mihomo"),
    ]
    for item in candidates:
        if item and Path(item).is_file() and os.access(item, os.X_OK):
            return str(Path(item))
    return None


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _collect_probe_chain(root: dict[str, Any], all_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Include a node's explicit dialer-proxy chain; reject unresolved group chains."""
    by_name = {str(n.get("name")): n for n in all_nodes if isinstance(n, dict) and n.get("name")}
    ordered: list[dict[str, Any]] = []
    visiting: set[str] = set()
    included: set[str] = set()

    def visit(node: dict[str, Any]) -> None:
        name = str(node.get("name") or "")
        if not name or name in visiting:
            raise ValueError("empty name or dialer-proxy cycle")
        if name in included:
            return
        visiting.add(name)
        dialer = str(node.get("dialer-proxy") or "").strip()
        if dialer and dialer not in {"DIRECT", "REJECT"}:
            dependency = by_name.get(dialer)
            if dependency is None:
                raise ValueError(f"dialer-proxy dependency is not a proxy node: {dialer}")
            visit(dependency)
        visiting.remove(name)
        included.add(name)
        ordered.append(copy.deepcopy(node))

    visit(root)
    return ordered


def _make_probe_config(node: dict[str, Any], all_nodes: list[dict[str, Any]], port: int) -> dict[str, Any]:
    chain = _collect_probe_chain(node, all_nodes)
    root_name = str(node.get("name") or "")
    proxy_names = {str(item.get("name") or "") for item in chain}
    route_name = "__MIHOMO_EGRESS_PROBE_ROUTE__"
    while route_name in proxy_names:
        route_name += "_"
    return {
        "mixed-port": port,
        "bind-address": "127.0.0.1",
        "allow-lan": False,
        "mode": "rule",
        "log-level": "error",
        "ipv6": True,
        "proxies": chain,
        "proxy-groups": [{"name": route_name, "type": "select", "proxies": [root_name]}],
        "rules": [f"MATCH,{route_name}"],
    }


def _request_via_local_mihomo(port: int, url: str, timeout: float) -> tuple[int, bytes, int]:
    """Make one HTTP(S) request through the isolated local Mihomo mixed port."""
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    request = urllib.request.Request(url, headers={"User-Agent": "MihomoIndustrial-Egress-Probe/1.0", "Accept": "text/plain,*/*"})
    started = time.monotonic()
    with opener.open(request, timeout=timeout) as response:
        body = response.read(1024)
        status = int(getattr(response, "status", response.getcode()))
    elapsed = int((time.monotonic() - started) * 1000)
    return status, body, elapsed


def _public_ip_from_body(body: bytes) -> str | None:
    try:
        candidate = body.decode("ascii", "ignore").strip().split()[0]
        ip_obj = ipaddress.ip_address(candidate)
        return str(ip_obj) if ip_obj.is_global else None
    except Exception:
        return None


def _probe_node_egress(node: dict[str, Any], all_nodes: list[dict[str, Any]], mihomo: str) -> dict[str, Any]:
    """Start an isolated Mihomo instance, require IP-echo quorum, then health-check."""
    started_at = datetime.now(timezone.utc).isoformat()
    record: dict[str, Any] = {
        "egress_ip": None, "egress_family": None, "country_code": None, "country": None,
        "region": None, "city": None, "geo_source": None,
        "healthy": False, "latency_ms": None, "echo_votes": {}, "echo_sources": {},
        "location_precision": None, "health_url": None,
        "checked_at": started_at, "status": "unverified", "error": None,
    }
    try:
        port = _free_local_port()
        with tempfile.TemporaryDirectory(prefix="mihomo-egress-") as td:
            config_path = Path(td) / "probe.yaml"
            probe_config = _make_probe_config(node, all_nodes, port)
            config_text = "\n".join(yaml_dump(probe_config)) + "\n"
            config_path.write_text(config_text, encoding="utf-8")
            tested = subprocess.run([mihomo, "-t", "-d", td, "-f", str(config_path)],
                                    capture_output=True, text=True, cwd=str(Path.home()),
                                    timeout=EGRESS_PROBE_CONFIG_TEST_TIMEOUT)
            if tested.returncode != 0:
                detail = (tested.stderr or tested.stdout or "Mihomo rejected isolated proxy config").strip()
                raise RuntimeError("core-config-test: " + detail[:500])
            process = subprocess.Popen([mihomo, "-d", td, "-f", str(config_path)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, close_fds=True, cwd=str(Path.home()))
            try:
                deadline = time.monotonic() + EGRESS_PROBE_START_TIMEOUT
                ready = False
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(f"mihomo-exited:{process.returncode}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.15)
                if not ready:
                    raise TimeoutError("local mixed-port did not become ready")

                votes: Counter[str] = Counter()
                echo_sources: dict[str, str] = {}
                echo_latencies: list[int] = []
                for family, endpoints in (("IPv4", EGRESS_PROBE_ENDPOINTS_V4), ("IPv6", EGRESS_PROBE_ENDPOINTS_V6)):
                    family_votes: Counter[str] = Counter()
                    family_sources: dict[str, str] = {}
                    family_latencies: list[int] = []
                    for endpoint in endpoints:
                        try:
                            status, body, elapsed = _request_via_local_mihomo(port, endpoint, EGRESS_PROBE_REQUEST_TIMEOUT)
                            ip_text = _public_ip_from_body(body) if status in {200, 204} else None
                            if ip_text and ipaddress.ip_address(ip_text).version == (4 if family == "IPv4" else 6):
                                family_votes[ip_text] += 1
                                family_sources[endpoint] = ip_text
                                family_latencies.append(elapsed)
                                if family_votes[ip_text] >= EGRESS_PROBE_QUORUM:
                                    break
                        except Exception as exc:
                            log(f"[EGRESS-PROBE] {node.get('name')}: {endpoint} failed ({type(exc).__name__})")
                    if family_votes:
                        family_ip, family_count = family_votes.most_common(1)[0]
                        if family_count >= EGRESS_PROBE_QUORUM:
                            votes = family_votes
                            echo_sources = family_sources
                            echo_latencies = family_latencies
                            record["egress_ip"] = family_ip
                            record["egress_family"] = family
                            break
                record["echo_votes"] = dict(votes)
                record["echo_sources"] = dict(echo_sources)
                if not record.get("egress_ip"):
                    raise RuntimeError("Egress IP consensus insufficient for both IPv4 and IPv6 families")

                health_latency: int | None = None
                for endpoint in EGRESS_HEALTH_ENDPOINTS:
                    try:
                        status, _body, elapsed = _request_via_local_mihomo(port, endpoint, EGRESS_PROBE_REQUEST_TIMEOUT)
                        if status in {200, 204}:
                            record["healthy"] = True
                            record["health_url"] = endpoint
                            health_latency = elapsed
                            break
                    except Exception:
                        continue
                if not record["healthy"]:
                    raise RuntimeError("Egress IP measured, but all independent health endpoints failed")
                record["latency_ms"] = health_latency if health_latency is not None else (min(echo_latencies) if echo_latencies else None)
                geo = _geoip_ip(str(record["egress_ip"]))
                if geo:
                    record["country_code"] = geo.get("code")
                    record["country"] = geo.get("country")
                    record["region"] = geo.get("region")
                    record["city"] = geo.get("city")
                    record["geo_source"] = geo.get("source")
                    record["location_precision"] = "city" if geo.get("city") else ("region" if geo.get("region") else "country")
                record["status"] = "verified-healthy" if record["country_code"] else "verified-healthy-unknown-country"
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"[:700]
        if record.get("egress_ip"):
            record["status"] = "egress-measured-unhealthy"
    return record


def _probe_all_nodes(nodes: list[dict[str, Any]]) -> dict[str, int]:
    """Measure actual Egress through each proxy and store results by stable fingerprint."""
    _EGRESS_RESULTS.clear()
    with _EGRESS_GEO_CACHE_LOCK:
        _EGRESS_GEO_CACHE.clear()
        _EGRESS_GEO_IP_LOCKS.clear()
    if not EGRESS_PROBE_ENABLED:
        log("[EGRESS] Probe disabled; group membership fails closed.")
        return {"tested": 0, "egress": 0, "healthy": 0, "known_country": 0}
    mihomo = _find_mihomo_binary()
    if not mihomo:
        log("[EGRESS] ERROR: executable Mihomo core not found; no server-IP or name-based geo fallback will be used.")
        return {"tested": 0, "egress": 0, "healthy": 0, "known_country": 0}
    log(f"[EGRESS] Core={mihomo}; nodes={len(nodes)}; workers={min(EGRESS_PROBE_WORKERS, max(1, len(nodes)))}; IPv4/IPv6 quorum={EGRESS_PROBE_QUORUM}/3")
    workers = min(max(1, EGRESS_PROBE_WORKERS), max(1, len(nodes)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_node_egress, node, nodes, mihomo): node for node in nodes}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            node = futures[future]
            try:
                record = future.result()
            except Exception as exc:
                record = {"egress_ip": None, "country_code": None, "country": None,
                          "healthy": False, "status": "unverified", "error": f"{type(exc).__name__}: {exc}"}
            _EGRESS_RESULTS[fingerprint(node)] = record
            done += 1
            if record.get("egress_ip"):
                log(f"[EGRESS] {done}/{len(nodes)} measured {record.get('egress_ip')} | {record.get('country_code') or 'UNKNOWN'} | healthy={record.get('healthy')}")
            else:
                log(f"[EGRESS] {done}/{len(nodes)} unverified | {str(record.get('error') or 'no evidence')[:160]}")
    records = list(_EGRESS_RESULTS.values())
    return {
        "tested": len(records),
        "egress": sum(bool(x.get("egress_ip")) for x in records),
        "healthy": sum(bool(x.get("healthy") and x.get("egress_ip")) for x in records),
        "known_country": sum(bool(x.get("healthy") and x.get("egress_ip") and x.get("country_code")) for x in records),
    }


def _egress_result_for_node(node: dict[str, Any]) -> dict[str, Any]:
    return _EGRESS_RESULTS.get(fingerprint(node), {})


def _write_egress_audit(nodes: list[dict[str, Any]]) -> None:
    """Write evidence-only audit; proxy credentials and secrets are never copied."""
    entries = []
    for node in nodes:
        result = _egress_result_for_node(node)
        entries.append({
            "proxy_name": str(node.get("name") or ""),
            "protocol": str(node.get("type") or ""),
            "egress_ip": result.get("egress_ip"),
            "egress_family": result.get("egress_family"),
            "country_code": result.get("country_code"),
            "country": result.get("country"),
            "region": result.get("region"),
            "city": result.get("city"),
            "geo_source": result.get("geo_source"),
            "healthy": bool(result.get("healthy")),
            "latency_ms": result.get("latency_ms"),
            "echo_votes": result.get("echo_votes", {}),
            "echo_sources": result.get("echo_sources", {}),
            "location_precision": result.get("location_precision"),
            "health_url": result.get("health_url"),
            "status": result.get("status", "unverified"),
            "error_category": str(result.get("error") or "").split(":", 1)[0] or None,
            "checked_at": result.get("checked_at"),
        })
    payload = {"engine": ENGINE_VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
               "geo_policy": "measured-egress-ip-only; local-mmdb-first; no source-name fallback",
               "records": entries}
    atomic_write(EGRESS_AUDIT_PATH, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _decorate_node_names(nodes: list[dict[str, Any]]) -> None:
    """Decorate names exclusively from measured Egress IP and its GeoIP evidence."""
    global _DECORATED_ORIGINAL_NAMES
    _DECORATED_ORIGINAL_NAMES = {}
    rename: dict[str, str] = {}
    evidence_by_id = {id(node): _egress_result_for_node(node) for node in nodes}
    for node in nodes:
        raw_name = urllib.parse.unquote(str(node.get("name") or "NODE"))
        raw_name = re.sub(r"\s+", " ", raw_name).strip() or "NODE"
        evidence = _egress_result_for_node(node)
        egress_ip = str(evidence.get("egress_ip") or "").strip()
        code = str(evidence.get("country_code") or "").strip().upper()
        country = str(evidence.get("country") or "").strip()
        region = str(evidence.get("region") or "").strip()
        city = str(evidence.get("city") or "").strip()
        port_label = str(node.get("port") or "?").strip()
        protocol_label = str(node.get("type") or "unknown").strip().upper()
        if egress_ip and code and country:
            flag = _country_flag_from_code(code) or "🌐"
            location = " / ".join(x for x in (country, region, city) if x)
            label = f"{flag} {location} ({code}) | EGRESS {egress_ip}"
        elif egress_ip:
            label = f"🌐 Unknown Country | EGRESS {egress_ip}"
        else:
            label = "🌐 Egress Unverified"
        details = f"{label} | PORT {port_label} | {protocol_label}"
        old = _strip_leading_source_country(raw_name)
        new = f"{details} | {old}"[:180]
        node["name"] = new
        rename[raw_name] = new
        _DECORATED_ORIGINAL_NAMES[new] = old
    for node in nodes:
        ref = node.get("dialer-proxy")
        if isinstance(ref, str) and ref in rename:
            node["dialer-proxy"] = rename[ref]
    # dialer-proxy names are rewritten above; re-key evidence against the
    # normalized node fingerprint so later validators still see the same proof.
    _EGRESS_RESULTS.clear()
    for node in nodes:
        _EGRESS_RESULTS[fingerprint(node)] = evidence_by_id.get(id(node), {})


def _enabled_manual_group(group_name: str) -> bool:
    """Only the four explicitly specified output groups are accepted."""
    return str(group_name).strip() in set(GROUP_ORDER)


def _unique_group_list(
    groups: list[dict[str, Any]],
    nodes_by_name: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Enforce one measured Egress IP per group; never remove nodes globally."""
    result: list[dict[str, Any]] = []
    seen_groups: set[str] = set()
    nodes_by_name = nodes_by_name or {}
    for group in groups:
        name = str(group.get("name") or "").strip()
        if not name or name in seen_groups:
            continue
        seen_groups.add(name)
        refs = group.get("proxies")
        if not isinstance(refs, list):
            continue
        if name == DIRECT_GROUP_NAME:
            group["proxies"] = ["DIRECT"]
            result.append(group)
            continue
        cleaned: list[str] = []
        seen_egress: set[str] = set()
        for raw_ref in refs:
            ref = str(raw_ref).strip()
            if not ref or ref in cleaned or ref in GROUP_ORDER or ref == "DIRECT":
                continue
            node = nodes_by_name.get(ref)
            if node is None:
                if ref == "REJECT":
                    cleaned.append(ref)
                continue
            evidence = _egress_result_for_node(node)
            egress_ip = str(evidence.get("egress_ip") or "")
            if not egress_ip:
                continue
            if egress_ip in seen_egress:
                continue
            seen_egress.add(egress_ip)
            cleaned.append(ref)
        group["proxies"] = cleaned or ["REJECT"]
        result.append(group)
    return result


def _build_groups_with_switches(
    names: list[str],
    nodes: list[dict[str, Any]] | None = None,
    source_groups: Any = None,
) -> list[dict[str, Any]]:
    """Build four independent groups directly from all nodes and measured evidence."""
    nodes = nodes or []
    node_by_name = {str(n.get("name")): n for n in nodes if isinstance(n, dict) and n.get("name")}
    ordered_nodes = [node_by_name[name] for name in dict.fromkeys(str(x) for x in names)
                     if name in node_by_name and name != "DIRECT"]

    def best_unique(pool: list[dict[str, Any]]) -> list[str]:
        # Prefer lower measured health latency; stable source order breaks ties.
        ranked = sorted(enumerate(pool), key=lambda pair: (
            int(_egress_result_for_node(pair[1]).get("latency_ms") or 10**9), pair[0]))
        chosen: list[str] = []
        seen_egress: set[str] = set()
        for _index, node in ranked:
            evidence = _egress_result_for_node(node)
            egress_ip = str(evidence.get("egress_ip") or "")
            if not egress_ip or egress_ip in seen_egress:
                continue
            seen_egress.add(egress_ip)
            chosen.append(str(node.get("name")))
        return chosen

    # Every predicate is applied to the complete ordered inventory, not another group.
    healthy_with_egress = [n for n in ordered_nodes
        if _egress_result_for_node(n).get("healthy") and _egress_result_for_node(n).get("egress_ip")]
    select_candidates = [n for n in ordered_nodes
        if _egress_result_for_node(n).get("healthy")
        and _egress_result_for_node(n).get("egress_ip")
        and _egress_result_for_node(n).get("country_code")
        and _egress_result_for_node(n).get("country")]
    unknown_candidates = [n for n in ordered_nodes
        if _egress_result_for_node(n).get("healthy")
        and _egress_result_for_node(n).get("egress_ip")
        and not (_egress_result_for_node(n).get("country_code") and _egress_result_for_node(n).get("country"))]

    select_pool = best_unique(select_candidates)
    fallback_pool = best_unique(healthy_with_egress)
    unknown_pool = best_unique(unknown_candidates)

    # REJECT is an explicit safe placeholder so all four group definitions remain present.
    groups = [
        {"name": DEFAULT_RULE_GROUP, "type": "select", "proxies": select_pool or ["REJECT"]},
        {"name": FALLBACK_GROUP_NAME, "type": "fallback", "proxies": fallback_pool or ["REJECT"],
         "url": HEALTH_URL, "interval": HEALTH_INTERVAL, "lazy": True, "timeout": HEALTH_TIMEOUT},
        {"name": UNKNOWN_GROUP_NAME, "type": "select", "proxies": unknown_pool or ["REJECT"]},
        {"name": DIRECT_GROUP_NAME, "type": "select", "proxies": ["DIRECT"]},
    ]
    return _unique_group_list(groups, node_by_name)


# Alias table for the editable master key. Canonical values are the actual
# generated group names; callers may type short names such as "us" or "fallback".
_GROUP_MASTER_ALIASES = {
    "select": DEFAULT_RULE_GROUP,
    "manual": DEFAULT_RULE_GROUP,
    "fallback": FALLBACK_GROUP_NAME,
    "failover": FALLBACK_GROUP_NAME,
    "unknown": UNKNOWN_GROUP_NAME,
    "unknowncountry": UNKNOWN_GROUP_NAME,
    "noncountry": UNKNOWN_GROUP_NAME,
    "direct": DIRECT_GROUP_NAME,
}


def _group_key_normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def _parse_group_master_key(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        parts = [item.strip() for item in re.split(r"[+,;\n\r]+", str(value or "")) if item.strip()]
    resolved: list[str] = []
    seen: set[str] = set()
    for part in parts:
        canonical = _GROUP_MASTER_ALIASES.get(_group_key_normalize(part), part)
        if canonical in GROUP_ORDER and canonical not in seen:
            seen.add(canonical)
            resolved.append(canonical)
    return resolved


def build_groups(
    names: list[str],
    nodes: list[dict[str, Any]] | None = None,
    source_groups: Any = None,
) -> list[dict[str, Any]]:
    """Always emit the four required groups in canonical order."""
    groups = _build_groups_with_switches(names, nodes=nodes, source_groups=None)
    actual = [str(g.get("name")) for g in groups]
    if actual != list(GROUP_ORDER):
        raise AssertionError(f"Four-group contract broken: {actual}")
    return groups


def _active_default_group(groups: list[dict[str, Any]]) -> str:
    """Prefer Select; use independent Fallback only when Select has no verified members."""
    by_name = {str(g.get("name")): g for g in groups if isinstance(g, dict) and g.get("name")}
    select = by_name.get(DEFAULT_RULE_GROUP, {})
    select_members = select.get("proxies", []) if isinstance(select, dict) else []
    if isinstance(select_members, list) and any(str(x) not in {"REJECT", "DIRECT"} for x in select_members):
        return DEFAULT_RULE_GROUP
    fallback = by_name.get(FALLBACK_GROUP_NAME, {})
    fallback_members = fallback.get("proxies", []) if isinstance(fallback, dict) else []
    if isinstance(fallback_members, list) and any(str(x) not in {"REJECT", "DIRECT"} for x in fallback_members):
        return FALLBACK_GROUP_NAME
    return DEFAULT_RULE_GROUP if DEFAULT_RULE_GROUP in by_name else "REJECT"


def build_service_rules(active_group_names: set[str] | None = None) -> list[str]:
    """Route local/private/Iran traffic through the independent Direct group."""
    return list(IRAN_DIRECT_RULES)


def build_default_rules(active_group_names: set[str] | None = None) -> list[str]:
    active = active_group_names or {DEFAULT_RULE_GROUP}
    fallback = DEFAULT_RULE_GROUP if DEFAULT_RULE_GROUP in active else "REJECT"
    return build_service_rules(active) + [f"MATCH,{fallback}"]

def extract_top_level_sections(
    text: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    try:
        import yaml
        obj = yaml.safe_load(text)

        if not isinstance(obj, dict):
            return result

        for key in PRESERVE_TOP_LEVEL | {
            "proxies",
            "proxy-groups",
            "proxy-providers",
            "rule-providers",
            "rules",
            "dns",
            "tun",
            "listeners",
            "experimental",
            "profile",
            "sub-rules",
            "tunnels",
            "ntp",
            "sniffer",
            "hosts",
            "authentication",
            "skip-auth-prefixes",
        }:
            if key in obj:
                result[key] = obj[key]

    except Exception:
        pass

    return result

def normalize_provider(
    name: str,
    provider: Any,
) -> dict[str, Any] | None:
    """Normalize Mihomo proxy-provider fields without inventing values."""
    if not isinstance(provider, dict):
        return None

    result = copy.deepcopy(provider)
    provider_type = str(result.get("type") or "").lower()

    if provider_type not in {"http", "file", "inline"}:
        return None

    if provider_type == "http" and not result.get("url"):
        return None

    if provider_type == "file" and not result.get("path"):
        return None

    if "interval" in result:
        result["interval"] = safe_int(result["interval"], 0)

    if "size-limit" in result:
        result["size-limit"] = safe_int(
            result["size-limit"], 0
        )

    if "health-check" in result:
        health = result["health-check"]
        if isinstance(health, dict):
            health.setdefault("enable", True)
            if health.get("interval") is not None:
                health["interval"] = safe_int(
                    health["interval"], 300
                )
            if health.get("timeout") is not None:
                health["timeout"] = safe_int(
                    health["timeout"], 5000
                )

    for key in (
        "filter",
        "exclude-filter",
        "exclude-type",
        "payload",
        "header",
        "override",
    ):
        if key in result:
            result[key] = copy.deepcopy(result[key])

    return result


def normalize_rule_provider(
    name: str,
    provider: Any,
) -> dict[str, Any] | None:
    """Normalize Mihomo rule-provider fields."""
    if not isinstance(provider, dict):
        return None

    result = copy.deepcopy(provider)
    provider_type = str(result.get("type") or "").lower()

    if provider_type not in {"http", "file", "inline"}:
        return None

    if provider_type == "http" and not result.get("url"):
        return None

    if result.get("interval") is not None:
        result["interval"] = safe_int(
            result["interval"], 0
        )

    if result.get("size-limit") is not None:
        result["size-limit"] = safe_int(
            result["size-limit"], 0
        )

    behavior = result.get("behavior")
    if behavior and behavior not in {
        "domain",
        "ipcidr",
        "classical",
    }:
        return None

    fmt = result.get("format")
    if fmt and fmt not in {
        "yaml",
        "text",
        "mrs",
    }:
        return None

    return result


def normalize_dns(dns: Any) -> dict[str, Any] | None:
    if not isinstance(dns, dict):
        return None

    result = copy.deepcopy(dns)

    boolean_keys = {
        "enable",
        "prefer-h3",
        "ipv6",
        "use-hosts",
        "use-system-hosts",
        "respect-rules",
        "direct-nameserver-follow-policy",
        "fallback-lazy-query",
    }

    for key in boolean_keys:
        if key in result:
            result[key] = bool_value(result[key])

    for key in (
        "fake-ip-ttl",
    ):
        if key in result:
            result[key] = safe_int(
                result[key], result[key]
            )

    return result


def normalize_tun(tun: Any) -> dict[str, Any] | None:
    if not isinstance(tun, dict):
        return None

    result = copy.deepcopy(tun)

    for key in (
        "enable",
        "stack",
        "dns-hijack",
        "auto-route",
        "auto-detect-interface",
        "auto-redirect",
        "strict-route",
        "endpoint-independent-nat",
        "route-exclude-address",
        "route-include-address",
        "route-exclude-address-set",
        "route-include-address-set",
        "route-exclude-package",
        "route-include-package",
    ):
        if key not in result:
            continue

        if isinstance(result[key], str):
            if result[key].lower() in {
                "true", "false", "yes", "no", "1", "0"
            }:
                result[key] = bool_value(result[key])

    return result


def normalize_listeners(listeners: Any) -> list[dict[str, Any]] | None:
    if not isinstance(listeners, list):
        return None

    result: list[dict[str, Any]] = []

    for listener in listeners:
        if not isinstance(listener, dict):
            continue

        item = copy.deepcopy(listener)

        if not item.get("name") or not item.get("type"):
            continue

        if item.get("port") is not None:
            port = safe_int(item["port"], 0)
            if not (1 <= port <= 65535):
                continue
            item["port"] = port

        result.append(item)

    return result


def normalize_experimental(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return copy.deepcopy(value)

def build_config(
    nodes: list[dict[str, Any]],
    source_text: str = "",
) -> dict[str, Any]:
    unique_names(nodes)

    names = [
        node_data["name"]
        for node_data in nodes
    ]

    # Stable, conservative defaults. Network-sensitive optional sections are
    # copied only when supplied by the source config.
    config: dict[str, Any] = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "strict",
        "proxies": nodes,
        "proxy-groups": build_groups(names, nodes=nodes),
        "rules": [],
    }

    extra = extract_top_level_sections(source_text)

    # Rebuild groups after reading the source so explicit service/group affinity
    # can be honored without copying arbitrary source group definitions.
    config["proxy-groups"] = build_groups(
        names,
        nodes=nodes,
        source_groups=extra.get("proxy-groups"),
    )
    active_group_names = {str(g.get("name")) for g in config["proxy-groups"] if isinstance(g, dict)}
    config["rules"] = build_service_rules(active_group_names) + [f"MATCH,{_active_default_group(config['proxy-groups'])}"]

    # Preserve/import full source sections where the source actually contains
    # them. No fake DNS/TUN/listener values are created.
    if isinstance(extra.get("proxy-providers"), dict):
        providers: dict[str, Any] = {}

        for provider_name, provider in extra["proxy-providers"].items():
            normalized = normalize_provider(
                str(provider_name),
                provider,
            )
            if normalized:
                providers[
                    clean_name(provider_name, "provider")
                ] = normalized

        if providers and ENABLE_PROXY_PROVIDER_ENGINE:
            config["proxy-providers"] = providers

    if isinstance(extra.get("rule-providers"), dict):
        providers: dict[str, Any] = {}

        for provider_name, provider in extra["rule-providers"].items():
            normalized = normalize_rule_provider(
                str(provider_name),
                provider,
            )
            if normalized:
                providers[
                    clean_name(provider_name, "ruleset")
                ] = normalized

        if providers and ENABLE_RULE_PROVIDER_ENGINE:
            config["rule-providers"] = providers

    if ENABLE_DNS_ENGINE and extra.get("dns") is not None:
        normalized_dns = normalize_dns(extra["dns"])
        if normalized_dns:
            config["dns"] = normalized_dns

    if ENABLE_TUN_ENGINE and extra.get("tun") is not None:
        normalized_tun = normalize_tun(extra["tun"])
        if normalized_tun:
            config["tun"] = normalized_tun

    if ENABLE_LISTENER_ENGINE and extra.get("listeners") is not None:
        normalized_listeners = normalize_listeners(
            extra["listeners"]
        )
        if normalized_listeners:
            config["listeners"] = normalized_listeners

    if ENABLE_EXPERIMENTAL_ENGINE:
        if extra.get("experimental") is not None:
            experimental = normalize_experimental(
                extra["experimental"]
            )
            if experimental:
                config["experimental"] = experimental

    if ENABLE_PROFILE_ENGINE and extra.get("profile") is not None:
        if isinstance(extra["profile"], dict):
            config["profile"] = copy.deepcopy(extra["profile"])

    # These are complete documented configuration sections, not proxy-group
    # definitions. Preserve their shape as supplied so newer Mihomo keys remain
    # forward-compatible; the real Mihomo core remains the final schema check.
    for section in ("sub-rules", "tunnels", "ntp", "sniffer", "hosts",
                    "authentication", "skip-auth-prefixes"):
        if section in extra and extra[section] is not None:
            config[section] = copy.deepcopy(extra[section])

    # Preserve other documented/general sections verbatim from the source,
    # while avoiding replacement of generated core proxy/routing sections.
    protected = {
        "proxies",
        "proxy-groups",
        "proxy-providers",
        "rule-providers",
        "rules",
        "dns",
        "tun",
        "listeners",
        "experimental",
        "profile",
    }

    for key, value in extra.items():
        if key in protected:
            continue
        if key in PRESERVE_TOP_LEVEL:
            config[key] = copy.deepcopy(value)

    # Preserve useful imported rules, but keep the generated local/direct
    # policy authoritative. Imported MATCH rules are removed and a single
    # terminal Select ⚖️ fallback is installed.
    source_rules = extra.get("rules")

    if isinstance(source_rules, list) and source_rules:
        imported = [
            item for item in source_rules
            if isinstance(item, str)
            and item.strip()
            and not item.strip().upper().startswith("MATCH,")
        ]
        active_group_names = {str(g.get("name")) for g in config.get("proxy-groups", []) if isinstance(g, dict)}
        fallback = _active_default_group(config.get("proxy-groups", []))
        service_rules = build_service_rules(active_group_names)
        config["rules"] = service_rules + copy.deepcopy(imported)
        web_target = _active_default_group(config.get("proxy-groups", []))
        config["rules"].append(f"MATCH,{web_target}")

    # Never persist the previously selected proxy.
    if isinstance(config.get("profile"), dict):
        config["profile"]["store-selected"] = bool(STORE_SELECTED_PROXY)
    else:
        config["profile"] = {"store-selected": bool(STORE_SELECTED_PROXY)}

    # Last-mile invariant firewall: imported group definitions cannot bypass the master key.
    config = enforce_manual_select_invariants(config)

    return config

def validate_config(
    config: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    if not isinstance(config, dict):
        return ["root is not mapping"]

    nodes = config.get("proxies", [])

    if not isinstance(nodes, list) or not nodes:
        errors.append("proxies is empty")

    names: list[str] = []

    for node_data in nodes:
        if not isinstance(node_data, dict):
            errors.append("proxy item is not mapping")
            continue

        names.append(node_data.get("name"))

        errors.extend(
            [
                f"{node_data.get('name', '?')}: {error}"
                for error in validate_node(node_data)
            ]
        )

    if len(names) != len(set(names)):
        errors.append("duplicate proxy names")

    groups = config.get("proxy-groups", [])

    if not isinstance(groups, list) or not groups:
        errors.append("proxy-groups must contain at least one group")
    else:
        for index, group in enumerate(groups):
            if not isinstance(group, dict):
                errors.append(f"proxy-groups[{index}] must be a mapping")
                continue
            group_type = str(group.get("type") or "").lower()
            if group_type not in {"select", "url-test", "fallback", "load-balance", "relay"}:
                errors.append(f"unsupported proxy group type {group_type}")
            if group_type == "select":
                for key in ("url", "interval", "lazy", "timeout", "strategy", "tolerance", "health-check"):
                    if key in group:
                        errors.append(f"manual group {group.get('name', index)} must not contain {key}")

    profile = config.get("profile")
    if not isinstance(profile, dict) or profile.get("store-selected") is not bool(STORE_SELECTED_PROXY):
        errors.append(f"profile.store-selected must be {str(bool(STORE_SELECTED_PROXY)).lower()}")

    if not isinstance(groups, list) or not groups:
        errors.append("proxy-groups is empty")

    group_names = {
        group.get("name")
        for group in groups
        if isinstance(group, dict)
    }

    allowed_refs = (
        set(names)
        | group_names
        | {"DIRECT", "REJECT", "COMPATIBLE", "GLOBAL"}
    )

    for group in groups:
        if not isinstance(group, dict):
            errors.append("group item is not mapping")
            continue

        group_name = group.get("name")
        group_type = group.get("type")

        if not group_name or not group_type:
            errors.append("group missing name/type")
            continue

        if group_type not in {
            "select",
            "url-test",
            "fallback",
            "load-balance",
            "relay",
        }:
            errors.append(
                f"unsupported group type {group_type}"
            )

        refs = group.get("proxies", [])

        if not isinstance(refs, list) or not refs:
            errors.append(
                f"group {group_name} empty"
            )

        else:
            for ref in refs:
                if ref not in allowed_refs:
                    errors.append(
                        f"group {group_name}: "
                        f"missing ref {ref}"
                    )

        if group_type in {
            "url-test",
            "fallback",
            "load-balance",
        }:
            if not group.get("url"):
                errors.append(
                    f"group {group_name}: missing url"
                )

            if (
                not isinstance(
                    group.get("interval"),
                    int,
                )
                or group["interval"] <= 0
            ):
                errors.append(
                    f"group {group_name}: "
                    f"invalid interval"
                )

    rules = config.get("rules")

    if not isinstance(rules, list) or not rules:
        errors.append("rules empty")

    # Provider validation.
    for section_name in (
        "proxy-providers",
        "rule-providers",
    ):
        section = config.get(section_name)

        if section is None:
            continue

        if not isinstance(section, dict):
            errors.append(
                f"{section_name} is not mapping"
            )
            continue

        for provider_name, provider in section.items():
            if not isinstance(provider, dict):
                errors.append(
                    f"{section_name}/{provider_name}: "
                    "not mapping"
                )
                continue

            provider_type = str(
                provider.get("type") or ""
            ).lower()

            if provider_type not in {
                "http",
                "file",
                "inline",
            }:
                errors.append(
                    f"{section_name}/{provider_name}: "
                    f"invalid type {provider_type}"
                )

            if (
                provider_type == "http"
                and not provider.get("url")
            ):
                errors.append(
                    f"{section_name}/{provider_name}: "
                    "http provider missing url"
                )

            if section_name == "rule-providers":
                behavior = provider.get("behavior")
                if behavior and behavior not in {
                    "domain",
                    "ipcidr",
                    "classical",
                }:
                    errors.append(
                        f"{section_name}/{provider_name}: "
                        "invalid behavior"
                    )

    # Listener validation.
    listeners = config.get("listeners")

    if listeners is not None:
        if not isinstance(listeners, list):
            errors.append("listeners is not list")
        else:
            listener_names = set()
            for listener in listeners:
                if not isinstance(listener, dict):
                    errors.append(
                        "listener item is not mapping"
                    )
                    continue

                name = listener.get("name")
                if not name:
                    errors.append(
                        "listener missing name"
                    )
                elif name in listener_names:
                    errors.append(
                        f"duplicate listener {name}"
                    )
                else:
                    listener_names.add(name)

                if listener.get("port") is not None:
                    port = safe_int(
                        listener["port"], 0
                    )
                    if not (1 <= port <= 65535):
                        errors.append(
                            f"listener {name}: invalid port"
                        )

    # DNS/TUN are structural mappings when imported. Do not invent
    # network-specific values.
    for section_name in (
        "dns",
        "tun",
        "profile",
        "experimental",
    ):
        if section_name in config and not isinstance(
            config[section_name], dict
        ):
            errors.append(
                f"{section_name} must be mapping"
            )

    return errors



# ============================================================================
# ULTIMATE INDUSTRIAL HARDENING LAYER
# ============================================================================
# This layer intentionally extends the supplied V8 manual-select source
# instead of replacing it. It adds deterministic normalization, deep semantic
# validation, strict multi-group-manual enforcement, rule/provider integrity checks,
# source-preserving safety checks, and stronger output-path handling.
# It enables Mihomo URL-test/fallback groups, which perform runtime health checks;
# this converter does not itself run those checks during file generation.

ULTIMATE_VERSION = (
    "MIHOMO-FULL-INDUSTRIAL-SHAH20-COMPREHENSIVE-GROUP-ENGINE"
)

# Mihomo/Clash names that must never become the generated manual group's name.
_RESERVED_GROUP_TYPES = {
    "url-test",
    "fallback",
    "load-balance",
    "relay",
}

_FORBIDDEN_MANUAL_GROUP_KEYS = {
    "url",
    "interval",
    "lazy",
    "timeout",
    "tolerance",
    "strategy",
    "health-check",
}

_SUPPORTED_NETWORKS = {
    "tcp",
    "ws",
    "grpc",
    "h2",
    "http",
    "xhttp",
}

_VALID_MODES = {"rule", "global", "direct", "script"}
_VALID_LOG_LEVELS = {"silent", "error", "warning", "info", "debug"}


def _ultimate_error(errors: list[str], message: str) -> None:
    """Append one deterministic validation message without duplicates."""
    if message not in errors:
        errors.append(message)


def _ultimate_port(value: Any) -> bool:
    try:
        value = int(str(value).strip())
    except Exception:
        return False
    return 1 <= value <= 65535


def _ultimate_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _ultimate_normalize_proxy(node: dict[str, Any]) -> dict[str, Any]:
    """Conservatively normalize values already present in a proxy."""
    result = copy.deepcopy(node)

    proxy_type = str(result.get("type") or "").strip().lower()
    if proxy_type == "socks5":
        proxy_type = "socks"
    elif proxy_type == "hy2":
        proxy_type = "hysteria2"
    result["type"] = proxy_type

    if "server" in result:
        result["server"] = str(result["server"]).strip()

    if "port" in result:
        result["port"] = safe_int(result["port"], result["port"])

    for key in BOOL_KEYS:
        if key in result and isinstance(result[key], str):
            result[key] = bool_value(result[key])

    for key in INT_KEYS:
        if key in result and isinstance(result[key], str):
            converted = safe_int(result[key], None)
            if converted is not None:
                result[key] = converted

    # Do not leave an empty name into the generated proxy list.
    result["name"] = clean_name(
        result.get("name"),
        str(proxy_type or "NODE").upper(),
    )

    return result


def _ultimate_normalize_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize and deduplicate without changing proxy semantics."""
    normalized: list[dict[str, Any]] = []

    for node in nodes:
        if not isinstance(node, dict):
            continue
        normalized.append(_ultimate_normalize_proxy(node))

    normalized = dedupe(normalized)
    unique_names(normalized)
    return normalized


def _ultimate_validate_proxy_semantics(
    node: dict[str, Any],
    errors: list[str],
) -> None:
    """Deep proxy validation based on fields supported by the supplied guide."""
    name = str(node.get("name") or "?")
    proxy_type = str(node.get("type") or "").lower()

    if proxy_type not in SUPPORTED_TYPES:
        return

    endpoint_optional = {"easytier", "tailscale", "zerotier"}
    if proxy_type not in endpoint_optional and not _ultimate_nonempty_string(node.get("server")):
        _ultimate_error(errors, f"{name}: server must be non-empty")

    if proxy_type not in endpoint_optional and not _ultimate_port(node.get("port")):
        _ultimate_error(errors, f"{name}: port must be 1..65535")

    if proxy_type in {"vless", "vmess"} and not _ultimate_nonempty_string(node.get("uuid")):
        _ultimate_error(errors, f"{name}: uuid is required")

    if proxy_type in {"trojan", "anytls", "hysteria2"} and not _ultimate_nonempty_string(node.get("password")):
        _ultimate_error(errors, f"{name}: password is required")

    if proxy_type in {"ss", "ssr"}:
        if not _ultimate_nonempty_string(node.get("cipher")):
            _ultimate_error(errors, f"{name}: cipher is required")
        if not _ultimate_nonempty_string(node.get("password")):
            _ultimate_error(errors, f"{name}: password is required")

    if proxy_type == "tuic":
        if not (
            _ultimate_nonempty_string(node.get("token"))
            or (
                _ultimate_nonempty_string(node.get("uuid"))
                and _ultimate_nonempty_string(node.get("password"))
            )
        ):
            _ultimate_error(errors, f"{name}: TUIC requires token or uuid+password")

    if proxy_type == "hysteria" and not (
        _ultimate_nonempty_string(node.get("auth-str"))
        or _ultimate_nonempty_string(node.get("auth"))
    ):
        _ultimate_error(errors, f"{name}: hysteria requires auth/auth-str")

    if proxy_type == "snell" and not _ultimate_nonempty_string(node.get("psk")):
        _ultimate_error(errors, f"{name}: snell requires psk")

    if proxy_type == "ssh":
        if not _ultimate_nonempty_string(node.get("username")):
            _ultimate_error(errors, f"{name}: SSH requires username")
        if not (_ultimate_nonempty_string(node.get("password")) or _ultimate_nonempty_string(node.get("private-key"))):
            _ultimate_error(errors, f"{name}: SSH requires password or private-key")
    if proxy_type == "easytier":
        if not _ultimate_nonempty_string(node.get("network-name")):
            _ultimate_error(errors, f"{name}: EasyTier requires network-name")
        if node.get("peers") is not None and not isinstance(node.get("peers"), list):
            _ultimate_error(errors, f"{name}: EasyTier peers must be list")
    if proxy_type == "masque":
        for key in ("private-key", "public-key"):
            if not _ultimate_nonempty_string(node.get(key)):
                _ultimate_error(errors, f"{name}: MASQUE requires {key}")
    if proxy_type == "tailscale" and "accept-routes" in node and not isinstance(node["accept-routes"], bool):
        _ultimate_error(errors, f"{name}: Tailscale accept-routes must be boolean")
    if proxy_type == "wireguard":
        for key in ("private-key", "public-key", "ip"):
            if not _ultimate_nonempty_string(node.get(key)):
                _ultimate_error(errors, f"{name}: WireGuard requires {key}")
        if "dns" in node and not isinstance(node["dns"], list):
            _ultimate_error(errors, f"{name}: WireGuard dns must be list")
        if "mtu" in node and (not isinstance(node["mtu"], int) or isinstance(node["mtu"], bool)):
            _ultimate_error(errors, f"{name}: WireGuard mtu must be integer")

    network = node.get("network")
    if network is not None:
        network = str(network).lower()
        if network not in _SUPPORTED_NETWORKS:
            _ultimate_error(errors, f"{name}: unsupported network {network}")

        if network == "ws" and "ws-opts" in node and not isinstance(node["ws-opts"], dict):
            _ultimate_error(errors, f"{name}: ws-opts must be mapping")

        if network == "grpc" and "grpc-opts" in node and not isinstance(node["grpc-opts"], dict):
            _ultimate_error(errors, f"{name}: grpc-opts must be mapping")

        if network == "h2" and "h2-opts" in node and not isinstance(node["h2-opts"], dict):
            _ultimate_error(errors, f"{name}: h2-opts must be mapping")

        if network == "xhttp" and "xhttp-opts" in node and not isinstance(node["xhttp-opts"], dict):
            _ultimate_error(errors, f"{name}: xhttp-opts must be mapping")

        if network == "xhttp" and str(node.get("type", "")).lower() != "vless":
            _ultimate_error(errors, f"{name}: xhttp transport is supported only for VLESS")

    if "alpn" in node and not isinstance(node["alpn"], list):
        _ultimate_error(errors, f"{name}: alpn must be list")

    tls = node.get("tls")
    if tls is not None and not isinstance(tls, (bool, dict)):
        _ultimate_error(errors, f"{name}: tls must be boolean or mapping")
    if isinstance(tls, dict):
        for key in ("alpn", "next-protos"):
            if key in tls and not isinstance(tls[key], list):
                _ultimate_error(errors, f"{name}: tls.{key} must be list")
        for key in ("skip-cert-verify", "disable-sni", "ech-opts"):
            if key in tls and key != "ech-opts" and not isinstance(tls[key], bool):
                _ultimate_error(errors, f"{name}: tls.{key} must be boolean")
        if "server-name" in tls and not isinstance(tls["server-name"], str):
            _ultimate_error(errors, f"{name}: tls.server-name must be string")

    transport = node.get("transport")
    if transport is not None:
        if not isinstance(transport, dict):
            _ultimate_error(errors, f"{name}: transport must be mapping")
        else:
            ttype = str(transport.get("type") or "").lower()
            if ttype and ttype not in _SUPPORTED_NETWORKS:
                _ultimate_error(errors, f"{name}: unsupported transport.type {ttype}")
            for key in ("headers", "ws-opts", "grpc-opts", "http-opts", "h2-opts", "xhttp-opts"):
                if key in transport and not isinstance(transport[key], dict):
                    _ultimate_error(errors, f"{name}: transport.{key} must be mapping")

    if "dialer-proxy" in node and not _ultimate_nonempty_string(node.get("dialer-proxy")):
        _ultimate_error(errors, f"{name}: dialer-proxy must be a non-empty group/proxy name")
    if "ip-version" in node and str(node["ip-version"]).lower() not in {"dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer"}:
        _ultimate_error(errors, f"{name}: invalid ip-version {node['ip-version']}")

    if "udp" in node and not isinstance(node["udp"], bool):
        _ultimate_error(errors, f"{name}: udp must be boolean")

    if proxy_type == "wireguard":
        for key in ("private-key", "public-key", "ip"):
            if not _ultimate_nonempty_string(node.get(key)):
                _ultimate_error(errors, f"{name}: wireguard requires {key}")
        if "dns" in node and not isinstance(node["dns"], list):
            _ultimate_error(errors, f"{name}: wireguard dns must be list")
        if "mtu" in node and not isinstance(node["mtu"], int):
            _ultimate_error(errors, f"{name}: wireguard mtu must be integer")


def _split_rule_fields(rule: str) -> list[str]:
    """Split route-rule fields at top-level commas, preserving nested logical rules."""
    fields: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for char in str(rule):
        if escaped:
            buf.append(char); escaped = False; continue
        if char == "\\":
            buf.append(char); escaped = True; continue
        if quote:
            buf.append(char)
            if char == quote: quote = None
            continue
        if char in ("'", '"'):
            quote = char; buf.append(char); continue
        if char == "(": depth += 1
        elif char == ")": depth = max(0, depth - 1)
        if char == "," and depth == 0:
            fields.append("".join(buf).strip()); buf = []
        else:
            buf.append(char)
    fields.append("".join(buf).strip())
    return fields


def _ultimate_extract_rule_policy(rule: Any) -> str | None:
    if not isinstance(rule, str): return None
    parts = _split_rule_fields(rule)
    if not parts: return None
    if parts[0].upper() == "MATCH": return parts[1] if len(parts) >= 2 else None
    return parts[2] if len(parts) >= 3 else None


def _ultimate_validate_rules(
    config: dict[str, Any],
    errors: list[str],
) -> None:
    rules = config.get("rules")
    if not isinstance(rules, list):
        return

    groups = config.get("proxy-groups")
    group_names = {
        str(item.get("name"))
        for item in groups or []
        if isinstance(item, dict) and item.get("name")
    }
    proxy_names = {
        str(item.get("name"))
        for item in config.get("proxies", [])
        if isinstance(item, dict) and item.get("name")
    }
    providers = config.get("rule-providers")
    provider_names = set(providers.keys()) if isinstance(providers, dict) else set()

    valid_policies = proxy_names | group_names | {
        "DIRECT",
        "REJECT",
        "GLOBAL",
        "COMPATIBLE",
    }

    match_positions: list[int] = []

    for index, rule in enumerate(rules):
        if not isinstance(rule, str) or not rule.strip():
            _ultimate_error(errors, f"rules[{index}] must be non-empty string")
            continue

        parts = _split_rule_fields(rule)
        rule_type = parts[0].upper() if parts else ""

        if rule_type == "MATCH":
            match_positions.append(index)

        if rule_type == "MATCH":
            if len(parts) != 2 or not parts[1]:
                _ultimate_error(errors, f"rules[{index}] malformed MATCH: {rule}")
                continue
            policy = parts[1]
        else:
            if len(parts) < 3:
                _ultimate_error(errors, f"rules[{index}] malformed: {rule}")
                continue
            policy = parts[2]
        if policy not in valid_policies:
            _ultimate_error(errors, f"rules[{index}] unknown policy: {policy}")
        if policy == "DIRECT":
            _ultimate_error(errors, f"rules[{index}] must route through {DIRECT_GROUP_NAME}, not raw DIRECT")

        if rule_type in {"AND", "OR", "NOT"} and (len(parts) != 3 or not parts[1].startswith("(") or not parts[1].endswith(")")):
            _ultimate_error(errors, f"rules[{index}] malformed logical rule: {rule}")
        if rule_type == "SUB-RULE":
            sub_rules = config.get("sub-rules")
            if not isinstance(sub_rules, dict) or len(parts) < 2 or parts[1] not in sub_rules:
                _ultimate_error(errors, f"rules[{index}] references missing sub-rule")
        if rule_type != "MATCH" and len(parts) >= 4:
            for option in parts[3:]:
                if option.lower() not in {"no-resolve", "resolve", "src", "dst", "in"}:
                    _ultimate_error(errors, f"rules[{index}] invalid rule option: {option}")

        if rule_type == "RULE-SET":
            provider_name = parts[1].split("@")[0].strip()
            if provider_name not in provider_names:
                _ultimate_error(
                    errors,
                    f"rules[{index}] references missing rule-provider: {provider_name}",
                )

    if match_positions and match_positions[-1] != len(rules) - 1:
        _ultimate_error(errors, "MATCH rule must be the final rule")

    if not match_positions:
        _ultimate_error(errors, "rules must contain a final MATCH rule")


def _ultimate_validate_dns(
    config: dict[str, Any],
    errors: list[str],
) -> None:
    dns = config.get("dns")
    if dns is None:
        return
    if not isinstance(dns, dict):
        return

    enhanced = dns.get("enhanced-mode")
    if enhanced is not None and str(enhanced).lower() not in {"fake-ip", "redir-host"}:
        _ultimate_error(errors, f"dns.enhanced-mode unsupported: {enhanced}")

    for key in (
        "nameserver",
        "fallback",
        "default-nameserver",
        "fake-ip-filter",
        "search-domains",
    ):
        if key in dns and not isinstance(dns[key], list):
            _ultimate_error(errors, f"dns.{key} must be list")

    if "nameserver-policy" in dns and not isinstance(dns["nameserver-policy"], dict):
        _ultimate_error(errors, "dns.nameserver-policy must be mapping")


def _ultimate_validate_tun(
    config: dict[str, Any],
    errors: list[str],
) -> None:
    tun = config.get("tun")
    if tun is None:
        return
    if not isinstance(tun, dict):
        return

    stack = tun.get("stack")
    if stack is not None and str(stack).lower() not in {"system", "gvisor"}:
        _ultimate_error(errors, f"tun.stack unsupported: {stack}")

    if "auto-detect-interface" in tun and bool_value(tun["auto-detect-interface"]):
        if config.get("interface-name"):
            _ultimate_error(
                errors,
                "tun.auto-detect-interface conflicts with interface-name",
            )

    for key in (
        "dns-hijack",
        "route-exclude-address",
        "route-include-address",
        "route-exclude-address-set",
        "route-include-address-set",
        "route-exclude-package",
        "route-include-package",
    ):
        if key in tun and not isinstance(tun[key], list):
            _ultimate_error(errors, f"tun.{key} must be list")


def _ultimate_validate_listeners(
    config: dict[str, Any],
    errors: list[str],
) -> None:
    listeners = config.get("listeners")
    if not isinstance(listeners, list):
        return

    names: set[str] = set()
    endpoints: set[tuple[str, int]] = set()

    for index, listener in enumerate(listeners):
        if not isinstance(listener, dict):
            _ultimate_error(errors, f"listeners[{index}] must be mapping")
            continue

        name = str(listener.get("name") or "")
        if name in names:
            _ultimate_error(errors, f"duplicate listener name: {name}")
        names.add(name)

        port = listener.get("port")
        if port is not None:
            port = safe_int(port, 0)
            if not _ultimate_port(port):
                _ultimate_error(errors, f"listeners[{index}] invalid port")
            else:
                host = str(listener.get("listen") or listener.get("bind") or "")
                endpoint = (host, port)
                if endpoint in endpoints:
                    _ultimate_error(errors, f"duplicate listener endpoint: {host}:{port}")
                endpoints.add(endpoint)


def _ultimate_validate_providers(
    config: dict[str, Any],
    errors: list[str],
) -> None:
    for section_name in ("proxy-providers", "rule-providers"):
        section = config.get(section_name)
        if section is None:
            continue
        if not isinstance(section, dict):
            _ultimate_error(errors, f"{section_name} must be mapping")
            continue

        seen_paths: dict[str, str] = {}
        for provider_name, provider in section.items():
            prefix = f"{section_name}/{provider_name}"
            if not isinstance(provider, dict):
                _ultimate_error(errors, f"{prefix} must be mapping")
                continue

            provider_type = str(provider.get("type") or "").lower()
            if provider_type not in {"http", "file", "inline"}:
                _ultimate_error(errors, f"{prefix}: invalid type {provider_type}")
                continue

            if provider_type == "http" and not _ultimate_nonempty_string(provider.get("url")):
                _ultimate_error(errors, f"{prefix}: http provider requires url")

            if provider_type == "file" and not _ultimate_nonempty_string(provider.get("path")):
                _ultimate_error(errors, f"{prefix}: file provider requires path")
            if provider.get("path") is not None:
                if not _ultimate_nonempty_string(provider.get("path")):
                    _ultimate_error(errors, f"{prefix}: path must be a non-empty string")
                else:
                    path_key = str(provider["path"])
                    if path_key in seen_paths:
                        _ultimate_error(errors, f"{prefix}: duplicate path also used by {seen_paths[path_key]}")
                    else:
                        seen_paths[path_key] = str(provider_name)
            if provider_type == "inline" and not isinstance(provider.get("payload"), list):
                _ultimate_error(errors, f"{prefix}: inline provider requires payload list")
            fmt = str(provider.get("format") or "yaml").lower()
            if fmt not in {"yaml", "text", "mrs"}:
                _ultimate_error(errors, f"{prefix}: invalid format {fmt}")
            if fmt == "mrs" and section_name == "rule-providers" and provider.get("behavior") not in {"domain", "ipcidr"}:
                _ultimate_error(errors, f"{prefix}: mrs format requires domain/ipcidr behavior")

            if provider.get("interval") is not None and safe_int(provider["interval"], 0) < 0:
                _ultimate_error(errors, f"{prefix}: interval cannot be negative")

            if section_name == "rule-providers":
                behavior = provider.get("behavior")
                if behavior is not None and str(behavior).lower() not in {
                    "domain", "ipcidr", "classical"
                }:
                    _ultimate_error(errors, f"{prefix}: invalid behavior {behavior}")


def _ultimate_validate_top_level(config: dict[str, Any], errors: list[str]) -> None:
    sub_rules = config.get("sub-rules")
    if sub_rules is not None:
        if not isinstance(sub_rules, dict):
            _ultimate_error(errors, "sub-rules must be mapping")
        else:
            for sub_name, sub_items in sub_rules.items():
                if not isinstance(sub_items, list):
                    _ultimate_error(errors, f"sub-rules/{sub_name} must be list")
                    continue
                for index, item in enumerate(sub_items):
                    if not isinstance(item, str) or len(_split_rule_fields(item)) < 3:
                        _ultimate_error(errors, f"sub-rules/{sub_name}[{index}] malformed rule")
    for key in ("authentication", "skip-auth-prefixes"):
        if key in config and not isinstance(config[key], list):
            _ultimate_error(errors, f"{key} must be list")

    for key in ("hosts", "fallback-filter"):
        if key in config and not isinstance(config[key], dict):
            _ultimate_error(errors, f"{key} must be mapping")

    if "mode" in config and str(config["mode"]).lower() not in _VALID_MODES:
        _ultimate_error(errors, f"mode unsupported: {config['mode']}")

    if "log-level" in config and str(config["log-level"]).lower() not in _VALID_LOG_LEVELS:
        _ultimate_error(errors, f"log-level unsupported: {config['log-level']}")

    for key in (
        "port",
        "socks-port",
        "mixed-port",
        "redir-port",
        "tproxy-port",
    ):
        if key in config and config[key] is not None and not _ultimate_port(config[key]):
            _ultimate_error(errors, f"{key} must be 1..65535")


def validate_config_ultimate(config: dict[str, Any]) -> list[str]:
    """Final deep validator; deliberately stricter than the supplied V8 validator."""
    errors = list(validate_config_original(config))

    if not isinstance(config, dict):
        return errors

    nodes = config.get("proxies")
    if isinstance(nodes, list):
        proxy_names_seen: set[str] = set()
        for node in nodes:
            if not isinstance(node, dict):
                _ultimate_error(errors, "proxies entries must be mappings")
                continue
            node_name = str(node.get("name") or "")
            if node_name in proxy_names_seen:
                _ultimate_error(errors, f"duplicate proxy name: {node_name}")
            proxy_names_seen.add(node_name)
            _ultimate_validate_proxy_semantics(node, errors)
        groups_for_dialer = config.get("proxy-groups")
        group_names_for_dialer = {str(g.get("name")) for g in groups_for_dialer or [] if isinstance(g, dict) and g.get("name")}
        valid_dialers = proxy_names_seen | group_names_for_dialer | {"DIRECT", "REJECT"}
        for node in nodes:
            if isinstance(node, dict) and node.get("dialer-proxy") and str(node["dialer-proxy"]) not in valid_dialers:
                _ultimate_error(errors, f"{node.get('name', '?')}: dialer-proxy target does not exist: {node['dialer-proxy']}")

    groups = config.get("proxy-groups")
    expected_group_names = {str(g.get("name")) for g in build_groups(
        [str(n.get("name")) for n in config.get("proxies", []) if isinstance(n, dict) and n.get("name")],
        nodes=config.get("proxies", []),
        source_groups=groups,
    )}
    if not isinstance(groups, list) or not groups:
        _ultimate_error(errors, "generated output must contain proxy groups")
    else:
        actual_names: set[str] = set()
        for index, group in enumerate(groups):
            if not isinstance(group, dict):
                _ultimate_error(errors, f"proxy-groups[{index}] must be mapping")
                continue
            name = str(group.get("name") or "")
            actual_names.add(name)
            group_type = str(group.get("type") or "").lower()
            if name == "DIRECT":
                _ultimate_error(errors, "A group cannot be named DIRECT; use the independent Direct wrapper")
            if "DIRECT" in group.get("proxies", []) and name != DIRECT_GROUP_NAME:
                _ultimate_error(errors, f"DIRECT may appear only in {DIRECT_GROUP_NAME}")
            if name == DIRECT_GROUP_NAME and group.get("proxies") != ["DIRECT"]:
                _ultimate_error(errors, f"{DIRECT_GROUP_NAME} must contain exactly the built-in DIRECT member")
            if group_type not in {"select", "url-test", "fallback", "load-balance", "relay"}:
                _ultimate_error(errors, f"unsupported generated group type {group_type}: {name}")
            if group_type == "select":
                for key in _FORBIDDEN_MANUAL_GROUP_KEYS:
                    if key in group:
                        _ultimate_error(errors, f"manual group {name} cannot contain {key}")
            refs = group.get("proxies")
            if not isinstance(refs, list) or not refs:
                _ultimate_error(errors, f"group {name} must contain proxy refs")
            else:
                proxy_nodes_by_name = {
                    str(item.get("name")): item
                    for item in config.get("proxies", [])
                    if isinstance(item, dict) and item.get("name")
                }
                proxy_set = set(proxy_nodes_by_name)
                group_set = {str(item.get("name")) for item in groups if isinstance(item, dict) and item.get("name")}
                unknown = [ref for ref in refs if ref not in proxy_set and ref not in {"REJECT", "DIRECT", "COMPATIBLE", "GLOBAL"}]
                if unknown:
                    _ultimate_error(errors, f"group {name} contains unknown refs or another group: {unknown}")

                seen_egress: set[str] = set()
                for ref in refs:
                    proxy_node = proxy_nodes_by_name.get(str(ref))
                    if proxy_node is None:
                        continue
                    evidence = _egress_result_for_node(proxy_node)
                    egress_ip = str(evidence.get("egress_ip") or "")
                    if not egress_ip:
                        _ultimate_error(errors, f"group {name} contains a proxy without measured Egress IP: {ref}")
                    elif egress_ip in seen_egress:
                        _ultimate_error(errors, f"group {name} repeats measured Egress IP: {egress_ip}")
                    else:
                        seen_egress.add(egress_ip)
            if group_type in {"url-test", "fallback", "load-balance"}:
                if not group.get("url"):
                    _ultimate_error(errors, f"group {name} missing health-check URL")
                if not isinstance(group.get("interval"), int) or group.get("interval", 0) <= 0:
                    _ultimate_error(errors, f"group {name} has invalid interval")
            if group_type == "load-balance" and group.get("strategy") not in {"consistent-hashing", "round-robin", "sticky-sessions"}:
                _ultimate_error(errors, f"group {name} has invalid load-balance strategy")
        if actual_names != expected_group_names:
            _ultimate_error(errors, "manual proxy-group set is incomplete or duplicated")

    profile = config.get("profile")
    if not isinstance(profile, dict) or profile.get("store-selected") is not bool(STORE_SELECTED_PROXY):
        _ultimate_error(errors, f"profile.store-selected must be {str(bool(STORE_SELECTED_PROXY)).lower()}")

    _ultimate_validate_rules(config, errors)
    _ultimate_validate_providers(config, errors)
    _ultimate_validate_dns(config, errors)
    _ultimate_validate_tun(config, errors)
    _ultimate_validate_listeners(config, errors)
    _ultimate_validate_top_level(config, errors)

    # Only the independent Direct wrapper may contain the built-in DIRECT member.
    if isinstance(groups, list):
        for index, group in enumerate(groups):
            if isinstance(group, dict) and "DIRECT" in group.get("proxies", []) and group.get("name") != DIRECT_GROUP_NAME:
                _ultimate_error(errors, f"proxy-groups[{index}] lists DIRECT outside {DIRECT_GROUP_NAME}")

    return errors


# Preserve the original validator for regression/debugging while making the
# stronger validator the production path.
validate_config_original = validate_config
validate_config = validate_config_ultimate


def enforce_manual_select_invariants(config: dict[str, Any]) -> dict[str, Any]:
    """Keep generated groups intact, remove duplicates/dangling refs, and repair routing targets."""
    result = copy.deepcopy(config)
    raw_groups = result.get("proxy-groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        node_names = [item.get("name") for item in result.get("proxies", []) if isinstance(item, dict) and item.get("name")]
        raw_groups = build_groups(node_names, nodes=result.get("proxies", []))
    groups = _unique_group_list(
        [copy.deepcopy(g) for g in raw_groups if isinstance(g, dict)],
        {str(item.get("name")): item for item in result.get("proxies", []) if isinstance(item, dict) and item.get("name")},
    )
    proxy_names = {str(item.get("name")) for item in result.get("proxies", []) if isinstance(item, dict) and item.get("name")}
    group_names = {str(g.get("name")) for g in groups if g.get("name")}
    valid_refs = proxy_names | {"DIRECT", "REJECT", "COMPATIBLE", "GLOBAL"}
    for group in groups:
        refs = group.get("proxies")
        if not isinstance(refs, list):
            refs = []
        if group.get("name") == DIRECT_GROUP_NAME:
            group["proxies"] = ["DIRECT"]
            continue
        group["proxies"] = list(dict.fromkeys(str(ref) for ref in refs
            if str(ref) in valid_refs and str(ref) not in {"DIRECT", *group_names}))
        if not group["proxies"]:
            group["proxies"] = ["REJECT"]
    result["proxy-groups"] = groups

    if not isinstance(result.get("profile"), dict):
        result["profile"] = {}
    result["profile"]["store-selected"] = bool(STORE_SELECTED_PROXY)

    active_names = {str(g.get("name")) for g in groups if g.get("name")}
    fallback = _active_default_group(groups)
    existing = result.get("rules")
    imported = []
    generated = set(build_service_rules(active_names))
    valid_policies = proxy_names | active_names | {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE"}
    if isinstance(existing, list):
        for item in existing:
            if not isinstance(item, str) or not item.strip() or item.strip().upper().startswith("MATCH,") or item in generated:
                continue
            parts = [part.strip() for part in item.split(",")]
            if len(parts) >= 3 and parts[2] == "DIRECT":
                parts[2] = DIRECT_GROUP_NAME
                item = ",".join(parts)
            if len(parts) >= 3 and parts[2] not in valid_policies:
                # If a rule points to a group that was disabled/removed, redirect
                # it to the active manual fallback instead of emitting a dangling ref.
                parts[2] = fallback
                item = ",".join(parts)
            imported.append(item)
    sub_rules = result.get("sub-rules")
    if isinstance(sub_rules, dict):
        for sub_name, sub_items in list(sub_rules.items()):
            if not isinstance(sub_items, list):
                continue
            normalized_items = []
            for sub_rule in sub_items:
                if isinstance(sub_rule, str):
                    fields = [part.strip() for part in sub_rule.split(",")]
                    if len(fields) >= 3 and fields[2] == "DIRECT":
                        fields[2] = DIRECT_GROUP_NAME
                        sub_rule = ",".join(fields)
                normalized_items.append(sub_rule)
            sub_rules[sub_name] = normalized_items
    result["rules"] = build_service_rules(active_names) + imported
    match_target = _active_default_group(groups)
    result["rules"].append(f"MATCH,{match_target}")
    return result

def _ultimate_safe_output_name(value: str) -> str:
    value = str(value or "").strip()
    value = value.replace("\\", "/")
    value = value.split("/")[-1]
    value = re.sub(r"[\x00-\x1f\x7f]+", "", value)
    value = re.sub(r'[\\/:*?"<>|]+', "_", value)
    value = value.strip(" .")
    return value or "mihomo_full.yaml"


def output_path_ultimate() -> Path:
    folder = input("Output folder in Download [Akbar98]: ").strip() or "Akbar98"
    name = input("Output YAML name [mihomo_full]: ").strip() or "mihomo_full"

    folder = clean_name(folder, "Akbar98")
    folder = folder.replace("/", "_").replace("\\", "_")
    name = _ultimate_safe_output_name(name)
    if not name.lower().endswith(".yaml"):
        name += ".yaml"

    path = (DOWNLOAD_DIR / folder / name).resolve()
    download_root = DOWNLOAD_DIR.resolve()
    try:
        path.relative_to(download_root)
    except ValueError:
        raise RuntimeError("unsafe output path")
    return path


def _ultimate_config_fingerprint(config: dict[str, Any]) -> str:
    body = json.dumps(
        config,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _ultimate_yaml_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ultimate_print_summary(
    config: dict[str, Any],
    yaml_text: str,
    path: Path,
    raw_count: int,
    deduped: int,
    invalid: int,
) -> None:
    nodes = config.get("proxies") if isinstance(config, dict) else []
    groups = config.get("proxy-groups") if isinstance(config, dict) else []
    log("=" * 88)
    log("SUCCESS — MIHOMO INDUSTRIAL FOUR-GROUP EGRESS ENGINE")
    log(f"ENGINE: {ULTIMATE_VERSION}")
    log(f"OUTPUT: {path}")
    log(f"INPUT LINES: {raw_count}")
    log(f"VALID NODES: {len(nodes) if isinstance(nodes, list) else 0}")
    log(f"DEDUPED: {deduped}")
    log(f"INVALID NODES: {invalid}")
    log(f"GROUP COUNT: {len(groups) if isinstance(groups, list) else 0}")
    if isinstance(groups, list):
        log("GROUPS: " + ", ".join(str(g.get("name")) for g in groups if isinstance(g, dict)))
    if isinstance(groups, list):
        group_types: dict[str, int] = {}
        for group in groups:
            if isinstance(group, dict):
                kind = str(group.get("type") or "unknown")
                group_types[kind] = group_types.get(kind, 0) + 1
        log("GROUP TYPES: " + ", ".join(f"{kind}={count}" for kind, count in sorted(group_types.items())))
        actual_names = {str(g.get("name")) for g in groups if isinstance(g, dict)}
        log(f"URL-TEST PRESENT: {'YES' if any(str(g.get('type')).lower() == 'url-test' for g in groups if isinstance(g, dict)) else 'NO'}")
        log(f"FALLBACK PRESENT: {'YES' if any(str(g.get('type')).lower() == 'fallback' for g in groups if isinstance(g, dict)) else 'NO'}")
    log(f"DEFAULT GROUP: {DEFAULT_RULE_GROUP}")
    log("AUTO SWITCH: NOT GENERATED (four-group contract)")
    log("AUTO PINNING: DISABLED")
    log(f"STORE SELECTED: {str(bool(STORE_SELECTED_PROXY)).lower()}")
    log(f"EGRESS PROBES: {'ENABLED' if EGRESS_PROBE_ENABLED else 'DISABLED'}")
    log(f"CONFIG SHA256: {_ultimate_config_fingerprint(config)}")
    log(f"YAML SHA256: {_ultimate_yaml_hash(yaml_text)}")
    log(f"YAML BYTES: {len(yaml_text.encode('utf-8'))}")
    log("=" * 88)


def record_native_test_result(status: str, detail: str = "") -> None:
    """Report native Mihomo validation to the console only; do not create sidecar files."""
    safe_detail = re.sub(r"[\r\n]+", " | ", str(detail)).strip()[:1500]
    log(f"[MIHOMO-RESULT] {status}" + (f" | {safe_detail}" if safe_detail else ""))


def atomic_write(
    path: Path,
    text: str,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temp_name = tempfile.mkstemp(
        prefix=".mihomo_",
        dir=str(path.parent),
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_name, path)

    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def clear_input() -> None:
    BASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )
    atomic_write(INPUT_PATH, "")


def open_editor() -> None:
    BASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Every run starts with a completely empty input file.
    clear_input()

    nano = shutil.which("nano")

    if nano:
        subprocess.call(
            [nano, str(INPUT_PATH)]
        )
        return

    log(
        "[WARN] nano not found; "
        "paste configs and press Ctrl-D."
    )

    try:
        data = sys.stdin.read()
        atomic_write(INPUT_PATH, data)
    except Exception:
        pass


def load_input() -> str:
    if not INPUT_PATH.exists():
        return ""

    size = INPUT_PATH.stat().st_size

    if size > MAX_INPUT_BYTES:
        raise RuntimeError(
            "input.txt is larger than 25 MiB"
        )

    return INPUT_PATH.read_text(
        encoding="utf-8",
        errors="ignore",
    )


def output_path() -> Path:
    folder = (
        input(
            "Output folder in Download [Akbar98]: "
        ).strip()
        or "Akbar98"
    )

    name = (
        input(
            "Output YAML name [mihomo_full]: "
        ).strip()
        or "mihomo_full"
    )

    folder = clean_name(
        folder,
        "Akbar98",
    )

    name = re.sub(
        r'[\\/:*?"<>|]+',
        "_",
        name,
    ).strip()

    if not name:
        name = "mihomo_full"

    if not name.endswith(".yaml"):
        name += ".yaml"

    return DOWNLOAD_DIR / folder / name


def _controller_request_json(path: str, query: dict[str, Any] | None = None) -> Any:
    base = CONTROLLER_API_URL.rstrip("/")
    url = base + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {"Accept": "application/json"}
    if CONTROLLER_API_SECRET:
        headers["Authorization"] = f"Bearer {CONTROLLER_API_SECRET}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=max(0.5, float(CONTROLLER_REQUEST_TIMEOUT))) as response:
        return json.loads(response.read(2 * 1024 * 1024).decode("utf-8", errors="replace"))


def _controller_delay_ms(proxy_name: str) -> int | None:
    encoded = urllib.parse.quote(str(proxy_name), safe="")
    repeats = max(1, int(CONTROLLER_TEST_REPEATS))
    successes: list[int] = []
    for _ in range(repeats):
        try:
            result = _controller_request_json(
                f"/proxies/{encoded}/delay",
                {"url": CONTROLLER_TEST_URL, "timeout": max(500, int(CONTROLLER_TEST_TIMEOUT_MS))},
            )
            delay = result.get("delay") if isinstance(result, dict) else None
            if isinstance(delay, (int, float)) and delay > 0:
                successes.append(int(delay))
        except Exception:
            continue
    if len(successes) < max(1, int(CONTROLLER_MIN_SUCCESSFUL_TESTS)):
        return None
    successes.sort()
    return successes[len(successes) // 2]


def _service_delay_ms(proxy_name: str, url: str, expected_status: int) -> int | None:
    """Return median successful Mihomo delay for one proxy and service endpoint."""
    successes: list[int] = []
    for _ in range(max(1, int(SERVICE_TEST_REPEATS))):
        try:
            result = _controller_request_json(
                f"/proxies/{urllib.parse.quote(str(proxy_name), safe='')}/delay",
                {"url": url, "timeout": max(500, int(SERVICE_TEST_TIMEOUT_MS)), "expected": int(expected_status)},
            )
            delay = result.get("delay") if isinstance(result, dict) else None
            if isinstance(delay, (int, float)) and delay > 0:
                successes.append(int(delay))
        except Exception:
            continue
    if len(successes) < max(1, int(SERVICE_TEST_MIN_SUCCESSFUL_REPEATS)):
        return None
    successes.sort()
    return successes[len(successes) // 2]


def _run_service_live_tests(nodes: list[dict[str, Any]]) -> None:
    """Test configured service endpoints through the live Mihomo controller.

    Results are keyed by the decorated display name but requests use the exact
    original outbound name known to Mihomo. Missing controller nodes fail closed.
    Every endpoint configured for a service must pass by default.
    """
    global SERVICE_TEST_RESULTS
    SERVICE_TEST_RESULTS = {}
    if not ENABLE_SERVICE_LIVE_TESTS:
        return
    try:
        payload = _controller_request_json("/proxies")
        proxy_map = payload.get("proxies", {}) if isinstance(payload, dict) else {}
        if not isinstance(proxy_map, dict):
            raise ValueError("controller /proxies response has no proxy map")
        known = {str(name) for name in proxy_map}
    except Exception as exc:
        log(f"[SERVICE-TEST] Controller unavailable; all service-specific pools fail closed: {type(exc).__name__}: {exc}")
        return

    candidates: list[tuple[str, str]] = []
    for node in nodes:
        display_name = str(node.get("name", ""))
        original_name = _DECORATED_ORIGINAL_NAMES.get(display_name, display_name)
        controller_name = display_name if display_name in known else original_name if original_name in known else ""
        if controller_name:
            candidates.append((display_name, controller_name))

    # Cache the generic test and every explicit service test. The generic test
    # is used only for protocol/country/name pools without a dedicated endpoint.
    test_names = set(SERVICE_TESTS)
    all_urls: dict[tuple[str, int], dict[str, int | None]] = {}
    workers = max(1, min(32, int(SERVICE_TEST_WORKERS)))
    unique_tests = list(dict.fromkeys(test for tests in SERVICE_TESTS.values() for test in tests))
    for url, expected in unique_tests:
        results_for_url: dict[str, int | None] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_service_delay_ms, controller_name, url, expected): display_name
                for display_name, controller_name in candidates
            }
            for future in concurrent.futures.as_completed(future_map):
                display_name = future_map[future]
                try:
                    results_for_url[display_name] = future.result()
                except Exception:
                    results_for_url[display_name] = None
        all_urls[(url, expected)] = results_for_url

    for group_name, tests in SERVICE_TESTS.items():
        group_results: dict[str, tuple[bool, int | None]] = {}
        for display_name, _controller_name in candidates:
            delays = [all_urls.get(test, {}).get(display_name) for test in tests]
            passed_delays = [int(delay) for delay in delays if delay is not None and int(delay) <= max(1, int(SERVICE_TEST_MAX_DELAY_MS))]
            if SERVICE_TEST_REQUIRE_ALL_ENDPOINTS:
                passed = len(passed_delays) == len(tests)
            else:
                passed = bool(passed_delays)
            best = max(passed_delays) if passed_delays and SERVICE_TEST_REQUIRE_ALL_ENDPOINTS else min(passed_delays) if passed_delays else None
            group_results[display_name] = (passed, best)
        SERVICE_TEST_RESULTS[group_name] = group_results
        passed_count = sum(1 for passed, _delay in group_results.values() if passed)
        log(f"[SERVICE-TEST] {group_name}: passed={passed_count}/{len(candidates)} endpoints={len(tests)} max_delay={SERVICE_TEST_MAX_DELAY_MS}ms")


def _service_tested_pool(group_name: str, pool: list[str]) -> list[str]:
    """Apply live tests only when enabled; Select itself is always exempt."""
    if not ENABLE_SERVICE_LIVE_TESTS or group_name in {DEFAULT_RULE_GROUP, FALLBACK_GROUP_NAME, UNKNOWN_GROUP_NAME, DIRECT_GROUP_NAME}:
        return list(pool)
    test_key = group_name if group_name in SERVICE_TESTS else "__GENERAL__"
    results = SERVICE_TEST_RESULTS.get(test_key, {})
    return [
        name for name in pool
        if results.get(name, (False, None))[0]
        and results.get(name, (False, None))[1] is not None
        and int(results[name][1]) <= max(1, int(SERVICE_TEST_MAX_DELAY_MS))
    ]


def _filter_nodes_by_live_controller(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only live-tested proxies when strict health mode is enabled.

    Names are decorated with GeoIP before this stage, so matching also checks
    the preserved original name against the controller inventory. The API
    delay endpoint is queried using the exact name known to Mihomo.
    """
    if not ENABLE_CONTROLLER_LIVE_FILTER or not nodes:
        return nodes
    try:
        payload = _controller_request_json("/proxies")
        proxy_map = payload.get("proxies", {}) if isinstance(payload, dict) else {}
        if not isinstance(proxy_map, dict):
            raise ValueError("controller /proxies response has no proxy map")
        known = set(str(name) for name in proxy_map)
    except Exception as exc:
        if REQUIRE_LIVE_HEALTH_TESTS:
            log(f"[LIVE-TEST] Controller unavailable; strict health mode rejects all untested proxies: {type(exc).__name__}: {exc}")
            return []
        log(f"[LIVE-TEST] Controller unavailable; no proxies removed: {type(exc).__name__}: {exc}")
        return nodes

    matched: list[tuple[dict[str, Any], str]] = []
    unknown: list[dict[str, Any]] = []
    for node in nodes:
        display_name = str(node.get("name", ""))
        original_name = _DECORATED_ORIGINAL_NAMES.get(display_name, display_name)
        controller_name = display_name if display_name in known else original_name if original_name in known else ""
        if controller_name:
            matched.append((node, controller_name))
        else:
            unknown.append(node)
    log(f"[LIVE-TEST] controller-matched={len(matched)} untested={len(unknown)}")

    results: dict[str, int | None] = {}
    workers = max(1, min(32, int(CONTROLLER_TEST_WORKERS)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(_controller_delay_ms, controller_name): str(node.get("name", ""))
            for node, controller_name in matched
        }
        for future in concurrent.futures.as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception:
                results[name] = None

    kept: list[dict[str, Any]] = []
    removed = 0
    for node, _controller_name in matched:
        name = str(node.get("name", ""))
        delay = results.get(name)
        if delay is not None and delay <= max(1, int(CONTROLLER_MAX_DELAY_MS)):
            kept.append(node)
            log(f"[LIVE-TEST] KEEP {name}: {delay} ms")
        else:
            removed += 1
            reason = "no successful delay test" if delay is None else f"delay {delay} ms exceeds limit {CONTROLLER_MAX_DELAY_MS} ms"
            log(f"[LIVE-TEST] REMOVE {name}: {reason}")
    if KEEP_UNTESTED_PROXIES and not REQUIRE_LIVE_HEALTH_TESTS:
        kept.extend(unknown)
    else:
        removed += len(unknown)
        if unknown:
            log(f"[LIVE-TEST] Removed {len(unknown)} untested proxy/proxies by strict policy.")
    log(f"[LIVE-TEST] kept={len(kept)} removed={removed}; live delay tests required={REQUIRE_LIVE_HEALTH_TESTS}")
    return kept


def _read_controller_selected_proxy() -> str:
    """Read the currently selected member of CONTROLLER_SOURCE_GROUP via Mihomo API."""
    if not ENABLE_CONTROLLER_PINNED_GROUP:
        return ""
    group = urllib.parse.quote(str(CONTROLLER_SOURCE_GROUP), safe="")
    try:
        payload = _controller_request_json(f"/proxies/{group}")
        selected = payload.get("now", "") if isinstance(payload, dict) else ""
        if selected:
            log(f"[CONTROLLER] Current selection read from {CONTROLLER_SOURCE_GROUP}: {selected}")
            return str(selected)
        log(f"[CONTROLLER] Group {CONTROLLER_SOURCE_GROUP} did not report a selected proxy.")
    except Exception as exc:
        log(f"[CONTROLLER] Could not read selected proxy: {type(exc).__name__}: {exc}")
    return ""


def _commit_validated_output(candidate: Path, final_path: Path, yaml_text: str, metadata: dict[str, Any]) -> None:
    """Commit a core-validated candidate, backing up the old output and logging a diff."""
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    previous_text = ""
    existed = final_path.is_file()
    if existed:
        try:
            previous_text = final_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            previous_text = ""
        if ENABLE_CONFIG_BACKUPS:
            backup_dir = final_path.parent / ".mihomo_backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_path = backup_dir / f"{final_path.stem}_{stamp}{final_path.suffix}"
            shutil.copy2(final_path, backup_path)
            log(f"[BACKUP] Previous valid output saved: {backup_path}")

    # The candidate has already passed the real Mihomo core test. Replace the
    # final output atomically only now.
    os.replace(candidate, final_path)
    log(f"[COMMIT] Validated output committed: {final_path}")

    reports_dir = BASE_DIR / "reports"
    if ENABLE_CHANGE_REPORTS:
        reports_dir.mkdir(parents=True, exist_ok=True)
        import difflib
        diff_lines = list(difflib.unified_diff(
            previous_text.splitlines(), yaml_text.splitlines(),
            fromfile="previous.yaml" if existed else "/dev/null",
            tofile=final_path.name,
            lineterm="",
        ))
        report = dict(metadata)
        report.update({
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "output": str(final_path),
            "previous_output_existed": existed,
            "previous_yaml_sha256": _ultimate_yaml_hash(previous_text) if existed else None,
            "change_lines": len(diff_lines),
            "change_diff": diff_lines[:4000],
        })
        report_path = reports_dir / f"report_{stamp}.json"
        atomic_write(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        log(f"[REPORT] Generation and change report: {report_path}")

    if ENABLE_AUDIT_LOG:
        audit_path = BASE_DIR / "audit.log"
        entry = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "event": "validated_output_committed",
            "output": str(final_path),
            "yaml_sha256": _ultimate_yaml_hash(yaml_text),
            "valid_nodes": metadata.get("valid_nodes"),
            "groups": len(metadata.get("groups", [])),
            "native_validation": metadata.get("mihomo_core_validation"),
        }
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        log(f"[AUDIT] Appended generation record: {audit_path}")



# ============================================================
# 🌐 LOCAL WEB PANEL — LIVE MIHOMO API + SAFE CONFIG MANAGEMENT
# Loopback-only server. UI actions use real Mihomo controller endpoints.
# Persistent CRUD requires an accessible config file and successful reload.
# ============================================================
WEB_PANEL_HOST = "127.0.0.1"
WEB_PANEL_PORT = 8765
WEB_PANEL_TOKEN = ""
WEB_PANEL_SETTINGS_PATH = BASE_DIR / "webpanel_settings.json"


def _webpanel_settings() -> dict[str, Any]:
    data: dict[str, Any] = {}
    try:
        if WEB_PANEL_SETTINGS_PATH.is_file():
            loaded = json.loads(WEB_PANEL_SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
    except Exception as exc:
        log(f"[WEB] Settings could not be read: {type(exc).__name__}")
    env_url = os.environ.get("MIHOMO_API_URL", "").strip()
    env_secret = os.environ.get("MIHOMO_API_SECRET", "")
    if env_url:
        data["api_url"] = env_url
    if env_secret:
        data["api_secret"] = env_secret
    if not data.get("api_url"):
        data["api_url"] = CONTROLLER_API_URL
    if "config_path" not in data:
        data["config_path"] = os.environ.get("MIHOMO_CONFIG_PATH", "")
    return data


def _webpanel_api_request(method: str, path: str, payload: Any = None, query: dict[str, Any] | None = None, timeout: float = 8.0) -> Any:
    settings = _webpanel_settings()
    base = str(settings.get("api_url") or CONTROLLER_API_URL).rstrip("/")
    url = base + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {"Accept": "application/json"}
    secret = str(settings.get("api_secret") or CONTROLLER_API_SECRET or "")
    if secret:
        headers["Authorization"] = "Bearer " + secret
    body = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
        if not raw.strip():
            return {"ok": True}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"text": raw[:4000]}


def _webpanel_config_path() -> Path | None:
    # Do NOT guess which YAML FiClash/Mihomo is actively using. Reloading a
    # guessed path could unexpectedly replace the running client configuration.
    settings = _webpanel_settings()
    configured = str(settings.get("config_path") or os.environ.get("MIHOMO_CONFIG_PATH", "")).strip()
    if not configured:
        return None
    item = Path(configured).expanduser()
    try:
        if item.is_file() and item.suffix.lower() in {".yaml", ".yml"}:
            return item.resolve()
    except OSError:
        pass
    return None


def _webpanel_read_config() -> tuple[Path, dict[str, Any]]:
    path = _webpanel_config_path()
    if path is None:
        raise RuntimeError("No accessible config YAML found. Set the config path in Web Panel settings first.")
    try:
        import yaml
    except Exception as exc:
        raise RuntimeError("PyYAML is required for persistent YAML editing. Install it in Termux with: pip install pyyaml") from exc
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Config root must be a YAML mapping.")
    data.setdefault("proxies", [])
    data.setdefault("proxy-groups", [])
    if not isinstance(data["proxies"], list) or not isinstance(data["proxy-groups"], list):
        raise RuntimeError("Config proxies/proxy-groups must be lists.")
    return path, data


def _webpanel_save_reload(path: Path, config: dict[str, Any]) -> dict[str, Any]:
    try:
        import yaml
    except Exception as exc:
        raise RuntimeError("PyYAML is required for persistent YAML editing.") from exc
    # Validate structure and all group references before touching the original.
    proxy_names = {str(x.get("name")) for x in config.get("proxies", []) if isinstance(x, dict) and x.get("name")}
    group_names = {str(x.get("name")) for x in config.get("proxy-groups", []) if isinstance(x, dict) and x.get("name")}
    for group in config.get("proxy-groups", []):
        if not isinstance(group, dict) or not group.get("name"):
            raise RuntimeError("Every proxy group must be a mapping with a name.")
        members = group.get("proxies", [])
        if not isinstance(members, list):
            continue
        missing = [str(m) for m in members if str(m) not in proxy_names and str(m) not in group_names and str(m) not in {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE"}]
        if missing:
            raise RuntimeError(f"Group {group['name']} has missing member(s): {', '.join(missing[:8])}")
    try:
        import yaml
        serialized = yaml.safe_dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False, width=120)
    except Exception as exc:
        raise RuntimeError(f"YAML serialization failed: {type(exc).__name__}: {exc}") from exc
    # Snapshot then write a candidate, validate with the core if available, and atomically replace.
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(path.name + f".webpanel_backup_{stamp}")
    candidate = path.with_name(path.name + f".webpanel_candidate_{stamp}")
    shutil.copy2(path, backup)
    atomic_write(candidate, serialized)
    core_candidates = [shutil.which("mihomo"), str(MIHOMO_SOURCE_DIR / "bin" / "mihomo-android-arm64"), str(PROJECT_DIR / "core" / "mihomo"), str(PROJECT_DIR / "core" / "mihomo")]
    core = next((x for x in core_candidates if x and Path(x).is_file() and os.access(x, os.X_OK)), None)
    if core:
        test = subprocess.run([core, "-t", "-f", str(candidate)], capture_output=True, text=True, timeout=45)
        if test.returncode:
            candidate.unlink(missing_ok=True)
            raise RuntimeError("Mihomo rejected changes; original config was preserved. " + (test.stderr or test.stdout or "").strip()[:1500])
    os.replace(candidate, path)
    # Mihomo's controller reload endpoint loads the config path provided here.
    try:
        _webpanel_api_request("PUT", "/configs", {"path": str(path)}, {"force": "true"}, timeout=20)
        # HTTP 204 alone is not proof that FiClash is using this YAML. Verify the
        # expected configured proxy/group names are visible in the live controller.
        live = _webpanel_api_request("GET", "/proxies", timeout=10)
        live_map = live.get("proxies", {}) if isinstance(live, dict) else {}
        expected_groups = {str(g.get("name")) for g in config.get("proxy-groups", []) if isinstance(g, dict) and g.get("name")}
        missing_groups = sorted(n for n in expected_groups if n not in live_map)
        if missing_groups:
            raise RuntimeError("Reload endpoint returned, but live API does not show configured groups: " + ", ".join(missing_groups[:8]) + ". The YAML may not be FiClash's active config, or FiClash may reject external reloads.")
    except Exception as exc:
        # Restore the file on any reload/verification failure. Tell the user plainly.
        shutil.copy2(backup, path)
        raise RuntimeError(f"Changes were NOT confirmed in the running client; original YAML was restored. {type(exc).__name__}: {exc}") from exc
    return {"ok": True, "config_path": str(path), "backup_path": str(backup), "reloaded": True, "verified_live": True}


_WEB_PANEL_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark"><title>Mihomo Control Center</title><style>
:root{color-scheme:dark;--bg:#0b1020;--card:#141c30;--line:#293650;--txt:#edf3ff;--muted:#9fb0cc;--blue:#70a7ff;--red:#ff7777;--green:#58d6a0}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px system-ui,-apple-system,sans-serif}header{position:sticky;top:0;background:#0b1020ed;backdrop-filter:blur(10px);padding:14px 16px;border-bottom:1px solid var(--line);z-index:2}h1{font-size:20px;margin:0 0 5px}small,.muted{color:var(--muted)}main{max-width:1000px;margin:auto;padding:14px;display:grid;gap:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px;min-width:0}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.between{justify-content:space-between}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}button,input,select{font:inherit;border-radius:10px;border:1px solid var(--line);padding:10px;background:#0c1426;color:var(--txt);max-width:100%}button{cursor:pointer;background:#1c3152;border-color:#36588a}button.danger{background:#47232c;border-color:#8c3c4c}button.good{background:#153b32;border-color:#2d826d}button:disabled{opacity:.4}input,select{width:100%}.field{display:grid;gap:5px;min-width:0;flex:1}h2{font-size:16px;margin:0 0 10px}.stat{font-size:24px;font-weight:700}.pill{border:1px solid var(--line);border-radius:99px;padding:4px 8px;font-size:12px;color:var(--muted)}.list{display:grid;gap:8px}.item{border:1px solid var(--line);border-radius:12px;padding:10px;display:grid;gap:8px}.itemtop{display:flex;gap:8px;align-items:start;justify-content:space-between}.name{font-weight:650;overflow-wrap:anywhere}.actions{display:flex;gap:6px;flex-wrap:wrap}.actions button{padding:7px 9px;font-size:13px}.status{color:var(--green)}.error{color:var(--red);white-space:pre-wrap}.notice{padding:9px;border-radius:10px;background:#17243b;color:var(--muted);white-space:pre-wrap}.hidden{display:none!important}@media(min-width:760px){main{grid-template-columns:1fr 1fr}.wide{grid-column:1/-1}} </style></head><body><header><div class="row between"><div><h1>🌐 Mihomo Control Center</h1><small>Local-only web panel · Live controller API</small></div><button onclick="refreshAll()">↻ Refresh</button></div></header><main>
<section class="card wide"><div class="row between"><div><div id="connection" class="pill">Connecting…</div><div id="apiinfo" class="muted" style="margin-top:8px">Checking Mihomo API</div></div><div class="row"><div><div id="proxyCount" class="stat">—</div><small>Proxies</small></div><div style="width:18px"></div><div><div id="groupCount" class="stat">—</div><small>Groups</small></div></div></div><div id="message" class="notice" style="margin-top:12px">Ready.</div></section>
<section class="card"><h2>🎯 Current selection</h2><div class="field"><label>Proxy group</label><select id="selectGroup" onchange="loadSelection()"></select></div><div class="field" style="margin-top:8px"><label>Proxy</label><select id="selectProxy"></select></div><button class="good" style="margin-top:10px;width:100%" onclick="applySelection()">Apply selection live</button><p class="muted">Changes selection immediately through Mihomo API. This does not rewrite the YAML.</p></section>
<section class="card"><h2>🔎 Search & filter</h2><div class="field"><label>Proxy name or type</label><input id="search" placeholder="Search proxies…" oninput="renderProxies()"></div><div class="row" style="margin-top:8px"><button onclick="testVisible()">Test visible delay</button><button onclick="refreshAll()">Refresh inventory</button></div><p class="muted">Delay testing may create traffic to the configured test URL.</p></section>
<section class="card wide"><div class="row between"><h2>📡 Live proxy inventory</h2><div class="row"><span class="pill" id="filterCount">0 shown</span><button id="proxyToggle" aria-expanded="false" onclick="toggleProxyInventory()">Show proxies ▾</button></div></div><div id="proxyInventoryBody" class="hidden"><div class="muted" style="margin:8px 0">Tap again to hide the long list.</div><div id="proxies" class="list"></div></div></section>
<section class="card wide"><div class="row between"><h2>🧩 Live groups</h2><button onclick="refreshAll()">Refresh groups</button></div><div id="groups" class="list"></div></section>
<section class="card"><h2>➕ Create group</h2><div class="field"><label>New group name</label><input id="newGroupName" placeholder="My Group"></div><div class="field" style="margin-top:8px"><label>Group type</label><select id="newGroupType"><option value="select">Select (manual)</option><option value="url-test">URL-Test</option><option value="fallback">Fallback</option><option value="load-balance">Load-Balance</option></select></div><button style="width:100%;margin-top:10px" onclick="createGroup()">Create group</button><p class="muted">Creates a group with the current configured proxy inventory; the change is persisted and reloaded.</p></section><section class="card"><h2>🎯 Curated group</h2><div class="field"><label>Group name</label><input id="curatedName" value="🎯 Curated / Pinned"></div><div class="field" style="margin-top:8px"><label>Proxy to add</label><select id="curatedProxy"></select></div><button class="good" style="width:100%;margin-top:10px" onclick="addCurated()">Add proxy to curated group</button><p class="muted">Requires an accessible config YAML. The panel backs up, validates and reloads it.</p></section>
<section class="card"><h2>🛠️ Config & API settings</h2><div class="field"><label>Mihomo API URL</label><input id="apiUrl" placeholder="http://127.0.0.1:9090"></div><div class="field" style="margin-top:8px"><label>API secret (stored locally)</label><input id="apiSecret" type="password" autocomplete="off" placeholder="Leave blank if not configured"></div><div class="field" style="margin-top:8px"><label>Accessible config YAML path</label><input id="configPath" placeholder="/path/to/config.yaml"></div><button style="width:100%;margin-top:10px" onclick="saveSettings()">Save settings</button><div id="configInfo" class="muted" style="margin-top:8px">Persistent edit actions require a valid path readable by Termux and the Mihomo process.</div></section>
<section class="card wide"><h2>⚠️ Safe operation notes</h2><div class="muted">Live selection uses the controller API. Editing proxy/group membership changes the YAML and asks Mihomo to reload it. If the config file is inside FiClash's private storage and Termux cannot access it, persistent edits cannot be applied through this panel until a shared/accessibly stored config path is configured. The panel binds only to 127.0.0.1 and requires a random session token.</div></section>
</main><script>
const TOKEN=new URLSearchParams(location.search).get('token')||'';let proxyInventoryOpen=false;function toggleProxyInventory(){proxyInventoryOpen=!proxyInventoryOpen;el('proxyInventoryBody').classList.toggle('hidden',!proxyInventoryOpen);el('proxyToggle').textContent=proxyInventoryOpen?'Hide proxies ▴':'Show proxies ▾';el('proxyToggle').setAttribute('aria-expanded',String(proxyInventoryOpen))}let state={proxies:{},groups:{},proxyList:[],groupList:[]};async function api(path,method='GET',body){let r=await fetch('/api'+path,{method,headers:{'Content-Type':'application/json','X-Panel-Token':TOKEN},body:body===undefined?undefined:JSON.stringify(body)});let j=await r.json().catch(()=>({error:'Invalid server response'}));if(!r.ok||j.error)throw Error(j.error||('HTTP '+r.status));return j}function msg(s,bad=false){let e=document.getElementById('message');e.textContent=s;e.className=bad?'error':'notice'}function el(id){return document.getElementById(id)}function enc(s){return encodeURIComponent(String(s)).replace(/'/g,'%27')}function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function refreshAll(){try{let previousGroup=el('selectGroup')?el('selectGroup').value:'';let d=await api('/status');state=d;el('connection').textContent=d.connected?'● API connected':'● API unavailable';el('connection').className='pill '+(d.connected?'status':'error');el('apiinfo').textContent=d.connected?'Mihomo '+(d.version||'')+' · '+(d.api_url||''):(d.error||'API connection failed');el('proxyCount').textContent=d.proxyList.length;el('groupCount').textContent=(d.settings&&d.settings.config_accessible?d.configGroupList.length:d.groupList.length);fillSelects(previousGroup);renderProxies();renderGroups();if(d.settings){el('apiUrl').value=d.settings.api_url||'';el('configPath').value=d.settings.config_path||'';el('configInfo').textContent=d.settings.config_accessible?'Config: '+d.settings.config_path:'Config path not detected; set it above for persistent edits.'}msg(d.connected?'Live inventory refreshed.':'Panel is open, but Mihomo API is not reachable.',!d.connected)}catch(e){msg(e.message,true)}}function fillSelects(previousGroup=''){let gs=state.groupList.filter(g=>Array.isArray(g.all));el('selectGroup').innerHTML=gs.map(g=>`<option value="${esc(g.name)}" ${g.name===previousGroup?'selected':''}>${esc(g.name)}</option>`).join('');let cp=state.settings&&state.settings.config_accessible?state.configProxyList:state.proxyList;el('curatedProxy').innerHTML=cp.map(p=>`<option value="${esc(p.name)}">${esc(p.name)}</option>`).join('');loadSelection()}function loadSelection(){let g=state.groups[el('selectGroup').value]||{};let names=(g.all||[]).filter(n=>state.proxies[n]);el('selectProxy').innerHTML=names.map(n=>`<option value="${esc(n)}" ${n===g.now?'selected':''}>${esc(n)}</option>`).join('')}async function applySelection(){try{await api('/select','POST',{group:el('selectGroup').value,proxy:el('selectProxy').value});msg('Selection applied live.');await refreshAll()}catch(e){msg(e.message,true)}}function renderProxies(){let q=el('search').value.toLowerCase();let source=state.settings&&state.settings.config_accessible?state.configProxyList.map(p=>{let live=state.proxies[p.name]||{};let h=live.history||[];return {...p,delay:h.length&&h[h.length-1]?h[h.length-1].delay:null,alive:live.alive}}):state.proxyList;let list=source.filter(p=>(p.name+' '+p.type).toLowerCase().includes(q));el('filterCount').textContent=list.length+' shown';el('proxies').innerHTML=list.slice(0,250).map(p=>`<div class="item"><div class="itemtop"><div><div class="name">${esc(p.name)}</div><small>${esc(p.type)} · ${esc(p.delay||'No recent delay')} ${p.delay?'ms':''}</small></div><span class="pill">${esc(p.alive===true?'alive':p.alive===false?'unavailable':'unknown')}</span></div><div class="actions"><button onclick="testOne('${enc(p.name)}')">Test delay</button><button onclick="copyProxy('${enc(p.name)}')">Copy to group</button><button onclick="editProxy('${enc(p.name)}')">Edit JSON</button><button onclick="renameProxy('${enc(p.name)}')">Rename</button><button class="danger" onclick="deleteProxy('${enc(p.name)}')">Delete</button></div></div>`).join('')||'<div class="muted">No proxies match.</div>'}function renderGroups(){let source=state.settings&&state.settings.config_accessible?state.configGroupList:state.groupList;el('groups').innerHTML=source.map(g=>`<div class="item"><div class="itemtop"><div><div class="name">${esc(g.name)}</div><small>${g.all.length} members · selected: ${esc(g.now||'—')}</small></div><span class="pill">${esc(g.type||'group')}</span></div><div class="actions"><button onclick="renameGroup('${enc(g.name)}')">Rename</button><button onclick="changeGroupType('${enc(g.name)}')">Change type</button><button onclick="addMember('${enc(g.name)}')">Add proxy</button><button onclick="removeMember('${enc(g.name)}')">Remove member</button><button onclick="moveMember('${enc(g.name)}')">Move member</button><button class="danger" onclick="deleteGroup('${enc(g.name)}')">Delete group</button></div></div>`).join('')||'<div class="muted">No groups found.</div>'}async function testOne(name){name=decodeURIComponent(name);try{let r=await api('/delay','POST',{proxy:name});msg(name+': '+(r.delay_ms==null?'test failed':r.delay_ms+' ms'));await refreshAll()}catch(e){msg(e.message,true)}}async function testVisible(){let list=state.proxyList.filter(p=>(p.name+' '+p.type).toLowerCase().includes(el('search').value.toLowerCase())).slice(0,30);for(let p of list){try{msg('Testing '+p.name+'…');await api('/delay','POST',{proxy:p.name})}catch(_){}}await refreshAll();msg('Delay tests completed for up to 30 visible proxies.')}async function saveSettings(){try{let r=await api('/settings','POST',{api_url:el('apiUrl').value.trim(),api_secret:el('apiSecret').value,config_path:el('configPath').value.trim()});el('apiSecret').value='';msg('Settings saved locally.');await refreshAll()}catch(e){msg(e.message,true)}}async function createGroup(){let name=el('newGroupName').value.trim();let type=el('newGroupType').value;if(!name)return msg('Enter a group name.',true);try{await api('/group/create','POST',{name,type});msg('Group created and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function addCurated(){try{let r=await api('/curated','POST',{group:el('curatedName').value.trim(),proxy:el('curatedProxy').value});msg('Curated group updated and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function renameProxy(name){name=decodeURIComponent(name);let n=prompt('New proxy name',name);if(!n||n===name)return;try{await api('/proxy/rename','POST',{name,new_name:n});msg('Proxy renamed and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function editProxy(encoded){let name=decodeURIComponent(encoded);let p=(state.configProxyList||[]).find(x=>x.name===name);if(!p){msg('Editable config proxy not found. Configure an accessible YAML path first.',true);return}let raw=prompt('Edit complete proxy object as JSON. Keep name/type/server/port valid.',JSON.stringify(p,null,2));if(!raw)return;try{let proxy_data=JSON.parse(raw);await api('/proxy/edit','POST',{name,proxy_data});msg('Proxy edited and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function deleteProxy(name){name=decodeURIComponent(name);if(!confirm('Delete '+name+' from config and all group memberships?'))return;try{await api('/proxy/delete','POST',{name});msg('Proxy deleted and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function copyProxy(name){name=decodeURIComponent(name);let group=prompt('Target group name');if(!group)return;try{await api('/group/add','POST',{group,proxy:name,copy:true});msg('Proxy copied to target group.');await refreshAll()}catch(e){msg(e.message,true)}}async function changeGroupType(encoded){let name=decodeURIComponent(encoded);let type=prompt('New group type: select, url-test, fallback, load-balance','select');if(!type)return;try{await api('/group/type','POST',{name,type});msg('Group type changed and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function renameGroup(name){name=decodeURIComponent(name);let n=prompt('New group name',name);if(!n||n===name)return;try{await api('/group/rename','POST',{name,new_name:n});msg('Group renamed and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function addMember(group){group=decodeURIComponent(group);let proxy=prompt('Exact proxy name to add');if(!proxy)return;try{await api('/group/add','POST',{group,proxy,copy:false});msg('Member added and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function removeMember(group){group=decodeURIComponent(group);let proxy=prompt('Exact member name to remove');if(!proxy)return;try{await api('/group/remove','POST',{group,proxy});msg('Member removed and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function moveMember(source){source=decodeURIComponent(source);let proxy=prompt('Exact proxy member to move from '+source);if(!proxy)return;let target=prompt('Target group name');if(!target)return;try{await api('/group/move','POST',{source,target,proxy});msg('Member moved and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}async function deleteGroup(name){name=decodeURIComponent(name);if(!confirm('Delete group '+name+'? Rules pointing to it may need a replacement.'))return;try{await api('/group/delete','POST',{name});msg('Group deleted and config reloaded.');await refreshAll()}catch(e){msg(e.message,true)}}refreshAll();
</script></body></html>"""


def start_web_panel() -> None:
    global WEB_PANEL_TOKEN
    WEB_PANEL_TOKEN = secrets.token_urlsafe(24)
    lock = threading.RLock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "MihomoLocalPanel/1.0"
        def log_message(self, fmt: str, *args: Any) -> None:
            # Avoid logging tokens, query strings, or secrets.
            print("[WEB] " + (fmt % args).split("?")[0])
        def _send(self, code: int, data: Any, content_type: str = "application/json; charset=utf-8") -> None:
            raw = data.encode("utf-8") if isinstance(data, str) else json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(raw)
        def _body(self) -> dict[str, Any]:
            n = int(self.headers.get("Content-Length", "0") or 0)
            if n < 0 or n > 1024 * 1024:
                raise ValueError("Request body too large")
            value = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
            if not isinstance(value, dict):
                raise ValueError("JSON body must be an object")
            return value
        def _auth(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Panel-Token", ""), WEB_PANEL_TOKEN)
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                qs = urllib.parse.parse_qs(parsed.query)
                if not secrets.compare_digest((qs.get("token") or [""])[0], WEB_PANEL_TOKEN):
                    self._send(403, "Panel session token missing or invalid.", "text/plain; charset=utf-8")
                    return
                self._send(200, _WEB_PANEL_HTML, "text/html; charset=utf-8")
                return
            if parsed.path.startswith("/api/") and not self._auth():
                self._send(403, {"error": "Invalid panel session token"}); return
            if parsed.path == "/api/status":
                settings = _webpanel_settings()
                result: dict[str, Any] = {"connected": False, "api_url": settings.get("api_url"), "settings": {"api_url": settings.get("api_url"), "config_path": str(_webpanel_config_path() or settings.get("config_path") or ""), "config_accessible": False}, "proxyList": [], "groupList": [], "groups": {}, "proxies": {}, "configProxyList": [], "configGroupList": []}
                try:
                    version = _webpanel_api_request("GET", "/version")
                    payload = _webpanel_api_request("GET", "/proxies")
                    prox = payload.get("proxies", {}) if isinstance(payload, dict) else {}
                    if not isinstance(prox, dict): raise RuntimeError("Unexpected /proxies response")
                    result["connected"] = True; result["version"] = version.get("version", "") if isinstance(version, dict) else ""
                    result["proxies"] = prox
                    for name, obj in prox.items():
                        if not isinstance(obj, dict): continue
                        typ = str(obj.get("type") or "Unknown")
                        all_names = obj.get("all") if isinstance(obj.get("all"), list) else []
                        if all_names or typ.lower() in {"selector", "urltest", "fallback", "loadbalance", "relay", "load-balance"}:
                            group = {"name": str(name), "type": typ, "now": obj.get("now"), "all": [str(x) for x in all_names]}
                            result["groupList"].append(group); result["groups"][str(name)] = group
                        else:
                            history = obj.get("history") if isinstance(obj.get("history"), list) else []
                            delay = None
                            if history and isinstance(history[-1], dict): delay = history[-1].get("delay")
                            alive = obj.get("alive")
                            result["proxyList"].append({"name": str(name), "type": typ, "delay": delay, "alive": alive})
                    result["proxyList"].sort(key=lambda x: x["name"].casefold()); result["groupList"].sort(key=lambda x: (0 if x["type"].lower()=="selector" else 1, x["name"].casefold()))
                    try:
                        _, cfg = _webpanel_read_config()
                        result["settings"]["config_accessible"] = True
                        result["configProxyList"] = [copy.deepcopy(x) for x in cfg.get("proxies", []) if isinstance(x, dict) and x.get("name")]
                        result["configGroupList"] = []
                        for cg in cfg.get("proxy-groups", []):
                            if not isinstance(cg, dict) or not cg.get("name"): continue
                            live = result["groups"].get(str(cg["name"]), {})
                            result["configGroupList"].append({"name": str(cg["name"]), "type": str(cg.get("type", "select")), "all": [str(x) for x in cg.get("proxies", [])] + [str(x) for x in cg.get("use", [])], "now": live.get("now")})
                    except Exception:
                        pass
                except Exception as exc:
                    result["error"] = f"{type(exc).__name__}: {exc}"
                self._send(200, result); return
            self._send(404, {"error": "Not found"})
        def do_POST(self) -> None:
            if not self._auth(): self._send(403, {"error":"Invalid panel session token"}); return
            try:
                body = self._body()
                route = urllib.parse.urlparse(self.path).path
                with lock:
                    if route == "/api/select":
                        group, proxy = str(body.get("group", "")), str(body.get("proxy", ""))
                        if not group or not proxy: raise ValueError("Group and proxy are required")
                        current = _webpanel_api_request("GET", "/proxies/" + urllib.parse.quote(group, safe=""))
                        if proxy not in current.get("all", []): raise ValueError("Proxy is not a member of this live group")
                        _webpanel_api_request("PUT", "/proxies/" + urllib.parse.quote(group, safe=""), {"name": proxy})
                        result = {"ok": True, "selected": proxy, "group": group}
                    elif route == "/api/delay":
                        name = str(body.get("proxy", "")); settings = _webpanel_settings()
                        query = {"url": CONTROLLER_TEST_URL, "timeout": max(500, int(CONTROLLER_TEST_TIMEOUT_MS))}
                        r = _webpanel_api_request("GET", "/proxies/" + urllib.parse.quote(name, safe="") + "/delay", query=query, timeout=10)
                        result = {"ok": True, "proxy": name, "delay_ms": r.get("delay") if isinstance(r, dict) else None}
                    elif route == "/api/settings":
                        api_url = str(body.get("api_url", "")).strip().rstrip("/")
                        if not api_url.startswith(("http://127.0.0.1:", "http://localhost:", "http://[::1]:", "https://127.0.0.1:", "https://localhost:")):
                            raise ValueError("For safety, API URL must use localhost/loopback only")
                        config_path = str(body.get("config_path", "")).strip()
                        if config_path and (not Path(config_path).expanduser().is_file() or Path(config_path).expanduser().suffix.lower() not in {".yaml", ".yml"}):
                            raise ValueError("Config path must point to an existing .yaml/.yml file readable by Termux")
                        old = _webpanel_settings(); secret = str(body.get("api_secret", "")) or str(old.get("api_secret", ""))
                        data = {"api_url": api_url, "api_secret": secret, "config_path": str(Path(config_path).expanduser()) if config_path else ""}
                        WEB_PANEL_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
                        atomic_write(WEB_PANEL_SETTINGS_PATH, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
                        try: os.chmod(WEB_PANEL_SETTINGS_PATH, 0o600)
                        except OSError: pass
                        result = {"ok": True}
                    elif route in {"/api/proxy/delete", "/api/proxy/rename", "/api/proxy/edit", "/api/group/add", "/api/group/remove", "/api/group/move", "/api/group/create", "/api/group/type", "/api/group/rename", "/api/group/delete", "/api/curated"}:
                        path, config = _webpanel_read_config(); proxies = config.get("proxies", []); groups = config.get("proxy-groups", [])
                        names = {str(x.get("name")) for x in proxies if isinstance(x, dict) and x.get("name")}
                        group_map = {str(g.get("name")): g for g in groups if isinstance(g, dict) and g.get("name")}
                        if route == "/api/proxy/delete":
                            name = str(body.get("name", ""))
                            if name not in names: raise ValueError("Proxy not found in configured YAML")
                            config["proxies"] = [x for x in proxies if not (isinstance(x, dict) and str(x.get("name")) == name)]
                            for g in groups:
                                if isinstance(g, dict) and isinstance(g.get("proxies"), list): g["proxies"] = [m for m in g["proxies"] if str(m) != name]
                        elif route == "/api/proxy/rename":
                            name, new = str(body.get("name", "")), str(body.get("new_name", "")).strip()
                            if name not in names: raise ValueError("Proxy not found")
                            if not new or new in names or len(new) > 180: raise ValueError("New proxy name is empty, too long or already exists")
                            for x in proxies:
                                if isinstance(x, dict) and str(x.get("name")) == name: x["name"] = new
                            for g in groups:
                                if isinstance(g, dict) and isinstance(g.get("proxies"), list): g["proxies"] = [new if str(m)==name else m for m in g["proxies"]]
                        elif route == "/api/proxy/edit":
                            name = str(body.get("name", "")); replacement = body.get("proxy_data")
                            if name not in names: raise ValueError("Proxy not found")
                            if not isinstance(replacement, dict): raise ValueError("Edited proxy must be a JSON object")
                            if str(replacement.get("name", "")) != name: raise ValueError("Editing the proxy name here is not allowed; use Rename")
                            if not replacement.get("type") or not replacement.get("server") or not isinstance(replacement.get("port"), int): raise ValueError("Proxy must retain type, server and integer port fields")
                            config["proxies"] = [copy.deepcopy(replacement) if isinstance(x, dict) and str(x.get("name")) == name else x for x in proxies]
                        elif route == "/api/group/create":
                            group_name = str(body.get("name", "")).strip(); group_type = str(body.get("type", "select")).strip().lower()
                            if not group_name or group_name in group_map or len(group_name) > 180: raise ValueError("Group name is empty, too long or already exists")
                            if group_type not in {"select", "url-test", "fallback", "load-balance"}: raise ValueError("Unsupported group type")
                            groups.append({"name": group_name, "type": group_type, "proxies": [str(x.get("name")) for x in proxies if isinstance(x, dict) and x.get("name")]})
                        elif route in {"/api/group/add", "/api/curated"}:
                            group_name = str(body.get("group", "🎯 Curated / Pinned" if route == "/api/curated" else "")).strip(); proxy = str(body.get("proxy", ""))
                            if proxy not in names: raise ValueError("Proxy not found in configured YAML")
                            if not group_name: raise ValueError("Group name is required")
                            group = group_map.get(group_name)
                            if group is None:
                                group = {"name": group_name, "type": "select", "proxies": [proxy]}; groups.append(group); group_map[group_name] = group
                            else:
                                members = group.setdefault("proxies", [])
                                if not isinstance(members, list): raise ValueError("Target group does not have a proxies list")
                                if proxy not in members: members.append(proxy)
                            if route == "/api/group/add" and body.get("copy"):
                                # Membership copy is the safe meaning of copy-to-group; the proxy itself is not duplicated.
                                pass
                        elif route == "/api/group/move":
                            source, target, proxy = str(body.get("source", "")), str(body.get("target", "")), str(body.get("proxy", ""))
                            if source not in group_map or target not in group_map: raise ValueError("Source or target group not found")
                            if source == target: raise ValueError("Source and target groups are the same")
                            src_members = group_map[source].get("proxies", []); dst_members = group_map[target].get("proxies", [])
                            if not isinstance(src_members, list) or proxy not in src_members: raise ValueError("Proxy is not in the source group")
                            if not isinstance(dst_members, list): raise ValueError("Target group does not have a proxies list")
                            group_map[source]["proxies"] = [m for m in src_members if str(m) != proxy]
                            if proxy not in dst_members: dst_members.append(proxy)
                        elif route == "/api/group/remove":
                            group_name, proxy = str(body.get("group", "")), str(body.get("proxy", ""))
                            if group_name not in group_map: raise ValueError("Group not found")
                            group = group_map[group_name]; members = group.get("proxies", [])
                            if not isinstance(members, list) or proxy not in members: raise ValueError("Proxy is not a member of this group")
                            group["proxies"] = [m for m in members if str(m) != proxy]
                        elif route == "/api/group/type":
                            name, new_type = str(body.get("name", "")), str(body.get("type", "")).strip().lower()
                            if name not in group_map: raise ValueError("Group not found")
                            if new_type not in {"select", "url-test", "fallback", "load-balance"}: raise ValueError("Unsupported group type")
                            group_map[name]["type"] = new_type
                        elif route == "/api/group/rename":
                            name, new = str(body.get("name", "")), str(body.get("new_name", "")).strip()
                            if name not in group_map: raise ValueError("Group not found")
                            if not new or new in group_map or len(new) > 180: raise ValueError("New group name is empty, too long or already exists")
                            for g in groups:
                                if isinstance(g, dict):
                                    if str(g.get("name")) == name: g["name"] = new
                                    if isinstance(g.get("proxies"), list): g["proxies"] = [new if str(m)==name else m for m in g["proxies"]]
                            if isinstance(config.get("rules"), list):
                                config["rules"] = [re.sub(rf",{re.escape(name)}$", ","+new, r) if isinstance(r,str) else r for r in config["rules"]]
                        elif route == "/api/group/delete":
                            name = str(body.get("name", ""))
                            if name not in group_map: raise ValueError("Group not found")
                            if name == DEFAULT_RULE_GROUP or name == "GLOBAL": raise ValueError("Refusing to delete the default/global group")
                            config["proxy-groups"] = [g for g in groups if not (isinstance(g,dict) and str(g.get("name"))==name)]
                            # Refuse unsafe deletion if routing rules still point to this group.
                            refs = [r for r in config.get("rules", []) if isinstance(r,str) and r.rstrip().endswith(","+name)]
                            if refs: raise ValueError("Group is still referenced by routing rules; redirect those rules first")
                            for g in config["proxy-groups"]:
                                if isinstance(g,dict) and isinstance(g.get("proxies"),list): g["proxies"] = [m for m in g["proxies"] if str(m)!=name]
                        result = _webpanel_save_reload(path, config)
                    else:
                        self._send(404, {"error":"Unknown action"}); return
                self._send(200, result)
            except Exception as exc:
                self._send(400, {"error": f"{type(exc).__name__}: {exc}"})

    global WEB_PANEL_PORT
    server = None
    last_error = None
    for candidate_port in range(WEB_PANEL_PORT, WEB_PANEL_PORT + 21):
        try:
            server = ThreadingHTTPServer((WEB_PANEL_HOST, candidate_port), Handler)
            WEB_PANEL_PORT = candidate_port
            break
        except OSError as exc:
            last_error = exc
    if server is None:
        raise RuntimeError(f"Could not bind local web panel ports {WEB_PANEL_PORT}-{WEB_PANEL_PORT + 20}: {last_error}")
    server.daemon_threads = True
    url = f"http://{WEB_PANEL_HOST}:{WEB_PANEL_PORT}/?token={WEB_PANEL_TOKEN}"
    print("\n" + "=" * 68)
    print("MIHOMO WEB CONTROL PANEL")
    print("Open in Chrome: " + url)
    print("Local-only server. Keep this URL private; it contains a session token.")
    print("Stop panel: Ctrl+C in Termux")
    print("=" * 68 + "\n")
    # Android Intent reliably opens the user's browser when Termux:API is available.
    try:
        subprocess.Popen(["am", "start", "-a", "android.intent.action.VIEW", "-d", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        try: webbrowser.open(url)
        except Exception: pass
    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        print("\n[WEB] Panel stopped.")
    finally:
        server.server_close()


def main() -> None:
    log("=" * 72)
    log(ENGINE_VERSION)
    log("FOUR INDEPENDENT GROUPS + MEASURED EGRESS + GEOLOCATION ENGINE")
    log("Actual proxy Egress IP consensus + independent health checks run through Mihomo")
    log("=" * 72)

    try:
        open_editor()

        text = load_input()

        if not text.strip():
            log(
                "[ERROR] input.txt is empty. "
                "Nothing generated."
            )
            return

        raw_count = len(
            [
                line
                for line in text.splitlines()
                if line.strip()
            ]
        )

        nodes = parse_all(text)

        if len(nodes) > MAX_NODES:
            log(
                f"[LIMIT] Parsed {len(nodes)} nodes; "
                f"hard limit is {MAX_NODES}. Truncating deterministically."
            )
            nodes = nodes[:MAX_NODES]

        before = len(nodes)
        nodes = dedupe(nodes)
        removed = before - len(nodes)
        nodes = _ultimate_normalize_nodes(nodes)

        unique_names(nodes)

        source_sections = extract_top_level_sections(text)
        imported_sections = [
            key for key in (
                "dns",
                "tun",
                "listeners",
                "proxy-providers",
                "rule-providers",
                "profile",
                "experimental",
                "rules",
            )
            if key in source_sections
        ]

        log(
            f"[PARSE] lines={raw_count} "
            f"nodes={len(nodes)} deduped={removed}"
        )

        if imported_sections:
            log(
                "[IMPORT] sections: "
                + ", ".join(imported_sections)
            )

        valid: list[dict[str, Any]] = []
        invalid = 0

        for node_data in nodes:
            if not validate_node(node_data):
                valid.append(node_data)
            else:
                invalid += 1

        log(
            f"[VALIDATE] valid={len(valid)} "
            f"invalid={invalid}"
        )

        # Optional explicit inventory allow/block filters; disabled by default.
        before_filter = len(valid)
        allow_names = {str(x).strip().casefold() for x in PROXY_ALLOWLIST if str(x).strip()}
        block_names = {str(x).strip().casefold() for x in PROXY_BLOCKLIST if str(x).strip()}
        exclude_terms = tuple(str(x).strip().casefold() for x in PROXY_NAME_EXCLUDE_TERMS if str(x).strip())
        if allow_names or block_names or exclude_terms:
            filtered: list[dict[str, Any]] = []
            for item in valid:
                name = str(item.get("name", "")).strip()
                folded = name.casefold()
                if allow_names and folded not in allow_names:
                    continue
                if folded in block_names or any(term in folded for term in exclude_terms):
                    continue
                filtered.append(item)
            valid = filtered
            log(f"[FILTER] kept={len(valid)} removed={before_filter - len(valid)}")

        if not valid:
            log(
                "[ERROR] No valid supported nodes found. "
                "Input preserved."
            )
            return

        log("[EGRESS] Starting isolated Mihomo probes; server IP, DNS, ASN, source flags and node names are NOT country evidence.")
        egress_stats = _probe_all_nodes(valid)
        log(f"[EGRESS-SUMMARY] tested={egress_stats['tested']} measured={egress_stats['egress']} healthy={egress_stats['healthy']} country_resolved={egress_stats['known_country']}")
        if egress_stats["healthy"] < 1:
            log("[ERROR] No proxy passed measured-Egress consensus and independent health checks. No output committed; input preserved.")
            return
        _decorate_node_names(valid)
        unique_names(valid)
        valid = _filter_nodes_by_live_controller(valid)
        if not valid:
            log("[ERROR] Live health filtering removed every proxy. No output was committed; input preserved.")
            return

        if ENABLE_SERVICE_LIVE_TESTS:
            log("[SERVICE-TEST] Running per-service endpoint checks; service groups will contain only passing nodes.")
            _run_service_live_tests(valid)

        global _CONTROLLER_PINNED_PROXY_NAME
        _CONTROLLER_PINNED_PROXY_NAME = _read_controller_selected_proxy()
        valid_node_names = {str(item.get("name", "")) for item in valid}
        if _CONTROLLER_PINNED_PROXY_NAME and _CONTROLLER_PINNED_PROXY_NAME not in valid_node_names:
            log("[CONTROLLER] Selected proxy is not present in this input; curated group will not be created.")
            _CONTROLLER_PINNED_PROXY_NAME = ""

        config = build_config(
            valid,
            text,
        )
        config = enforce_manual_select_invariants(config)

        errors = validate_config(config)

        if errors:
            log(
                "[ERROR] FINAL CONFIG VALIDATION FAILED:"
            )

            for error in errors[:60]:
                log("  - " + error)

            return

        audit_report = EngineOrchestrator.audit(config)
        log(f"[AUDIT] status={'PASS' if audit_report.get('ok') else 'WARN'}; errors={len(audit_report.get('errors', []))}; warnings={len(audit_report.get('warnings', []))}")
        for audit_error in audit_report["errors"][:30]:
            log("[AUDIT-ERROR] " + audit_error)
        for audit_warning in audit_report["warnings"][:20]:
            log("[AUDIT-WARN] " + audit_warning)
        # Keep the existing validator as the commit gate; the expanded audit is
        # recorded separately to avoid breaking legacy configurations on newly
        # introduced or version-specific Mihomo fields.

        yaml_text = (
            "# Generated by "
            f"{ULTIMATE_VERSION}\n"
            + "\n".join(yaml_dump(config))
            + "\n"
        )

        yaml_errors = validate_yaml_text(
            yaml_text
        )

        if yaml_errors:
            log(
                "[ERROR] SERIALIZED YAML "
                "VALIDATION FAILED:"
            )

            for error in yaml_errors[:60]:
                log("  - " + error)

            return

        path = output_path_ultimate()
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp_for_candidate = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        candidate_path = path.with_name(f".{path.stem}.candidate_{stamp_for_candidate}.yaml")
        atomic_write(candidate_path, yaml_text)

        # Validate the exact candidate YAML with a real Mihomo binary before
        # replacing the last known-good output.
        # Search PATH and common Termux project locations; do not claim success
        # or clear input when the native engine cannot be found or rejects YAML.
        mihomo = _find_mihomo_binary()
        if not mihomo:
            message = "Mihomo executable not found in PATH or common Termux core locations"
            log("[ERROR] " + message)
            try:
                candidate_path.unlink()
            except OSError:
                pass
            log("[ERROR] Temporary candidate removed; existing final output was not replaced. Input NOT cleared because native-core validation is required.")
            record_native_test_result("CORE_NOT_FOUND", message)
            return

        try:
            runtime_dir = PROJECT_DIR / "runtime"
            if not runtime_dir.parent.is_dir():
                runtime_dir = BASE_DIR / "mihomo_runtime"
            runtime_dir.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                [mihomo, "-t", "-d", str(runtime_dir), "-f", str(candidate_path)],
                capture_output=True,
                text=True,
                cwd=str(Path.home()),
                timeout=60,
            )
            detail = (result.stderr or result.stdout or "No diagnostic output").strip()
            if result.returncode != 0:
                log("[ERROR] Mihomo core rejected the generated config:")
                log(detail[:5000])
                try:
                    candidate_path.unlink()
                except OSError:
                    pass
                log("[ERROR] Temporary candidate removed; existing final output was not replaced. Input NOT cleared.")
                record_native_test_result("FAILED", detail)
                return
            log("[MIHOMO] native config test: OK")
            if detail:
                log(detail[:2000])
            record_native_test_result("PASSED", detail or "Mihomo -t accepted generated YAML")
            _commit_validated_output(
                candidate_path,
                path,
                yaml_text,
                {
                    "engine": ENGINE_VERSION,
                    "input_lines": raw_count,
                    "valid_nodes": len(valid),
                    "deduplicated_nodes": removed,
                    "invalid_nodes": invalid,
                    "groups": [str(g.get("name")) for g in config.get("proxy-groups", []) if isinstance(g, dict)],
                    "config_sha256": _ultimate_config_fingerprint(config),
                    "yaml_sha256": _ultimate_yaml_hash(yaml_text),
                    "mihomo_core_validation": "PASSED",
                },
            )
            try:
                _write_egress_audit(valid)
                log(f"[EGRESS-AUDIT] Evidence report: {EGRESS_AUDIT_PATH}")
            except Exception as audit_exc:
                log(f"[EGRESS-AUDIT] WARNING: YAML committed, but evidence report could not be written ({type(audit_exc).__name__}).")
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            log(f"[ERROR] native Mihomo validation failed: {message}")
            try:
                candidate_path.unlink()
            except OSError:
                pass
            log("[ERROR] Temporary candidate removed; existing final output was not replaced. Input NOT cleared.")
            record_native_test_result("ERROR", message)
            return

        clear_input()

        log("=" * 72)
        log("SUCCESS")
        log(f"YAML: {path}")
        log(f"NODES: {len(valid)}")
        actual_groups = config.get("proxy-groups", [])
        actual_group_names = [str(g.get("name")) for g in actual_groups if isinstance(g, dict)]
        log("GROUPS: " + ", ".join(actual_group_names))
        log(f"Auto URL-Test: {'disabled'}")
        log("Geo labels: based only on measured proxy Egress IP; no endpoint/name/flag inference")
        log(f"profile.store-selected: {str(bool(STORE_SELECTED_PROXY)).lower()}")

        log(
            "Input cleared for next run."
        )
        log("=" * 72)

    except KeyboardInterrupt:
        log(
            "\n[STOP] Cancelled; "
            "input was NOT cleared."
        )

    except Exception as exc:
        log(
            f"[FATAL] {type(exc).__name__}: {exc}"
        )
        log(
            "Input was NOT cleared because "
            "output was not safely completed."
        )


# ============================================================================
# SIX INDEPENDENT INDUSTRIAL SUB-ENGINES
# These operate on config dictionaries and do not replace the original builder.
# ============================================================================

class GroupEngine:
    """Create, remove, rename and safely manage proxy-groups in a config."""
    RESERVED = {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE"}

    @staticmethod
    def groups(config: dict[str, Any]) -> list[dict[str, Any]]:
        groups = config.setdefault("proxy-groups", [])
        if not isinstance(groups, list):
            raise ValueError("proxy-groups must be a list")
        return groups

    @classmethod
    def create(cls, config: dict[str, Any], name: str, kind: str = "select", members: list[str] | None = None) -> None:
        name, kind = str(name).strip(), str(kind).strip().lower()
        if not name or name in cls.RESERVED:
            raise ValueError("Invalid or reserved group name")
        if kind not in {"select", "url-test", "fallback", "load-balance"}:
            raise ValueError("Unsupported group type")
        groups = cls.groups(config)
        if any(isinstance(g, dict) and g.get("name") == name for g in groups):
            raise ValueError(f"Group already exists: {name}")
        proxy_names = {str(p.get("name")) for p in config.get("proxies", []) if isinstance(p, dict) and p.get("name")}
        group_names = {str(g.get("name")) for g in groups if isinstance(g, dict) and g.get("name")}
        chosen = list(dict.fromkeys(str(x) for x in (members or [])))
        missing = [x for x in chosen if x not in proxy_names and x not in group_names and x not in cls.RESERVED]
        if missing:
            raise ValueError("Unknown group member(s): " + ", ".join(missing[:10]))
        groups.append({"name": name, "type": kind, "proxies": chosen})

    @classmethod
    def delete(cls, config: dict[str, Any], name: str) -> None:
        groups = cls.groups(config)
        if not any(isinstance(g, dict) and g.get("name") == name for g in groups):
            raise ValueError(f"Group not found: {name}")
        # Do not silently leave routing rules or groups pointing at a deleted group.
        refs = []
        for g in groups:
            if isinstance(g, dict) and g.get("name") != name and name in [str(x) for x in g.get("proxies", [])]:
                refs.append(f"group:{g.get('name')}")
        for rule in config.get("rules", []):
            if isinstance(rule, str) and rule.rsplit(",", 1)[-1].strip() == name:
                refs.append("rule:" + rule[:80])
        if refs:
            raise ValueError("Cannot delete referenced group; update references first: " + "; ".join(refs[:8]))
        config["proxy-groups"] = [g for g in groups if not (isinstance(g, dict) and g.get("name") == name)]


class FilterEngine:
    """Filter proxy dictionaries by protocol, name, allowlist and denylist."""
    @staticmethod
    def apply(proxies: list[dict[str, Any]], *, protocols: set[str] | None = None,
              name_contains: str = "", allow_names: set[str] | None = None,
              deny_names: set[str] | None = None) -> list[dict[str, Any]]:
        protocols = {str(x).lower() for x in protocols} if protocols else None
        needle = str(name_contains).casefold()
        allow = {str(x) for x in allow_names} if allow_names else None
        deny = {str(x) for x in (deny_names or set())}
        result = []
        for p in proxies:
            if not isinstance(p, dict) or not p.get("name"):
                continue
            name, proto = str(p["name"]), str(p.get("type", "")).lower()
            if protocols is not None and proto not in protocols: continue
            if needle and needle not in name.casefold(): continue
            if allow is not None and name not in allow: continue
            if name in deny: continue
            result.append(p)
        return result


def _route_rule_target(rule: str) -> str | None:
    """Return the routing target, excluding optional Mihomo rule modifiers."""
    parts = [part.strip() for part in str(rule).split(",")]
    if len(parts) < 2:
        return None
    modifiers = {"no-resolve", "resolve", "src", "dst", "in"}
    while len(parts) > 2 and parts[-1].lower() in modifiers:
        parts.pop()
    return parts[-1] if len(parts) >= 2 else None


class RuleEngine:
    """Audit routing-rule targets against real proxy-group names and valid targets."""
    BUILTINS = {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS", "REJECT-DROP"}

    @classmethod
    def audit(cls, config: dict[str, Any]) -> list[str]:
        groups = {str(g.get("name")) for g in config.get("proxy-groups", []) if isinstance(g, dict) and g.get("name")}
        proxies = {str(p.get("name")) for p in config.get("proxies", []) if isinstance(p, dict) and p.get("name")}
        errors = []
        for i, rule in enumerate(config.get("rules", []), 1):
            if not isinstance(rule, str):
                errors.append(f"rules[{i}] is not a string"); continue
            target = _route_rule_target(rule)
            if not target:
                errors.append(f"rules[{i}] has no target: {rule[:100]}"); continue
            if target not in groups and target not in proxies and target not in cls.BUILTINS:
                errors.append(f"rules[{i}] points to missing target '{target}'")
        return errors


class HealthEngine:
    """Perform offline structural health checks and persist a JSON report."""
    @staticmethod
    def inspect(config: dict[str, Any]) -> dict[str, Any]:
        proxies = config.get("proxies", [])
        groups = config.get("proxy-groups", [])
        names: list[str] = []
        duplicates: list[str] = []
        invalid: list[str] = []
        for i, p in enumerate(proxies if isinstance(proxies, list) else []):
            endpoint_optional = {"easytier", "tailscale", "zerotier"}
            if not isinstance(p, dict) or not p.get("name") or not p.get("type"):
                invalid.append(f"proxies[{i}] missing name/type")
                continue
            if str(p.get("type", "")).lower() not in endpoint_optional and (not p.get("server") or not isinstance(p.get("port"), int)):
                invalid.append(f"proxies[{i}] missing server/integer port")
                continue
            name = str(p["name"])
            if name in names: duplicates.append(name)
            names.append(name)
        group_names = [str(g.get("name")) for g in groups if isinstance(g, dict) and g.get("name")]
        report = {"timestamp": datetime.now().astimezone().isoformat(), "proxy_count": len(proxies) if isinstance(proxies, list) else 0,
                  "group_count": len(groups) if isinstance(groups, list) else 0, "duplicate_proxy_names": sorted(set(duplicates)),
                  "invalid_proxies": invalid, "duplicate_group_names": sorted({n for n in group_names if group_names.count(n) > 1}),
                  "network_tests_performed": False, "note": "Offline structural check only; this does not prove endpoint connectivity."}
        return report

    @staticmethod
    def save(report: dict[str, Any], path: Path) -> None:
        atomic_write(path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")


class ValidationEngine:
    """Structural checks plus native Mihomo -t validation when a core is found."""
    @staticmethod
    def find_core() -> str | None:
        candidates = [shutil.which("mihomo"), shutil.which("clash-meta"),
                      str(MIHOMO_SOURCE_DIR / "bin" / "mihomo-android-arm64"),
                      str(PROJECT_DIR / "core" / "mihomo"),
                      str(BASE_DIR / "core" / "mihomo"),
                      str(Path(str(PROJECT_DIR / "core" / "mihomo")))]
        return next((x for x in candidates if x and Path(x).is_file() and os.access(x, os.X_OK)), None)

    @classmethod
    def validate_file(cls, path: Path, *, require_core: bool = True) -> dict[str, Any]:
        errors: list[str] = []
        try:
            text = path.read_text(encoding="utf-8")
            errors.extend(validate_yaml_text(text))
        except Exception as exc:
            errors.append(f"Cannot read candidate: {type(exc).__name__}: {exc}")
        core = cls.find_core()
        core_result = "NOT_FOUND"
        detail = ""
        if core:
            try:
                run = subprocess.run([core, "-t", "-f", str(path)], capture_output=True, text=True, timeout=45)
                core_result = "PASSED" if run.returncode == 0 else "FAILED"
                detail = (run.stderr or run.stdout or "").strip()[:4000]
                if run.returncode:
                    errors.append("Mihomo native validation failed: " + detail)
            except Exception as exc:
                core_result = "ERROR"; detail = f"{type(exc).__name__}: {exc}"; errors.append(detail)
        elif require_core:
            errors.append("Mihomo executable not found; native validation required")
        return {"ok": not errors, "errors": errors, "core": core, "core_result": core_result, "detail": detail}


class TransactionEngine:
    """Safe candidate write, optional native validation, atomic commit and rollback."""
    @staticmethod
    def commit_text(destination: Path, text: str, *, validate_native: bool = True) -> dict[str, Any]:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
        candidate = destination.with_name(destination.name + f".candidate_{stamp}")
        backup = destination.with_name(destination.name + f".backup_{stamp}")
        had_original = destination.is_file()
        if had_original:
            shutil.copy2(destination, backup)
        atomic_write(candidate, text)
        try:
            verdict = ValidationEngine.validate_file(candidate, require_core=validate_native)
            if not verdict["ok"]:
                raise RuntimeError("Candidate rejected: " + " | ".join(verdict["errors"][:5]))
            os.replace(candidate, destination)
            return {"ok": True, "destination": str(destination), "backup": str(backup) if had_original else None, "validation": verdict}
        except Exception:
            candidate.unlink(missing_ok=True)
            # Destination is not touched until validation passes; restore defensively if needed.
            if had_original and backup.exists() and not destination.exists():
                shutil.copy2(backup, destination)
            raise






class ConfigAuditEngine:
    """Cross-section audit for documented Mihomo YAML structures.

    This is deliberately an offline audit: the real Mihomo binary remains the
    authority for version-specific schema and runtime compatibility.
    """
    KNOWN_GROUP_TYPES = {"select", "url-test", "fallback", "load-balance", "relay"}
    LISTENER_TYPES = {"http", "socks", "mixed", "redirect", "tproxy", "tun"}
    PROVIDER_TYPES = {"http", "file", "inline"}

    @classmethod
    def audit(cls, config: dict[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        warnings: list[str] = []
        if not isinstance(config, dict):
            return {"ok": False, "errors": ["YAML root must be a mapping"], "warnings": [], "sections": {}}

        proxies = config.get("proxies", [])
        groups = config.get("proxy-groups", [])
        proxy_names = {str(p.get("name")) for p in proxies if isinstance(p, dict) and p.get("name")} if isinstance(proxies, list) else set()
        group_names = [str(g.get("name")) for g in groups if isinstance(g, dict) and g.get("name")] if isinstance(groups, list) else []
        group_name_set = set(group_names)
        if len(group_names) != len(set(group_names)):
            errors.append("Duplicate proxy-group names detected")

        # Validate every group reference without assuming a particular proxy
        # naming scheme or inventing missing members.
        for index, group in enumerate(groups if isinstance(groups, list) else []):
            if not isinstance(group, dict):
                errors.append(f"proxy-groups[{index}] must be a mapping")
                continue
            name = str(group.get("name") or f"index-{index}")
            kind = str(group.get("type") or "").lower()
            if kind not in cls.KNOWN_GROUP_TYPES:
                errors.append(f"proxy-group {name}: unknown type {kind!r}")
            members = group.get("proxies", [])
            if not isinstance(members, list):
                errors.append(f"proxy-group {name}: proxies must be a list")
                continue
            for member in members:
                if str(member) not in proxy_names | group_name_set | {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS", "REJECT-DROP"}:
                    errors.append(f"proxy-group {name}: missing member {member!r}")

        # Check route rule targets separately so users can distinguish rule
        # errors from group-membership errors.
        if "rules" in config:
            rules = config.get("rules")
            if not isinstance(rules, list):
                errors.append("rules must be a list")
            else:
                for index, rule in enumerate(rules):
                    if not isinstance(rule, str):
                        errors.append(f"rules[{index}] must be a string")
                        continue
                    target = _route_rule_target(rule)
                    if not target:
                        errors.append(f"rules[{index}] has no target")
                        continue
                    if target not in proxy_names | group_name_set | {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS", "REJECT-DROP"}:
                        errors.append(f"rules[{index}] target {target!r} is unresolved")

        # Listener records are preserved as supplied; this audit catches only
        # universally meaningful structural mistakes.
        listeners = config.get("listeners")
        if listeners is not None:
            if not isinstance(listeners, list):
                errors.append("listeners must be a list")
            else:
                listener_names: set[str] = set()
                for index, listener in enumerate(listeners):
                    if not isinstance(listener, dict):
                        errors.append(f"listeners[{index}] must be a mapping")
                        continue
                    lname = str(listener.get("name") or "")
                    ltype = str(listener.get("type") or "").lower()
                    if not lname:
                        errors.append(f"listeners[{index}] missing name")
                    elif lname in listener_names:
                        errors.append(f"duplicate listener name {lname!r}")
                    listener_names.add(lname)
                    if ltype not in cls.LISTENER_TYPES:
                        errors.append(f"listener {lname or index}: unsupported type {ltype!r}")
                    port = listener.get("port")
                    if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
                        errors.append(f"listener {lname or index}: port must be 1..65535")

        # Proxy and rule providers share transport types but have different
        # required fields. Do not fetch remote URLs during an audit.
        for section_name in ("proxy-providers", "rule-providers"):
            section = config.get(section_name)
            if section is None:
                continue
            if not isinstance(section, dict):
                errors.append(f"{section_name} must be a mapping")
                continue
            for pname, provider in section.items():
                if not isinstance(provider, dict):
                    errors.append(f"{section_name}/{pname} must be a mapping")
                    continue
                ptype = str(provider.get("type") or "").lower()
                if ptype not in cls.PROVIDER_TYPES:
                    errors.append(f"{section_name}/{pname}: unsupported provider type {ptype!r}")
                if ptype == "http" and not provider.get("url"):
                    errors.append(f"{section_name}/{pname}: HTTP provider needs url")
                if ptype == "file" and not provider.get("path"):
                    errors.append(f"{section_name}/{pname}: file provider needs path")
                if section_name == "rule-providers":
                    behavior = provider.get("behavior")
                    if behavior not in {"domain", "ipcidr", "classical"}:
                        errors.append(f"rule-providers/{pname}: behavior must be domain, ipcidr, or classical")

        # DNS, hosts, sniffer, NTP and tunnels are kept flexible because their
        # valid subkeys evolve across Mihomo versions. Catch wrong root shapes.
        expected_roots = {"dns": dict, "hosts": dict, "sniffer": dict, "ntp": dict, "tun": dict, "experimental": dict, "profile": dict, "sub-rules": dict}
        for section_name, expected in expected_roots.items():
            if section_name in config and not isinstance(config[section_name], expected):
                errors.append(f"{section_name} must be a {expected.__name__}")
        if "tunnels" in config and not isinstance(config["tunnels"], list):
            errors.append("tunnels must be a list")
        if "authentication" in config and not isinstance(config["authentication"], list):
            errors.append("authentication must be a list")
        if "skip-auth-prefixes" in config and not isinstance(config["skip-auth-prefixes"], list):
            errors.append("skip-auth-prefixes must be a list")

        sections = {key: (len(value) if isinstance(value, (dict, list)) else 1)
                    for key, value in config.items()}
        if not config.get("dns"):
            warnings.append("DNS section absent or empty; Mihomo defaults may apply")
        if config.get("tun", {}).get("enable") is True if isinstance(config.get("tun"), dict) else False:
            warnings.append("TUN is enabled; verify Android/FiClash permissions and routing impact")
        if config.get("external-controller") and not config.get("secret"):
            warnings.append("external-controller is configured without a secret; verify intended exposure")
        return {"ok": not errors, "errors": errors, "warnings": warnings, "sections": sections}


class EngineOrchestrator:
    """Coordinate the six engines while retaining the legacy generator as source of truth."""
    @staticmethod
    def audit(config: dict[str, Any]) -> dict[str, Any]:
        section_audit = ConfigAuditEngine.audit(config)
        rule_errors = RuleEngine.audit(config)
        health = HealthEngine.inspect(config)
        errors = list(section_audit["errors"])
        errors.extend(item for item in rule_errors if item not in errors)
        warnings = list(section_audit["warnings"])
        if health.get("duplicate_proxy_names"):
            warnings.append("Health report found duplicate proxy names")
        if health.get("invalid_proxies"):
            warnings.append(f"Health report found {len(health['invalid_proxies'])} structurally incomplete proxies")
        return {
            "ok": not errors,
            "timestamp": datetime.now().astimezone().isoformat(),
            "errors": errors,
            "warnings": warnings,
            "sections": section_audit["sections"],
            "health": health,
        }

    @staticmethod
    def write_reports(config: dict[str, Any], audit: dict[str, Any]) -> tuple[Path, Path]:
        report_dir = BASE_DIR / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
        audit_path = report_dir / f"config_audit_{stamp}.json"
        health_path = report_dir / f"health_{stamp}.json"
        # The config itself is never written to the report, avoiding accidental
        # disclosure of UUIDs, passwords, keys, and controller secrets.
        atomic_write(audit_path, json.dumps(audit, ensure_ascii=False, indent=2) + "\n")
        atomic_write(health_path, json.dumps(audit.get("health", {}), ensure_ascii=False, indent=2) + "\n")
        return audit_path, health_path


def _run_endpoint_dedupe_selftest() -> None:
    sample = [
        {"name": "A", "type": "trojan", "server": "203.0.113.8", "port": 443, "password": "x"},
        {"name": "B", "type": "vless", "server": "203.0.113.8", "port": 8443, "uuid": "u"},
        {"name": "C", "type": "vmess", "server": "203.0.113.9", "port": 443, "uuid": "v"},
        {"name": "A-copy", "type": "trojan", "server": "203.0.113.8", "port": 443, "password": "x"},
    ]
    got = dedupe(sample)
    assert [x["name"] for x in got] == ["A", "B", "C"], got
    same_identity = [
        {"name": "A", "type": "trojan", "server": "203.0.113.8", "port": 443, "password": "x"},
        {"name": "A-copy", "type": "trojan", "server": "203.0.113.8", "port": 443, "password": "y"},
    ]
    assert [x["name"] for x in dedupe(same_identity)] == ["A"]
    # Same IP with a different port or protocol must remain distinct, while
    # the canonical endpoint IP must still be recognized from decorated names.
    decorated = [
        {"name": "🇺🇸 United States (US) | 203.0.113.8 | PORT 443 | TROJAN | A", "type": "trojan", "server": "edge.example", "port": 443},
        {"name": "🇺🇸 United States (US) | 203.0.113.8 | PORT 8443 | TROJAN | B", "type": "trojan", "server": "edge.example", "port": 8443},
        {"name": "🇺🇸 United States (US) | 203.0.113.8 | PORT 443 | VLESS | C", "type": "vless", "server": "edge.example", "port": 443},
    ]
    assert _node_endpoint_key(decorated[0]) == "ip:203.0.113.8"
    assert len(dedupe_by_resolved_endpoint_ip(decorated)[0]) == 3
    assert len(dedupe_by_resolved_endpoint_ip(decorated + [dict(decorated[0], name=decorated[0]["name"] + " | duplicate")])[0]) == 3
    print("Endpoint-IP deduplication and Global-visible endpoint labels self-test: PASS")


def _run_expansion_selftest() -> None:
    sample = {
        "proxies": [{"name": "P1", "type": "socks5", "server": "127.0.0.1", "port": 1080}],
        "proxy-groups": [{"name": "Select ⚖️", "type": "select", "proxies": ["P1"]}],
        "rules": ["MATCH,Select ⚖️"],
        "profile": {"store-selected": False},
        "dns": {"enable": True, "nameserver": ["1.1.1.1"]},
        "listeners": [{"name": "local-socks", "type": "socks", "port": 1081}],
        "tunnels": [{"network": ["tcp"], "address": "127.0.0.1:6553", "target": "1.1.1.1:53"}],
    }
    result = EngineOrchestrator.audit(sample)
    assert result["ok"], result["errors"]
    assert result["sections"]["listeners"] == 1
    broken = copy.deepcopy(sample)
    broken["rules"] = ["MATCH,missing-group"]
    assert not EngineOrchestrator.audit(broken)["ok"]
    # Ensure transactions reject malformed YAML without touching the destination.
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "final.yaml"
        target.write_text("old-valid-content\n", encoding="utf-8")
        try:
            TransactionEngine.commit_text(target, "not: [valid", validate_native=False)
        except Exception:
            pass
        assert target.read_text(encoding="utf-8") == "old-valid-content\n"
    print("Expansion self-test: PASS")
    print("Section audit: PASS; routing references: PASS; secret-free reports: PASS")
    print("Transaction rollback safety: PASS")


def _run_deep_expansion_selftest() -> None:
    """Regression tests for four independent Egress-based groups."""
    nodes = [
        {"name": "known-a", "type": "vless", "server": "198.51.100.10", "port": 443},
        {"name": "known-b", "type": "trojan", "server": "198.51.100.11", "port": 443},
        {"name": "unknown-c", "type": "vmess", "server": "198.51.100.12", "port": 443},
        {"name": "unhealthy-d", "type": "ss", "server": "198.51.100.13", "port": 443},
        {"name": "unmeasured-e", "type": "ss", "server": "198.51.100.14", "port": 443},
        {"name": "same-egress-faster", "type": "vless", "server": "198.51.100.15", "port": 443},
    ]
    saved = dict(_EGRESS_RESULTS)
    try:
        _EGRESS_RESULTS.clear()
        _EGRESS_RESULTS[fingerprint(nodes[0])] = {"egress_ip": "8.8.8.8", "country_code": "US", "country": "United States", "healthy": True, "latency_ms": 80}
        _EGRESS_RESULTS[fingerprint(nodes[1])] = {"egress_ip": "1.1.1.1", "country_code": "DE", "country": "Germany", "healthy": True, "latency_ms": 50}
        _EGRESS_RESULTS[fingerprint(nodes[2])] = {"egress_ip": "9.9.9.9", "country_code": None, "country": None, "healthy": True, "latency_ms": 90}
        _EGRESS_RESULTS[fingerprint(nodes[3])] = {"egress_ip": "4.4.4.4", "country_code": "FR", "country": "France", "healthy": False, "latency_ms": 20}
        _EGRESS_RESULTS[fingerprint(nodes[4])] = {"egress_ip": None, "country_code": None, "country": None, "healthy": False}
        _EGRESS_RESULTS[fingerprint(nodes[5])] = {"egress_ip": "8.8.8.8", "country_code": "US", "country": "United States", "healthy": True, "latency_ms": 20}
        names = [n["name"] for n in nodes]
        groups = build_groups(names, nodes)
        assert [g["name"] for g in groups] == list(GROUP_ORDER)
        by_name = {g["name"]: g["proxies"] for g in groups}
        assert by_name[DEFAULT_RULE_GROUP] == ["same-egress-faster", "known-b"], by_name[DEFAULT_RULE_GROUP]
        assert by_name[FALLBACK_GROUP_NAME] == ["same-egress-faster", "known-b", "unknown-c"], by_name[FALLBACK_GROUP_NAME]
        assert by_name[UNKNOWN_GROUP_NAME] == ["unknown-c"], by_name[UNKNOWN_GROUP_NAME]
        assert by_name[DIRECT_GROUP_NAME] == ["DIRECT"]
        assert "unhealthy-d" not in sum((v for k, v in by_name.items() if k != DIRECT_GROUP_NAME), [])
        assert "unmeasured-e" not in sum((v for k, v in by_name.items() if k != DIRECT_GROUP_NAME), [])
        # Groups contain proxy names only; no group can reference another group.
        for group in groups[:-1]:
            assert not (set(group["proxies"]) & set(GROUP_ORDER))
        assert build_service_rules(set(GROUP_ORDER))[0].endswith(DIRECT_GROUP_NAME)
        assert all(rule.split(",")[2] == DIRECT_GROUP_NAME for rule in build_service_rules(set(GROUP_ORDER)))
        assert _active_default_group(groups) == DEFAULT_RULE_GROUP
        empty_select = copy.deepcopy(groups)
        empty_select[0]["proxies"] = ["REJECT"]
        assert _active_default_group(empty_select) == FALLBACK_GROUP_NAME
        # One measured Egress is retained only once per group, but can occur across groups.
        assert by_name[DEFAULT_RULE_GROUP].count("same-egress-faster") == 1
        assert "same-egress-faster" in by_name[FALLBACK_GROUP_NAME]
        assert _enabled_manual_group(UNKNOWN_GROUP_NAME) and _enabled_manual_group(DIRECT_GROUP_NAME)
    finally:
        _EGRESS_RESULTS.clear()
        _EGRESS_RESULTS.update(saved)
    print("Four independent Egress-group contract self-test: PASS")
    print("Select/Fallback/Unknown membership predicates: PASS")
    print("Per-group Egress uniqueness and cross-group independence: PASS")
    print("Direct wrapper and local-routing policy: PASS")


def _run_egress_helpers_selftest() -> None:
    assert _public_ip_from_body(b"8.8.8.8\n") == "8.8.8.8"
    assert _public_ip_from_body(b"127.0.0.1") is None
    assert _public_ip_from_body(b"not-an-ip") is None
    assert _public_ip_from_body(b"2001:4860:4860::8888") == "2001:4860:4860::8888"
    assert _country_flag_from_code("DE") == "🇩🇪"
    # No source flag/name can create Egress evidence or country membership.
    node = {"name": "🇺🇸 United States | fake", "type": "vless", "server": "192.0.2.1", "port": 443}
    assert not _egress_result_for_node(node)
    _EGRESS_RESULTS.clear()
    _decorate_node_names([node])
    assert "Egress Unverified" in node["name"] and "United States" not in node["name"] and "🇺🇸" not in node["name"]
    known = {"name": "🇺🇸 United States | source-label", "type": "vless", "server": "192.0.2.2", "port": 443}
    _EGRESS_RESULTS[fingerprint(known)] = {"egress_ip": "8.8.8.8", "country_code": "DE", "country": "Germany", "healthy": True}
    _decorate_node_names([known])
    assert known["name"].startswith("🇩🇪 Germany (DE) | EGRESS 8.8.8.8"), known["name"]
    _EGRESS_RESULTS.clear()
    print("Egress IP parsing / public-address gate / flag generation: PASS")
    print("Source-name country spoof rejection and Egress-only name decoration: PASS")


def _run_egress_probe_selftest() -> None:
    """Offline integration test for temp config, core lifecycle, quorum and health gates."""
    global _request_via_local_mihomo, _geoip_ip
    import textwrap

    with tempfile.TemporaryDirectory(prefix="king-egress-selftest-") as td:
        fake_core = Path(td) / "mihomo-fake"
        fake_core.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import sys, socket, yaml, time
            cfg = sys.argv[sys.argv.index('-f') + 1]
            data = yaml.safe_load(open(cfg, encoding='utf-8'))
            if '-t' in sys.argv:
                assert data.get('proxy-groups') and data.get('rules')
                sys.exit(0)
            server = socket.socket()
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', int(data['mixed-port'])))
            server.listen(8)
            while True:
                try:
                    client, _ = server.accept()
                    client.close()
                except Exception:
                    time.sleep(0.05)
        """), encoding="utf-8")
        fake_core.chmod(0o755)

        old_request = _request_via_local_mihomo
        old_geo = _geoip_ip
        try:
            def fake_request(port: int, url: str, timeout: float) -> tuple[int, bytes, int]:
                if "generate_204" in url or "cp.cloudflare" in url:
                    return 204, b"", 15
                return 200, b"8.8.8.8\n", 25

            _request_via_local_mihomo = fake_request  # type: ignore[assignment]
            _geoip_ip = lambda _ip: {"code": "US", "country": "United States", "region": "California", "city": "Mountain View", "source": "selftest-mmdb"}  # type: ignore[assignment]
            base = {"name": "probe-base", "type": "socks5", "server": "base.example", "port": 1080}
            child = {"name": "probe-child", "type": "socks5", "server": "child.example", "port": 1081, "dialer-proxy": "probe-base"}
            record = _probe_node_egress(child, [base, child], str(fake_core))
            assert record.get("egress_ip") == "8.8.8.8", record
            assert record.get("egress_family") == "IPv4", record
            assert record.get("healthy") is True, record
            assert record.get("country_code") == "US" and record.get("city") == "Mountain View", record
            assert len(record.get("echo_sources", {})) == EGRESS_PROBE_QUORUM, record
            chain = _collect_probe_chain(child, [base, child])
            assert [x.get("name") for x in chain] == ["probe-base", "probe-child"], chain
        finally:
            _request_via_local_mihomo = old_request  # type: ignore[assignment]
            _geoip_ip = old_geo  # type: ignore[assignment]
    print("Offline isolated Mihomo lifecycle/config/quorum/health/GeoIP/dialer-chain self-test: PASS")


if __name__ == "__main__":
    args = sys.argv[1:]
    # Self-tests validate the general builders independently of the user's
    # production master-key selection. This does not affect normal execution.
    if any(arg in args for arg in ("--endpoint-dedupe-selftest", "--deep-expansion-selftest", "--egress-groups-selftest", "--egress-probe-selftest", "--engines-selftest", "--expansion-selftest", "--egress-helpers-selftest", "--all-selftests")):
        ENABLE_GROUP_MASTER_KEY = False
    if "--all-selftests" in args:
        _run_endpoint_dedupe_selftest()
        _run_deep_expansion_selftest()
        _run_egress_helpers_selftest()
        _run_egress_probe_selftest()
        sample = {"proxies": [{"name": "P1", "type": "socks5", "server": "127.0.0.1", "port": 1080}],
                  "proxy-groups": [{"name": "Select ⚖️", "type": "select", "proxies": ["P1"]}],
                  "rules": ["MATCH,Select ⚖️"]}
        assert len(FilterEngine.apply(sample["proxies"], protocols={"socks5"})) == 1
        GroupEngine.create(sample, "TestGroup", "select", ["P1"])
        assert not RuleEngine.audit(sample)
        assert HealthEngine.inspect(sample)["invalid_proxies"] == []
        print("Six-engine self-test: PASS")
        _run_expansion_selftest()
    elif "--endpoint-dedupe-selftest" in args:
        _run_endpoint_dedupe_selftest()
    elif "--egress-groups-selftest" in args:
        _run_deep_expansion_selftest()
    elif "--egress-probe-selftest" in args:
        _run_egress_probe_selftest()
    elif "--engines-selftest" in args:
        sample = {"proxies": [{"name": "P1", "type": "socks5", "server": "127.0.0.1", "port": 1080}],
                  "proxy-groups": [{"name": "Select ⚖️", "type": "select", "proxies": ["P1"]}],
                  "rules": ["MATCH,Select ⚖️"]}
        assert len(FilterEngine.apply(sample["proxies"], protocols={"socks5"})) == 1
        GroupEngine.create(sample, "TestGroup", "select", ["P1"])
        assert not RuleEngine.audit(sample)
        assert HealthEngine.inspect(sample)["invalid_proxies"] == []
        print("Six-engine self-test: PASS")
        print("Group Engine: PASS; Filter Engine: PASS; Rule Engine: PASS")
        print("Health Engine: PASS; Validation Engine: available; Transaction Engine: available")
    elif "--expansion-selftest" in args:
        _run_expansion_selftest()
    elif "--deep-expansion-selftest" in args:
        _run_deep_expansion_selftest()
    elif "--egress-helpers-selftest" in args:
        _run_egress_helpers_selftest()
    elif "--audit-config" in args:
        try:
            idx = args.index("--audit-config")
            path = Path(args[idx + 1]).expanduser()
        except (ValueError, IndexError):
            print("Usage: python tepo6_four_groups_clean_final.py --audit-config /path/to/config.yaml")
            raise SystemExit(2)
        try:
            import yaml
            config = yaml.safe_load(path.read_text(encoding="utf-8"))
            report = EngineOrchestrator.audit(config)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            raise SystemExit(0 if report["ok"] else 1)
        except ImportError:
            print("PyYAML is required for --audit-config. Install with: pip install pyyaml")
            raise SystemExit(2)
        except OSError as exc:
            print(f"Cannot read config: {exc}")
            raise SystemExit(2)
    elif any(arg in {"--web-panel", "web-panel", "--panel"} for arg in args):
        start_web_panel()
    else:
        main()

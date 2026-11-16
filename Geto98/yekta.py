#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Precise standalone configuration deduplicator for Termux.

Workflow:
1. Opens Nano with an empty input file.
2. Reads pasted configurations.
3. Validates supported configurations.
4. Removes duplicates using protocol + host + port.
5. Preserves original configuration text.
6. Saves unique, duplicate, and invalid entries separately.
7. Copies unique configurations to Android clipboard.
8. Clears the input file after processing.

No DNS, ping, network connection, or configuration modification.
"""

import os
import re
import sys
import ipaddress
import subprocess
import base64
from urllib.parse import urlsplit, unquote


BASE_DIR = "/storage/emulated/0/Download/YektaSazi"

INPUT_FILE = os.path.join(BASE_DIR, "input.txt")
OUTPUT_FILE = os.path.join(BASE_DIR, "yekta_unique.txt")
INVALID_FILE = os.path.join(BASE_DIR, "yekta_invalid.txt")
DUPLICATES_FILE = os.path.join(BASE_DIR, "yekta_duplicates.txt")


def say(message=""):
    print(message, flush=True)


def write_exact_lines(path, lines):
    with open(path, "w", encoding="utf-8", newline="") as file:
        for line in lines:
            file.write(line)
            file.write("\n")


def normalize_host(host):
    if not host:
        return None

    host = host.strip().rstrip(".")

    if not host or any(char.isspace() for char in host):
        return None

    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass

    try:
        domain = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(domain) > 253 or "." not in domain:
        return None

    labels = domain.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            return None

    return domain


def valid_ss_auth(parts):
    userinfo = parts.username

    if not userinfo:
        return False

    decoded = unquote(userinfo)
    candidates = [decoded]

    padded = decoded + "=" * ((4 - len(decoded) % 4) % 4)

    try:
        decoded_b64 = (
            base64.urlsafe_b64decode(
                padded.encode("ascii")
            ).decode("utf-8")
        )
        candidates.append(decoded_b64)
    except Exception:
        pass

    for candidate in candidates:
        if ":" in candidate:
            method, password = candidate.split(":", 1)

            if method.strip() and password:
                return True

    return False


def parse_config(line):
    raw = line.strip()

    if not raw or "://" not in raw:
        raise ValueError("Invalid URL structure")

    protocol = raw.split("://", 1)[0].lower()

    if protocol not in {"vless", "trojan", "ss"}:
        raise ValueError("Unsupported protocol: " + protocol)

    try:
        parsed = urlsplit(raw)
        host = normalize_host(parsed.hostname)
        port = parsed.port
    except Exception as error:
        raise ValueError("Invalid address or port") from error

    if not host:
        raise ValueError("Invalid server IP or domain")

    if port is None or not 1 <= port <= 65535:
        raise ValueError("Invalid or missing port")

    if protocol == "vless":
        if not parsed.username or not unquote(parsed.username).strip():
            raise ValueError("Missing VLESS UUID")

    elif protocol == "trojan":
        if parsed.username is None or not unquote(parsed.username):
            raise ValueError("Missing Trojan password")

    elif protocol == "ss":
        if not valid_ss_auth(parsed):
            raise ValueError("Invalid Shadowsocks authentication")

    return protocol, host, int(port)


def open_fresh_nano():
    os.makedirs(BASE_DIR, exist_ok=True)

    with open(INPUT_FILE, "w", encoding="utf-8", newline="") as file:
        file.write("")

    say("\nOpening Nano with an empty input file.")
    say("Paste your configurations.")
    say("Press Ctrl+O, Enter, then Ctrl+X to save and exit.\n")

    try:
        result = subprocess.run(
            ["nano", INPUT_FILE],
            check=False
        )

        if result.returncode not in (0, None):
            say(
                "Warning: Nano exited with code "
                + str(result.returncode)
            )

    except FileNotFoundError:
        say("Nano is not installed.")
        say("Install it using: pkg install nano")
        raise SystemExit(1)


def copy_clipboard(text):
    try:
        result = subprocess.run(
            ["termux-clipboard-set"],
            input=text,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

        return result.returncode == 0

    except FileNotFoundError:
        return False


def main():
    os.makedirs(BASE_DIR, exist_ok=True)

    say("=" * 54)
    say("       PRECISE CONFIGURATION DEDUPLICATOR")
    say("=" * 54)

    say("Nano opens with an empty input file.")
    say("Duplicate key: protocol + host + port")
    say("Supported protocols: VLESS / Trojan / Shadowsocks")
    say("No DNS, ping, network access, or connection.\n")

    open_fresh_nano()

    try:
        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8-sig",
            errors="replace",
            newline=""
        ) as file:
            content = file.read()

    except OSError as error:
        say("Input read error: " + str(error))
        return 1

    source_lines = content.splitlines()

    kept = []
    invalid = []
    duplicates = []
    seen = set()

    for original in source_lines:

        if not original.strip():
            continue

        try:
            key = parse_config(original)

        except ValueError:
            invalid.append(original)
            continue

        if key in seen:
            duplicates.append(original)

        else:
            seen.add(key)
            kept.append(original)

    write_exact_lines(OUTPUT_FILE, kept)
    write_exact_lines(INVALID_FILE, invalid)
    write_exact_lines(DUPLICATES_FILE, duplicates)

    clipboard_text = "\n".join(kept)

    if kept:
        clipboard_text += "\n"

    copied = copy_clipboard(clipboard_text)

    with open(
        INPUT_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        file.write("")

    say("\n" + "=" * 54)
    say("                    RESULTS")
    say("=" * 54)

    say("Input lines:             " + str(len(source_lines)))
    say("Unique valid configs:    " + str(len(kept)))
    say("Duplicate configs:       " + str(len(duplicates)))
    say("Invalid configs:         " + str(len(invalid)))

    say("\nOutput file: " + OUTPUT_FILE)
    say("Duplicates file: " + DUPLICATES_FILE)
    say("Invalid file: " + INVALID_FILE)

    say("Input file has been cleared.")

    if copied:
        say("\nUnique configurations copied to Android clipboard.")
        say("Open your main project Nano and paste the result.")

    else:
        say("\nAutomatic clipboard copy failed.")
        say("Install Termux:API and run:")
        say("pkg install termux-api")
        say("Unique configurations are saved in the output file.")

    say("\nRun again using:")
    say("python ~/yekta_sazi_daghigh.py")

    return 0


if __name__ == "__main__":

    try:
        sys.exit(main())

    except KeyboardInterrupt:
        say("\nOperation cancelled.")
        sys.exit(130)

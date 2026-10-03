#!/usr/bin/env python3
"""CAMSWEEP | Local network discovery and camera clues.

    python3 camsweep.py
    python3 camsweep.py --hide-mac
    python3 camsweep.py --json report.json

Discover devices -> identify manufacturers -> inspect ports -> explain clues.

Standard-library Python. No special WiFi adapter or root access required.
Use on networks you own or have permission to assess. Sleeping or isolated
cameras can remain invisible; a clean scan is not an all-clear.
"""

import argparse
import errno
import ipaddress
import json
import math
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ===========================================================================
# 01  PORTS, MANUFACTURERS, AND NETWORK DATA
# ===========================================================================
# These are detection hints, not a database of confirmed cameras.

CAMERA_PORTS = {
    554: "RTSP",
    8554: "RTSP-alt",
    10554: "RTSP-alt",
    37777: "Dahua-DVR",
    34567: "XMeye-DVR",
    8000: "shared-use",
    88: "shared-use",
    8899: "DVR",
    2020: "cam",
    80: "web",
    443: "web-tls",
    8080: "web-alt",
    8443: "web-tls-alt",
    49152: "dynamic-port",
}
# Streaming and recorder ports are clues, not confirmed identities.
STRONG_PORTS = {554, 8554, 10554, 37777, 34567}
# Shared-use ports also appear on servers and ordinary computers.
MEDIUM_PORTS = {8000, 88, 8899, 2020}
WEB_PORTS = {80, 443, 8080, 8443, 49152}

# Curated OUI (first 3 MAC bytes) -> vendor, focused on camera + smart-home brands.
CAM_OUI = {
    "3CA070": "Blink (Amazon camera)",
    "F0272D": "Wyze",
    "2CAA8E": "Wyze",
    "D03F27": "Wyze",
    "001788": "Philips Hue/IoT",
    "B0C554": "Reolink",
    "EC71DB": "Reolink",
    "9CA3A9": "Reolink",
    "BCAD28": "Amcrest",
    "3C1F3B": "Amcrest",
    "C0F945": "Hikvision",
    "44192F": "Hikvision",
    "BCBA5C": "Hikvision",
    "E0508B": "Dahua",
    "3CEF8C": "Dahua",
    "90020A": "Dahua",
    "001C27": "Foscam",
    "00626E": "Foscam",
    "8CEBC6": "Arlo",
    "40167E": "Arlo",
    "AC8BA9": "Eufy/Anker",
    "E0B94D": "Google/Nest",
    "F4F5D8": "Google/Nest",
    "1CF29A": "Google/Nest",
    "00248C": "Ring",
    "34D270": "Ring",
    "B47C9C": "Amazon (Ring/Echo)",
}
SMART_OUI_HINT = re.compile(
    r"amazon|google|nest|ring|wyze|blink|reolink|amcrest|hikvision|hangzhou|"
    r"dahua|foscam|arlo|eufy|anker|tp-link|tapo|xiaomi|tuya|espressif|"
    r"shenzhen|d-link|ubiquiti|logitech|sonoff|lorex|swann|vivotek|axis",
    re.I,
)
CAM_BRAND_HINT = re.compile(
    r"wyze|blink|reolink|amcrest|hikvision|hangzhou|dahua|foscam|arlo|eufy|"
    r"lorex|swann|vivotek|axis comm|nest|dropcam|xiongmai|xmeye",
    re.I,
)


@dataclass
class Network:
    """The local interface, its IPv4 range, and the router used by this scan."""

    ip: str
    subnet: str
    interface: str
    gateway: str | None
    mac: str = ""


# ===========================================================================
# 02  NETWORK DISCOVERY
# ===========================================================================
# Read the active interface and retain its real subnet mask.


def command(argv, timeout=8):
    """Run a bounded OS command without a shell; report failures clearly."""

    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"{argv[0]} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def normalized_mac(value):
    """Normalize a device MAC while rejecting multicast and empty addresses."""

    parts = re.split("[:-]", value.strip())
    if len(parts) != 6 or any(not re.fullmatch("[0-9a-fA-F]{1,2}", p) for p in parts):
        return ""
    mac = "".join(f"{int(p, 16):02X}" for p in parts)
    # Exclude broadcast and multicast addresses, but retain locally administered MACs.
    return "" if mac == "000000000000" or int(mac[:2], 16) & 1 else mac


def parse_mac_interface(text, interface, gateway):
    """Read an IPv4 address and its actual subnet mask from macOS ifconfig."""

    match = re.search(r"\binet (\d+\.\d+\.\d+\.\d+) netmask (\S+)", text)
    if not match:
        raise RuntimeError(f"No IPv4 address/netmask on {interface}")
    ip, mask = match.groups()
    if mask.startswith("0x"):
        mask = str(ipaddress.IPv4Address(int(mask, 16)))
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    mac = re.search(r"\bether (\S+)", text)
    return Network(
        ip, str(net), interface, gateway, normalized_mac(mac[1]) if mac else ""
    )


def detect_network():
    """Find the active interface and attached subnet using the host OS."""

    system = platform.system()
    if system == "Darwin":
        route = command(["route", "-n", "get", "default"])
        iface = re.search(r"interface:\s*(\S+)", route)
        gateway = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", route)
        if not iface:
            raise RuntimeError(
                "No active default interface. Connect to your LAN first."
            )
        name = iface[1]
        if name.startswith(("utun", "tun", "tap", "ppp")):
            raise RuntimeError(
                "Default route is a VPN/tunnel. "
                "Disconnect the VPN and retry on your LAN."
            )
        return parse_mac_interface(
            command(["ifconfig", name]), name, gateway[1] if gateway else None
        )
    if system == "Linux":
        routes = json.loads(command(["ip", "-j", "-4", "route", "show", "default"]))
        routes = sorted(
            (r for r in routes if r.get("dev")), key=lambda r: r.get("metric", 0)
        )
        if not routes:
            raise RuntimeError("No IPv4 default route. Connect to your LAN first.")
        route = routes[0]
        name = route["dev"]
        if name.startswith(("tun", "tap", "wg")):
            raise RuntimeError(
                "Default interface is a VPN/tunnel. "
                "Disconnect it before scanning your LAN."
            )
        adapters = json.loads(
            command(["ip", "-j", "-4", "address", "show", "dev", name])
        )
        for adapter in adapters:
            for addr in adapter.get("addr_info", []):
                if addr.get("family") == "inet" and addr.get("scope") == "global":
                    ip = addr["local"]
                    return Network(
                        ip,
                        str(
                            ipaddress.IPv4Network(
                                f"{ip}/{addr['prefixlen']}", strict=False
                            )
                        ),
                        name,
                        route.get("gateway"),
                        normalized_mac(adapter.get("address", "")),
                    )
        raise RuntimeError(f"No IPv4 address on {name}")
    if system == "Windows":
        script = """$ErrorActionPreference='Stop';
$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
Where-Object {$_.State -eq 'Alive'} |
Sort-Object @{Expression={$_.RouteMetric + $_.InterfaceMetric}} | Select-Object -First 1;
if (!$r) {throw 'No default route'};
$a=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex |
Where-Object {$_.AddressState -eq 'Preferred'} | Select-Object -First 1;
$m=Get-NetAdapter -InterfaceIndex $r.InterfaceIndex;
@{ip=$a.IPAddress; prefix=$a.PrefixLength; interface=$r.InterfaceIndex;
 gateway=$r.NextHop; mac=$m.MacAddress} | ConvertTo-Json -Compress"""
        data = json.loads(
            command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        )
        return Network(
            data["ip"],
            str(ipaddress.IPv4Network(f"{data['ip']}/{data['prefix']}", strict=False)),
            str(data["interface"]),
            data["gateway"],
            normalized_mac(data.get("mac") or ""),
        )
    raise RuntimeError(f"Unsupported platform: {system}")


def parse_neighbors(text, net, interface=None):
    """Keep valid device entries from the selected interface and subnet."""

    table = {}
    for line in text.splitlines():
        # macOS and ip-neigh include interface names; exclude other interfaces.
        iface = re.search(r"\b(?:on|dev) (\S+)", line)
        if interface and iface and iface[1] != interface:
            continue
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        mac_match = re.search(
            r"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b|"
            r"\b(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}\b",
            line,
        )
        if not ip_match or not mac_match:
            continue
        try:
            addr = ipaddress.IPv4Address(ip_match[0])
        except ValueError:
            continue
        mac = normalized_mac(mac_match[0])
        if (
            mac
            and addr in net
            and not addr.is_multicast
            and (
                net.prefixlen >= 31
                or addr not in (net.network_address, net.broadcast_address)
            )
        ):
            table[str(addr)] = mac
    return table


def neighbors(network, net):
    """Read the local neighbor cache without performing a vendor lookup."""

    system = platform.system()
    if system == "Linux":
        args = ["ip", "-4", "neigh", "show", "dev", network.interface]
    elif system == "Windows":
        args = ["arp", "-a", "-N", network.ip]
    else:
        args = ["arp", "-an"]
    return parse_neighbors(command(args), net, network.interface)


# ===========================================================================
# 03  DEVICE AND PORT PROBES
# ===========================================================================
# A refused TCP connection is still evidence that a device answered.


def ping(ip, timeout):
    """Send one bounded reachability probe using the platform ping utility."""

    system = platform.system()
    if system == "Windows":
        args = ["ping", "-n", "1", "-w", str(math.ceil(timeout * 1000)), ip]
    elif system == "Darwin":
        args = ["ping", "-n", "-c", "1", "-W", str(math.ceil(timeout * 1000)), ip]
    else:
        args = ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip]
    try:
        return (
            subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1,
            ).returncode
            == 0
        )
    except subprocess.TimeoutExpired:
        return False


def probe(ip, port, timeout):
    """An explicit refusal also proves a host responded; a timeout does not."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, port))
        except (OSError, OverflowError):
            return False, False
    return code == 0, code in (0, errno.ECONNREFUSED, 10061)


def scan_host(ip, timeout):
    """Check one device for open ports and any explicit TCP response."""

    ports, replied = {}, False
    for port, label in CAMERA_PORTS.items():
        opened, responded = probe(ip, port, timeout)
        replied |= responded
        if opened:
            ports[port] = label
    return ports, replied


# ===========================================================================
# 04  MANUFACTURER AND SAVED IDENTITY
# ===========================================================================
# Manufacturer hints and saved names are different sources of information.


def load_vendors():
    """Load local manufacturer prefixes once, then add the bundled hints."""

    vendors = {}
    for path in (
        "/opt/homebrew/share/nmap/nmap-mac-prefixes",
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/local/share/nmap/nmap-mac-prefixes",
    ):
        try:
            for line in Path(path).read_text().splitlines():
                fields = line.split(None, 1)
                if len(fields) == 2 and re.fullmatch("[0-9A-Fa-f]{6}", fields[0]):
                    vendors[fields[0].upper()] = fields[1]
        except OSError:
            continue
    # Prefer the curated hints when an optional local database also has a match.
    vendors.update(CAM_OUI)
    return vendors


def vendor_for(mac, vendors):
    """Match a hardware prefix; randomized MACs do not identify a maker."""

    if not mac:
        return "unknown"
    # The locally administered bit means a vendor-prefix guess is unreliable.
    if int(mac[:2], 16) & 2:
        return "private/local MAC"
    return vendors.get(mac[:6], "unknown")


def apply_saved_labels(rows, path):
    """Labels are prior user knowledge, never a new network-detection claim."""
    if not path.exists():
        return
    data = json.loads(path.read_text())
    if (
        not isinstance(data, dict)
        or data.get("version") != 1
        or not isinstance(data.get("devices"), dict)
    ):
        raise ValueError(f"Invalid saved-device file: {path}")
    for row in rows:
        identity = data["devices"].get(row["mac"])
        if identity:
            if not isinstance(identity, dict) or not isinstance(
                identity.get("name"), str
            ):
                raise ValueError(f"Invalid saved identity for {row['mac']}")
            row["label"] = identity["name"]
            row["label_source"] = identity.get("source", "manually assigned")


# ===========================================================================
# 05  CAMERA CLUES AND DEVICE EVIDENCE
# ===========================================================================
# Keep live responses separate from entries seen only in the neighbor cache.


def verdict(ip, network, vendor, ports):
    """Explain the strongest observed clue without claiming a confirmed camera."""

    if ip == network.ip:
        return "THIS COMPUTER", False
    if ip == network.gateway:
        return "ROUTER", False
    # Rank service clues before manufacturer hints; neither proves identity.
    if STRONG_PORTS.intersection(ports):
        return "CAMERA CLUE: streaming/DVR port", True
    if CAM_BRAND_HINT.search(vendor):
        return "CAMERA CLUE: brand (may be a hub)", True
    if MEDIUM_PORTS.intersection(ports):
        return "CHECK: shared-use port", False
    if SMART_OUI_HINT.search(vendor):
        return "CHECK: smart-home vendor", False
    return "No camera clue found", False


def assemble_rows(network, net, before, after, pinged, tcp, vendors):
    """Merge discovery evidence while keeping stale cache entries unconfirmed."""

    macs = {**before, **after}
    if ipaddress.IPv4Address(network.ip) in net:
        macs[network.ip] = network.mac
    ips = (
        set(macs)
        | {ip for ip, alive in pinged.items() if alive}
        | {ip for ip, (ports, replied) in tcp.items() if ports or replied}
    )
    rows = []
    for ip in sorted(ips, key=ipaddress.IPv4Address):
        if ipaddress.IPv4Address(ip) not in net:
            continue
        ports, tcp_reply = tcp.get(ip, ({}, False))
        evidence = []
        if pinged.get(ip):
            evidence.append("ping reply")
        if tcp_reply:
            evidence.append("TCP reply")
        if ip in after and (ip not in before or before[ip] != after[ip]):
            evidence.append("new neighbor entry")
        if ip == network.ip:
            evidence.append("local interface")
        state = "responding" if evidence else "cached/unconfirmed"
        mac = macs.get(ip, "")
        vendor = vendor_for(mac, vendors)
        assessment, flagged = verdict(ip, network, vendor, ports)
        rows.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "state": state,
                "evidence": evidence or ["neighbor cache only"],
                "ports": {str(k): v for k, v in ports.items()},
                "verdict": assessment,
                "camera_clue": flagged,
            }
        )
    return rows


# ===========================================================================
# 06  THE SCAN PIPELINE
# ===========================================================================
# Take a baseline, probe in parallel, then merge the observed evidence.


def sweep(network, net, timeout):
    """Discover neighbors, probe the subnet, and assemble the device inventory."""

    import shutil

    warnings = []

    def read_neighbors():
        """Report cache-read failures without discarding other discovery methods."""

        try:
            return neighbors(network, net)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            message = f"Neighbor discovery unavailable: {exc}"
            if message not in warnings:
                warnings.append(message)
            return {}

    # Snapshot first so cached devices are not mistaken for fresh responses.
    before = read_neighbors()
    hosts = [str(ip) for ip in net.hosts() if str(ip) != network.ip]
    pinged = {}

    # Stage 1: find devices even when no camera service is listening.
    if shutil.which("ping"):
        progress(f"01 / DISCOVER    Probing {len(hosts)} IPv4 addresses")
        with ThreadPoolExecutor(max_workers=48) as pool:
            pending = {pool.submit(ping, ip, max(timeout, 0.5)): ip for ip in hosts}
            for job in as_completed(pending):
                pinged[pending[job]] = job.result()
    else:
        warnings.append(
            "ping utility missing; discovery uses TCP and the neighbor cache."
        )

    # Stage 2: collect open ports and explicit connection refusals.
    progress("02 / INSPECT     Checking device ports")
    tcp = {}
    with ThreadPoolExecutor(max_workers=64) as pool:
        pending = {pool.submit(scan_host, ip, timeout): ip for ip in hosts}
        done = 0
        for job in as_completed(pending):
            tcp[pending[job]] = job.result()
            done += 1
            if done % 8 == 0 or done == len(hosts):
                progress("ports", done, len(hosts))

    # Stage 3: merge replies with neighbor entries resolved during this sweep.
    after = read_neighbors()
    return assemble_rows(
        network, net, before, after, pinged, tcp, load_vendors()
    ), warnings


# ===========================================================================
# 07  TERMINAL PRESENTATION
# ===========================================================================
# Readable output for recording, with plain text when redirected.


def terminal_width():
    """Keep the output comfortable in both wide and narrow terminals."""

    import shutil

    return max(32, min(120, shutil.get_terminal_size((100, 24)).columns))


def color_enabled():
    """Use color only in an interactive terminal that has not opted out."""

    import os

    return (
        sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM") != "dumb"
    )


def clean_text(value):
    """Remove control characters from device names before displaying them."""

    return "".join(ch for ch in str(value) if ch.isprintable())


def paint(value, style):
    """Style terminal text without adding escape sequences to redirected output."""

    value = clean_text(value)
    codes = {
        "title": "1;36",
        "bold": "1",
        "muted": "90",
        "live": "32",
        "cached": "33",
        "clue": "1;31",
        "check": "33",
    }
    return f"\033[{codes[style]}m{value}\033[0m" if color_enabled() else value


def rule():
    """Draw a quiet divider sized to the current terminal."""

    print(paint("  " + "-" * (terminal_width() - 4), "muted"))


def wrapped(value, style=None, indent="  "):
    """Wrap a paragraph while preserving the terminal layout and indentation."""

    import textwrap

    for line in textwrap.wrap(
        clean_text(value),
        width=terminal_width() - len(indent) - 1,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]:
        print(indent + (paint(line, style) if style else line))


def print_header(network, net):
    """Introduce the detected network before discovery begins."""

    print()
    wrapped("CAMSWEEP", "title")
    wrapped("LOCAL NETWORK / DEVICE DISCOVERY", "muted")
    rule()
    wrapped(f"Network  {net}    Interface  {network.interface}")
    wrapped(
        f"This computer  {network.ip}    Router  {network.gateway or 'unknown'}",
        "muted",
    )
    print()


def progress(label, done=None, total=None):
    """Show a compact live progress bar, or plain completion text in logs."""

    if done is None:
        wrapped(label, "muted")
        sys.stdout.flush()
        return
    fraction = done / total if total else 1
    count = round(20 * fraction)
    text = f"  [{'=' * count}{'.' * (20 - count)}] {fraction:>4.0%}  {done}/{total}"
    if sys.stdout.isatty():
        print(
            "\r" + paint(text[: terminal_width() - 1], "muted"),
            end="\n" if done == total else "",
            flush=True,
        )
    elif done == total:
        wrapped(f"Port checks complete: {done}/{total} addresses.", "muted")


def print_rows(rows, hide_mac=False):
    """Present device identities, liveness, and camera clues as separate facts."""

    active = sum(r["state"] == "responding" for r in rows)
    cached = len(rows) - active
    clues = sum(r["camera_clue"] for r in rows)
    print()
    wrapped("SCAN RESULTS", "bold")
    wrapped(
        f"{len(rows)} entries  /  {active} responding  /  "
        f"{cached} cached  /  {clues} camera clue{'s' if clues != 1 else ''}",
        "bold",
    )
    rule()
    wide = terminal_width() >= 96
    if wide:
        print(
            paint(
                f"  {'DEVICE':<25}  {'IP ADDRESS':<15}  {'STATE':<10}  ASSESSMENT",
                "muted",
            )
        )
        print()
    if not rows:
        wrapped("No devices observed in this range.", "muted")
    for row in rows:
        saved = bool(row.get("label"))
        name = clean_text(
            row.get("label")
            or (
                "This computer"
                if row["verdict"] == "THIS COMPUTER"
                else "Router"
                if row["verdict"] == "ROUTER"
                else row["vendor"]
            )
        )
        display_name = name + (" *" if saved else "")
        state = "RESPONDING" if row["state"] == "responding" else "CACHED"
        state_style = "live" if state == "RESPONDING" else "cached"
        assessment = row["verdict"]
        verdict_style = (
            "clue"
            if row["camera_clue"]
            else "check"
            if assessment.startswith("CHECK")
            else "muted"
        )
        if wide:
            short_name = (
                display_name if len(display_name) <= 25 else display_name[:22] + "..."
            )
            print(
                "  "
                + paint(f"{short_name:<25}", "bold")
                + "  "
                + f"{row['ip']:<15}  "
                + paint(f"{state:<10}", state_style)
                + "  "
                + paint(assessment, verdict_style)
            )
            if len(display_name) > 25:
                wrapped(display_name, "bold", indent="    ")
        else:
            wrapped(display_name, "bold")
            wrapped(f"{row['ip']}  /  {state}", state_style, indent="    ")
            wrapped(assessment, verdict_style, indent="    ")
        if saved:
            wrapped(f"Maker: {row['vendor']}", "muted", indent="    ")
        mac = (
            ":".join(row["mac"][i : i + 2] for i in range(0, len(row["mac"]), 2))
            or "unavailable"
        )
        ports = (
            ", ".join(f"{p}/{name}" for p, name in row["ports"].items())
            or "none in tested set"
        )
        details = f"Ports: {ports}" if hide_mac else f"MAC {mac}  |  Ports: {ports}"
        wrapped(details, "muted", indent="    ")
        print()
    rule()
    wrapped("HOW TO READ THIS", "bold")
    if any(row.get("label") for row in rows):
        wrapped("* Saved names are prior identifications, not new detections.", "muted")
    wrapped(
        "RESPONDING = observed this scan (includes this computer). "
        "CACHED = neighbor record only; current presence unconfirmed.",
        "muted",
    )
    wrapped(
        "Camera clues are not confirmed cameras. A brand match may be a hub; "
        "private MACs may hide the maker.",
        "muted",
    )
    wrapped(
        "Sleeping or isolated devices, other networks, "
        "and SD-card-only cameras can be missed.",
        "muted",
    )
    print()
    wrapped("BATTERY CAMERA TIP", "bold")
    wrapped(
        "Keep Live View open in its app while scanning "
        "to give the camera a chance to respond."
    )
    print()


# ===========================================================================
# 08  COMMAND-LINE ENTRY POINT
# ===========================================================================
# Run with no arguments, or hide MAC addresses while recording.


def positive_timeout(value):
    """Validate a finite timeout before opening any network connections."""

    value = float(value)
    if not math.isfinite(value) or not 0.05 <= value <= 10:
        raise argparse.ArgumentTypeError("timeout must be between 0.05 and 10 seconds")
    return value


def main(argv=None):
    """Connect argument parsing, discovery, presentation, and optional JSON export."""

    # Parse and validate before starting any discovery work.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subnet", help="Override the detected IPv4 subnet (CIDR)")
    parser.add_argument("--json", type=Path, help="Also write a JSON report")
    parser.add_argument(
        "--hide-mac",
        action="store_true",
        help="Hide MAC addresses in terminal output (JSON reports retain them)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=0.35,
        help="Per-port timeout seconds (default: 0.35)",
    )
    args = parser.parse_args(argv)
    network = detect_network()
    net = ipaddress.IPv4Network(args.subnet or network.subnet, strict=False)
    # Avoid accidentally probing huge routed ranges due to a VPN or unusual netmask.
    if net.num_addresses > 4096:
        raise RuntimeError(
            f"{net} is too large for this LAN sweep. "
            "Use --subnet with a range of /20 or smaller."
        )
    if not net.is_private or net.is_loopback or net.is_multicast or net.is_link_local:
        raise RuntimeError(f"{net} is not a supported private LAN range.")
    if not net.subnet_of(ipaddress.IPv4Network(network.subnet)):
        raise RuntimeError(f"{net} is outside the attached LAN {network.subnet}.")
    print_header(network, net)
    started = time.monotonic()
    rows, warnings = sweep(network, net, args.timeout)
    try:
        apply_saved_labels(
            rows, Path(__file__).resolve().with_name("camsweep-devices.json")
        )
    except (OSError, ValueError) as exc:
        warnings.append(f"Saved labels not loaded: {exc}")
    # Hiding MACs is a display choice; the underlying report stays intact.
    print_rows(rows, hide_mac=args.hide_mac)
    for warning in warnings:
        print(f"Notice: {warning}", file=sys.stderr)
    report = {
        "subnet": str(net),
        "you": network.ip,
        "gateway": network.gateway,
        "interface": network.interface,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "flagged": sum(r["camera_clue"] for r in rows),
        "devices": rows,
        "warnings": warnings,
    }
    wrapped(f"Completed in {report['elapsed_seconds']}s", "muted")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")
        wrapped(f"JSON report: {args.json}", "muted")
    return report


# Start only when executed directly; importing the module never scans.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"camsweep: {exc}", file=sys.stderr)
        sys.exit(1)

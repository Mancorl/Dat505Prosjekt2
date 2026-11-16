#!/usr/bin/env python3
"""
cups_detector.py — CUPS CVE-2024-47176 attack detection tool.
Detects the specific browse-packet + malicious IPP response pattern
used by the lab exploit script.
"""

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime

from scapy.all import (
    IP, UDP, TCP, Raw, sniff, rdpcap, wrpcap
)

logger = logging.getLogger("cups-detector")

# --------------------------------------------------------------------------- #
# Detection rules (tuned to the exploit script's markers)
# --------------------------------------------------------------------------- #

# Markers your attack script injects into the PPD via IPP attributes
MALICIOUS_PPD_MARKERS = [
    b"FoomaticRIPCommandLine",
    b"cupsFilter2",
    b"/tmp/I_AM_VULNERABLE",
    b"foomatic-rip",
]

# Browse packet regex: type state uri "location" "info" "make-model"
BROWSE_RE = re.compile(
    rb'^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(ipp://[^\s]+)'
    rb'\s+"([^"]*)"\s+"([^"]*)"(?:\s+"([^"]*)")?\s*$'
)

# Suspicious: browse URI points at a non-standard port (not 631)
SUSPICIOUS_URI_PORT_RE = re.compile(rb'ipp://[^:]+:(\d+)/')

# Threshold for repeated discovery messages from one source
DISCOVERY_BURST_THRESHOLD = 5
DISCOVERY_WINDOW_SECONDS = 10

# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
alerts = []
discovery_tracker = defaultdict(list)  # src_ip -> [timestamps]


def emit_alert(alert_type, severity, src, dst, detail, raw_summary=""):
    alert = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": alert_type,
        "severity": severity,
        "src": src,
        "dst": dst,
        "detail": detail,
        "raw_summary": raw_summary,
    }
    alerts.append(alert)
    logger.warning("[%s] %s -> %s : %s", alert_type, src, dst, detail)


# --------------------------------------------------------------------------- #
# Packet handlers
# --------------------------------------------------------------------------- #
def handle_udp_browse(pkt):
    """Detect forged CUPS browse advertisements on UDP/631."""
    if not pkt.haslayer(Raw):
        return
    payload = bytes(pkt[Raw].load)
    src = f"{pkt[IP].src}:{pkt[UDP].sport}"
    dst = f"{pkt[IP].dst}:{pkt[UDP].dport}"

    # Rule 1: malformed / unexpected browse packet structure
    m = BROWSE_RE.match(payload)
    if not m:
        # A UDP/631 packet that doesn't parse as a browse announcement is suspicious
        emit_alert(
            "MALFORMED_BROWSE",
            "medium", src, dst,
            "UDP/631 payload does not match CUPS browse format",
            payload[:120].decode("utf-8", "replace"),
        )
        return

    printer_type, printer_state, uri, location, info, make_model = m.groups()

    uri_str = uri.decode("utf-8", "replace")

    # Rule 2: unauthorized advertisement from a source that keeps sending
    now = datetime.utcnow().timestamp()
    discovery_tracker[pkt[IP].src].append(now)
    # prune old timestamps
    cutoff = now - DISCOVERY_WINDOW_SECONDS
    discovery_tracker[pkt[IP].src] = [
        t for t in discovery_tracker[pkt[IP].src] if t > cutoff
    ]
    if len(discovery_tracker[pkt[IP].src]) >= DISCOVERY_BURST_THRESHOLD:
        emit_alert(
            "REPEATED_DISCOVERY",
            "high", src, dst,
            f"{len(discovery_tracker[pkt[IP].src])} browse packets in "
            f"{DISCOVERY_WINDOW_SECONDS}s from same source",
            uri_str,
        )

    # Rule 3: URI points at a non-standard IPP port (classic exploit pattern)
    port_m = SUSPICIOUS_URI_PORT_RE.search(uri)
    if port_m and port_m.group(1) not in (b"631", b"443"):
        emit_alert(
            "SUSPICIOUS_IPP_URI",
            "high", src, dst,
            f"Printer advertisement points at non-standard port {port_m.group(1).decode()}",
            uri_str,
        )

    # Rule 4: type/state values inconsistent with legitimate printers
    #      (your script uses type=4, state=3; many real printers differ)
    type_val = int(printer_type.decode(), 16)
    state_val = int(printer_state.decode(), 16)
    if type_val & 0x04 and state_val != 3:
        emit_alert(
            "UNEXPECTED_PRINTER_STATE",
            "low", src, dst,
            f"Printer type/state combination unusual: type=0x{type_val:x}, state={printer_state.decode()}",
            uri_str,
        )


def handle_tcp_ipp(pkt):
    """Detect malicious PPD content in IPP responses on TCP/631 (or custom port)."""
    if not pkt.haslayer(Raw):
        return
    payload = bytes(pkt[Raw].load)
    src = f"{pkt[IP].src}:{pkt[TCP].sport}"
    dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"

    # Rule 5: the exploit script returns PPD text inside the IPP body
    for marker in MALICIOUS_PPD_MARKERS:
        if marker.lower() in payload.lower():
            emit_alert(
                "MALICIOUS_PPD_INJECTION",
                "critical", src, dst,
                f"IPP response contains exploit marker: {marker.decode()}",
                payload[:160].decode("utf-8", "replace"),
            )
            break  # one alert per packet

    # Rule 6: HTTP response to an IPP request that lacks a proper
    #         application/ipp content-type but carries PPD-like text
    if payload.startswith(b"HTTP/"):
        if b"application/ipp" not in payload.lower() and b"*" in payload and b":" in payload:
            emit_alert(
                "SUSPICIOUS_IPP_CONTENT",
                "medium", src, dst,
                "HTTP response lacks application/ipp but contains PPD-like directives",
                payload[:120].decode("utf-8", "replace"),
            )


def packet_handler(pkt):
    if IP not in pkt:
        return
    if UDP in pkt and (pkt[UDP].dport == 631 or pkt[UDP].sport == 631):
        handle_udp_browse(pkt)
    elif TCP in pkt and (pkt[TCP].dport == 631 or pkt[TCP].sport == 631 or
                          pkt[TCP].dport in (29995, 29999) or
                          pkt[TCP].sport in (29995, 29999)):
        handle_tcp_ipp(pkt)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def export_results(path, fmt):
    if not alerts:
        logger.info("No alerts to export.")
        return
    if fmt == "json":
        with open(path, "w") as f:
            json.dump(alerts, f, indent=2)
    else:  # csv
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)
    logger.info("Exported %d alerts to %s", len(alerts), path)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Detect CUPS CVE-2024-47176 exploitation traffic.",
    )
    p.add_argument("--pcap", help="Offline PCAP file to analyze.")
    p.add_argument("--iface", default=None,
                   help="Live capture interface (default: Scapy default).")
    p.add_argument("--count", type=int, default=0,
                   help="Stop after N packets (0 = unlimited).")
    p.add_argument("--csv", default="cups_alerts.csv",
                   help="CSV export path.")
    p.add_argument("--json", default="cups_alerts.json",
                   help="JSON export path.")
    p.add_argument("--export-fmt", choices=["csv", "json", "both"], default="both")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    level = logging.WARNING if args.verbose == 0 else (
        logging.INFO if args.verbose == 1 else logging.DEBUG
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.pcap:
        logger.info("Analyzing offline PCAP: %s", args.pcap)
        packets = rdpcap(args.pcap)
        for pkt in packets:
            packet_handler(pkt)
    else:
        logger.info("Starting live capture on %s ...", args.iface or "default iface")
        sniff(
            iface=args.iface,
            prn=packet_handler,
            store=False,
            count=args.count if args.count > 0 else 0,
            filter="udp port 631 or tcp port 631 or tcp port 29995 or tcp port 29999",
        )

    if args.export_fmt in ("csv", "both"):
        export_results(args.csv, "csv")
    if args.export_fmt in ("json", "both"):
        export_results(args.json, "json")

    logger.info("Detection complete. %d alert(s) generated.", len(alerts))
    return 0 if not alerts else 1


if __name__ == "__main__":
    sys.exit(main())
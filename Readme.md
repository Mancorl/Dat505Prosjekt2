Two tools for a school lab demonstrating the CUPS exploit chain (CVE-2024-47176 / 47076 / 47175 / 47177):

    cups_attack.py — attacker tool. Forges a printer advertisement, runs a malicious IPP server, and injects FoomaticRIPCommandLine into the target's generated PPD.

    CUPS_Attack_detection.py — detection tool. Sniffs the same traffic (live or from PCAP) and raises alerts for the attack pattern.


Cups_attack.py:
What it does

Sends a UDP/631 CUPS browse advertisement pointing at your machine.

Starts an IPP server that returns a crafted attribute containing FoomaticRIPCommandLine.

Target's cups-browsed writes the directive into a PPD under /etc/cups/ppd/.

When a print job is sent to that printer, foomatic-rip executes the injected command.

Usage:

sudo python3 cups_attack.py \
    --target 172.18.0.2 \
    --server-host 192.168.10.184 \
    --server-port 29999 \
    --command 'echo 1 > /tmp/I_AM_VULNERABLE' \
    --pcap browse.pcap \
    -vv \
    --no-interactive

Key arguments:
| Flag | Meaning |
|---|---|
| `--target` | CUPS server IP (`cups-browsed` host) |
| `--target-port` | UDP port, default `631` |
| `--server-host` | Your IP reachable from the target |
| `--server-port` | Port for the malicious IPP server |
| `--command` | Shell command injected via `FoomaticRIPCommandLine` |
| `--pcap` | Save the crafted browse packet to a PCAP |
| `-v` / `-vv` | INFO / DEBUG logging |
| `--no-interactive` | Run once instead of showing the menu |

Triggering the payload:
Adter the printer is registered, order a printjob, i did it through the webbrowser on this address, but it depends on the ip address of your docker bridge:

https://172.18.0.2:631/printers/

Choose your printer and trigger a test print to excecute the payload

Verifying the payload:

docker exec -it c382c3c49bad bash
Note: change c382c3c49bad to the given name of your docker instance

cd tmp

ls
your payload

CUPS_Attack_detection.py

What it detects:
| Alert | Severity | Trigger |
|---|---|---|
| `MALFORMED_BROWSE` | Medium | UDP/631 payload not matching the browse format |
| `REPEATED_DISCOVERY` | High | ≥ 5 browse packets from one source in 10 s |
| `SUSPICIOUS_IPP_URI` | High | Advertisement URI uses a non-standard port |
| `UNEXPECTED_PRINTER_STATE` | Low | Unusual type/state combination |
| `MALICIOUS_PPD_INJECTION` | Critical | IPP body contains `FoomaticRIPCommandLine`, `cupsFilter2`, `/tmp/I_AM_VULNERABLE` or `foomatic-rip` |
| `SUSPICIOUS_IPP_CONTENT` | Medium | HTTP response without `application/ipp` but with PPD-like text |

Usage:

Live Capture:
sudo python3 CUPS_Attack_detection.py --iface br-bc7a26718617 -v --count 200
Note: Replace br-... with your bridge interface

Offline PCAP analysis:
sudo python3 CUPS_Attack_detection.py --pcap browse.pcap --export-fmt both -vv

### Key arguments

| Flag | Meaning |
|---|---|
| `--pcap <file>` | Analyze an offline capture instead of live traffic |
| `--iface <name>` | Live capture interface (use the Docker bridge, e.g. `br-…`, not `eth0`) |
| `--count <N>` | Stop after N packets (`0` = unlimited) |
| `--csv <path>` / `--json <path>` | Export paths |
| `--export-fmt` | `csv`, `json` or `both` |
| `-v` / `-vv` | `INFO` / `DEBUG` logging |


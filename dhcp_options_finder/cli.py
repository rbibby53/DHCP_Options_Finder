"""dhcpprobe command-line interface."""
import argparse
import sys

from . import __version__
from .baseline import compare, load_baseline
from .net import ProbeError, default_interface, list_interfaces, parse_codes, parse_mac, probe
from .report import format_json, format_text, to_record


def main():
    ap = argparse.ArgumentParser(prog="dhcpprobe",
        description="Query DHCP server(s) and show every option they return.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("-i", "--iface", help="interface (default: the one with the default route)")
    ap.add_argument("-l", "--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("-m", "--mode", choices=["discover", "inform"], default="discover",
                    help="discover = what a new client gets (no lease taken); "
                         "inform = config for a host that already has an IP")
    ap.add_argument("--mac", help="client MAC to send: a MAC (to see that device's reservation), "
                                  "'iface' for this interface's MAC, or 'random'. Default: random "
                                  "for discover, interface MAC for inform")
    ap.add_argument("-V", "--vendor-class", help="option 60 to send (e.g. 'PXEClient', 'MSFT 5.0')")
    ap.add_argument("-H", "--hostname", help="option 12 to send")
    ap.add_argument("-r", "--request", default="1-254",
                    help="option codes to request, e.g. '1,3,6,43,66,67,150'")
    ap.add_argument("-s", "--server", help="send unicast to this server instead of broadcast")
    ap.add_argument("--server-port", type=int, default=67, help=argparse.SUPPRESS)
    ap.add_argument("--ciaddr", help="client IP for INFORM (default: interface IP)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0, help="seconds to collect replies")
    ap.add_argument("-1", "--first", action="store_true", help="stop after the first reply")
    ap.add_argument("-x", "--hex", action="store_true", help="also show raw hex for each option")
    ap.add_argument("-j", "--json", action="store_true", help="JSON output")
    ap.add_argument("-b", "--baseline", metavar="FILE",
                    help="compare the first reply to a saved JSON export; exit 3 if anything changed")
    ap.add_argument("--save-baseline", metavar="FILE", help="save the replies as JSON to use as a baseline")
    a = ap.parse_args()

    try:
        if a.list:
            d = default_interface()
            for i in list_interfaces():
                star = "*" if d and i["name"] == d["name"] else " "
                print(f"{star} {i['name']:<20} {i['ip'] or '-':<16} {i['mac']}  "
                      f"{'up' if i['up'] else 'down'}")
            return
        baseline = load_baseline(a.baseline) if a.baseline else None
        use_iface = (a.mac or "").lower() == "iface"
        mac = parse_mac(a.mac) if a.mac and not use_iface else None
        replies = probe(iface=a.iface, mode=a.mode, mac=mac, use_iface_mac=use_iface,
                        vendor_class=a.vendor_class, hostname=a.hostname,
                        request=parse_codes(a.request), server=a.server,
                        server_port=a.server_port, ciaddr=a.ciaddr, timeout=a.timeout,
                        first=a.first, log=None if a.json else (lambda m: print(m, file=sys.stderr)))
    except (ProbeError, ValueError, OSError) as e:
        sys.exit(f"Error: {e}")
    print(format_json(replies, baseline) if a.json else format_text(replies, a.hex, baseline))
    if a.save_baseline and replies:
        with open(a.save_baseline, "w", encoding="utf-8") as f:
            f.write(format_json(replies))
        print(f"Saved baseline to {a.save_baseline}", file=sys.stderr)
    if not replies:
        sys.exit(1)
    if baseline is not None and compare(to_record(replies[0]), baseline):
        sys.exit(3)


if __name__ == "__main__":
    main()

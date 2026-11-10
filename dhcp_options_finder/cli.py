"""dhcpprobe command-line interface."""
import argparse
import sys

from . import __version__, profiles
from .baseline import compare, load_baseline
from .net import ProbeError, default_interface, list_interfaces, parse_codes, parse_mac, probe, sweep
from .options import VENDOR_CLASS_PRESETS
from .report import format_json, format_sweep, format_sweep_json, format_text, to_record

# Settings a profile can supply. CLI flags win; then the profile; then these defaults.
DEFAULTS = {"iface": None, "mode": "discover", "mac": None, "vendor_class": None, "hostname": None,
            "server": None, "request": "1-254", "timeout": 5.0}


def _parser():
    ap = argparse.ArgumentParser(
        prog="dhcpprobe",
        description="Query DHCP server(s) and show every option they return.",
        epilog="Exit codes: 0 replies received, 1 no replies, 3 differs from --baseline.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("-i", "--iface", help="interface (default: the one with the default route)")
    ap.add_argument("-l", "--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("-m", "--mode", choices=["discover", "inform"],
                    help="discover = what a new client gets, no lease taken (default); "
                         "inform = config for a host that already has an IP")
    ap.add_argument("--mac", help="client MAC to send: a MAC (to see that device's reservation), "
                                  "'iface' for this interface's MAC, or 'random'. Default: random "
                                  "for discover, interface MAC for inform")
    ap.add_argument("-V", "--vendor-class", help="option 60 to send (e.g. 'OptiIpPhone', 'PXEClient')")
    ap.add_argument("-H", "--hostname", help="option 12 to send")
    ap.add_argument("-r", "--request", help="option codes to request, e.g. '1,3,6,43,66,67,150' "
                                            "(default 1-254)")
    ap.add_argument("-s", "--server", help="send unicast to this server instead of broadcast")
    ap.add_argument("--server-port", type=int, default=67, help=argparse.SUPPRESS)
    ap.add_argument("--ciaddr", help="client IP for INFORM (default: interface IP)")
    ap.add_argument("-t", "--timeout", type=float, help="seconds to collect replies (default 5)")
    ap.add_argument("-1", "--first", action="store_true", help="stop after the first reply")
    ap.add_argument("-x", "--hex", action="store_true", help="also show raw hex for each option")
    ap.add_argument("-j", "--json", action="store_true", help="JSON output")

    g = ap.add_argument_group("baselines")
    g.add_argument("-b", "--baseline", metavar="FILE",
                   help="compare the first reply to a saved JSON export; exit 3 if anything changed")
    g.add_argument("--save-baseline", metavar="FILE", help="save the replies as JSON to use as a baseline")

    g = ap.add_argument_group("vendor class sweep")
    g.add_argument("--sweep", action="store_true",
                   help="probe once per vendor class (same MAC) and show what each class gets "
                        f"differently. Classes: {', '.join(repr(v) for v in VENDOR_CLASS_PRESETS)}")
    g.add_argument("--sweep-classes", metavar="LIST",
                   help="comma-separated classes to sweep instead of the presets ('' = no option 60)")

    g = ap.add_argument_group("profiles")
    g.add_argument("-p", "--profile", metavar="NAME", help="load saved settings (flags still override)")
    g.add_argument("--save-profile", metavar="NAME", help="save this command's settings as a profile")
    g.add_argument("--list-profiles", action="store_true", help="list saved profiles and exit")
    g.add_argument("--delete-profile", metavar="NAME", help="delete a saved profile and exit")
    return ap


def _settings(a):
    """Effective settings: flags, then profile, then defaults."""
    prof = {}
    if a.profile:
        prof = profiles.get(a.profile)
        if prof is None:
            raise ValueError(f"No profile named {a.profile!r}. See --list-profiles.")
        if prof.get("use_iface_mac") and not prof.get("mac"):
            prof = {**prof, "mac": "iface"}
    out = {}
    for k, default in DEFAULTS.items():
        flag = getattr(a, k)
        out[k] = flag if flag is not None else prof.get(k, default)
    out["timeout"] = float(out["timeout"])
    return out


def _list_profiles():
    names = profiles.names()
    if not names:
        print(f"No saved profiles ({profiles.path()}).")
        return
    for n in names:
        p = profiles.get(n)
        bits = [f"{k}={p[k]}" for k in profiles.FIELDS if k in p]
        print(f"  {n:<20} {' '.join(bits)}")


def main():
    a = _parser().parse_args()
    log = None if a.json else (lambda m: print(m, file=sys.stderr))
    try:
        if a.list:
            d = default_interface()
            for i in list_interfaces():
                star = "*" if d and i["name"] == d["name"] else " "
                print(f"{star} {i['name']:<20} {i['ip'] or '-':<16} {i['mac']}  "
                      f"{'up' if i['up'] else 'down'}")
            return
        if a.list_profiles:
            _list_profiles()
            return
        if a.delete_profile:
            profiles.delete(a.delete_profile)
            print(f"Deleted profile {a.delete_profile!r}.", file=sys.stderr)
            return

        st = _settings(a)
        if a.save_profile:
            mac = st["mac"] or ""
            profiles.put(a.save_profile, {**st, "mac": "" if mac.lower() == "iface" else mac,
                                          "use_iface_mac": mac.lower() == "iface"})
            print(f"Saved profile {a.save_profile!r} to {profiles.path()}", file=sys.stderr)

        use_iface = (st["mac"] or "").lower() == "iface"
        mac = parse_mac(st["mac"]) if st["mac"] and not use_iface else None
        common = dict(iface=st["iface"], mode=st["mode"], mac=mac, use_iface_mac=use_iface,
                      hostname=st["hostname"], request=parse_codes(st["request"]),
                      server=st["server"], server_port=a.server_port, ciaddr=a.ciaddr,
                      timeout=st["timeout"])

        if a.sweep or a.sweep_classes is not None:
            classes = (VENDOR_CLASS_PRESETS if a.sweep_classes is None
                       else [c.strip() for c in a.sweep_classes.split(",")])
            progress = None if a.json else (
                lambda n, total, vc: print(f"Probe {n}/{total}: {vc or '(no option 60)'}", file=sys.stderr))
            used_mac, results = sweep(classes, progress=progress, **common)
            print(format_sweep_json(used_mac, results) if a.json else format_sweep(used_mac, results))
            sys.exit(0 if any(r for _, r in results) else 1)

        baseline = load_baseline(a.baseline) if a.baseline else None
        replies = probe(vendor_class=st["vendor_class"], first=a.first, log=log, **common)
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

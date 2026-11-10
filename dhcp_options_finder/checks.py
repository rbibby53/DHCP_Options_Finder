"""Config checks: flag likely DHCP scope misconfigurations in a reply."""
import ipaddress
import struct

from .options import _fmt_time, _ip


def _u32(b):
    return struct.unpack("!I", b)[0] if b is not None and len(b) == 4 else None


def _ips(b):
    return [_ip(b[i:i + 4]) for i in range(0, len(b), 4)] if b and len(b) % 4 == 0 else []


def check_reply(p):
    """Flag likely misconfigurations. Returns [{level: warn|info, option, message}]."""
    out = []
    o = dict(p["options"])

    def add(level, option, message):
        out.append({"level": level, "option": option, "message": message})

    client = p["yiaddr"] if p["yiaddr"] != "0.0.0.0" else p.get("ciaddr", "0.0.0.0")
    net = None
    if 1 not in o or len(o[1]) != 4:
        add("warn", 1, "No subnet mask (1). Clients will guess the mask from the address class.")
    elif client != "0.0.0.0":
        try:
            net = ipaddress.IPv4Network(f"{client}/{_ip(o[1])}", strict=False)
        except ValueError:
            add("warn", 1, f"Subnet mask {_ip(o[1])} is not a valid contiguous mask.")
    if net and net.prefixlen < 31 and ipaddress.IPv4Address(client) in (
            net.network_address, net.broadcast_address):
        add("warn", None, f"Offered address {client} is the network or broadcast address of {net}.")

    routers = _ips(o.get(3))
    if not routers:
        add("warn", 3, "No router (3). Clients will have no default gateway.")
    elif net:
        for r in routers:
            if ipaddress.IPv4Address(r) not in net:
                add("warn", 3, f"Router {r} is outside the client subnet {net}.")
    if net and 28 in o and len(o[28]) == 4 and _ip(o[28]) != str(net.broadcast_address):
        add("warn", 28, f"Broadcast address {_ip(o[28])} doesn't match {net} "
                        f"(expected {net.broadcast_address}).")

    dns = _ips(o.get(6))
    if not dns:
        add("warn", 6, "No DNS servers (6).")
    elif len(dns) == 1:
        add("info", 6, "Only one DNS server (6), so there's no redundancy.")
    if 42 not in o:
        add("info", 42, "No NTP servers (42). Devices that take time from DHCP (many BAS "
                        "controllers, IP phones) won't sync, which skews trend and alarm timestamps.")

    lease, t1, t2 = _u32(o.get(51)), _u32(o.get(58)), _u32(o.get(59))
    if lease is not None and lease != 0xFFFFFFFF:
        if lease < 3600:
            add("info", 51, f"Short lease ({_fmt_time(lease)}). Fine for guest networks; "
                            "unusual for infrastructure.")
        if p.get("mac_source") == "interface" and lease % 60:
            add("info", 51, f"Lease time {_fmt_time(lease)} isn't a whole number of minutes, so it's "
                            "probably what's left of this computer's existing lease, not the scope's "
                            "configured lease. Probe with a random MAC to see the configured value.")
        if t1 is not None and t2 is not None and not t1 < t2 <= lease:
            add("warn", 58, f"Renewal timers are out of order: T1 {t1}s, T2 {t2}s, lease {lease}s "
                            "(expected T1 < T2 <= lease).")
    if 44 in o or 46 in o:
        add("info", 44 if 44 in o else 46, "WINS/NetBIOS options (44/46) are set. These are legacy; "
                                           "remove them if nothing on this segment still uses WINS.")

    tftp = {}
    if p.get("siaddr", "0.0.0.0") != "0.0.0.0" and (66 in o or 150 in o or p.get("file")):
        tftp["siaddr"] = p["siaddr"]
    if 66 in o:
        try:
            tftp["option 66"] = str(ipaddress.IPv4Address(o[66].decode("ascii").strip("\x00").strip()))
        except (ValueError, UnicodeDecodeError):
            pass  # hostname; can't compare without DNS
    for ip in _ips(o.get(150))[:1]:
        tftp["option 150"] = ip
    if len(set(tftp.values())) > 1:
        add("info", 66, "TFTP server differs between " + ", ".join(f"{k} ({v})" for k, v in tftp.items())
            + ". Devices differ in which one they use.")
    return out

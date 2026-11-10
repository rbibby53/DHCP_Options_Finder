"""IPv6 Router Solicitation / Router Advertisement (RFC 4861 and friends)."""
import ipaddress
import struct

from .options import _dns_names, _fmt_time

ALL_ROUTERS = "ff02::2"
RS_TYPE, RA_TYPE = 133, 134
PREFERENCE = {0: "medium", 1: "high", 2: "reserved", 3: "low"}  # 2-bit Prf field

OPTION_NAMES = {1: "Source Link-Layer Address", 3: "Prefix Information", 5: "MTU",
                24: "Route Information", 25: "Recursive DNS Servers (RDNSS)",
                26: "RA Flags Extension", 31: "DNS Search List (DNSSL)", 37: "Captive Portal",
                38: "NAT64 Prefix (PREF64)"}


def checksum(src, dst, icmp):
    """ICMPv6 checksum over the IPv6 pseudo-header (RFC 8200 section 8.1)."""
    pseudo = (ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
              + struct.pack("!I3xB", len(icmp), 58))
    data = pseudo + icmp + (b"\x00" if len(icmp) % 2 else b"")
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_rs(src=None, mac=None):
    """Router Solicitation. Checksum is filled in when the source is known; Linux and macOS
    recompute it anyway. A source link-layer option is only allowed with a real source."""
    body = bytearray(struct.pack("!BBHI", RS_TYPE, 0, 0, 0))
    if mac and src:
        body += bytes([1, 1]) + mac
    if src:
        struct.pack_into("!H", body, 2, checksum(src, ALL_ROUTERS, bytes(body)))
    return bytes(body)


def _lifetime(n):
    return "infinite" if n == 0xFFFFFFFF else _fmt_time(n)


def _prefix(raw, plen):
    raw = (raw + b"\x00" * 16)[:16]
    return ipaddress.IPv6Network((ipaddress.IPv6Address(raw), plen), strict=False)


def parse_ra(pkt):
    """Parse an RA (ICMPv6 message, no IPv6 header). None if it isn't one."""
    if len(pkt) < 16 or pkt[0] != RA_TYPE or pkt[1] != 0:
        return None
    hop, flags, lifetime, reachable, retrans = struct.unpack("!BBHII", pkt[4:16])
    ra = {
        "hop_limit": hop, "managed": bool(flags & 0x80), "other": bool(flags & 0x40),
        "home_agent": bool(flags & 0x20), "preference": PREFERENCE[(flags >> 3) & 3],
        "proxy": bool(flags & 0x04), "router_lifetime": lifetime,
        "reachable_ms": reachable, "retrans_ms": retrans,
        "prefixes": [], "routes": [], "rdnss": [], "dnssl": [], "mtu": None, "mac": None,
        "captive_portal": None, "pref64": [], "unknown": [],
    }
    i = 16
    while i + 2 <= len(pkt):
        t, ln = pkt[i], pkt[i + 1] * 8
        if ln == 0 or i + ln > len(pkt):
            break  # malformed; RFC says discard the rest
        o = pkt[i:i + ln]
        if t == 1 and ln >= 8:
            ra["mac"] = o[2:8].hex(":")
        elif t == 3 and ln == 32:
            plen, pf, valid, pref = struct.unpack("!BBII", o[2:12])
            ra["prefixes"].append({"prefix": str(_prefix(o[16:32], plen)), "length": plen,
                                   "on_link": bool(pf & 0x80), "autonomous": bool(pf & 0x40),
                                   "valid": valid, "preferred": pref})
        elif t == 5 and ln >= 8:
            ra["mtu"] = struct.unpack("!I", o[4:8])[0]
        elif t == 24 and ln >= 8:
            plen, rf, life = struct.unpack("!BBI", o[2:8])
            ra["routes"].append({"prefix": str(_prefix(o[8:], plen)), "lifetime": life,
                                 "preference": PREFERENCE[(rf >> 3) & 3]})
        elif t == 25 and ln >= 24:
            life = struct.unpack("!I", o[4:8])[0]
            ra["rdnss"] += [{"server": str(ipaddress.IPv6Address(o[j:j + 16])), "lifetime": life}
                            for j in range(8, ln - 15, 16)]
        elif t == 31 and ln >= 16:
            life = struct.unpack("!I", o[4:8])[0]
            try:
                names = [n for n in _dns_names(o[8:].rstrip(b"\x00") + b"\x00") if n]
            except (ValueError, IndexError):
                names = []
            ra["dnssl"] += [{"domain": n, "lifetime": life} for n in names]
        elif t == 37:
            ra["captive_portal"] = o[2:].rstrip(b"\x00").decode("utf-8", "replace")
        elif t == 38 and ln == 16:
            sl_plc = struct.unpack("!H", o[2:4])[0]
            plen = {0: 96, 1: 64, 2: 56, 3: 48, 4: 40, 5: 32}.get(sl_plc & 7)
            if plen:
                ra["pref64"].append({"prefix": str(_prefix(o[4:16], plen)),
                                     "lifetime": (sl_plc >> 3) * 8})
        elif t != 26:
            ra["unknown"].append({"type": t, "raw": o.hex()})
        i += ln
    return ra


def describe(ra):
    """[(label, value)] rows for display."""
    flags = [n for n, on in (("Managed (M): use DHCPv6 for addresses", ra["managed"]),
                             ("Other config (O): use DHCPv6 for DNS etc.", ra["other"])) if on]
    life = ra["router_lifetime"]
    rows = [("Default router", f"yes, lifetime {_fmt_time(life)}, preference {ra['preference']}"
             if life else "no (lifetime 0: advertises routes/prefixes only)")]
    if life or flags:  # flags only matter coming from a default router
        rows.append(("Flags", "; ".join(flags) or "none (SLAAC only, no DHCPv6)"))
    if ra["mac"]:
        rows.append(("Router MAC", ra["mac"]))
    for p in ra["prefixes"]:
        how = ", ".join(x for x, on in (("on-link", p["on_link"]), ("SLAAC", p["autonomous"])) if on)
        rows.append(("Prefix", f"{p['prefix']} ({how or 'no flags'}; valid {_lifetime(p['valid'])}, "
                               f"preferred {_lifetime(p['preferred'])})"))
    for r in ra["routes"]:
        rows.append(("Route", f"{r['prefix']} (lifetime {_lifetime(r['lifetime'])}, "
                              f"preference {r['preference']})"))
    for d in ra["rdnss"]:
        rows.append(("DNS server (RDNSS)", f"{d['server']} (lifetime {_lifetime(d['lifetime'])})"))
    for d in ra["dnssl"]:
        rows.append(("Search domain (DNSSL)", f"{d['domain']} (lifetime {_lifetime(d['lifetime'])})"))
    if ra["mtu"]:
        rows.append(("MTU", str(ra["mtu"])))
    for p in ra["pref64"]:
        rows.append(("NAT64 prefix (PREF64)", f"{p['prefix']} (lifetime {p['lifetime']} s)"))
    if ra["captive_portal"]:
        rows.append(("Captive portal", ra["captive_portal"]))
    if ra["hop_limit"]:
        rows.append(("Hop limit", str(ra["hop_limit"])))
    for u in ra["unknown"]:
        rows.append((f"Option {u['type']}", f"0x{u['raw']}"))
    return rows

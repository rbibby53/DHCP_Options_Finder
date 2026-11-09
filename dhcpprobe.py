#!/usr/bin/env python3
"""
DHCP Options Finder (dhcpprobe CLI) - ask the DHCP server(s) on a segment which options they hand out.

Sends a DHCPDISCOVER (default) or DHCPINFORM that requests every option code
(1-254), collects every OFFER/ACK that comes back within the timeout, and
decodes the options. Never sends a DHCPREQUEST, so no lease is taken.

Linux only. Must run as root (binds UDP/68). Python 3.8+, stdlib only.
"""
import argparse
import ipaddress
import json
import os
import random
import select
import socket
import struct
import sys
import time

__version__ = "0.1.0"

MAGIC = b"\x63\x82\x53\x63"
SO_BINDTODEVICE = 25
SIOCGIFADDR = 0x8915

MSG_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
             6: "NAK", 7: "RELEASE", 8: "INFORM"}

# code: (name, decoder)
OPTIONS = {
    1: ("Subnet Mask", "ip"), 2: ("Time Offset", "s32"), 3: ("Router", "ips"),
    4: ("Time Server", "ips"), 5: ("Name Server (IEN 116)", "ips"),
    6: ("DNS Servers", "ips"), 7: ("Log Server", "ips"), 8: ("Cookie Server", "ips"),
    9: ("LPR Server", "ips"), 10: ("Impress Server", "ips"),
    11: ("Resource Location Server", "ips"), 12: ("Host Name", "str"),
    13: ("Boot File Size", "u16"), 14: ("Merit Dump File", "str"),
    15: ("Domain Name", "str"), 16: ("Swap Server", "ip"), 17: ("Root Path", "str"),
    18: ("Extensions Path", "str"), 19: ("IP Forwarding", "bool"),
    20: ("Non-Local Source Routing", "bool"), 21: ("Policy Filter", "ippairs"),
    22: ("Max Datagram Reassembly", "u16"), 23: ("Default IP TTL", "u8"),
    24: ("Path MTU Aging Timeout", "time"), 25: ("Path MTU Plateau Table", "u16s"),
    26: ("Interface MTU", "u16"), 27: ("All Subnets Local", "bool"),
    28: ("Broadcast Address", "ip"), 29: ("Perform Mask Discovery", "bool"),
    30: ("Mask Supplier", "bool"), 31: ("Perform Router Discovery", "bool"),
    32: ("Router Solicitation Address", "ip"), 33: ("Static Routes", "ippairs"),
    34: ("Trailer Encapsulation", "bool"), 35: ("ARP Cache Timeout", "time"),
    36: ("Ethernet Encapsulation", "bool"), 37: ("TCP Default TTL", "u8"),
    38: ("TCP Keepalive Interval", "time"), 39: ("TCP Keepalive Garbage", "bool"),
    40: ("NIS Domain", "str"), 41: ("NIS Servers", "ips"), 42: ("NTP Servers", "ips"),
    43: ("Vendor Specific Info", "vendor43"), 44: ("NetBIOS Name Servers (WINS)", "ips"),
    45: ("NetBIOS Datagram Distribution", "ips"), 46: ("NetBIOS Node Type", "nbnode"),
    47: ("NetBIOS Scope", "str"), 48: ("X Window Font Server", "ips"),
    49: ("X Window Display Manager", "ips"), 50: ("Requested IP", "ip"),
    51: ("Lease Time", "time"), 52: ("Option Overload", "u8"),
    53: ("Message Type", "msgtype"), 54: ("Server Identifier", "ip"),
    55: ("Parameter Request List", "u8s"), 56: ("Message", "str"),
    57: ("Max DHCP Message Size", "u16"), 58: ("Renewal Time (T1)", "time"),
    59: ("Rebinding Time (T2)", "time"), 60: ("Vendor Class Identifier", "str"),
    61: ("Client Identifier", "hex"), 62: ("NetWare/IP Domain", "str"),
    64: ("NIS+ Domain", "str"), 65: ("NIS+ Servers", "ips"),
    66: ("TFTP Server Name", "str"), 67: ("Bootfile Name", "str"),
    68: ("Mobile IP Home Agent", "ips"), 69: ("SMTP Servers", "ips"),
    70: ("POP3 Servers", "ips"), 71: ("NNTP Servers", "ips"), 72: ("WWW Servers", "ips"),
    73: ("Finger Servers", "ips"), 74: ("IRC Servers", "ips"),
    75: ("StreetTalk Servers", "ips"), 76: ("STDA Servers", "ips"),
    77: ("User Class", "hex"), 81: ("Client FQDN", "fqdn"),
    82: ("Relay Agent Information", "opt82"), 85: ("NDS Servers", "ips"),
    86: ("NDS Tree Name", "str"), 87: ("NDS Context", "str"),
    93: ("Client System Architecture", "u16s"), 94: ("Client Network Interface ID", "hex"),
    97: ("Client Machine ID (UUID/GUID)", "hex"), 100: ("POSIX Timezone (PCode)", "str"),
    101: ("TZ Database Timezone (TCode)", "str"), 108: ("IPv6-Only Preferred", "time"),
    114: ("Captive Portal URI", "str"), 116: ("Auto-Configure", "u8"),
    118: ("Subnet Selection", "ip"), 119: ("Domain Search List", "dnslist"),
    120: ("SIP Servers", "sip"), 121: ("Classless Static Routes", "cidr"),
    125: ("Vendor-Identifying Vendor Specific", "opt125"),
    128: ("PXE: TFTP Server / Etherboot", "hex"), 129: ("PXE: Call Server", "hex"),
    138: ("CAPWAP Access Controllers", "ips"), 150: ("TFTP Server Address (Cisco)", "ips"),
    176: ("Avaya IP Telephone", "str"), 208: ("PXELINUX Magic", "hex"),
    209: ("PXELINUX Config File", "str"), 210: ("PXELINUX Path Prefix", "str"),
    211: ("PXELINUX Reboot Time", "time"), 212: ("6rd", "hex"),
    213: ("Access Network Domain Name", "dnslist"), 242: ("Avaya IP Phone (site)", "str"),
    249: ("MS Classless Static Routes", "cidr"), 252: ("WPAD URL", "str"),
}

OPT82_SUB = {1: "Circuit-ID", 2: "Remote-ID", 5: "Link Selection",
             9: "Vendor-Specific", 11: "Server ID Override", 151: "VSS", 152: "VSS Control"}


# ---------------------------------------------------------------- decoding

def _ip(b):
    return str(ipaddress.IPv4Address(bytes(b)))


def _printable(b):
    try:
        s = bytes(b).decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if all(32 <= ord(c) < 127 for c in s.rstrip("\x00")) else None


def _hex(b):
    return bytes(b).hex(":") if b else ""


def _str_or_hex(b):
    s = _printable(b)
    return s.rstrip("\x00") if s is not None and s.rstrip("\x00") else f"0x{bytes(b).hex()}"


def _fmt_time(n):
    if n == 0xFFFFFFFF:
        return "infinite"
    parts, rem = [], n
    for unit, sec in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if rem >= sec:
            parts.append(f"{rem // sec}{unit}")
            rem %= sec
    return f"{n} s ({' '.join(parts) or '0s'})"


def _dns_names(data):
    """RFC 1035 wire-format name list with compression (RFC 3397)."""
    names, i = [], 0
    while i < len(data):
        labels, j, jumped, end, hops = [], i, False, None, 0
        while True:
            if j >= len(data):
                raise ValueError("truncated")
            ln = data[j]
            if ln == 0:
                j += 1
                break
            if ln & 0xC0 == 0xC0:
                ptr = ((ln & 0x3F) << 8) | data[j + 1]
                if not jumped:
                    end = j + 2
                jumped, j, hops = True, ptr, hops + 1
                if hops > 64:
                    raise ValueError("pointer loop")
                continue
            labels.append(bytes(data[j + 1:j + 1 + ln]).decode("ascii", "replace"))
            j += 1 + ln
        names.append(".".join(labels))
        i = end if jumped else j
    return names


def _tlv(data):
    out, i = [], 0
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("bad TLV")
        c, ln = data[i], data[i + 1]
        if i + 2 + ln > len(data):
            raise ValueError("bad TLV")
        out.append((c, bytes(data[i + 2:i + 2 + ln])))
        i += 2 + ln
    return out


def _sub_value(v):
    s = _printable(v)
    if s is not None and s.strip("\x00"):
        return s.rstrip("\x00")
    if len(v) == 4:
        return f"{_ip(v)} (0x{v.hex()})"
    return f"0x{v.hex()}"


def decode(code, data):
    """Return a human-readable value (str or list[str])."""
    kind = OPTIONS.get(code, (None, "auto"))[1]
    d = bytes(data)
    try:
        if kind == "ip" and len(d) == 4:
            return _ip(d)
        if kind == "ips" and len(d) % 4 == 0 and d:
            return [_ip(d[i:i + 4]) for i in range(0, len(d), 4)]
        if kind == "ippairs" and len(d) % 8 == 0:
            return [f"{_ip(d[i:i+4])} -> {_ip(d[i+4:i+8])}" for i in range(0, len(d), 8)]
        if kind == "u8" and len(d) == 1:
            return str(d[0])
        if kind == "u8s":
            return ", ".join(str(x) for x in d)
        if kind == "u16" and len(d) == 2:
            return str(struct.unpack("!H", d)[0])
        if kind == "u16s" and len(d) % 2 == 0:
            return ", ".join(str(x) for x in struct.unpack(f"!{len(d)//2}H", d))
        if kind == "s32" and len(d) == 4:
            return f"{struct.unpack('!i', d)[0]} s"
        if kind == "time" and len(d) == 4:
            return _fmt_time(struct.unpack("!I", d)[0])
        if kind == "bool" and len(d) == 1:
            return "true" if d[0] else "false"
        if kind == "str":
            return _str_or_hex(d)
        if kind == "hex":
            return f"0x{d.hex()}"
        if kind == "msgtype" and len(d) == 1:
            return MSG_TYPES.get(d[0], str(d[0]))
        if kind == "nbnode" and len(d) == 1:
            return {1: "B-node", 2: "P-node", 4: "M-node", 8: "H-node"}.get(d[0], str(d[0]))
        if kind == "dnslist":
            return _dns_names(d)
        if kind == "sip" and d:
            return _dns_names(d[1:]) if d[0] == 0 else [_ip(d[i:i+4]) for i in range(1, len(d), 4)]
        if kind == "fqdn" and len(d) >= 3:
            name = d[3:]
            try:
                n = ", ".join(_dns_names(name)) if d[0] & 0x04 else name.decode()
            except Exception:
                n = name.decode("ascii", "replace")
            return f"{n} (flags=0x{d[0]:02x})"
        if kind == "cidr":
            routes, i = [], 0
            while i < len(d):
                w = d[i]
                n = (w + 7) // 8
                dst = d[i + 1:i + 1 + n] + b"\x00" * (4 - n)
                gw = d[i + 1 + n:i + 5 + n]
                if len(gw) != 4:
                    raise ValueError("truncated")
                routes.append(f"{_ip(dst)}/{w} via {_ip(gw)}")
                i += 5 + n
            return routes
        if kind == "opt82":
            return [f"{OPT82_SUB.get(c, f'sub {c}')}: {_sub_value(v)}" for c, v in _tlv(d)]
        if kind == "opt125":
            out, i = [], 0
            while i + 5 <= len(d):
                ent, ln = struct.unpack("!IB", d[i:i + 5])
                blob = d[i + 5:i + 5 + ln]
                try:
                    subs = [f"sub {c}: {_sub_value(v)}" for c, v in _tlv(blob)]
                except ValueError:
                    subs = [f"0x{blob.hex()}"]
                out.append(f"enterprise {ent}: " + "; ".join(subs))
                i += 5 + ln
            return out
        if kind == "vendor43":
            # Opaque by spec. Show raw, and a TLV breakdown if it parses cleanly.
            raw = f"0x{d.hex()}"
            s = _printable(d)
            try:
                subs = _tlv(d)
                return [raw] + [f"sub {c}: {_sub_value(v)}" for c, v in subs]
            except ValueError:
                return [raw] + ([f"ascii: {s}"] if s else [])
    except Exception:
        pass
    # Unknown option or length mismatch: best-effort.
    s = _printable(d)
    if s is not None and s.strip("\x00"):
        return s.rstrip("\x00")
    return f"0x{d.hex()}"


def _parse_opts(buf, store, order):
    i = 0
    while i < len(buf):
        c = buf[i]
        if c == 255:
            break
        if c == 0:
            i += 1
            continue
        if i + 1 >= len(buf):
            break
        ln = buf[i + 1]
        v = buf[i + 2:i + 2 + ln]
        if c not in store:
            store[c] = b""
            order.append(c)
        store[c] += v  # RFC 3396: concatenate split long options
        i += 2 + ln


def parse_packet(pkt):
    if len(pkt) < 240 or pkt[236:240] != MAGIC:
        return None
    op, htype, hlen, hops, xid, secs, flags = struct.unpack("!BBBBIHH", pkt[:12])
    ciaddr, yiaddr, siaddr, giaddr = (pkt[12:16], pkt[16:20], pkt[20:24], pkt[24:28])
    sname, bfile = pkt[44:108], pkt[108:236]
    store, order = {}, []
    _parse_opts(pkt[240:], store, order)
    overload = store.get(52, b"\x00")[0] if 52 in store else 0
    if overload & 1:
        _parse_opts(bfile, store, order)
    if overload & 2:
        _parse_opts(sname, store, order)
    return {
        "op": op, "xid": xid, "flags": flags,
        "ciaddr": _ip(ciaddr), "yiaddr": _ip(yiaddr),
        "siaddr": _ip(siaddr), "giaddr": _ip(giaddr),
        "chaddr": _hex(pkt[28:28 + min(hlen, 16)]),
        "sname": "" if overload & 2 else sname.split(b"\x00")[0].decode("ascii", "replace"),
        "file": "" if overload & 1 else bfile.split(b"\x00")[0].decode("ascii", "replace"),
        "options": [(c, store[c]) for c in order],
    }


# ---------------------------------------------------------------- building

def build_packet(mode, xid, mac, ciaddr, prl, vendor_class, hostname, broadcast):
    msg = 1 if mode == "discover" else 8
    hdr = struct.pack("!BBBBIHH", 1, 1, 6, 0, xid, 0, 0x8000 if broadcast else 0)
    hdr += socket.inet_aton(ciaddr) + b"\x00" * 12
    hdr += mac + b"\x00" * 10 + b"\x00" * 64 + b"\x00" * 128 + MAGIC
    o = bytes([53, 1, msg])
    o += bytes([61, 7, 1]) + mac
    o += bytes([57, 2]) + struct.pack("!H", 1500)
    if vendor_class:
        vc = vendor_class.encode()
        o += bytes([60, len(vc)]) + vc
    if hostname:
        hn = hostname.encode()
        o += bytes([12, len(hn)]) + hn
    # PRL may exceed 255 bytes; split per RFC 3396.
    for i in range(0, len(prl), 255):
        chunk = bytes(prl[i:i + 255])
        o += bytes([55, len(chunk)]) + chunk
    o += b"\xff"
    pkt = hdr + o
    return pkt + b"\x00" * max(0, 300 - len(pkt))  # BOOTP minimum


# ---------------------------------------------------------------- host info

class ProbeError(Exception):
    pass


def _psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        return None


def list_interfaces():
    """[{name, ip, mac, up}] for interfaces that have an IPv4 address or a MAC."""
    ps = _psutil()
    out = []
    if ps:
        stats = ps.net_if_stats()
        for name, addrs in ps.net_if_addrs().items():
            ip = next((a.address for a in addrs if a.family == socket.AF_INET), None)
            mac = next((a.address for a in addrs if a.family == ps.AF_LINK), None)
            mac = mac.replace("-", ":").lower() if mac else None
            if not mac or mac == "00:00:00:00:00:00":
                continue  # loopback/tunnels: no L2 to DHCP on
            out.append({"name": name, "ip": ip, "mac": mac,
                        "up": bool(stats.get(name) and stats[name].isup)})
    elif sys.platform.startswith("linux"):
        for name in sorted(os.listdir("/sys/class/net")):
            try:
                mac = _read(f"/sys/class/net/{name}/address")
            except OSError:
                continue
            if mac in ("", "00:00:00:00:00:00"):
                continue
            state = _read(f"/sys/class/net/{name}/operstate")
            out.append({"name": name, "ip": _linux_iface_ip(name), "mac": mac, "up": state == "up"})
    else:
        raise ProbeError("psutil is required on this platform:  pip install psutil")
    return out


def _read(path):
    with open(path) as f:
        return f.read().strip()


def _linux_iface_ip(iface):
    import fcntl  # Linux-only; keep import local so Windows can load this module
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface.encode()[:15]))
        return socket.inet_ntoa(r[20:24])
    except OSError:
        return None
    finally:
        s.close()


def default_interface(ifaces=None):
    """Interface holding the default route (found via a no-traffic UDP connect)."""
    ifaces = ifaces if ifaces is not None else list_interfaces()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET; nothing is sent
        ip = s.getsockname()[0]
    except OSError:
        ip = None
    finally:
        s.close()
    for i in ifaces:
        if ip and i["ip"] == ip:
            return i
    up = [i for i in ifaces if i["up"] and i["ip"]]
    return up[0] if up else (ifaces[0] if ifaces else None)


def get_interface(name):
    for i in list_interfaces():
        if i["name"] == name:
            return i
    raise ProbeError(f"Interface {name!r} not found.")


def parse_mac(s):
    if s.lower() == "random":
        return bytes([0x02] + [random.randint(0, 255) for _ in range(5)])  # locally administered
    b = bytes.fromhex(s.replace(":", "").replace("-", "").replace(".", ""))
    if len(b) != 6:
        raise ValueError("MAC must be 6 bytes")
    return b


def parse_codes(s):
    out = []
    for part in s.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return [c for c in out if 1 <= c <= 254]


def is_admin():
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


# ---------------------------------------------------------------- probe

def _open_socket(iface):
    """UDP/68 socket pinned to one interface, per-OS."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT") and sys.platform == "darwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    bind_ip = "0.0.0.0"
    try:
        if sys.platform.startswith("linux"):
            s.setsockopt(socket.SOL_SOCKET, 25, iface["name"].encode() + b"\0")  # SO_BINDTODEVICE
        elif sys.platform == "darwin":
            s.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(iface["name"]))  # IP_BOUND_IF
        elif os.name == "nt":
            # Windows has no bind-to-device; binding the interface IP selects the egress NIC.
            if not iface["ip"]:
                raise ProbeError(f"{iface['name']} has no IPv4 address; Windows needs one to pick the NIC.")
            bind_ip = iface["ip"]
    except PermissionError:
        s.close()
        raise ProbeError("Permission denied binding to the interface. Run as root/sudo.") from None
    except ProbeError:
        s.close()
        raise
    try:
        s.bind((bind_ip, 68))
    except PermissionError:
        s.close()
        raise ProbeError("Permission denied on UDP/68. Run as root (sudo) or Administrator.") from None
    except OSError as e:
        s.close()
        raise ProbeError(f"Can't bind UDP/68 ({e}). Another DHCP client may own the port "
                         "(e.g. dhclient). Stop it, or run from another host.") from e
    return s


def probe(iface=None, mode="discover", mac=None, vendor_class=None, hostname=None,
          request=None, server=None, server_port=67, ciaddr=None, timeout=5.0,
          first=False, broadcast_flag=True, log=None):
    """Send one DISCOVER/INFORM and return a list of parsed replies."""
    log = log or (lambda m: None)
    if isinstance(iface, str):
        iface = get_interface(iface)
    iface = iface or default_interface()
    if not iface:
        raise ProbeError("No usable network interface found.")
    mac = mac or bytes.fromhex(iface["mac"].replace(":", ""))
    request = request or list(range(1, 255))
    ci = "0.0.0.0"
    if mode == "inform":
        ci = ciaddr or iface["ip"]
        if not ci:
            raise ProbeError(f"{iface['name']} has no IPv4 address; INFORM needs one.")

    xid = random.getrandbits(32)
    pkt = build_packet(mode, xid, mac, ci, request, vendor_class, hostname, broadcast_flag)
    s = _open_socket(iface)
    dest = server or "255.255.255.255"
    log(f"Sent DHCP{mode.upper()} on {iface['name']} (chaddr {_hex(mac)}, xid 0x{xid:08x}) "
        f"to {dest}; listening {timeout:g}s")
    try:
        s.sendto(pkt, (dest, server_port))
        replies, deadline = [], time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([s], [], [], left)
            if not r:
                break
            try:
                data, src = s.recvfrom(4096)
            except ConnectionResetError:  # Windows ICMP port-unreachable noise
                continue
            p = parse_packet(data)
            if not p or p["op"] != 2 or p["xid"] != xid:
                continue
            p["source"] = src[0]
            replies.append(p)
            log(f"Reply from {src[0]}")
            if first:
                break
    finally:
        s.close()
    return replies


# ---------------------------------------------------------------- output

def option_name(code):
    if code in OPTIONS:
        return OPTIONS[code][0]
    return "(site-specific)" if code >= 224 else "(unknown)"


def summarize(p):
    """Structured view of one reply, used by text, JSON and the GUI."""
    opts = dict(p["options"])
    mt = MSG_TYPES.get(opts[53][0], "?") if 53 in opts and opts[53] else "BOOTP"
    sid = _ip(opts[54]) if 54 in opts and len(opts[54]) == 4 else None
    header = [(label, p[k]) for k, label in (
        ("yiaddr", "Offered IP (yiaddr)"), ("siaddr", "Next Server (siaddr)"),
        ("giaddr", "Relay Agent (giaddr)"), ("sname", "Server Name (sname)"),
        ("file", "Boot File (file)")) if p[k] and p[k] != "0.0.0.0"]
    options = []
    for c, d in sorted(p["options"], key=lambda x: x[0]):
        v = decode(c, d)
        options.append({"code": c, "name": option_name(c),
                        "values": (v if isinstance(v, list) else [v]) or [""],
                        "raw": bytes(d).hex()})
    return {"source": p["source"], "type": mt, "server_id": sid, "header": header,
            "fields": {k: p[k] for k in ("yiaddr", "siaddr", "giaddr", "sname", "file")},
            "options": options}


def format_text(replies, show_hex=False):
    if not replies:
        return ("No replies. Check: right interface, server scope/VLAN, firewall (UDP 67/68), "
                "or try the other mode.")
    lines = []
    for n, p in enumerate(replies, 1):
        s = summarize(p)
        lines.append(f"=== Reply {n}: DHCP{s['type']} from {s['source']}  "
                     f"(Server ID {s['server_id'] or '-'}) ===")
        for label, v in s["header"]:
            lines.append(f"  {label:<34} {v}")
        lines += ["", f"  {'Code':>4}  {'Option':<34} Value", f"  {'-'*4}  {'-'*34} {'-'*40}"]
        for o in s["options"]:
            lines.append(f"  {o['code']:>4}  {o['name']:<34} {o['values'][0]}")
            lines += [f"  {'':>4}  {'':<34} {x}" for x in o["values"][1:]]
            if show_hex:
                lines.append(f"  {'':>4}  {'':<34} raw: {o['raw']}")
        lines.append("")
    servers = sorted({summarize(p)["server_id"] for p in replies} - {None})
    if len(servers) > 1:
        lines.append(f"WARNING: {len(servers)} DHCP servers answered: {', '.join(servers)}")
    return "\n".join(lines)


def format_json(replies):
    out = []
    for p in replies:
        s = summarize(p)
        out.append({"source": s["source"], "type": s["type"], "server_id": s["server_id"],
                    **s["fields"],
                    "options": [{"code": o["code"], "name": o["name"],
                                 "value": o["values"] if len(o["values"]) > 1 else o["values"][0],
                                 "raw": o["raw"]} for o in s["options"]]})
    return json.dumps(out, indent=2)


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(
        description="Query DHCP server(s) and show every option they return.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("-i", "--iface", help="interface (default: the one with the default route)")
    ap.add_argument("-l", "--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("-m", "--mode", choices=["discover", "inform"], default="discover",
                    help="discover = what a new client gets (no lease taken); "
                         "inform = config for a host that already has an IP")
    ap.add_argument("--mac", help="chaddr/client-id to use, or 'random'. Use a device's MAC "
                                  "to see its reservation-specific options")
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
    a = ap.parse_args()

    try:
        if a.list:
            d = default_interface()
            for i in list_interfaces():
                star = "*" if d and i["name"] == d["name"] else " "
                print(f"{star} {i['name']:<20} {i['ip'] or '-':<16} {i['mac']}  "
                      f"{'up' if i['up'] else 'down'}")
            return
        replies = probe(iface=a.iface, mode=a.mode, mac=parse_mac(a.mac) if a.mac else None,
                        vendor_class=a.vendor_class, hostname=a.hostname,
                        request=parse_codes(a.request), server=a.server,
                        server_port=a.server_port, ciaddr=a.ciaddr, timeout=a.timeout,
                        first=a.first, log=None if a.json else (lambda m: print(m, file=sys.stderr)))
    except (ProbeError, ValueError) as e:
        sys.exit(f"Error: {e}")
    print(format_json(replies) if a.json else format_text(replies, a.hex))
    sys.exit(0 if replies else 1)


if __name__ == "__main__":
    main()

"""DHCP option table and decoders (RFC 2132 and friends, plus vendor option 43 layouts)."""
import ipaddress
import struct

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
    160: ("Provisioning Server URL (Polycom)", "str"),
    176: ("Avaya IP Telephone", "str"), 208: ("PXELINUX Magic", "hex"),
    209: ("PXELINUX Config File", "str"), 210: ("PXELINUX Path Prefix", "str"),
    211: ("PXELINUX Reboot Time", "time"), 212: ("6rd", "hex"),
    213: ("Access Network Domain Name", "dnslist"), 242: ("Avaya IP Phone (site)", "str"),
    249: ("MS Classless Static Routes", "cidr"), 252: ("WPAD URL", "str"),
}

# Vendor classes (option 60) offered as presets and used by the sweep. "" = no option 60.
VENDOR_CLASS_PRESETS = ["", "OptiIpPhone", "Cisco AP c9130", "ubnt", "ArubaAP", "PXEClient", "MSFT 5.0"]

OPT82_SUB = {1: "Circuit-ID", 2: "Remote-ID", 5: "Link Selection",
             9: "Vendor-Specific", 11: "Server ID Override", 151: "VSS", 152: "VSS Control"}


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
        n, ip = struct.unpack("!I", v)[0], _ip(v)
        # Small values are almost always numbers (VLAN IDs, flags); others usually addresses.
        return f"{n} (or IP {ip})" if v[0] == 0 else f"{ip} (or {n})"
    return f"0x{v.hex()}"


MSFT43 = {1: "Disable NetBIOS over TCP/IP", 2: "Release lease on shutdown",
          3: "Default router metric base"}


def decode_vendor43(d, vendor_class=None):
    """Option 43 is vendor-defined. Recognise common layouts; fall back to TLV/text/hex.

    Returns a list: first line is the headline, raw hex is always last.
    """
    vc = (vendor_class or "").strip()
    raw = f"raw: 0x{d.hex()}"
    try:
        subs = _tlv(d)
    except ValueError:
        subs = None
    sd = dict(subs or [])

    # Siemens/Unify OpenStage/OpenScape: 1=vendor tag "Siemens", 2=voice VLAN (u32), 3=DLS URL
    if sd.get(1, b"").rstrip(b"\x00") == b"Siemens" or vc.startswith("OptiIpPhone"):
        out = ["Siemens/Unify phone provisioning"]
        for c, v in subs or []:
            if c == 1:
                out.append(f"Vendor tag: {_str_or_hex(v)}")
            elif c == 2 and len(v) == 4:
                out.append(f"Voice VLAN ID: {struct.unpack('!I', v)[0]}")
            elif c == 3:
                out.append(f"DLS server: {_str_or_hex(v)}")
            else:
                out.append(f"sub {c}: {_sub_value(v)}")
        return out + [raw]

    # Cisco lightweight APs: type 0xF1 = list of WLC management IPs
    if subs and len(sd.get(241, b"")) % 4 == 0 and sd.get(241):
        wlcs = [_ip(sd[241][i:i + 4]) for i in range(0, len(sd[241]), 4)]
        out = ["Cisco AP controller list"] + [f"WLC: {w}" for w in wlcs]
        out += [f"sub {c}: {_sub_value(v)}" for c, v in subs if c != 241]
        return out + [raw]

    # Ubiquiti UniFi: sub 1 = controller IP
    if vc.lower().startswith("ubnt") and len(sd.get(1, b"")) == 4:
        return ["UniFi controller", f"Controller: {_ip(sd[1])}"] + [raw]

    # Microsoft vendor options (vendor class "MSFT 5.0")
    if vc.startswith("MSFT") and subs:
        out = ["Microsoft vendor options"]
        for c, v in subs:
            val = struct.unpack("!I", v)[0] if len(v) == 4 else None
            if c in (1, 2) and val is not None:
                out.append(f"{MSFT43[c]}: {'yes' if val else 'no'} ({val})")
            elif c in MSFT43 and val is not None:
                out.append(f"{MSFT43[c]}: {val}")
            else:
                out.append(f"sub {c}: {_sub_value(v)}")
        return out + [raw]

    # Plain text payloads (Aruba controllers, Mitel/Avaya provisioning strings)
    text = _printable(d)
    if text and text.strip("\x00") and not subs:
        text = text.rstrip("\x00")
        if vc.startswith("ArubaInstantAP"):
            return ["Aruba Instant AP", f"Group,IP,key: {text}", raw]
        if vc.startswith("ArubaAP"):
            return ["Aruba controller", f"Controller: {text}", raw]
        return [text, raw]

    if subs:
        return [f"sub {c}: {_sub_value(v)}" for c, v in subs] + [raw]
    return [f"0x{d.hex()}"]


def decode(code, data, vendor_class=None):
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
            return decode_vendor43(d, vendor_class)
    except Exception:
        pass
    # Unknown option or length mismatch: best-effort.
    s = _printable(d)
    if s is not None and s.strip("\x00"):
        return s.rstrip("\x00")
    return f"0x{d.hex()}"

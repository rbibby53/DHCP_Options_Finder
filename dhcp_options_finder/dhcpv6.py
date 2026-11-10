"""DHCPv6 (RFC 8415): build Information-Request / Solicit, parse and decode replies."""
import ipaddress
import random
import struct

from .options import _dns_names, _fmt_time, _printable, _str_or_hex

CLIENT_PORT, SERVER_PORT = 546, 547
ALL_SERVERS = "ff02::1:2"  # All_DHCP_Relay_Agents_and_Servers

MSG_TYPES = {1: "SOLICIT", 2: "ADVERTISE", 3: "REQUEST", 4: "CONFIRM", 5: "RENEW", 6: "REBIND",
             7: "REPLY", 8: "RELEASE", 9: "DECLINE", 10: "RECONFIGURE", 11: "INFORMATION-REQUEST",
             12: "RELAY-FORW", 13: "RELAY-REPL"}
SOLICIT, ADVERTISE, REPLY, INFORMATION_REQUEST = 1, 2, 7, 11

STATUS = {0: "Success", 1: "UnspecFail", 2: "NoAddrsAvail", 3: "NoBinding", 4: "NotOnLink",
          5: "UseMulticast", 6: "NoPrefixAvail"}
DUID_TYPES = {1: "DUID-LLT", 2: "DUID-EN", 3: "DUID-LL", 4: "DUID-UUID"}

# code: (name, decoder)
OPTIONS = {
    1: ("Client Identifier", "duid"), 2: ("Server Identifier", "duid"),
    3: ("IA_NA (address)", "ia_na"), 4: ("IA_TA (temporary address)", "ia_ta"),
    5: ("IA Address", "iaaddr"), 6: ("Option Request", "u16s"), 7: ("Server Preference", "u8"),
    8: ("Elapsed Time", "u16"), 9: ("Relay Message", "hex"), 11: ("Authentication", "hex"),
    12: ("Server Unicast", "ip6"), 13: ("Status Code", "status"), 14: ("Rapid Commit", "flag"),
    15: ("User Class", "hex"), 16: ("Vendor Class", "vclass"), 17: ("Vendor-Specific Info", "vopts"),
    18: ("Interface-Id", "hex"), 19: ("Reconfigure Message", "u8"), 20: ("Reconfigure Accept", "flag"),
    21: ("SIP Server Domain Names", "dnslist"), 22: ("SIP Server Addresses", "ip6s"),
    23: ("DNS Servers", "ip6s"), 24: ("Domain Search List", "dnslist"),
    25: ("IA_PD (prefix delegation)", "ia_pd"), 26: ("IA Prefix", "iaprefix"),
    27: ("NIS Servers", "ip6s"), 28: ("NIS+ Servers", "ip6s"), 29: ("NIS Domain Name", "dnslist"),
    30: ("NIS+ Domain Name", "dnslist"), 31: ("SNTP Servers", "ip6s"),
    32: ("Information Refresh Time", "time"), 33: ("BCMCS Domain Names", "dnslist"),
    34: ("BCMCS Addresses", "ip6s"), 37: ("Relay Remote-Id", "hex"), 38: ("Subscriber-Id", "hex"),
    39: ("Client FQDN", "fqdn"), 41: ("POSIX Timezone", "str"), 42: ("TZ Database Timezone", "str"),
    56: ("NTP Servers", "ntp"), 59: ("Boot File URL", "str"), 60: ("Boot File Parameters", "strlist"),
    61: ("Client System Architecture", "u16s"), 64: ("AFTR Name (DS-Lite)", "dnslist"),
    65: ("ERP Local Domain Name", "dnslist"), 82: ("SOL_MAX_RT", "time"), 83: ("INF_MAX_RT", "time"),
    86: ("PCP Servers", "ip6s"), 103: ("Captive Portal URI", "str"),
}

# Asked for in every request. Servers only send what's configured *and* requested.
REQUEST_OPTIONS = [23, 24, 31, 56, 32, 21, 22, 27, 28, 29, 30, 33, 34, 41, 42, 59, 60, 64, 65,
                   82, 83, 86, 103, 17]


def option_name(code):
    return OPTIONS.get(code, (f"(unknown option {code})",))[0]


# ---------------------------------------------------------------- building

def duid_ll(mac):
    """DUID-LL (type 3, hardware type 1 = Ethernet) from a 6-byte MAC."""
    return struct.pack("!HH", 3, 1) + mac


def _opt(code, data):
    return struct.pack("!HH", code, len(data)) + data


def build(msg_type, xid, duid, oro=None, ia_na=False, ia_pd=False):
    """One client message. Never includes Rapid Commit, so a Solicit can't bind a lease."""
    body = _opt(1, duid) + _opt(8, b"\x00\x00")
    body += _opt(6, b"".join(struct.pack("!H", c) for c in (oro or REQUEST_OPTIONS)))
    if ia_na:
        body += _opt(3, struct.pack("!III", random.getrandbits(32), 0, 0))
    if ia_pd:
        body += _opt(25, struct.pack("!III", random.getrandbits(32), 0, 0))
    return bytes([msg_type]) + xid.to_bytes(3, "big") + body


# ---------------------------------------------------------------- parsing

def parse_options(buf):
    """[(code, bytes)] in order; stops quietly at a truncated option."""
    out, i = [], 0
    while i + 4 <= len(buf):
        code, ln = struct.unpack("!HH", buf[i:i + 4])
        if i + 4 + ln > len(buf):
            break
        out.append((code, bytes(buf[i + 4:i + 4 + ln])))
        i += 4 + ln
    return out


def parse(pkt):
    """Parse a server message; None if it isn't one."""
    if len(pkt) < 4 or pkt[0] in (12, 13):  # relay messages aren't for us
        return None
    return {"type": MSG_TYPES.get(pkt[0], str(pkt[0])), "msg_type": pkt[0],
            "xid": int.from_bytes(pkt[1:4], "big"), "options": parse_options(pkt[4:])}


# ---------------------------------------------------------------- decoding

def _ip6(b):
    return str(ipaddress.IPv6Address(bytes(b)))


def _ip6s(b):
    if not b or len(b) % 16:
        raise ValueError("not a list of IPv6 addresses")
    return [_ip6(b[i:i + 16]) for i in range(0, len(b), 16)]


def _status(b):
    code = struct.unpack("!H", b[:2])[0]
    msg = b[2:].decode("utf-8", "replace")
    return f"{STATUS.get(code, code)}{': ' + msg if msg else ''}"


def decode_duid(b):
    if len(b) < 2:
        return f"0x{b.hex()}"
    t = struct.unpack("!H", b[:2])[0]
    name = DUID_TYPES.get(t, f"DUID type {t}")
    if t == 1 and len(b) >= 8:
        return f"{name} {b[8:].hex(':')} (time {struct.unpack('!I', b[4:8])[0]})"
    if t == 3 and len(b) >= 4:
        return f"{name} {b[4:].hex(':')}"
    if t == 2 and len(b) >= 6:
        return f"{name} enterprise {struct.unpack('!I', b[2:6])[0]} id 0x{b[6:].hex()}"
    return f"{name} 0x{b[2:].hex()}"


def _lifetimes(pref, valid):
    return f"preferred {_fmt_time(pref)}, valid {_fmt_time(valid)}"


def _ia(b, kind):
    """IA_NA / IA_TA / IA_PD: header + nested addresses/prefixes/status."""
    if kind == "ia_ta":
        iaid, rest, head = struct.unpack("!I", b[:4])[0], b[4:], ""
    else:
        iaid, t1, t2 = struct.unpack("!III", b[:12])
        rest, head = b[12:], f", T1 {_fmt_time(t1)}, T2 {_fmt_time(t2)}"
    out = [f"IAID {iaid}{head}"]
    for code, data in parse_options(rest):
        out += [f"{option_name(code)}: {v}" for v in _as_list(decode(code, data))]
    return out


def decode(code, data):
    """Readable value: str or list[str]."""
    kind = OPTIONS.get(code, (None, "auto"))[1]
    d = bytes(data)
    try:
        if kind == "ip6" and len(d) == 16:
            return _ip6(d)
        if kind == "ip6s":
            return _ip6s(d)
        if kind == "u8" and len(d) == 1:
            return str(d[0])
        if kind == "u16" and len(d) == 2:
            v = struct.unpack("!H", d)[0]
            return f"{v / 100:g} s" if code == 8 else str(v)
        if kind == "u16s" and len(d) % 2 == 0:
            return ", ".join(str(x) for x in struct.unpack(f"!{len(d) // 2}H", d))
        if kind == "time" and len(d) == 4:
            return _fmt_time(struct.unpack("!I", d)[0])
        if kind == "flag":
            return "set"
        if kind == "str":
            return _str_or_hex(d)
        if kind == "hex":
            return f"0x{d.hex()}"
        if kind == "duid":
            return decode_duid(d)
        if kind == "status" and len(d) >= 2:
            return _status(d)
        if kind == "dnslist":
            return _dns_names(d)
        if kind in ("ia_na", "ia_ta", "ia_pd"):
            return _ia(d, kind)
        if kind == "iaaddr" and len(d) >= 24:
            addr, (pref, valid) = _ip6(d[:16]), struct.unpack("!II", d[16:24])
            extra = [f"{option_name(c)}: {v}" for c, x in parse_options(d[24:])
                     for v in _as_list(decode(c, x))]
            return "; ".join([f"{addr} ({_lifetimes(pref, valid)})"] + extra)
        if kind == "iaprefix" and len(d) >= 25:
            pref, valid, plen = struct.unpack("!IIB", d[:9])
            net = ipaddress.IPv6Network((ipaddress.IPv6Address(d[9:25]), plen), strict=False)
            return f"{net} ({_lifetimes(pref, valid)})"
        if kind == "ntp":
            out = []
            for sub, v in parse_options(d):
                if sub in (1, 2) and len(v) == 16:
                    out.append(("server " if sub == 1 else "multicast ") + _ip6(v))
                elif sub == 3:
                    out += [f"server {n}" for n in _dns_names(v)]
                else:
                    out.append(f"sub {sub}: 0x{v.hex()}")
            return out
        if kind == "vopts" and len(d) >= 4:
            ent = struct.unpack("!I", d[:4])[0]
            subs = [f"sub {c}: {_printable(v) or '0x' + v.hex()}" for c, v in parse_options(d[4:])]
            return [f"enterprise {ent}"] + subs
        if kind == "vclass" and len(d) >= 4:
            ent, i, out = struct.unpack("!I", d[:4])[0], 4, []
            while i + 2 <= len(d):
                ln = struct.unpack("!H", d[i:i + 2])[0]
                out.append(_str_or_hex(d[i + 2:i + 2 + ln]))
                i += 2 + ln
            return [f"enterprise {ent}"] + out
        if kind == "strlist":
            i, out = 0, []
            while i + 2 <= len(d):
                ln = struct.unpack("!H", d[i:i + 2])[0]
                out.append(_str_or_hex(d[i + 2:i + 2 + ln]))
                i += 2 + ln
            return out
        if kind == "fqdn" and d:
            return f"{', '.join(_dns_names(d[1:])) or '(none)'} (flags=0x{d[0]:02x})"
    except (ValueError, struct.error, IndexError):
        pass
    s = _printable(d)
    return s.rstrip("\x00") if s and s.strip("\x00") else f"0x{d.hex()}"


def _as_list(v):
    return v if isinstance(v, list) else [v]


def summarize(msg):
    """Structured view of one parsed reply."""
    opts = dict(msg["options"])
    options = [{"code": c, "name": option_name(c), "values": _as_list(decode(c, d)) or [""],
                "raw": d.hex()} for c, d in msg["options"]]
    status = _status(opts[13]) if 13 in opts and len(opts[13]) >= 2 else None
    return {"type": msg["type"], "source": msg.get("source"), "request": msg.get("request"),
            "server_id": decode_duid(opts[2]) if 2 in opts else None,
            "preference": opts[7][0] if 7 in opts and opts[7] else None,
            "status": status, "options": options}

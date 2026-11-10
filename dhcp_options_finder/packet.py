"""Build DHCP requests and parse replies."""
import socket
import struct

from .options import _hex, _ip

MAGIC = b"\x63\x82\x53\x63"


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

"""Builders and fake servers for IPv6 tests (Router Advertisements and DHCPv6)."""
import ipaddress
import socket
import struct
import threading
import time


def a6(s):
    return ipaddress.IPv6Address(s).packed


# ---------------------------------------------------------------- RA builder

def ra_opt(t, body):
    """NDP option: type, length in 8-octet units (body padded)."""
    total = len(body) + 2
    pad = (-total) % 8
    return bytes([t, (total + pad) // 8]) + body + b"\x00" * pad


def prefix_opt(prefix, plen, on_link=True, auto=True, valid=2592000, preferred=604800):
    flags = (0x80 if on_link else 0) | (0x40 if auto else 0)
    return ra_opt(3, struct.pack("!BBII4x", plen, flags, valid, preferred) + a6(prefix))


def route_opt(prefix, plen, lifetime=1800):
    n = 0 if plen == 0 else 8 if plen <= 64 else 16
    return ra_opt(24, struct.pack("!BBI", plen, 0, lifetime) + a6(prefix)[:n])


def rdnss_opt(*servers, lifetime=3600):
    return ra_opt(25, struct.pack("!HI", 0, lifetime) + b"".join(a6(s) for s in servers))


def dnssl_opt(*domains, lifetime=3600):
    wire = b"".join(b"".join(bytes([len(p)]) + p.encode() for p in d.split(".")) + b"\x00" for d in domains)
    return ra_opt(31, struct.pack("!HI", 0, lifetime) + wire)


def mtu_opt(mtu):
    return ra_opt(5, struct.pack("!HI", 0, mtu))


def build_ra(*options, managed=False, other=False, lifetime=1800, mac=b"\x00\x11\x22\x33\x44\x55"):
    flags = (0x80 if managed else 0) | (0x40 if other else 0)
    body = struct.pack("!BBHBBHII", 134, 0, 0, 64, flags, lifetime, 0, 0)
    body += ra_opt(1, mac) if mac else b""
    return body + b"".join(options)


HOME_RA = build_ra(prefix_opt("2001:db8:1::", 64), rdnss_opt("2001:db8:1::1"), dnssl_opt("example.net"),
                   mtu_opt(1500), other=True)
THREAD_BR = build_ra(route_opt("fd3e:1234:5678::", 64), lifetime=0)  # e.g. a HomePod


# ---------------------------------------------------------------- DHCPv6 builder

def d6opt(code, data):
    return struct.pack("!HH", code, len(data)) + data


SERVER_DUID = struct.pack("!HH", 3, 1) + bytes.fromhex("001122334455")


def build_reply(request):
    """Answer an Information-Request with REPLY and a Solicit with ADVERTISE."""
    mtype, xid = request[0], request[1:4]
    opts = dict()
    i = 4
    while i + 4 <= len(request):
        c, ln = struct.unpack("!HH", request[i:i + 4])
        opts[c] = request[i + 4:i + 4 + ln]
        i += 4 + ln
    body = d6opt(1, opts[1]) + d6opt(2, SERVER_DUID)
    body += d6opt(23, a6("2001:db8:1::53") + a6("2001:db8:1::54"))
    body += d6opt(24, b"\x07example\x03net\x00")
    body += d6opt(56, d6opt(1, a6("2001:db8:1::123")) + d6opt(3, b"\x04time\x07example\x03net\x00"))
    body += d6opt(32, struct.pack("!I", 86400))
    if mtype == 1:  # SOLICIT -> ADVERTISE with an address in the IA_NA
        iaid = opts[3][:4]
        addr = d6opt(5, a6("2001:db8:1::1000") + struct.pack("!II", 3600, 7200))
        body += d6opt(3, iaid + struct.pack("!II", 1800, 2880) + addr) + d6opt(7, b"\xff")
        return bytes([2]) + xid + body
    return bytes([7]) + xid + body


class FakeDHCPv6(threading.Thread):
    """Listens on ::1:<random port>, answers to the client's port 546."""

    def __init__(self, replies=2):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.bind(("::1", 0))
        self.sock.settimeout(10)
        self.port = self.sock.getsockname()[1]
        self.replies = replies

    def run(self):
        try:
            for _ in range(self.replies):
                data, src = self.sock.recvfrom(4096)
                self.sock.sendto(build_reply(data), (src[0], 546))
        except OSError:
            pass
        finally:
            self.sock.close()


class FakeRouter(threading.Thread):
    """Sends RAs to ::1 over a raw ICMPv6 socket (needs root), a few times."""

    def __init__(self, *ras, repeat=6, interval=0.3):
        super().__init__(daemon=True)
        self.ras, self.repeat, self.interval = ras, repeat, interval

    def run(self):
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
        try:
            for _ in range(self.repeat):
                for pkt in self.ras:
                    s.sendto(pkt, ("::1", 0))
                time.sleep(self.interval)
        finally:
            s.close()

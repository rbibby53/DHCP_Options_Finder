"""Minimal fake DHCP server used by the tests. Answers on a high port so no root is needed for it."""
import socket
import struct
import threading

ip = socket.inet_aton


def opt(c, b):
    return bytes([c, len(b)]) + b


def build_reply(request: bytes) -> bytes:
    xid, chaddr, mt = request[4:8], request[28:44], request[242]
    hdr = (bytes([2, 1, 6, 0]) + xid + b"\0\0\x80\0" + b"\0" * 4 + ip("10.20.30.40")
           + ip("10.20.30.1") + b"\0" * 4 + chaddr)
    sname = b"\0" * 64
    # Option overload (52=1): 66/67 live in the 'file' field.
    bfile = (opt(66, b"tftp.example.com") + opt(67, b"pxelinux.0") + b"\xff").ljust(128, b"\0")
    o = opt(53, bytes([2 if mt == 1 else 5])) + opt(54, ip("10.20.30.1"))
    o += opt(51, struct.pack("!I", 86400)) + opt(58, struct.pack("!I", 43200))
    o += opt(1, ip("255.255.255.0")) + opt(3, ip("10.20.30.1"))
    o += opt(6, ip("10.1.1.1") + ip("10.1.1.2")) + opt(15, b"example.com") + opt(42, ip("10.1.1.123"))
    o += opt(43, bytes([1, 4]) + ip("10.5.5.5") + bytes([2, 5]) + b"hello")
    o += opt(46, b"\x08")
    o += opt(119, b"\x03bas\x07example\x03com\x00\x02it\xc0\x04")  # compression pointer
    o += opt(121, bytes([24, 10, 50, 0]) + ip("10.20.30.254") + bytes([0]) + ip("10.20.30.1"))
    o += opt(150, ip("10.9.9.9")) + opt(52, b"\x01")
    o += opt(125, struct.pack("!IB", 3561, 6) + bytes([1, 4]) + b"ABCD")
    o += opt(82, bytes([1, 6]) + b"Gi1/0/" + bytes([2, 6]) + bytes.fromhex("001122334455"))
    o += opt(252, b"http://wpad/wpad.dat")
    big = b"A" * 300  # RFC 3396: split across two option instances
    o += opt(224, big[:200]) + opt(224, big[200:]) + b"\xff"
    return hdr + sname + bfile + b"\x63\x82\x53\x63" + o


class FakeServer(threading.Thread):
    def __init__(self, host="127.0.0.1", replies=1):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.sock.settimeout(10)
        self.port = self.sock.getsockname()[1]
        self.replies = replies

    def run(self):
        try:
            for _ in range(self.replies):
                data, src = self.sock.recvfrom(2048)
                self.sock.sendto(build_reply(data), (src[0], 68))
        except OSError:
            pass
        finally:
            self.sock.close()

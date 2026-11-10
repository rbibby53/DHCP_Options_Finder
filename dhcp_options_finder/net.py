"""Interfaces, sockets and the probe itself (Linux, macOS, Windows)."""
import os
import random
import select
import socket
import struct
import sys
import time

from .options import _hex
from .packet import build_packet, parse_packet


class ProbeError(Exception):
    def __init__(self, msg, permission=False):
        super().__init__(msg)
        self.permission = permission


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
        raise ProbeError("Permission denied binding to the interface. Run as root/sudo.",
                         permission=True) from None
    except ProbeError:
        s.close()
        raise
    try:
        s.bind((bind_ip, 68))
    except PermissionError:
        s.close()
        raise ProbeError("Permission denied on UDP/68. Run as root (sudo) or Administrator.",
                         permission=True) from None
    except OSError as e:
        s.close()
        raise ProbeError(f"Can't bind UDP/68 ({e}). Another DHCP client may own the port "
                         "(e.g. dhclient). Stop it, or run from another host.") from e
    return s


def probe(iface=None, mode="discover", mac=None, vendor_class=None, hostname=None,
          request=None, server=None, server_port=67, ciaddr=None, timeout=5.0,
          first=False, broadcast_flag=True, log=None, use_iface_mac=False):
    """Send one DISCOVER/INFORM and return a list of parsed replies.

    MAC used: `mac` if given; otherwise a random one for DISCOVER (so an existing lease
    on this computer doesn't skew the offer), or the interface MAC for INFORM or when
    `use_iface_mac` is set.
    """
    log = log or (lambda m: None)
    if isinstance(iface, str):
        iface = get_interface(iface)
    iface = iface or default_interface()
    if not iface:
        raise ProbeError("No usable network interface found.")
    if mac:
        mac_source = "custom"
    elif mode == "discover" and not use_iface_mac:
        mac, mac_source = parse_mac("random"), "random"
    else:
        mac, mac_source = bytes.fromhex(iface["mac"].replace(":", "")), "interface"
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
    log(f"Sent DHCP{mode.upper()} on {iface['name']} (chaddr {_hex(mac)} [{mac_source}], xid 0x{xid:08x}) "
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
            p.update(source=src[0], mac_source=mac_source, sent_vendor_class=vendor_class)
            replies.append(p)
            log(f"Reply from {src[0]}")
            if first:
                break
    finally:
        s.close()
    return replies

"""IPv6 probes: Router Solicitation/Advertisement and DHCPv6 (Linux, macOS, Windows)."""
import os
import random
import re
import select
import socket
import subprocess
import sys
import threading
import time

from . import dhcpv6, ra
from .net import ProbeError, default_interface, get_interface, parse_mac


def iface_index(iface):
    """OS interface index (needed for link-local scope and multicast)."""
    if os.name == "nt":
        if iface.get("ip6ll_scope", "") and iface["ip6ll_scope"].isdigit():
            return int(iface["ip6ll_scope"])
        try:  # psutil names are friendly names ("Ethernet"); netsh lists Idx -> Name
            out = subprocess.run(["netsh", "interface", "ipv6", "show", "interfaces"],
                                 capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError) as e:
            raise ProbeError(f"Couldn't look up the IPv6 interface index: {e}") from e
        for line in out.splitlines():
            m = re.match(r"\s*(\d+)\s+\d+\s+\d+\s+\S+\s+(.+?)\s*$", line)
            if m and m.group(2) == iface["name"]:
                return int(m.group(1))
        raise ProbeError(f"Windows doesn't list {iface['name']!r} as an IPv6 interface.")
    try:
        return socket.if_nametoindex(iface["name"])
    except OSError as e:
        raise ProbeError(f"No interface index for {iface['name']!r}: {e}") from e


def _addr(host, port, idx):
    """Socket address; the interface index only belongs on link-local/multicast addresses
    (Windows rejects a scope on e.g. ::1 or a global address with WSAEADDRNOTAVAIL)."""
    scoped = host.lower().startswith(("fe80", "ff02"))
    return (host, port, 0, idx if scoped else 0)


def _resolve(iface):
    if isinstance(iface, str):
        iface = get_interface(iface)
    iface = iface or default_interface()
    if not iface:
        raise ProbeError("No usable network interface found.")
    if not socket.has_ipv6:
        raise ProbeError("This Python has no IPv6 support.")
    if not iface.get("ip6ll"):
        raise ProbeError(f"{iface['name']} has no IPv6 link-local address, so IPv6 is probably "
                         "disabled on it.")
    return iface, iface_index(iface)


def _perm(e):
    return ProbeError("Permission denied. IPv6 probes need root (sudo) or Administrator: "
                      f"{e}", permission=True)


def _bind_device(s, iface):
    if sys.platform.startswith("linux"):
        try:
            s.setsockopt(socket.SOL_SOCKET, 25, iface["name"].encode() + b"\0")  # SO_BINDTODEVICE
        except PermissionError as e:
            s.close()
            raise _perm(e) from None


# ---------------------------------------------------------------- router advertisements

def ra_probe(iface=None, timeout=5.0, solicit=True, rs_dest=ra.ALL_ROUTERS, log=None):
    """Send a Router Solicitation and collect Router Advertisements for `timeout` seconds.
    Returns [{source, ra}], one per router (latest RA wins)."""
    log = log or (lambda m: None)
    iface, idx = _resolve(iface)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except PermissionError as e:
        raise _perm(e) from None
    except OSError as e:
        raise ProbeError(f"Can't open an ICMPv6 socket: {e}") from e
    try:
        _bind_device(s, iface)
        for opt, val in ((socket.IPV6_MULTICAST_IF, idx), (socket.IPV6_MULTICAST_HOPS, 255),
                         (socket.IPV6_UNICAST_HOPS, 255)):
            s.setsockopt(socket.IPPROTO_IPV6, opt, val)
        if os.name == "nt":  # Windows raw sockets must be bound before receiving
            s.bind(_addr(iface["ip6ll"], 0, idx))
        if solicit:
            mac = bytes.fromhex(iface["mac"].replace(":", "")) if iface.get("mac") else None
            s.sendto(ra.build_rs(iface["ip6ll"], mac), _addr(rs_dest, 0, idx))
            log(f"Sent Router Solicitation on {iface['name']}; listening {timeout:g}s")
        routers, deadline = {}, time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            r, _, _ = select.select([s], [], [], left)
            if not r:
                break
            try:
                data, addr = s.recvfrom(65535)
            except (ConnectionResetError, OSError):
                continue
            parsed = ra.parse_ra(data)
            if parsed:
                src = addr[0].split("%")[0]
                if src not in routers:
                    log(f"Router Advertisement from {src}")
                routers[src] = {"source": src, "ra": parsed}
        return list(routers.values())
    finally:
        s.close()


# ---------------------------------------------------------------- DHCPv6

def dhcpv6_probe(iface=None, info=True, solicit=True, pd=False, mac=None, use_iface_mac=False,
                 server=None, server_port=dhcpv6.SERVER_PORT, timeout=5.0, log=None):
    """Information-Request and/or Solicit (no Rapid Commit, never a Request, so no lease).
    Returns parsed replies, each tagged with source and which request it answers."""
    log = log or (lambda m: None)
    iface, idx = _resolve(iface)
    if not (info or solicit):
        return []
    if use_iface_mac and iface.get("mac"):
        mac = bytes.fromhex(iface["mac"].replace(":", ""))
    duid = dhcpv6.duid_ll(mac or parse_mac("random"))

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT") and sys.platform == "darwin":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        _bind_device(s, iface)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
        try:
            s.bind(_addr(iface["ip6ll"], dhcpv6.CLIENT_PORT, idx) if os.name == "nt"
                   else ("::", dhcpv6.CLIENT_PORT))
        except PermissionError as e:
            raise _perm(e) from None
        except OSError as e:
            raise ProbeError(f"Can't bind UDP/546 ({e}). Another DHCPv6 client may own the port.") from e

        dest = server or dhcpv6.ALL_SERVERS
        pending = {}
        for kind, on in (("information-request", info), ("solicit", solicit)):
            if not on:
                continue
            xid = random.getrandbits(24)
            msg_type = dhcpv6.INFORMATION_REQUEST if kind == "information-request" else dhcpv6.SOLICIT
            pkt = dhcpv6.build(msg_type, xid, duid, ia_na=kind == "solicit", ia_pd=kind == "solicit" and pd)
            s.sendto(pkt, _addr(dest, server_port, idx))
            pending[xid] = kind
        log(f"Sent DHCPv6 {', '.join(pending.values())} on {iface['name']} to {dest}; "
            f"listening {timeout:g}s")

        replies, deadline = [], time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            r, _, _ = select.select([s], [], [], left)
            if not r:
                break
            try:
                data, addr = s.recvfrom(65535)
            except (ConnectionResetError, OSError):
                continue
            msg = dhcpv6.parse(data)
            if (not msg or msg["xid"] not in pending
                    or msg["msg_type"] not in (dhcpv6.ADVERTISE, dhcpv6.REPLY)):
                continue
            msg.update(source=addr[0].split("%")[0], request=pending[msg["xid"]])
            replies.append(msg)
            log(f"DHCPv6 {msg['type']} from {msg['source']}")
        return replies
    finally:
        s.close()


# ---------------------------------------------------------------- both at once

def probe6(iface=None, ra_on=True, info=True, solicit=True, pd=False, timeout=5.0, log=None,
           rs_dest=ra.ALL_ROUTERS, **dhcp_kw):
    """Run the RA listener and DHCPv6 probes in parallel. Errors in one don't stop the other;
    they're reported in result['errors'] unless both fail with a permission problem."""
    log = log or (lambda m: None)
    iface, _ = _resolve(iface)
    result = {"iface": iface["name"], "link_local": iface["ip6ll"], "routers": [], "dhcpv6": [],
              "errors": {}, "ran": {"ra": ra_on, "dhcpv6": info or solicit}, "solicited": solicit}
    failures = []

    def run(key, fn, **kw):
        try:
            result["routers" if key == "ra" else "dhcpv6"] = fn(iface=iface, timeout=timeout, log=log, **kw)
        except ProbeError as e:
            failures.append(e)
            result["errors"][key] = str(e)

    threads = []
    if ra_on:
        threads.append(threading.Thread(target=run, args=("ra", ra_probe), kwargs={"rs_dest": rs_dest}))
    if info or solicit:
        threads.append(threading.Thread(target=run, args=("dhcpv6", dhcpv6_probe),
                                        kwargs=dict(info=info, solicit=solicit, pd=pd, **dhcp_kw)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if failures and len(failures) == len(threads) and all(f.permission for f in failures):
        raise failures[0]
    return result

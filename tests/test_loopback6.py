"""End-to-end IPv6 over loopback: DHCPv6 against a fake server, RAs from a fake router.

Needs UDP/546 and raw ICMPv6 (root/Administrator), so it runs only with
DHCPPROBE_LOOPBACK=1 (CI sets this). Skips if the host has no IPv6 at all.
"""
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from dhcp_options_finder import dhcpv6, net6, report6  # noqa: E402
from fakeserver6 import HOME_RA, THREAD_BR, FakeDHCPv6, FakeRouter  # noqa: E402


def _has_ipv6():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.skipif(os.environ.get("DHCPPROBE_LOOPBACK") != "1",
                       reason="set DHCPPROBE_LOOPBACK=1 (needs UDP/546 and raw ICMPv6)"),
    pytest.mark.skipif(not _has_ipv6(), reason="no IPv6 on this host"),
]

LO = {"linux": "lo", "darwin": "lo0"}.get(sys.platform, "Loopback Pseudo-Interface 1")
IFACE = {"name": LO, "ip": "127.0.0.1", "ip6ll": "::1", "ip6ll_scope": "1", "mac": None, "up": True}


def test_dhcpv6_info_and_solicit_loopback():
    srv = FakeDHCPv6(replies=2)
    srv.start()
    replies = net6.dhcpv6_probe(iface=IFACE, server="::1", server_port=srv.port, timeout=4)
    srv.join(5)
    kinds = sorted((m["request"], m["type"]) for m in replies)
    assert kinds == [("information-request", "REPLY"), ("solicit", "ADVERTISE")]
    adv = next(dhcpv6.summarize(m) for m in replies if m["request"] == "solicit")
    assert any(o["code"] == 3 and "2001:db8:1::1000" in " ".join(o["values"]) for o in adv["options"])


def test_router_advertisements_loopback():
    router = FakeRouter(HOME_RA, THREAD_BR)
    router.start()
    routers = net6.ra_probe(iface=IFACE, timeout=3, rs_dest="::1")
    router.join(5)
    assert len(routers) == 1  # both RAs come from ::1; the latest one wins
    assert routers[0]["source"] == "::1"


def test_probe6_combined_loopback():
    srv = FakeDHCPv6(replies=2)
    srv.start()
    router = FakeRouter(HOME_RA)
    router.start()
    res = net6.probe6(iface=IFACE, timeout=3, server="::1", server_port=srv.port, rs_dest="::1")
    srv.join(5)
    router.join(5)
    assert res["errors"] == {}
    assert res["routers"] and len(res["dhcpv6"]) == 2
    assert "Router ::1" in report6.format_text6(res)

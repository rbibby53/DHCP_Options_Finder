"""End-to-end: real UDP/68 socket against the fake server on loopback.

Needs permission to bind UDP/68, so it only runs when DHCPPROBE_LOOPBACK=1
(CI sets this and uses sudo on Linux/macOS).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from dhcp_options_finder import net, report
from fakeserver import FakeServer

pytestmark = pytest.mark.skipif(os.environ.get("DHCPPROBE_LOOPBACK") != "1",
                                reason="set DHCPPROBE_LOOPBACK=1 (needs UDP/68)")

LO = {"linux": "lo", "darwin": "lo0"}.get(sys.platform, "Loopback")


@pytest.mark.parametrize("mode", ["discover", "inform"])
def test_probe_loopback(mode):
    srv = FakeServer()
    srv.start()
    iface = {"name": LO, "ip": "127.0.0.1", "mac": "02:aa:bb:cc:dd:ee", "up": True}
    replies = net.probe(iface=iface, mode=mode, server="127.0.0.1", server_port=srv.port,
                        timeout=5, first=True)
    srv.join(5)
    assert len(replies) == 1
    s = report.summarize(replies[0])
    assert s["type"] == ("OFFER" if mode == "discover" else "ACK")
    assert any(o["code"] == 43 for o in s["options"])


def test_list_interfaces():
    ifs = net.list_interfaces()
    assert ifs, "no interfaces found"
    assert net.default_interface(ifs) is not None

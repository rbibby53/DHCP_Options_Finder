import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import dhcpprobe as d
from fakeserver import build_reply

MAC = bytes.fromhex("02aabbccddee")


def reply(mode="discover"):
    req = d.build_packet(mode, 0x12345678, MAC, "0.0.0.0", list(range(1, 255)), "PXEClient", None, True)
    p = d.parse_packet(build_reply(req))
    p["source"] = "10.20.30.1"
    return p


def opts(p):
    return {o["code"]: o["values"] for o in d.summarize(p)["options"]}


def test_request_packet():
    pkt = d.build_packet("discover", 1, MAC, "0.0.0.0", list(range(1, 255)), "PXEClient", "host1", True)
    p = d.parse_packet(pkt)
    o = dict(p["options"])
    assert o[53] == b"\x01"
    assert len(o[55]) == 254  # PRL split per RFC 3396, reassembled on parse
    assert o[60] == b"PXEClient" and o[12] == b"host1"
    assert len(pkt) >= 300


def test_header_and_type():
    s = d.summarize(reply())
    assert s["type"] == "OFFER" and s["server_id"] == "10.20.30.1"
    assert s["fields"]["yiaddr"] == "10.20.30.40"
    assert d.summarize(reply("inform"))["type"] == "ACK"


def test_common_options():
    o = opts(reply())
    assert o[1] == ["255.255.255.0"]
    assert o[6] == ["10.1.1.1", "10.1.1.2"]
    assert o[51] == ["86400 s (1d)"]
    assert o[46] == ["H-node"]
    assert o[150] == ["10.9.9.9"]
    assert o[252] == ["http://wpad/wpad.dat"]


def test_complex_options():
    o = opts(reply())
    assert o[43][1:] == ["sub 1: 10.5.5.5 (0x0a050505)", "sub 2: hello"]
    assert o[119] == ["bas.example.com", "it.example.com"]
    assert o[121] == ["10.50.0.0/24 via 10.20.30.254", "0.0.0.0/0 via 10.20.30.1"]
    assert o[125] == ["enterprise 3561: sub 1: ABCD"]
    assert o[82] == ["Circuit-ID: Gi1/0/", "Remote-ID: 0x001122334455"]


def test_overload_and_split():
    o = opts(reply())
    assert o[66] == ["tftp.example.com"] and o[67] == ["pxelinux.0"]
    assert o[224] == ["A" * 300]


def test_outputs():
    r = [reply()]
    assert "DHCPOFFER from 10.20.30.1" in d.format_text(r)
    j = json.loads(d.format_json(r))
    assert j[0]["options"][0]["code"] == 1


def test_helpers():
    assert d.parse_codes("1,3, 6-8") == [1, 3, 6, 7, 8]
    assert d.parse_mac("AA-BB-CC-DD-EE-FF") == bytes.fromhex("aabbccddeeff")
    assert d.parse_mac("random")[0] == 0x02
    assert d._fmt_time(0xFFFFFFFF) == "infinite"


def test_garbage_does_not_crash():
    assert d.parse_packet(b"\x00" * 10) is None
    for code in (3, 43, 119, 121, 125, 82, 81, 120, 200):
        d.decode(code, b"\xff\x01")  # malformed lengths fall back to hex

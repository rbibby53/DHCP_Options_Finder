"""IPv6: RS/RA and DHCPv6 encoding, decoding and checks (no sockets needed)."""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from dhcp_options_finder import dhcpv6, ra, report6  # noqa: E402
from fakeserver6 import (  # noqa: E402
    HOME_RA,
    THREAD_BR,
    a6,
    build_ra,
    build_reply,
    d6opt,
    dnssl_opt,
    mtu_opt,
    prefix_opt,
    rdnss_opt,
    route_opt,
)

# ------------------------------------------------------------ RS / RA

def test_rs_checksum_is_valid():
    src = "fe80::3e22:fbff:fe1a:2b3c"
    rs = ra.build_rs(src, bytes.fromhex("3c22fb1a2b3c"))
    assert rs[0] == 133 and rs[8:10] == b"\x01\x01" and len(rs) == 16
    # A correct checksum makes the one's-complement sum over pseudo-header + message zero
    assert ra.checksum(src, ra.ALL_ROUTERS, rs) == 0
    assert ra.build_rs() == bytes([133, 0, 0, 0, 0, 0, 0, 0])  # no source: no SLLA, no checksum


def test_checksum_known_vector():
    # RFC 1071 style: verify against an independent straightforward computation
    src, dst, msg = "fe80::1", "ff02::1", bytes([134, 0, 0, 0]) + b"\x40\x00\x07\x08" + b"\x00" * 8
    pseudo = a6(src) + a6(dst) + struct.pack("!I", len(msg)) + b"\x00\x00\x00\x3a"
    words = [int.from_bytes((pseudo + msg)[i:i + 2], "big") for i in range(0, len(pseudo + msg), 2)]
    s = sum(words)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    assert ra.checksum(src, dst, msg) == (~s & 0xFFFF)


def test_parse_home_ra():
    r = ra.parse_ra(HOME_RA)
    assert r["router_lifetime"] == 1800 and r["other"] and not r["managed"]
    assert r["prefixes"] == [{"prefix": "2001:db8:1::/64", "length": 64, "on_link": True,
                              "autonomous": True, "valid": 2592000, "preferred": 604800}]
    assert r["rdnss"] == [{"server": "2001:db8:1::1", "lifetime": 3600}]
    assert r["dnssl"] == [{"domain": "example.net", "lifetime": 3600}]
    assert r["mtu"] == 1500 and r["mac"] == "00:11:22:33:44:55"
    rows = dict(ra.describe(r))
    assert rows["Default router"].startswith("yes") and "Other config" in rows["Flags"]


def test_parse_thread_border_router():
    r = ra.parse_ra(THREAD_BR)
    assert r["router_lifetime"] == 0
    assert r["routes"] == [{"prefix": "fd3e:1234:5678::/64", "lifetime": 1800, "preference": "medium"}]
    assert ra.describe(r)[0][1].startswith("no (lifetime 0")


def test_parse_rejects_and_survives_garbage():
    assert ra.parse_ra(b"\x85\x00" + b"\x00" * 14) is None  # type 133 isn't an RA
    assert ra.parse_ra(b"\x86") is None
    bad = build_ra() + bytes([3, 0])  # zero-length option: stop parsing, keep what we have
    assert ra.parse_ra(bad)["router_lifetime"] == 1800


# ------------------------------------------------------------ DHCPv6

DUID = dhcpv6.duid_ll(bytes.fromhex("02aabbccddee"))


def test_build_solicit_has_no_rapid_commit():
    pkt = dhcpv6.build(dhcpv6.SOLICIT, 0xABCDEF, DUID, ia_na=True, ia_pd=True)
    msg = dhcpv6.parse(pkt)
    codes = [c for c, _ in msg["options"]]
    assert msg["msg_type"] == 1 and msg["xid"] == 0xABCDEF
    assert codes == [1, 8, 6, 3, 25] and 14 not in codes  # no Rapid Commit -> no lease
    oro = dict(msg["options"])[6]
    assert 23 in struct.unpack(f"!{len(oro) // 2}H", oro)


def test_decode_advertise():
    req = dhcpv6.build(dhcpv6.SOLICIT, 1, DUID, ia_na=True)
    msg = dhcpv6.parse(build_reply(req))
    msg.update(source="fe80::1", request="solicit")
    s = dhcpv6.summarize(msg)
    vals = {o["code"]: o["values"] for o in s["options"]}
    assert s["type"] == "ADVERTISE" and s["preference"] == 255
    assert s["server_id"] == "DUID-LL 00:11:22:33:44:55"
    assert vals[23] == ["2001:db8:1::53", "2001:db8:1::54"]
    assert vals[24] == ["example.net"]
    assert vals[56] == ["server 2001:db8:1::123", "server time.example.net"]
    assert vals[32] == ["86400 s (1d)"]
    assert vals[3][1].startswith("IA Address: 2001:db8:1::1000 (preferred 3600 s (1h)")


def test_decode_prefix_status_and_unknown():
    iapd = struct.pack("!III", 7, 0, 0) + d6opt(26, struct.pack("!IIB", 100, 200, 56) + a6("2001:db8:ab00::"))
    assert dhcpv6.decode(25, iapd)[1] == (
        "IA Prefix: 2001:db8:ab00::/56 (preferred 100 s (1m 40s), valid 200 s (3m 20s))")
    assert dhcpv6.decode(13, b"\x00\x02no addresses") == "NoAddrsAvail: no addresses"
    assert dhcpv6.decode(999, b"hello") == "hello"
    assert dhcpv6.decode(23, b"\x01\x02") == "0x0102"  # wrong length falls back


# ------------------------------------------------------------ checks

def result(routers=(), replies=(), errors=None, ra_on=True, dhcp_on=True):
    rs = [{"source": src, "ra": ra.parse_ra(pkt)} for src, pkt in routers]
    ms = []
    for kind, pkt in replies:
        m = dhcpv6.parse(pkt)
        m.update(source="fe80::53", request=kind)
        ms.append(m)
    return {"iface": "eth0", "link_local": "fe80::1", "routers": rs, "dhcpv6": ms,
            "errors": errors or {}, "ran": {"ra": ra_on, "dhcpv6": dhcp_on}, "solicited": True}


def levels(res):
    return [(f["level"], f["message"].split(".")[0]) for f in report6.check6(res)]


def info_reply():
    return ("information-request", build_reply(dhcpv6.build(dhcpv6.INFORMATION_REQUEST, 1, DUID)))


def test_clean_home_network_has_no_findings():
    assert report6.check6(result([("fe80::1", HOME_RA)], [info_reply()])) == []


def test_rogue_ra_and_thread_split():
    res = result([("fe80::1", HOME_RA), ("fe80::bad", HOME_RA), ("fe80::a", THREAD_BR),
                  ("fe80::b", build_ra(route_opt("fd99::", 64), lifetime=0))], [info_reply()])
    msgs = [f["message"] for f in report6.check6(res)]
    assert any("2 routers claim to be the default IPv6 router" in m for m in msgs)
    assert any(m.startswith("Thread/Matter border router(s): fe80::a routes fd3e:1234:5678::/64")
               for m in msgs)
    assert any("different Thread prefixes" in m for m in msgs)


def test_flags_without_dhcpv6_and_missing_dns():
    managed = build_ra(prefix_opt("2001:db8::", 64, auto=False), managed=True, other=True)
    msgs = [f["message"] for f in report6.check6(result([("fe80::1", managed)]))]
    assert any("set the M, O flag but no DHCPv6 server answered" in m for m in msgs)
    assert any("No IPv6 DNS servers" in m for m in msgs)


def test_android_note_when_dns_only_from_dhcpv6():
    ra_no_dns = build_ra(prefix_opt("2001:db8::", 64), other=True)
    msgs = [f["message"] for f in report6.check6(result([("fe80::1", ra_no_dns)], [info_reply()]))]
    assert any("Android has no DHCPv6 client" in m for m in msgs)


def test_prefix_and_mtu_problems():
    bad = build_ra(prefix_opt("2001:db8::", 56), prefix_opt("2001:db8:1::", 64, valid=10, preferred=20),
                   prefix_opt("2001:db8:2::", 64, valid=0, preferred=0), mtu_opt(1200),
                   rdnss_opt("2001:db8::1"), dnssl_opt("x.example"))
    msgs = [f["message"] for f in report6.check6(result([("fe80::1", bad)], dhcp_on=False))]
    assert any("SLAAC needs a /64" in m for m in msgs)
    assert any("preferred lifetime longer than valid" in m for m in msgs)
    assert any("withdrawing prefix 2001:db8:2::/64" in m for m in msgs)
    assert any("below the IPv6 minimum of 1280" in m for m in msgs)


def test_no_routers_and_errors_reported():
    msgs = [f["message"] for f in report6.check6(result(errors={"dhcpv6": "boom"}))]
    assert any(m.startswith("No Router Advertisements") for m in msgs)
    assert any(m == "Couldn't check DHCPv6: boom" for m in msgs)


def test_text_and_json_output():
    res = result([("fe80::1", HOME_RA)], [info_reply()])
    text = report6.format_text6(res)
    assert "=== Router Advertisements: 1 router(s) ===" in text
    assert "DNS server (RDNSS)" in text and "REPLY to information-request from fe80::53" in text
    assert "No issues found." in text
    j = json.loads(report6.format_json6(res))
    assert j["family"] == "ipv6" and j["routers"][0]["rdnss"][0]["server"] == "2001:db8:1::1"
    assert j["dhcpv6"][0]["options"][2]["name"] == "DNS Servers"


# ------------------------------------------------------------ sockets & CLI (no network)

def test_scope_only_on_link_local():
    from dhcp_options_finder import net6
    assert net6._addr("fe80::1", 546, 7) == ("fe80::1", 546, 0, 7)
    assert net6._addr("ff02::1:2", 547, 7) == ("ff02::1:2", 547, 0, 7)
    assert net6._addr("::1", 546, 7) == ("::1", 546, 0, 0)
    assert net6._addr("2001:db8::1", 547, 7) == ("2001:db8::1", 547, 0, 0)


def test_cli_ipv6(monkeypatch, capsys):
    from dhcp_options_finder import cli
    seen = {}

    def fake_probe6(**kw):
        seen.update(kw)
        return result([("fe80::1", HOME_RA)], [info_reply()])

    monkeypatch.setattr(cli, "probe6", fake_probe6)
    monkeypatch.setattr(sys, "argv", ["dhcpprobe", "-6", "--no-solicit", "--pd", "-t", "2"])
    try:
        cli.main()
    except SystemExit as e:
        assert e.code == 0
    out = capsys.readouterr().out
    assert "=== Router Advertisements: 1 router(s) ===" in out
    assert seen["solicit"] is False and seen["info"] is True and seen["pd"] is True
    assert seen["server_port"] == 547 and seen["timeout"] == 2.0

    monkeypatch.setattr(sys, "argv", ["dhcpprobe", "-6", "--sweep"])
    try:
        cli.main()
    except SystemExit as e:
        assert "IPv4-only" in str(e.code)


# ------------------------------------------------------------ Windows learned-state fallback

WIN_STATE = {  # shape produced by net6._WIN_PS (PowerShell ConvertTo-Json)
    "managed": "Disabled", "other": "Enabled", "hop": 64,
    "routes": [{"prefix": "::/0", "hop": "fe80::1%14", "valid": 1795.2},
               {"prefix": "fd3e:1234:5678::/64", "hop": "fe80::a", "valid": 1700},
               {"prefix": "::/0", "hop": "fe80::bad", "valid": 9.223e11}],
    "addrs": [{"ip": "2001:db8:1::abcd", "len": 64, "valid": 2591000, "preferred": 604000},
              {"ip": "2001:db8:1::1234", "len": 64, "valid": 2591000, "preferred": 0}],
    "dns": "2001:db8:1::53",  # PowerShell collapses one-element arrays
}


def test_windows_state_mapping():
    from dhcp_options_finder import net6
    routers, dns = net6.windows_routers(WIN_STATE)
    by = {r["source"]: r["ra"] for r in routers}
    assert set(by) == {"fe80::1", "fe80::a", "fe80::bad"} and dns == ["2001:db8:1::53"]
    gw = by["fe80::1"]
    assert gw["router_lifetime"] == 1795 and gw["other"] and not gw["managed"]
    assert by["fe80::1"]["prefixes"][0]["prefix"] == "2001:db8:1::/64" and len(by["fe80::1"]["prefixes"]) == 1
    assert by["fe80::bad"]["router_lifetime"] == 0xFFFF  # infinite TimeSpan clamps to max RA lifetime
    assert by["fe80::a"]["router_lifetime"] == 0
    assert by["fe80::a"]["routes"][0]["prefix"] == "fd3e:1234:5678::/64"
    assert all(r["via"] == "windows" for r in routers)


def test_windows_checks_skip_rdnss_but_catch_rogue_and_thread():
    from dhcp_options_finder import net6
    routers, dns = net6.windows_routers(WIN_STATE)
    res = {"iface": "Ethernet", "link_local": "fe80::2", "routers": routers, "dhcpv6": [], "errors": {},
           "ran": {"ra": True, "dhcpv6": True}, "solicited": True, "ra_source": "windows", "os_dns": dns}
    msgs = [f["message"] for f in report6.check6(res)]
    assert not any("RDNSS" in m or "Android" in m for m in msgs)
    assert any("2 routers claim to be the default IPv6 router" in m for m in msgs)
    assert any(m.startswith("Thread/Matter border router(s): fe80::a") for m in msgs)
    text = report6.format_text6(res)
    assert "Windows doesn't let apps read Router Advertisements" in text
    assert "IPv6 DNS servers in use: 2001:db8:1::53" in text
    res["os_dns"] = []
    assert any("No IPv6 DNS servers" in f["message"] for f in report6.check6(res))

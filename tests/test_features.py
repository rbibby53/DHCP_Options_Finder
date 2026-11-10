"""v0.2 features: vendor decoders, config checks, baseline compare, MAC selection."""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dhcp_options_finder import baseline, checks, cli, net, options, packet, report

ip = socket.inet_aton


def opt(c, b):
    return bytes([c, len(b)]) + b


def reply(options, yiaddr="10.58.40.242", siaddr="0.0.0.0", mac_source="random", vclass=None):
    """Build and parse a server reply carrying exactly `options` ({code: bytes})."""
    hdr = (bytes([2, 1, 6, 0]) + b"\x00\x00\x00\x01" + b"\x00\x00\x80\x00" + b"\x00" * 4
           + ip(yiaddr) + ip(siaddr) + b"\x00" * 4 + b"\x02" + b"\x00" * 15)
    body = hdr + b"\x00" * 192 + b"\x63\x82\x53\x63"
    body += b"".join(opt(c, v) for c, v in options.items()) + b"\xff"
    p = packet.parse_packet(body)
    p.update(source="10.58.40.1", mac_source=mac_source, sent_vendor_class=vclass)
    return p


GOOD = {53: b"\x02", 54: ip("10.54.38.12"), 1: ip("255.255.255.0"), 3: ip("10.58.40.1"),
        6: ip("10.54.38.5") + ip("10.54.38.10"), 42: ip("10.54.38.1"),
        51: struct.pack("!I", 86400)}


def values(p, code):
    return next(o["values"] for o in report.summarize(p)["options"] if o["code"] == code)


def findings(p):
    return {(f["level"], f["option"]) for f in checks.check_reply(p)}


# ------------------------------------------------------------ vendor decoders

def test_siemens_vlan_discovery():
    v43 = bytes.fromhex("01075369656d656e73020400000029")  # captured from a real KSU scope
    out = values(reply({**GOOD, 43: v43}), 43)
    assert out[:3] == ["Siemens/Unify phone provisioning", "Vendor tag: Siemens", "Voice VLAN ID: 41"]
    dls = b"sdlp://10.1.1.5:18443"
    out = values(reply({**GOOD, 43: v43 + bytes([3, len(dls)]) + dls}), 43)
    assert "DLS server: sdlp://10.1.1.5:18443" in out


def test_cisco_wlc_list():
    out = values(reply({**GOOD, 43: bytes.fromhex("f108c0a80a05c0a80a14")}), 43)
    assert out[:3] == ["Cisco AP controller list", "WLC: 192.168.10.5", "WLC: 192.168.10.20"]


def test_unifi_controller_needs_vendor_class():
    v43 = bytes.fromhex("0104c0a80102")
    assert values(reply({**GOOD, 43: v43}, vclass="ubnt"), 43)[:2] == [
        "UniFi controller", "Controller: 192.168.1.2"]
    assert values(reply({**GOOD, 43: v43}), 43)[0] == "sub 1: 192.168.1.2 (or 3232235778)"


def test_microsoft_and_aruba():
    ms = bytes([1, 4, 0, 0, 0, 1, 3, 4, 0, 0, 0, 5])
    assert values(reply({**GOOD, 43: ms}, vclass="MSFT 5.0"), 43)[:3] == [
        "Microsoft vendor options", "Disable NetBIOS over TCP/IP: yes (1)",
        "Default router metric base: 5"]
    assert values(reply({**GOOD, 43: b"10.1.1.50"}, vclass="ArubaAP"), 43)[:2] == [
        "Aruba controller", "Controller: 10.1.1.50"]


def test_reply_option_60_wins_over_sent_class():
    p = reply({**GOOD, 60: b"ubnt", 43: bytes.fromhex("0104c0a80102")}, vclass="PXEClient")
    assert values(p, 43)[0] == "UniFi controller"


def test_four_byte_suboption_shows_number_and_ip():
    assert options._sub_value(b"\x00\x00\x00\x29") == "41 (or IP 0.0.0.41)"
    assert options._sub_value(ip("10.5.5.5")) == "10.5.5.5 (or 168101125)"


# ------------------------------------------------------------ checks

def test_clean_scope_has_no_findings():
    assert checks.check_reply(reply(GOOD)) == []


def test_findings_for_real_world_scope():
    # The scope from the first real run: no NTP, WINS set, odd lease on the interface MAC
    opts = {**GOOD, 44: ip("130.218.123.30"), 51: struct.pack("!I", 24516)}
    del opts[42]
    f = findings(reply(opts, mac_source="interface"))
    assert f == {("info", 42), ("info", 44), ("info", 51)}
    # Same lease with a random MAC isn't flagged as "remaining time"
    assert ("info", 51) not in findings(reply(opts, mac_source="random"))


def test_addressing_findings():
    f = findings(reply({**GOOD, 3: ip("10.99.0.1"), 28: ip("10.58.40.127")}))
    assert {("warn", 3), ("warn", 28)} <= f
    f = findings(reply({k: v for k, v in GOOD.items() if k not in (1, 3, 6)}))
    assert {("warn", 1), ("warn", 3), ("warn", 6)} <= f
    assert ("warn", None) in findings(reply(GOOD, yiaddr="10.58.40.255"))
    assert ("info", 6) in findings(reply({**GOOD, 6: ip("10.54.38.5")}))
    # Home/small office: the only resolver is the gateway itself -> not worth flagging
    assert ("info", 6) not in findings(reply({**GOOD, 6: ip("10.58.40.1")}))


def test_timer_and_tftp_findings():
    bad_timers = {**GOOD, 58: struct.pack("!I", 80000), 59: struct.pack("!I", 40000)}
    assert ("warn", 58) in findings(reply(bad_timers))
    tftp = {**GOOD, 66: b"10.9.9.9", 150: ip("10.9.9.10")}
    assert ("info", 66) in findings(reply(tftp, siaddr="10.9.9.9"))
    same = {**GOOD, 66: b"10.9.9.9", 150: ip("10.9.9.9")}
    assert ("info", 66) not in findings(reply(same, siaddr="10.9.9.9"))


# ------------------------------------------------------------ baseline

def test_baseline_roundtrip_and_drift(tmp_path):
    base = reply({**GOOD, 44: ip("130.218.123.30")})
    path = tmp_path / "base.json"
    path.write_text(report.format_json([base]))
    b = baseline.load_baseline(str(path))
    assert baseline.compare(report.to_record(base), b) == []

    # Server ID / message type differences are ignored; real config changes are not
    now = reply({**GOOD, 54: ip("10.54.38.13"), 6: ip("10.54.38.5") + ip("10.54.38.11"),
                 15: b"kennesaw.edu"})
    changes = {(c["kind"], c["option"]) for c in baseline.compare(report.to_record(now), b)}
    assert changes == {("changed", 6), ("added", 15), ("removed", 44)}
    text = report.format_text([now], baseline=b)
    assert "~   6 DNS Servers: 10.54.38.5, 10.54.38.10 -> 10.54.38.5, 10.54.38.11" in text
    assert "-  44 NetBIOS Name Servers (WINS): was 130.218.123.30  (removed)" in text


def test_load_baseline_rejects_other_json(tmp_path):
    path = tmp_path / "x.json"
    path.write_text('{"hello": 1}')
    try:
        baseline.load_baseline(str(path))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ------------------------------------------------------------ MAC selection

def test_mac_selection(monkeypatch):
    sent = {}

    class FakeSock:
        def sendto(self, pkt, addr):
            sent["chaddr"] = pkt[28:34]

        def close(self):
            pass

    monkeypatch.setattr(net, "_open_socket", lambda iface: FakeSock())
    monkeypatch.setattr(net.select, "select", lambda *a: ([], [], []))
    iface = {"name": "eth0", "ip": "10.58.40.50", "mac": "3c:22:fb:1a:2b:3c", "up": True}
    real = bytes.fromhex("3c22fb1a2b3c")

    net.probe(iface=iface, mode="discover", timeout=0.01)
    assert sent["chaddr"] != real and sent["chaddr"][0] == 0x02  # random, locally administered
    net.probe(iface=iface, mode="discover", timeout=0.01, use_iface_mac=True)
    assert sent["chaddr"] == real
    net.probe(iface=iface, mode="inform", timeout=0.01)
    assert sent["chaddr"] == real
    net.probe(iface=iface, mode="discover", timeout=0.01, mac=bytes.fromhex("001122334455"))
    assert sent["chaddr"] == bytes.fromhex("001122334455")


def test_cli_baseline_exit_codes(monkeypatch, tmp_path, capsys):
    current = {"opts": GOOD}
    monkeypatch.setattr(cli, "probe", lambda **kw: [reply(current["opts"])])
    path = str(tmp_path / "b.json")

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["dhcpprobe", *args])
        try:
            cli.main()
        except SystemExit as e:
            return e.code
        return 0

    assert run("--save-baseline", path) == 0
    assert run("--baseline", path) == 0
    assert "Changes vs baseline:\n    None." in capsys.readouterr().out
    current["opts"] = {**GOOD, 6: ip("10.54.38.5")}
    assert run("--baseline", path, "--json") == 3
    out = capsys.readouterr().out
    assert '"changes_vs_baseline"' in out and '"findings"' in out

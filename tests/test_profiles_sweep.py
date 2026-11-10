"""v0.3: saved profiles and the vendor class sweep."""
import json
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from test_features import GOOD, reply  # noqa: E402

from dhcp_options_finder import cli, net, profiles, report  # noqa: E402

ip = socket.inet_aton


@pytest.fixture(autouse=True)
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("DHCPOF_CONFIG_DIR", str(tmp_path / "cfg"))
    for var in ("DHCPOF_OWNER", "SUDO_UID", "SUDO_GID", "SUDO_USER"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path / "cfg"


# ------------------------------------------------------------ profiles

def test_profile_roundtrip(config):
    assert profiles.names() == [] and profiles.last() == {}
    profiles.put("Siemens phone", {"vendor_class": "OptiIpPhone", "timeout": "3", "mac": "",
                                   "bogus": "dropped"})
    profiles.save_last({"iface": "eth0", "mode": "inform"})
    assert profiles.names() == ["Siemens phone"]  # _last is hidden
    assert profiles.get("Siemens phone") == {"vendor_class": "OptiIpPhone", "timeout": "3"}
    assert profiles.last() == {"iface": "eth0", "mode": "inform"}
    profiles.delete("Siemens phone")
    assert profiles.names() == []
    with pytest.raises(ValueError):
        profiles.put("_last", {})


def test_corrupt_file_is_ignored(config):
    config.mkdir()
    (config / "profiles.json").write_text("{not json")
    assert profiles.load() == {}
    profiles.save_last({"mode": "discover"})  # overwrites cleanly
    assert json.loads((config / "profiles.json").read_text())["_last"] == {"mode": "discover"}


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX only")
def test_owner_from_sudo_env(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    assert profiles._owner() == (501, 20)
    monkeypatch.setenv("DHCPOF_OWNER", "1000:1000")
    assert profiles._owner() == (1000, 1000)


def norm(p):
    return p.replace("\\", "/")


def test_platform_config_dirs(monkeypatch):
    monkeypatch.delenv("DHCPOF_CONFIG_DIR")
    monkeypatch.setattr(profiles, "_real_home", lambda: "/home/u")
    monkeypatch.setattr(profiles, "_os", lambda: "mac")
    # Normalise separators: this runs on Windows CI too, where os.path.join uses "\\".
    assert norm(profiles.config_dir()) == "/home/u/Library/Application Support/DHCP Options Finder"
    monkeypatch.setattr(profiles, "_os", lambda: "linux")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert norm(profiles.config_dir()) == "/home/u/.config/dhcp-options-finder"


def run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["dhcpprobe", *args])
    try:
        cli.main()
    except SystemExit as e:
        return e.code
    return 0


def test_cli_profile_supplies_defaults_and_flags_override(monkeypatch, capsys):
    seen = {}

    def fake_probe(**kw):
        seen.update(kw)
        return [reply(GOOD)]

    monkeypatch.setattr(cli, "probe", fake_probe)
    assert run_cli(monkeypatch, "-V", "OptiIpPhone", "-t", "2", "--mac", "iface",
                   "--save-profile", "phone") == 0
    assert profiles.get("phone") == {"vendor_class": "OptiIpPhone", "timeout": 2.0, "mode": "discover",
                                     "request": "1-254", "use_iface_mac": True}
    seen.clear()
    assert run_cli(monkeypatch, "-p", "phone", "-t", "7") == 0
    assert seen["vendor_class"] == "OptiIpPhone" and seen["timeout"] == 7.0 and seen["use_iface_mac"]
    assert run_cli(monkeypatch, "--list-profiles") == 0
    assert "phone" in capsys.readouterr().out
    assert "No profile named" in str(run_cli(monkeypatch, "-p", "nope"))


# ------------------------------------------------------------ sweep

def fake_server(by_class):
    def probe(vendor_class=None, mac=None, **kw):
        probe.macs.add(mac)
        opts = by_class.get(vendor_class or "")
        return [reply(opts)] if opts is not None else []
    probe.macs = set()
    return probe


def test_sweep_uses_one_mac_and_reports_differences(monkeypatch):
    siemens = {**GOOD, 43: bytes.fromhex("01075369656d656e73020400000029"), 60: b"OptiIpPhone"}
    pxe = {**GOOD, 66: b"10.9.9.9", 67: b"pxelinux.0"}
    fake = fake_server({"": GOOD, "OptiIpPhone": siemens, "PXEClient": pxe, "MSFT 5.0": GOOD})
    monkeypatch.setattr(net, "probe", fake)
    iface = {"name": "eth0", "ip": "10.58.40.50", "mac": "3c:22:fb:1a:2b:3c", "up": True}
    mac, results = net.sweep(["", "OptiIpPhone", "PXEClient", "MSFT 5.0", "ubnt"], iface=iface)
    assert fake.macs == {mac} and mac[0] == 0x02

    rows = {r["vendor_class"]: r for r in report.sweep_summary(results)["rows"]}
    assert rows[""]["status"] == "reference"
    assert rows["MSFT 5.0"]["status"] == "same"
    assert rows["ubnt"]["status"] == "no reply"
    # option 60 echoed back by the server is not reported as a difference
    assert [(c["kind"], c["option"]) for c in rows["OptiIpPhone"]["changes"]] == [("added", 43)]
    assert "Voice VLAN ID: 41" in rows["OptiIpPhone"]["changes"][0]["now"]
    assert {c["option"] for c in rows["PXEClient"]["changes"]} == {66, 67}

    text = report.format_sweep(mac, results)
    assert "(none)" in text and "reference: 7 options" in text and "same as reference" in text
    assert json.loads(report.format_sweep_json(mac, results))["reference"] == ""


def test_sweep_without_plain_reply_picks_first_answer(monkeypatch):
    monkeypatch.setattr(net, "probe", fake_server({"PXEClient": GOOD}))
    iface = {"name": "eth0", "ip": None, "mac": "3c:22:fb:1a:2b:3c", "up": True}
    mac, results = net.sweep(["", "PXEClient"], iface=iface, use_iface_mac=True)
    assert mac == bytes.fromhex("3c22fb1a2b3c")
    s = report.sweep_summary(results)
    assert s["reference"] == "PXEClient"
    assert "so 'PXEClient' is the reference" in report.format_sweep(mac, results)


def test_cli_sweep_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(cli, "sweep", lambda classes, **kw: (b"\x02" * 6, [(c, []) for c in classes]))
    assert run_cli(monkeypatch, "--sweep-classes", ",PXEClient") == 1
    assert "No replies to any probe." in capsys.readouterr().out

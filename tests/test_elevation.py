"""Relaunch-as-admin helpers (pure logic; nothing is actually elevated)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

tk = pytest.importorskip("tkinter")
from dhcp_options_finder import gui as g  # noqa: E402


def test_relaunch_argv_uses_launcher(monkeypatch):
    launcher = os.path.join(os.path.dirname(__file__), "..", "dhcpprobe_gui.py")
    monkeypatch.setattr(g.sys, "argv", [launcher])
    argv = g._relaunch_argv()
    assert argv[0] == sys.executable and argv[1].endswith("dhcpprobe_gui.py")
    monkeypatch.setattr(g.sys, "argv", [""])
    assert g._relaunch_argv() == [sys.executable, "-m", "dhcp_options_finder.gui"]


def test_macos_uses_osascript_with_escaped_command(monkeypatch):
    calls = {}
    monkeypatch.setattr(g, "_os", lambda: "mac")
    # Pretend-macOS on any host: Windows' os module has no getuid/getgid.
    monkeypatch.setattr(g.os, "getuid", lambda: 501, raising=False)
    monkeypatch.setattr(g.os, "getgid", lambda: 20, raising=False)
    monkeypatch.setattr(g, "_relaunch_argv", lambda: ['/Applications/My "App"/x', "a b"])
    monkeypatch.setattr(g.subprocess, "Popen", lambda args, **kw: calls.setdefault("args", args))
    g.relaunch_elevated()
    script = calls["args"][2]
    assert calls["args"][:2] == ["osascript", "-e"]
    assert script.startswith('do shell script "') and script.endswith('" with administrator privileges')
    assert "DHCPOF_OWNER=501:20" in script
    assert '\\"App\\"' in script and "'a b'" in script and ">/dev/null 2>&1 &" in script


def test_linux_has_no_auto_relaunch(monkeypatch):
    monkeypatch.setattr(g, "_os", lambda: "linux")
    with pytest.raises(OSError):
        g.relaunch_elevated()
    assert g.sudo_hint().startswith("sudo -E ")

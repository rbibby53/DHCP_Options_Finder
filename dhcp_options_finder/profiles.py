"""Saved probe profiles and last-used settings, kept as JSON in the user's config folder.

Locations:
  Windows  %APPDATA%\\DHCP Options Finder\\profiles.json
  macOS    ~/Library/Application Support/DHCP Options Finder/profiles.json
  Linux    $XDG_CONFIG_HOME/dhcp-options-finder/profiles.json (default ~/.config/...)

The app usually runs elevated, so under sudo (or the GUI's own relaunch) profiles stay in
the invoking user's folder and stay owned by them.
"""
import json
import os
import sys

FIELDS = ("iface", "mode", "mac", "use_iface_mac", "vendor_class", "hostname", "server",
          "request", "timeout", "family", "v6_ra", "v6_info", "v6_solicit", "v6_pd")
LAST = "_last"  # reserved key: settings from the most recent probe


def _real_home():
    user = os.environ.get("SUDO_USER")
    if os.name != "nt" and user and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd
            return pwd.getpwnam(user).pw_dir
        except (ImportError, KeyError):
            pass
    return os.path.expanduser("~")


def _os():
    """'windows', 'mac' or 'linux'. A function so tests can fake it without touching os/sys."""
    if os.name == "nt":
        return "windows"
    return "mac" if sys.platform == "darwin" else "linux"


def config_dir():
    if os.environ.get("DHCPOF_CONFIG_DIR"):
        return os.environ["DHCPOF_CONFIG_DIR"]
    home = _real_home()
    if _os() == "windows":
        return os.path.join(os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"),
                            "DHCP Options Finder")
    if _os() == "mac":
        return os.path.join(home, "Library", "Application Support", "DHCP Options Finder")
    xdg = os.environ.get("XDG_CONFIG_HOME") if not os.environ.get("SUDO_USER") else None
    return os.path.join(xdg or os.path.join(home, ".config"), "dhcp-options-finder")


def path():
    return os.path.join(config_dir(), "profiles.json")


def _owner():
    """uid/gid to hand files back to when we're running elevated on someone's behalf."""
    raw = os.environ.get("DHCPOF_OWNER") or (
        f"{os.environ['SUDO_UID']}:{os.environ.get('SUDO_GID', os.environ['SUDO_UID'])}"
        if os.environ.get("SUDO_UID") else "")
    try:
        uid, gid = (int(x) for x in raw.split(":"))
        return uid, gid
    except ValueError:
        return None


def load():
    try:
        with open(path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data):
    d = config_dir()
    os.makedirs(d, exist_ok=True)
    tmp = path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path())
    owner = _owner()
    if owner and hasattr(os, "chown"):
        for p in (d, path()):
            try:
                os.chown(p, *owner)
            except OSError:
                pass


def clean(settings):
    return {k: settings[k] for k in FIELDS if k in settings and settings[k] not in (None, "")}


def names():
    return sorted(k for k in load() if k != LAST)


def get(name):
    return load().get(name)


def put(name, settings):
    if not name or name == LAST:
        raise ValueError("Pick a profile name.")
    data = load()
    data[name] = clean(settings)
    _save(data)


def delete(name):
    data = load()
    if data.pop(name, None) is not None:
        _save(data)


def save_last(settings):
    try:
        data = load()
        data[LAST] = clean(settings)
        _save(data)
    except OSError:
        pass  # remembering settings is a convenience; never fail a probe over it


def last():
    return load().get(LAST) or {}

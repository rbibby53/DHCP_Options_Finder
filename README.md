<p align="center">
  <img src="assets/icon-256.png" width="112" alt="DHCP Options Finder icon">
</p>

<h1 align="center">DHCP Options Finder</h1>

<p align="center">
  <b>Ask the DHCP server what it's actually handing out, and decode every option.</b><br>
  Desktop GUI and CLI for Windows, macOS and Linux.
</p>

<p align="center">
  <a href="https://github.com/rbibby53/DHCP_Options_Finder/actions/workflows/ci.yml"><img src="https://github.com/rbibby53/DHCP_Options_Finder/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/rbibby53/DHCP_Options_Finder/releases/latest"><img src="https://img.shields.io/github/v/release/rbibby53/DHCP_Options_Finder?sort=semver" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational" alt="Platforms">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/rbibby53/DHCP_Options_Finder" alt="License"></a>
</p>

<p align="center">
  <a href="https://github.com/rbibby53/DHCP_Options_Finder/releases/latest"><b>⬇ Download</b></a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#cli">CLI</a> ·
  <a href="#troubleshooting">Troubleshooting</a>
</p>

<p align="center">
  <img src="docs/screenshot.png" width="820" alt="DHCP Options Finder showing a decoded DHCPOFFER">
</p>

## Why

Checking what a scope delivers usually means a packet capture or logging into the DHCP server. That's slow when you're standing at a controller, phone or AP that won't come up. DHCP Options Finder sends one probe from your laptop and shows the reply as a readable table: router, DNS, NTP, option 43, TFTP/boot settings, classless routes, all of it.

- **Takes no lease.** It sends DISCOVER or INFORM and never REQUEST.
- **Asks for everything.** Requests all 254 option codes, so servers that only return what's requested still show their full config.
- **Sees every server.** Collects every reply in the window and warns when more than one DHCP server answers (possible rogue).
- **Impersonates a device.** Set the client MAC and vendor class (option 60) to see reservation- and class-specific options, e.g. option 43 for a particular AP or controller.
- **Knows the vendor formats.** Option 43 is decoded for Siemens/Unify phones (voice VLAN, DLS server), Cisco APs (WLC list), UniFi (controller), Aruba and Microsoft. Anything else falls back to sub-options, text or hex.
- **Checks the config.** Flags likely mistakes: router outside the subnet, mismatched broadcast address, missing DNS or NTP, out-of-order renewal timers, conflicting TFTP servers, leftover WINS.
- **Spots drift.** Save a known-good scope as a baseline; later probes show exactly what changed.
- **Decodes the hard ones:** 82 relay info, 119 domain search (with compression), 121/249 classless routes, 125 vendor-identifying info, option overload (52) and RFC 3396 split options.
- **Exports** to text or JSON, or copies selected rows to the clipboard.

## Quick start

### Download

Grab the build for your OS from the **[latest release](https://github.com/rbibby53/DHCP_Options_Finder/releases/latest)**:

| OS | File | Run |
|---|---|---|
| Windows | `DHCPOptionsFinder-windows-x64.exe` | Double-click. If it needs admin rights, it offers to relaunch itself |
| macOS (Apple silicon) | `DHCPOptionsFinder-macos-arm64.zip` | Unzip and open. If it needs admin rights, it asks for your password and relaunches |
| Linux | `DHCPOptionsFinder-linux-x64.tar.gz` | `tar xzf …` then `sudo ./DHCPOptionsFinder` (glibc 2.39+: Fedora 40+, Ubuntu 24.04+, Debian 13, RHEL 10) |

CLI-only builds (`dhcpprobe-cli-*`) and `SHA256SUMS.txt` are attached to every release.

Intel Macs are no longer supported. The last Intel build is in [v0.1.0](https://github.com/rbibby53/DHCP_Options_Finder/releases/tag/v0.1.0); running [from source](#from-source) still works.

> [!NOTE]
> Builds are not code-signed yet. On macOS, if Gatekeeper blocks the app: right-click, then **Open**, or run `xattr -dr com.apple.quarantine DHCPOptionsFinder.app`. On Windows, SmartScreen will warn: click **More info**, then **Run anyway**.

### From source

```bash
git clone https://github.com/rbibby53/DHCP_Options_Finder.git
cd DHCP_Options_Finder
pip install -r requirements.txt
sudo python3 dhcpprobe_gui.py      # Windows: py dhcpprobe_gui.py
```

You need Python 3.11+ with Tkinter (Fedora: `sudo dnf install python3-tkinter`, Debian/Ubuntu: `sudo apt install python3-tk`, Homebrew: `brew install python-tk`).

### Using it

1. Pick the **interface** on the segment you care about. The one with the default route is preselected.
2. Choose a **mode**:
   - **Discover** shows what a brand-new client on this segment would get. Use this most of the time.
   - **Inform** shows the config for a host that already has an IP. No address is offered, but options are.
3. Optionally set a **Client MAC** (a device's real MAC, to see its reservation) and a **Vendor class** (e.g. `OptiIpPhone`, `PXEClient`, your AP's class string). With the MAC blank, Discover uses a random MAC so an existing lease on your computer doesn't skew the answer. Tick **Use this computer's MAC** to send yours instead.
4. Click **Run Probe**. Each reply gets its own tab, with config checks at the top. Double-click a row for the full value, and tick **Show raw hex** to see the bytes.
5. To track changes, **Save JSON…** a known-good result, then later click **Compare to Baseline…** and pick that file. Changed options are highlighted and listed above the table.

## CLI

The same engine works without the GUI:

```bash
sudo python3 dhcpprobe.py --list                             # interfaces (* = default route)
sudo python3 dhcpprobe.py -i eth0                            # DISCOVER, request all options
sudo python3 dhcpprobe.py -i eth0 -m inform                  # INFORM from the current IP
sudo python3 dhcpprobe.py -i eth0 -V "PXEClient" -x          # send option 60, show raw hex
sudo python3 dhcpprobe.py -i eth0 -V OptiIpPhone             # what a Siemens/Unify phone gets
sudo python3 dhcpprobe.py -i eth0 --mac 3c:22:fb:1a:2b:3c    # options for that MAC's reservation
sudo python3 dhcpprobe.py -i eth0 --mac iface                # use this computer's MAC (default: random)
sudo python3 dhcpprobe.py -i eth0 -s 10.20.30.1              # unicast to one server
sudo python3 dhcpprobe.py -i eth0 -j > options.json          # JSON for scripts (includes checks)
sudo python3 dhcpprobe.py -i eth0 --save-baseline bas.json   # record a known-good scope
sudo python3 dhcpprobe.py -i eth0 --baseline bas.json        # compare; exit 3 if anything changed
```

<details>
<summary>Example output</summary>

```text
=== Reply 1: DHCPOFFER from 10.20.30.1  (Server ID 10.20.0.12) ===
  Offered IP (yiaddr)                10.20.30.142
  Relay Agent (giaddr)               10.20.30.1

  Code  Option                             Value
  ----  ---------------------------------- ----------------------------------------
     1  Subnet Mask                        255.255.255.0
     3  Router                             10.20.30.1
     6  DNS Servers                        10.20.0.5
                                           10.20.0.10
    15  Domain Name                        example.edu
    28  Broadcast Address                  10.20.30.255
    43  Vendor Specific Info               Siemens/Unify phone provisioning
                                           Vendor tag: Siemens
                                           Voice VLAN ID: 41
                                           raw: 0x01075369656d656e73020400000029
    44  NetBIOS Name Servers (WINS)        10.20.0.30
    51  Lease Time                         691200 s (8d)
    53  Message Type                       OFFER
    54  Server Identifier                  10.20.0.12

  Checks:
    i No NTP servers (42). Devices that take time from DHCP (many BAS controllers, IP phones) won't sync, which skews trend and alarm timestamps.
    i WINS/NetBIOS options (44/46) are set. These are legacy; remove them if nothing on this segment still uses WINS.

  Changes vs baseline:
    ~   6 DNS Servers: 10.20.0.5, 10.20.0.11 -> 10.20.0.5, 10.20.0.10
```
</details>

Run `python3 dhcpprobe.py --help` for every flag. Exit codes: `0` a server replied, `1` no replies, `3` the reply differs from `--baseline`. That makes it usable from a scheduled job or monitoring system to catch scope changes.

Baseline comparison works on the raw option bytes and ignores options that legitimately vary between probes: the requested IP (50), message type (53), server identifier (54, so failover partners don't count as drift), client ID (61) and relay agent info (82).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied on UDP/68` | DHCP clients must use port 68. On Windows and macOS the app offers to relaunch with admin rights; on Linux run it with `sudo -E`. |
| `Can't bind UDP/68 … address in use` | Another DHCP client owns the port, often `dhclient` on Linux. NetworkManager's built-in client doesn't conflict. |
| No replies | Check you're on the right interface/VLAN and that the scope or a relay (`ip helper-address`) covers this segment. Try the other mode. |
| Option 43 missing | The server probably keys it on vendor class. Set **Vendor class (60)** to what the device sends. |
| Windows: nothing back in Discover | Try **Inform**. Its reply is unicast to your IP, which is more likely to reach the app on Windows. |

## How it works

DHCP Options Finder builds a standard BOOTP/DHCP packet with option 55 (Parameter Request List) set to codes 1–254. Option 55 is split across instances per RFC 3396, since it doesn't fit in 255 bytes. It's sent from UDP/68 to 255.255.255.255:67 (or a server you name) with the broadcast flag set. The socket is pinned to the selected NIC (`SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` on macOS, bound to the interface address on Windows). Replies are matched on transaction ID and decoded. Nothing beyond that single packet is ever sent.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
python -m pytest                                           # unit tests
sudo -E DHCPPROBE_LOOPBACK=1 python3 -m pytest tests/test_loopback.py   # real sockets vs a fake server
```

CI runs lint plus unit and loopback tests on Windows, macOS and Linux against Python 3.11 (oldest supported) and 3.15 (latest). Release builds use Python 3.15.

### Releasing

1. In a PR, bump the version in `pyproject.toml` and `__version__` in `dhcpprobe.py`, and move the `[Unreleased]` notes in `CHANGELOG.md` under a new `## [X.Y.Z] - date` heading.
2. Merge it. The **Release** workflow sees that `vX.Y.Z` doesn't exist yet, builds every platform, creates the tag, and publishes the GitHub Release using the changelog section as release notes.

Merges that don't change the version don't release anything. Running **Release** by hand from the Actions tab builds the apps as downloadable artifacts without publishing.

## License

[AGPL-3.0](LICENSE) © Ryan J. Bibby

# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-11-10

### Added
- **IPv6 mode.** **Protocol → IPv6** in the GUI, `-6` in the CLI.
  - **Router Advertisements:** sends a Router Solicitation and decodes every RA: default-router lifetime and preference, M/O flags, prefixes (on-link/SLAAC, lifetimes), Route Information, RDNSS, DNSSL, MTU, NAT64 prefix (PREF64), captive portal.
  - **DHCPv6:** Information-Request for options (DNS, domains, NTP, SNTP, vendor options, timezone, boot URL and more), and Solicit to see the address (and, with `--pd`, the delegated prefix) a server would assign. Never sends a Request, so no lease is taken.
  - **IPv6 checks:** more than one default router (rogue RA), M/O flags with no DHCPv6 server, M flag with no address offered, no RDNSS (Android has no DHCPv6), no IPv6 DNS at all, SLAAC on a non-/64 prefix, bad prefix lifetimes, MTU below 1280, multiple DHCPv6 servers, and Thread/Matter border routers, including different border routers advertising different Thread prefixes.
  - Text and JSON output; profiles remember the protocol and IPv6 checks.

### Notes
- Sweep and baselines are IPv4-only for now.
- Router Advertisements need a raw socket. They work on Linux and macOS; on Windows, reading RAs may not work on every system, and when it doesn't the probe says so and still runs DHCPv6.


## [0.3.0] - 2026-11-10

### Added
- **Vendor class sweep:** probe once per vendor class (Siemens/Unify, Cisco AP, UniFi, Aruba, PXE, Microsoft, plus custom classes), all with the same MAC, and see which options each class gets. **Sweep Vendor Classes** in the GUI; `--sweep` / `--sweep-classes` in the CLI, with text or JSON output.
- **Profiles:** save named settings and reuse them. The GUI restores your last settings on launch; the CLI has `--profile`, `--save-profile`, `--list-profiles` and `--delete-profile`. Profiles stay in your user folder and owned by you, even under sudo or the GUI's admin relaunch.
- **pipx install:** `pipx install git+https://github.com/rbibby53/DHCP_Options_Finder.git` gives you `dhcpprobe` and `dhcp-options-finder` commands. Releases also attach the wheel.
- **macOS signing and notarization** in the release workflow, enabled once the Apple secrets are added (see `docs/macos-signing.md`).
- **Build provenance attestations** for every release file (`gh attestation verify`).

### Changed
- The "only one DNS server" check no longer fires when that server is the gateway itself (the usual home and small-office setup).
- The NTP check explains that it matters for devices on isolated VLANs.
- The GUI no longer repeats option 43 raw hex as a row; it's in the Raw (hex) column.
- The engine is now a package, `dhcp_options_finder`. `dhcpprobe.py` and `dhcpprobe_gui.py` still work from a checkout.
- Release workflow: actions pinned to commit SHAs, read-only token by default, with write access only for the publish job.


## [0.2.0] - 2026-11-09

### Added
- Vendor decoders for option 43: Siemens/Unify phones (voice VLAN ID, DLS server), Cisco AP WLC lists, UniFi controller, Aruba controller strings, and Microsoft vendor options. The vendor class from the reply (or the one sent) picks the decoder.
- Config checks on every reply: missing or invalid subnet mask, router outside the subnet, broadcast address mismatch, offered address equal to the network/broadcast address, missing DNS or NTP, single DNS server, short lease, out-of-order T1/T2, conflicting TFTP servers (siaddr/66/150), legacy WINS/NetBIOS, and a lease time that looks like the remaining time on this computer's own lease.
- Baseline comparison: `--save-baseline` / `--baseline` in the CLI (exit code 3 on drift) and **Compare to Baseline…** in the GUI, which highlights changed and added options and lists removed ones.
- Relaunch with administrator rights on Windows (UAC) and macOS (password prompt) when the probe hits a permission error.
- Option 160 (Polycom provisioning URL) and an `OptiIpPhone` vendor class preset.

### Changed
- Discover now uses a random, locally administered MAC by default, so an existing lease on this computer doesn't skew the offer. Use **Use this computer's MAC** (GUI) or `--mac iface` (CLI) for the old behaviour.
- 4-byte sub-option values show as both a number and an IP address (e.g. `41 (or IP 0.0.0.41)`) instead of always as an IP.
- JSON output includes `findings` per reply, and `changes_vs_baseline` when a baseline is given.

### Removed
- Intel Mac (macOS x64) builds. Releases now ship macOS Apple silicon only; v0.1.0 is the last release with an Intel build. Running from source on an Intel Mac still works but isn't tested.

## [0.1.0] - 2026-11-09

First release.

### Added
- Desktop GUI (Tkinter) and `dhcpprobe` CLI sharing one engine.
- DHCPDISCOVER and DHCPINFORM probes requesting option codes 1–254; no lease is taken.
- Collects replies from every server and warns when more than one answers.
- Client MAC, vendor class (60), hostname (12), unicast server and custom request-list overrides.
- Decoders for common option types plus 43, 81, 82, 119, 120, 121/249, 125, option overload and RFC 3396 split options.
- Text/JSON export, clipboard copy, raw hex view.
- Apps for Windows x64, macOS (Apple silicon and Intel) and Linux x64, built with Python 3.15 and PyInstaller 6.22.3, plus CLI-only builds and SHA-256 checksums.

### Requirements
- Running from source needs Python 3.11 or newer.
- The Linux build needs glibc 2.39+ (Fedora 40+, Ubuntu 24.04+, Debian 13, RHEL 10).

[Unreleased]: https://github.com/rbibby53/DHCP_Options_Finder/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/rbibby53/DHCP_Options_Finder/releases/tag/v0.4.0
[0.3.0]: https://github.com/rbibby53/DHCP_Options_Finder/releases/tag/v0.3.0
[0.2.0]: https://github.com/rbibby53/DHCP_Options_Finder/releases/tag/v0.2.0
[0.1.0]: https://github.com/rbibby53/DHCP_Options_Finder/releases/tag/v0.1.0

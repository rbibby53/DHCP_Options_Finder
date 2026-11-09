# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/rbibby53/DHCP_Options_Finder/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rbibby53/DHCP_Options_Finder/releases/tag/v0.1.0

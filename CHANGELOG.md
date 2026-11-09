# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Minimum Python is now 3.11 (3.9 and 3.10 are end-of-life). Tested on 3.11 and 3.15; release builds use Python 3.15.
- GitHub Actions moved to current majors (checkout v7, setup-python v7, upload-artifact v7, download-artifact v8, action-gh-release v3), all on Node 24.
- Dev and build tools pinned in `requirements-dev.txt` (PyInstaller 6.22.3, pytest 9.2.0, ruff 0.17.4, Pillow 13.0.0).
- Linux release builds on Ubuntu 24.04 (glibc 2.39).
- Dependabot groups updates into one PR per ecosystem.

## [0.1.0] - 2026-11-09

### Added
- Desktop GUI (Tkinter) and `dhcpprobe` CLI sharing one engine.
- DHCPDISCOVER and DHCPINFORM probes requesting option codes 1–254; no lease is taken.
- Collects replies from every server and warns when more than one answers.
- Client MAC, vendor class (60), hostname (12), unicast server and custom request-list overrides.
- Decoders for common option types plus 43, 81, 82, 119, 120, 121/249, 125, option overload and RFC 3396 split options.
- Text/JSON export, clipboard copy, raw hex view.
- Builds for Windows, macOS (arm64 and x64) and Linux, published to GitHub Releases.

[0.1.0]: https://github.com/rbibby53/DHCP_Options_Finder/releases/tag/v0.1.0

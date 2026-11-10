"""Release guard: versions must agree and be in the changelog, or the release workflow refuses to run."""
import os
import re
import sys
import tomllib

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

import dhcp_options_finder  # noqa: E402


def test_versions_match_and_changelog_entry():
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        ver = tomllib.load(f)["project"]["version"]
    assert dhcp_options_finder.__version__ == ver
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
        assert re.search(rf"^## \[{re.escape(ver)}\]", f.read(), re.M), f"CHANGELOG.md needs '## [{ver}]'"

"""Compare a reply against a saved known-good export."""
import json

# Options that legitimately differ between probes and shouldn't count as drift.
BASELINE_IGNORE = {50, 53, 54, 61, 82}

def load_baseline(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict) or "options" not in data:
        raise ValueError(f"{path} isn't a DHCP Options Finder JSON export.")
    return data


def _val(o):
    v = o.get("value", "")
    if isinstance(v, list):
        return ", ".join(x for x in v if not str(x).startswith("raw: 0x"))
    return str(v)


def compare(record, baseline, ignore=BASELINE_IGNORE):
    """Differences between a reply record and a baseline record, compared on raw bytes."""
    cur = {o["code"]: o for o in record["options"] if o["code"] not in ignore}
    old = {o["code"]: o for o in baseline["options"] if o["code"] not in ignore}
    changes = []
    for c in sorted(set(cur) | set(old)):
        if c not in old:
            changes.append({"kind": "added", "option": c, "name": cur[c]["name"], "now": _val(cur[c])})
        elif c not in cur:
            changes.append({"kind": "removed", "option": c, "name": old[c]["name"], "was": _val(old[c])})
        elif cur[c]["raw"] != old[c]["raw"]:
            changes.append({"kind": "changed", "option": c, "name": cur[c]["name"],
                            "was": _val(old[c]), "now": _val(cur[c])})
    for k, label in (("siaddr", "Next Server (siaddr)"), ("sname", "Server Name (sname)"),
                     ("file", "Boot File (file)")):
        if (record.get(k) or "") != (baseline.get(k) or ""):
            changes.append({"kind": "changed", "option": None, "name": label,
                            "was": baseline.get(k) or "", "now": record.get(k) or ""})
    return changes


def format_change(c, added="new", removed="removed"):
    code = f"{c['option']:>3} " if c["option"] is not None else "    "
    if c["kind"] == "added":
        return f"+ {code}{c['name']}: {c['now']}  ({added})"
    if c["kind"] == "removed":
        return f"- {code}{c['name']}: was {c['was']}  ({removed})"
    return f"~ {code}{c['name']}: {c['was']} -> {c['now']}"

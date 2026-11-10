"""Turn parsed replies into summaries, text and JSON."""
import json

from .baseline import BASELINE_IGNORE, compare, format_change
from .checks import check_reply
from .options import MSG_TYPES, OPTIONS, _hex, _ip, decode


def option_name(code):
    if code in OPTIONS:
        return OPTIONS[code][0]
    return "(site-specific)" if code >= 224 else "(unknown)"


def summarize(p):
    """Structured view of one reply, used by text, JSON and the GUI."""
    opts = dict(p["options"])
    mt = MSG_TYPES.get(opts[53][0], "?") if 53 in opts and opts[53] else "BOOTP"
    sid = _ip(opts[54]) if 54 in opts and len(opts[54]) == 4 else None
    header = [(label, p[k]) for k, label in (
        ("yiaddr", "Offered IP (yiaddr)"), ("siaddr", "Next Server (siaddr)"),
        ("giaddr", "Relay Agent (giaddr)"), ("sname", "Server Name (sname)"),
        ("file", "Boot File (file)")) if p[k] and p[k] != "0.0.0.0"]
    vclass = opts[60].decode("ascii", "replace") if 60 in opts else p.get("sent_vendor_class")
    options = []
    for c, d in sorted(p["options"], key=lambda x: x[0]):
        v = decode(c, d, vclass)
        options.append({"code": c, "name": option_name(c),
                        "values": (v if isinstance(v, list) else [v]) or [""],
                        "raw": bytes(d).hex()})
    return {"source": p["source"], "type": mt, "server_id": sid, "header": header,
            "fields": {k: p[k] for k in ("yiaddr", "siaddr", "giaddr", "sname", "file")},
            "options": options, "findings": check_reply(p)}


def to_record(p):
    """JSON-ready dict for one reply (the format saved as a baseline)."""
    s = summarize(p)
    return {"source": s["source"], "type": s["type"], "server_id": s["server_id"], **s["fields"],
            "options": [{"code": o["code"], "name": o["name"],
                         "value": o["values"] if len(o["values"]) > 1 else o["values"][0],
                         "raw": o["raw"]} for o in s["options"]],
            "findings": s["findings"]}

def format_text(replies, show_hex=False, baseline=None):
    if not replies:
        return ("No replies. Check: right interface, server scope/VLAN, firewall (UDP 67/68), "
                "or try the other mode.")
    lines = []
    for n, p in enumerate(replies, 1):
        s = summarize(p)
        lines.append(f"=== Reply {n}: DHCP{s['type']} from {s['source']}  "
                     f"(Server ID {s['server_id'] or '-'}) ===")
        for label, v in s["header"]:
            lines.append(f"  {label:<34} {v}")
        lines += ["", f"  {'Code':>4}  {'Option':<34} Value", f"  {'-'*4}  {'-'*34} {'-'*40}"]
        for o in s["options"]:
            lines.append(f"  {o['code']:>4}  {o['name']:<34} {o['values'][0]}")
            lines += [f"  {'':>4}  {'':<34} {x}" for x in o["values"][1:]]
            if show_hex:
                lines.append(f"  {'':>4}  {'':<34} raw: {o['raw']}")
        lines += ["", "  Checks:"]
        if s["findings"]:
            lines += [f"    {'!' if f['level'] == 'warn' else 'i'} {f['message']}" for f in s["findings"]]
        else:
            lines.append("    No issues found.")
        if baseline is not None and n == 1:
            ch = compare(to_record(p), baseline)
            lines += ["", "  Changes vs baseline:"]
            lines += [f"    {format_change(c)}" for c in ch] or ["    None."]
        lines.append("")
    servers = sorted({summarize(p)["server_id"] for p in replies} - {None})
    if len(servers) > 1:
        lines.append(f"WARNING: {len(servers)} DHCP servers answered: {', '.join(servers)}")
    return "\n".join(lines)


def format_json(replies, baseline=None):
    out = [to_record(p) for p in replies]
    if baseline is not None and out:
        out[0]["changes_vs_baseline"] = compare(out[0], baseline)
    return json.dumps(out, indent=2)


# ---------------------------------------------------------------- vendor class sweep

SWEEP_IGNORE = BASELINE_IGNORE | {60}  # servers often echo the class back


def sweep_summary(results):
    """Compare each vendor class's reply with the reference (no option 60, else first reply)."""
    answered = [(vc, r) for vc, r in results if r]
    ref_vc, ref = next(((vc, r) for vc, r in answered if not vc), answered[0] if answered else (None, None))
    ref_rec = to_record(ref[0]) if ref else None
    rows = []
    for vc, replies in results:
        row = {"vendor_class": vc, "replies": [to_record(p) for p in replies], "changes": []}
        if not replies:
            row["status"] = "no reply"
        elif vc == ref_vc:
            row["status"] = "reference"
        else:
            rec = row["replies"][0]
            row["changes"] = compare(rec, ref_rec, SWEEP_IGNORE)
            if rec["yiaddr"] != ref_rec["yiaddr"] and "0.0.0.0" not in (rec["yiaddr"], ref_rec["yiaddr"]):
                row["changes"].insert(0, {"kind": "changed", "option": None, "name": "Offered IP (yiaddr)",
                                          "was": ref_rec["yiaddr"], "now": rec["yiaddr"]})
            row["status"] = "differs" if row["changes"] else "same"
        rows.append(row)
    return {"reference": ref_vc, "rows": rows}


def _label(vc):
    return vc if vc else "(none)"


def format_sweep(mac, results):
    s = sweep_summary(results)
    lines = [f"Vendor class sweep: {len(results)} probes, client MAC {_hex(mac)} for every probe", ""]
    width = max(len(_label(r["vendor_class"])) for r in s["rows"]) + 2
    for r in s["rows"]:
        name = _label(r["vendor_class"]).ljust(width)
        if r["status"] == "reference":
            rec = r["replies"][0]
            lines.append(f"  {name}reference: {len(rec['options'])} options from "
                         f"{rec['server_id'] or rec['source']}")
        elif r["status"] == "no reply":
            lines.append(f"  {name}no reply")
        elif r["status"] == "same":
            lines.append(f"  {name}same as reference")
        else:
            lines.append(f"  {name}{format_change(r['changes'][0])}")
            lines += [f"  {' ' * width}{format_change(c)}" for c in r["changes"][1:]]
    if s["reference"] is None:
        lines.append("\nNo replies to any probe.")
    elif s["reference"]:
        lines.append(f"\nNo reply without option 60, so {s['reference']!r} is the reference.")
    return "\n".join(lines)


def format_sweep_json(mac, results):
    s = sweep_summary(results)
    return json.dumps({"mac": _hex(mac), "reference": s["reference"], "results": s["rows"]}, indent=2)

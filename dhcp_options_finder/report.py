"""Turn parsed replies into summaries, text and JSON."""
import json

from .baseline import compare, format_change
from .checks import check_reply
from .options import MSG_TYPES, OPTIONS, _ip, decode


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

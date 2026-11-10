"""IPv6 results: config checks plus text and JSON output."""
import ipaddress
import json

from . import dhcpv6, ra

ULA = ipaddress.IPv6Network("fc00::/7")


def _is_ula(prefix):
    try:
        return ipaddress.IPv6Network(prefix).subnet_of(ULA)
    except (ValueError, TypeError):
        return False


def _offers_address(msg):
    """True if a reply carries an IA_NA with at least one IA Address inside."""
    return any(code == 3 and len(data) >= 12 and any(c == 5 for c, _ in dhcpv6.parse_options(data[12:]))
               for code, data in msg["options"])


def check6(result):
    """Flag likely IPv6 misconfigurations. [{level: warn|info, message}]"""
    out = []

    def add(level, message):
        out.append({"level": level, "message": message})

    routers, replies, errors = result["routers"], result["dhcpv6"], result["errors"]
    for key, label in (("ra", "Router Advertisements"), ("dhcpv6", "DHCPv6")):
        if key in errors:
            add("info", f"Couldn't check {label}: {errors[key]}")

    default = [r for r in routers if r["ra"]["router_lifetime"]]
    ran_ra = result["ran"]["ra"] and "ra" not in errors
    ran_dhcp = result["ran"]["dhcpv6"] and "dhcpv6" not in errors

    if ran_ra and not routers:
        add("info", "No Router Advertisements. Hosts here get no IPv6 default route or SLAAC "
                    "addresses (expected if IPv6 isn't deployed on this segment).")
    if len(default) > 1:
        add("warn", f"{len(default)} routers claim to be the default IPv6 router: "
                    f"{', '.join(r['source'] for r in default)}. Unless that's intended (e.g. two "
                    "first-hop routers), look for a rogue RA source.")

    flagged = [r for r in default if r["ra"]["managed"] or r["ra"]["other"]]
    if flagged and ran_dhcp and not replies:
        which = ", ".join(sorted({f for r in flagged for f, on in
                                  (("M", r["ra"]["managed"]), ("O", r["ra"]["other"])) if on}))
        add("warn", f"Routers set the {which} flag but no DHCPv6 server answered. Clients that follow "
                    "the flags won't get DHCPv6 addresses or options; check the DHCPv6 server or "
                    "the router's DHCPv6 relay.")
    solicited = result.get("solicited", True)
    if (any(r["ra"]["managed"] for r in default) and ran_dhcp and replies and solicited
            and not any(_offers_address(m) for m in replies)):
        add("info", "Routers set the M flag (use DHCPv6 for addresses) but no DHCPv6 server "
                    "offered an address.")

    rdnss = [d for r in default for d in r["ra"]["rdnss"]]
    dhcp_dns = any(c == 23 for r in replies for c, _ in r["options"])
    if result.get("ra_source") == "windows":
        # Windows reports learned state, not the RAs themselves: it can't say whether a DNS
        # server came from RDNSS or DHCPv6, so only flag the case where there's none at all.
        if default and not result.get("os_dns") and not dhcp_dns and ran_dhcp:
            add("warn", "No IPv6 DNS servers from either Router Advertisements or DHCPv6.")
    elif default and not rdnss:
        if dhcp_dns:
            add("info", "No DNS servers in Router Advertisements (RDNSS); DNS comes only from DHCPv6. "
                        "Android has no DHCPv6 client, so Android devices get no IPv6 DNS here.")
        elif ran_dhcp:
            add("warn", "No IPv6 DNS servers from either RDNSS or DHCPv6.")

    for r in routers:
        src = r["source"]
        for p in r["ra"]["prefixes"]:
            if p["autonomous"] and p["length"] != 64:
                add("warn", f"{src} offers SLAAC on {p['prefix']}, but SLAAC needs a /64. "
                            "Hosts won't autoconfigure addresses from it.")
            if p["preferred"] > p["valid"]:
                add("warn", f"{src}: prefix {p['prefix']} has preferred lifetime longer than valid "
                            "lifetime, so hosts ignore it.")
            if p["valid"] == 0:
                add("info", f"{src} is withdrawing prefix {p['prefix']} (valid lifetime 0).")
        if r["ra"]["mtu"] is not None and r["ra"]["mtu"] < 1280:
            add("warn", f"{src} advertises MTU {r['ra']['mtu']}, below the IPv6 minimum of 1280.")

    # Thread / Matter border routers: lifetime-0 RAs carrying Route Information for ULA prefixes
    border = {}
    for r in routers:
        ula_routes = [x["prefix"] for x in r["ra"]["routes"] if _is_ula(x["prefix"]) and x["lifetime"]]
        if ula_routes and not r["ra"]["router_lifetime"]:
            border[r["source"]] = ula_routes
    if border:
        add("info", "Thread/Matter border router(s): " + "; ".join(
            f"{src} routes {', '.join(p)}" for src, p in border.items()) + ".")
        prefixes = {p for ps in border.values() for p in ps}
        if len(border) > 1 and len(prefixes) > 1:
            add("info", "Border routers advertise different Thread prefixes "
                        f"({', '.join(sorted(prefixes))}). "
                        "That usually means more than one Thread network (e.g. Apple and Google/Amazon "
                        "border routers not sharing credentials), so devices on one aren't reachable "
                        "through the other's border routers.")

    servers = {dhcpv6.summarize(m)["server_id"] for m in replies} - {None}
    if len(servers) > 1:
        add("info", f"{len(servers)} DHCPv6 servers answered. Check for a rogue server if that "
                    "isn't expected.")
    for m in replies:
        st = dhcpv6.summarize(m)["status"]
        if st and not st.startswith("Success"):
            add("info", f"DHCPv6 {m['request']} answered by {m['source']} with status {st}.")
    return out


# ---------------------------------------------------------------- output

def to_record6(result):
    return {
        "family": "ipv6", "iface": result["iface"], "link_local": result["link_local"],
        "routers": [{"source": r["source"], **r["ra"]} for r in result["routers"]],
        "dhcpv6": [{**{k: v for k, v in dhcpv6.summarize(m).items() if k != "options"},
                    "options": [{"code": o["code"], "name": o["name"],
                                 "value": o["values"] if len(o["values"]) > 1 else o["values"][0],
                                 "raw": o["raw"]} for o in dhcpv6.summarize(m)["options"]]}
                   for m in result["dhcpv6"]],
        "router_source": result.get("ra_source", "captured"), "os_dns": result.get("os_dns", []),
        "errors": result["errors"], "findings": check6(result),
    }


def format_json6(result):
    return json.dumps(to_record6(result), indent=2)


def format_text6(result, show_hex=False):
    lines = [f"IPv6 on {result['iface']} (link-local {result['link_local']})", ""]
    if result["ran"]["ra"]:
        lines.append(f"=== Router Advertisements: {len(result['routers'])} router(s) ===")
        if result.get("ra_source") == "windows":
            lines.append("  (Windows doesn't let apps read Router Advertisements; this is what Windows "
                         "learned from them after a Router Solicitation)")
            if result.get("os_dns"):
                lines.append(f"  IPv6 DNS servers in use: {', '.join(result['os_dns'])}")
        if "ra" in result["errors"]:
            lines.append(f"  (not checked: {result['errors']['ra']})")
        for r in result["routers"]:
            lines += ["", f"  Router {r['source']}"]
            lines += [f"    {label:<24} {value}" for label, value in ra.describe(r["ra"])]
        lines.append("")
    if result["ran"]["dhcpv6"]:
        n = len(result["dhcpv6"])
        lines.append(f"=== DHCPv6: {n} repl{'y' if n == 1 else 'ies'} ===")
        if "dhcpv6" in result["errors"]:
            lines.append(f"  (not checked: {result['errors']['dhcpv6']})")
        for m in result["dhcpv6"]:
            s = dhcpv6.summarize(m)
            lines += ["", f"  {s['type']} to {m['request']} from {m['source']}"
                          + (f"  (preference {s['preference']})" if s["preference"] is not None else "")]
            lines += [f"  {'Code':>4}  {'Option':<30} Value", f"  {'-' * 4}  {'-' * 30} {'-' * 36}"]
            for o in s["options"]:
                lines.append(f"  {o['code']:>4}  {o['name']:<30} {o['values'][0]}")
                lines += [f"  {'':>4}  {'':<30} {x}" for x in o["values"][1:]]
                if show_hex:
                    lines.append(f"  {'':>4}  {'':<30} raw: {o['raw']}")
        lines.append("")
    lines.append("Checks:")
    findings = check6(result)
    lines += [f"  {'!' if f['level'] == 'warn' else 'i'} {f['message']}" for f in findings] or [
        "  No issues found."]
    return "\n".join(lines)

#!/usr/bin/env python3

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.ipc import ControlClient, ControlError

DAY_ALIASES = {
    "weekdays": "0,1,2,3,4",
    "weekends": "5,6",
    "everyday": "0,1,2,3,4,5,6",
    "all": None,
    "mon": "0",
    "tue": "1",
    "wed": "2",
    "thu": "3",
    "fri": "4",
    "sat": "5",
    "sun": "6",
}


def infer_type(pattern: str) -> tuple[str, str]:
    if pattern.startswith("re:"):
        return pattern[3:], "regex"
    if pattern.startswith("."):
        return "*" + pattern, "wildcard"
    if any(c in pattern for c in "*?["):
        return pattern, "wildcard"
    return pattern, "exact"


def check_root(program: str) -> None:
    if os.geteuid() != 0:
        print(f"{program} must be run as root", file=sys.stderr)
        raise SystemExit(1)


def parse_days(raw):
    if not raw:
        return None
    if raw.lower() in DAY_ALIASES:
        return DAY_ALIASES[raw.lower()]
    out = []
    for tok in raw.replace(" ", "").split(","):
        key = tok.lower()
        if DAY_ALIASES.get(key):
            out.append(DAY_ALIASES[key])
        else:
            out.append(str(int(tok)))
    return ",".join(out)


def parse_time(raw):
    if not raw:
        return None, None
    if "-" not in raw:
        raise SystemExit("time must be START-END (e.g. 9-5 or 09:00-17:00)")
    a, b = raw.split("-", 1)

    def norm(t):
        t = t.strip()
        if ":" in t:
            h, m = t.split(":", 1)
            return f"{int(h):02d}:{int(m):02d}"
        return f"{int(t):02d}:00"

    return norm(a), norm(b)


def cmd_block(args, client):
    pattern, mtype = infer_type(args.pattern)
    t0, t1 = parse_time(args.time)
    days = parse_days(args.days)
    result = client.call(
        "block",
        pattern=pattern,
        type=mtype,
        time_start=t0,
        time_end=t1,
        days_of_week=days,
    )
    print(f"blocked {args.pattern}  (rule {result['id']}, {mtype})")


def cmd_allow(args, client):
    pattern, mtype = infer_type(args.pattern)
    result = client.call("allow", pattern=pattern, type=mtype)
    print(f"allow rule added for {args.pattern}  (rule {result['id']})")


def cmd_unblock(args, client):
    result = client.call("unblock", pattern=args.pattern)
    print(f"removed {result['removed']} rule(s) matching {args.pattern}")


def cmd_whitelist(args, client):
    pattern, mtype = infer_type(args.pattern)
    client.call("whitelist", pattern=pattern, type=mtype)
    print(f"whitelisted {args.pattern}")


def cmd_check(args, client):
    r = client.call("check", domain=args.domain)
    if r["rule"] is None:
        print(f"{r['domain']} → {r['action']} (no rule)")
    else:
        rule = r["rule"]
        when = _describe_when(rule)
        print(
            f"{r['domain']} → {r['action']} "
            f"(rule {rule['id']}: {rule['pattern']!r}, "
            f"{rule['type']}, {when})"
        )


def cmd_list(args, client):
    r = client.call("list")
    if not r["rules"] and not r["whitelist"]:
        print("(no rules)")
        return
    if r["rules"]:
        print(f"{'ID':>4}  {'Pattern':<32} {'Type':<9} {'Action':<9} When")
        for rule in r["rules"]:
            print(
                f"{rule['id']:>4}  {rule['pattern']:<32} "
                f"{rule['type']:<9} {rule['action']:<9} "
                f"{_describe_when(rule)}"
            )
    if r["whitelist"]:
        print()
        print("Whitelist:")
        for w in r["whitelist"]:
            print(f"      {w['pattern']:<32} {w['type']}")


def cmd_ping(args, client):
    print(json.dumps(client.call("ping"), indent=2))


def cmd_firewall(args, client):
    if args.action == "status":
        r = client.call("firewall_status")
        if not r["available"]:
            print("firewall: unavailable (module not loaded)")
            return
        state = "enable" if r["enabled"] else "disable"
        applied = "yes" if r["applied"] else "no"
        print(f"firewall: {state}")
        print(f"  table:     {r['table']}")
        print(f"  block set: {r['block_set']}")
        print(f"  applied:   {applied}")
        return

    if args.action == "enable":
        r = client.call("firewall_enable")
        print("firewall enabled" if r["changed"] else "firewall already enabled")
    elif args.action == "disable":
        r = client.call("firewall_disable")
        print("firewall disabled" if r["changed"] else "firewall already disabled")
    else:
        raise SystemExit(f"unknown action: {args.action}")


def cmd_categories(args, client):
    if args.action == "list":
        r = client.call("categories_list")
        rows = r["categories"]
        if not rows:
            print("(no categories)")
            return
        print(f"{'Name':<12} {'Active':>8} {'Total':>8}")
        for c in rows:
            active = c["active"] or 0
            total = c["total"] or 0
            mark = "" if active else "  (disabled)"
            print(f"{c['name']:<12} {active:>8} {total:>8}{mark}")
        return

    if args.action == "enable":
        r = client.call("categories_enable", name=args.name)
        print(f"enabled {r['category']}: {r['rules_updated']} rule(s) re-enabled")
    elif args.action == "disable":
        r = client.call("categories_disable", name=args.name)
        print(f"disabled {r['category']}: {r['rules_updated']} rule(s) disabled")
    else:
        raise SystemExit(f"unknown action: {args.action}")


def cmd_update(args, client):
    cats = args.categories.split(",") if args.categories else None
    r = client.call("update", timeout=300, categories=cats)
    for cat, n in r["updated"].items():
        print(f"  {cat}: {n} domains")
    print(f"total rules: {r['total_rules']}")


def cmd_status(args, client):
    r = client.call("status")

    def human_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
            n /= 1024
        return f"{n:.1f} TB"

    def human_uptime(seconds):
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    fw = r["firewall"]
    fw_line = (
        f"enabled ({fw['table']}, {fw['blocked_ips']} IPs in block set)"
        if fw["enabled"]
        else "disabled"
    )

    print(
        f"daemon:    running (pid {r['pid']}, up {human_uptime(r['uptime_seconds'])})"
    )
    print(f"config:    {r['config_path']}")
    print(
        f"db:        {r['db_path']} "
        f"({human_size(r['db_size_bytes'])}, {r['query_count']:,} queries)"
    )
    print(f"rules:     {r['rules_active']:,} active")
    print(f"whitelist: {r['whitelist_count']:,}")
    print(f"firewall:  {fw_line}")
    print(f"upstreams: {', '.join(s.strip() for s in r['upstreams'])}")
    print(f"listen:    {r['listen']}")

    cache = r.get("cache")
    if cache:
        hit_pct = cache["hit_rate"] * 100
        print(
            f"cache:     {cache['size']}/{cache['max_size']} entries, "
            f"{hit_pct:.1f}% hit rate "
            f"({cache['hits']:,} hits, {cache['misses']:,} misses)"
        )


def cmd_flush_cache(args, client):
    client.call("flush_cache")
    print("cache cleared")


def cmd_logs(args, client):
    r = client.call(
        "logs",
        tail=args.tail,
        domain=args.domain,
        since=args.since,
        action=args.action,
    )
    entries = r["entries"]
    if not entries:
        print("(no matching entries)")
        return

    entries = list(reversed(entries))

    for e in entries:
        ts = e["timestamp"]
        client_ip = e["client"] or "?"
        domain = (e["domain"] or "?")[:32]
        action = e["action"] or "?"
        rule = f"  (rule {e['rule_id']})" if e.get("rule_id") else ""
        print(f"{ts}  {client_ip:<15}  {domain:<32}  {action}{rule}")


def cmd_reload(args, client):
    r = client.call("reload")
    print(f"reloaded {r['rules']} rules")


def _describe_when(rule):
    days = rule.get("days_of_week")
    t0 = rule.get("time_start")
    t1 = rule.get("time_end")
    if not days and not t0:
        return "always"
    parts = []
    if days:
        parts.append(f"days={days}")
    if t0 and t1:
        parts.append(f"{t0}-{t1}")
    return " ".join(parts)


def build_parser():
    p = argparse.ArgumentParser(prog="warpperctl")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("block", help="block a domain")
    b.add_argument("pattern")
    b.add_argument("--time", help="START-END, e.g. 9-5 or 09:00-17:00")
    b.add_argument("--days", help="weekdays|weekends|mon,tue,...|0,1,2")
    b.set_defaults(fn=cmd_block)

    a = sub.add_parser("allow", help="explicit allow (overrides later blocks)")
    a.add_argument("pattern")
    a.set_defaults(fn=cmd_allow)

    u = sub.add_parser("unblock", help="remove all rules matching pattern")
    u.add_argument("pattern")
    u.set_defaults(fn=cmd_unblock)

    w = sub.add_parser("whitelist", help="permanent allow")
    w.add_argument("pattern")
    w.set_defaults(fn=cmd_whitelist)

    c = sub.add_parser("check", help="what would happen for this domain?")
    c.add_argument("domain")
    c.set_defaults(fn=cmd_check)

    fw = sub.add_parser("firewall", help="manage the nftables firewall layer")
    fw.add_argument("action", choices=["enable", "disable", "status"])
    fw.set_defaults(fn=cmd_firewall)

    cat = sub.add_parser("categories", help="manage blocklist categories")
    cat_sub = cat.add_subparsers(dest="action", required=True)

    cat_sub.add_parser("list").set_defaults(fn=cmd_categories)

    ce = cat_sub.add_parser("enable")
    ce.add_argument("name")
    ce.set_defaults(fn=cmd_categories)

    cd = cat_sub.add_parser("disable")
    cd.add_argument("name")
    cd.set_defaults(fn=cmd_categories)

    u = sub.add_parser("update", help="fetch and apply blocklist updates")
    u.add_argument("--categories", help="comma-separated list (default: all)")
    u.set_defaults(fn=cmd_update)

    lg = sub.add_parser("logs", help="show recent query log entries")
    lg.add_argument(
        "--tail", type=int, default=50, help="max entries to show (default 50)"
    )
    lg.add_argument("--domain", help="filter by domain or subdomain")
    lg.add_argument("--since", help="duration like 30m, 2h, 1d")
    lg.add_argument(
        "--action",
        choices=["allow", "block", "redirect", "servfail"],
        help="filter by action",
    )
    lg.set_defaults(fn=cmd_logs)

    sub.add_parser("flush-cache").set_defaults(fn=cmd_flush_cache)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    sub.add_parser("ping").set_defaults(fn=cmd_ping)
    sub.add_parser("reload").set_defaults(fn=cmd_reload)

    return p


def main(argv=None):
    check_root("warpperctl")

    args = build_parser().parse_args(argv)
    client = ControlClient()
    try:
        args.fn(args, client)
    except ControlError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import argparse
import json
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

    sub.add_parser("list").set_defaults(fn=cmd_list)
    sub.add_parser("ping").set_defaults(fn=cmd_ping)
    sub.add_parser("reload").set_defaults(fn=cmd_reload)

    return p


def main():
    args = build_parser().parse_args()
    client = ControlClient()
    try:
        args.fn(args, client)
    except ControlError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

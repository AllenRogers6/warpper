from datetime import datetime, UTC

import pytest

from modules.rule_engine import RuleEngine, _parse_days, domain_matches


@pytest.mark.parametrize(
    "domain,pattern,mtype,expected",
    [
        ("example.com", "example.com", "exact", True),
        ("example.com", "EXAMPLE.com", "exact", False),
        ("sub.example.com", "*.example.com", "wildcard", True),
        ("example.com", "*.example.com", "wildcard", False),
        ("ads.example.com", ".*ads.*", "regex", True),
        ("example.com", "", "regex", False),
        ("example.com", "[invalid", "regex", False),
        ("example.com", "example", "regex", False),
    ],
)
def test_domain_matches(domain, pattern, mtype, expected):
    assert domain_matches(domain, pattern, mtype) is expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0,1,2,3,4", {0, 1, 2, 3, 4}),
        ("mon,tue,wed", {0, 1, 2}),
        ("mon,1,2", {0, 1, 2}),
        ("9,10", set()),
        ("garbage", set()),
        ("", set()),
        (None, set()),
    ],
)
def test_parse_days(raw, expected):
    assert _parse_days(raw) == expected


def _add_rule(engine, pattern, mtype, action, **kwargs):
    import sqlite3
    from modules.database import get_connection

    conn = get_connection(engine.db_path)
    cols = ["pattern", "type", "action", "enabled"]
    vals = [pattern, mtype, action, 1]
    for k, v in kwargs.items():
        cols.append(k)
        vals.append(v)
    placeholders = ",".join("?" * len(cols))
    conn.execute(
        f"INSERT INTO rules ({','.join(cols)}) VALUES ({placeholders})",
        vals,
    )
    conn.commit()
    conn.close()
    engine.reload_rules()


def test_default_is_allow(rule_engine):
    action, rule = rule_engine.evaluate("example.com")
    assert action == "allow"
    assert rule is None


def test_exact_block(rule_engine):
    _add_rule(rule_engine, "ads.example.com", "exact", "block")
    action, rule = rule_engine.evaluate("ads.example.com")
    assert action == "block"
    assert rule["pattern"] == "ads.example.com"


def test_whitelist_beats_block(rule_engine):
    _add_rule(rule_engine, "*.example.com", "wildcard", "block")
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    conn.execute(
        "INSERT INTO whitelist (pattern, type) VALUES (?,?)",
        ("safe.example.com", "exact"),
    )
    conn.commit()
    conn.close()
    rule_engine.reload_rules()

    action, _ = rule_engine.evaluate("safe.example.com")
    assert action == "allow"
    action, _ = rule_engine.evaluate("ads.example.com")
    assert action == "block"


def test_disabled_rule_is_ignored(rule_engine):
    import sqlite3
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) VALUES (?,?,?,0)",
        ("ads.example.com", "exact", "block"),
    )
    conn.commit()
    conn.close()
    rule_engine.reload_rules()
    action, _ = rule_engine.evaluate("ads.example.com")
    assert action == "allow"


def test_time_window_excludes_off_hours(rule_engine):
    _add_rule(
        rule_engine,
        "reddit.com",
        "exact",
        "block",
        time_start="09:00",
        time_end="17:00",
    )
    from modules.rule_engine import is_rule_active

    rule = rule_engine.rules_cache[0]
    at_10am = datetime(2026, 1, 5, 10, 0, tzinfo=UTC)
    at_8pm = datetime(2026, 1, 5, 20, 0, tzinfo=UTC)
    assert is_rule_active(rule, at_10am)
    assert not is_rule_active(rule, at_8pm)

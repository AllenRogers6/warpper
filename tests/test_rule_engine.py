from datetime import UTC, datetime

import pytest

from modules.rule_engine import _parse_days, domain_matches


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

    rule = rule_engine._exact["reddit.com"]
    at_10am = datetime(2026, 1, 5, 10, 0, tzinfo=UTC)
    at_8pm = datetime(2026, 1, 5, 20, 0, tzinfo=UTC)
    assert is_rule_active(rule, at_10am)
    assert not is_rule_active(rule, at_8pm)


def test_add_rule_appends_to_cache(rule_engine):
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    cur = conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES (?, 'exact', 'block', 1)",
        ("foo.example",),
    )
    conn.commit()
    rule_id = cur.lastrowid
    conn.close()

    before = rule_engine.rule_count
    rule_engine.add_rule(rule_id)
    assert rule_engine.rule_count == before + 1
    assert "foo.example" in rule_engine._exact
    assert rule_engine._exact["foo.example"]["action"] == "block"


def test_add_rule_skips_disabled(rule_engine):
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    cur = conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES (?, 'exact', 'block', 0)",
        ("disabled.example",),
    )
    conn.commit()
    rule_id = cur.lastrowid
    conn.close()

    before = rule_engine.rule_count
    rule_engine.add_rule(rule_id)
    assert rule_engine.rule_count == before
    assert "disabled.example" not in rule_engine._exact


def test_remove_rules_by_pattern(rule_engine):
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES ('foo.example', 'exact', 'block', 1)"
    )
    conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES ('foo.example', 'wildcard', 'block', 1)"
    )
    conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES ('bar.example', 'exact', 'block', 1)"
    )
    conn.commit()
    conn.close()
    rule_engine.reload_rules()

    removed = rule_engine.remove_rules_by_pattern("foo.example")
    assert removed == 2
    assert "foo.example" not in rule_engine._exact
    assert all(r["pattern"] != "foo.example" for r in rule_engine._wildcard)
    assert "bar.example" in rule_engine._exact


def test_set_category_enabled(rule_engine):
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    cat_id = conn.execute("INSERT INTO categories (name) VALUES ('test')").lastrowid
    for p in ("a.example", "b.example", "c.example"):
        conn.execute(
            "INSERT INTO rules (pattern, type, action, category_id, enabled) "
            "VALUES (?, 'exact', 'block', ?, 1)",
            (p, cat_id),
        )
    conn.commit()
    conn.close()
    rule_engine.reload_rules()

    updated = rule_engine.set_category_enabled(cat_id, enabled=False)
    assert updated == 3
    for r in rule_engine.all_rules():
        assert r.get("category_id") != cat_id


def test_exact_lookup_is_o1(rule_engine):
    import time

    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    for i in range(10000):
        conn.execute(
            "INSERT INTO rules (pattern, type, action, enabled) "
            "VALUES (?, 'exact', 'block', 1)",
            (f"domain{i}.example",),
        )
    conn.commit()
    conn.close()
    rule_engine.reload_rules()

    start = time.perf_counter()
    for i in range(1000):
        rule_engine.evaluate(f"domain{i * 10}.example")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"1000 lookups took {elapsed:.3f}s"


def test_wildcard_and_regex_still_work(rule_engine):
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES (?, 'wildcard', 'block', 1)",
        ("*.doubleclick.net",),
    )
    conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES (?, 'regex', 'block', 1)",
        (r"^ads\d+\.example$",),
    )
    conn.commit()
    conn.close()
    rule_engine.reload_rules()

    assert rule_engine.evaluate("foo.doubleclick.net")[0] == "block"
    assert rule_engine.evaluate("ads7.example")[0] == "block"
    assert rule_engine.evaluate("adsx.example")[0] == "allow"


def test_disabled_rules_dropped_from_cache(rule_engine):
    from modules.database import get_connection

    conn = get_connection(rule_engine.db_path)
    cat_id = conn.execute("INSERT INTO categories (name) VALUES ('temp')").lastrowid
    for i in range(100):
        conn.execute(
            "INSERT INTO rules (pattern, type, action, category_id, enabled) "
            "VALUES (?, 'exact', 'block', ?, 1)",
            (f"x{i}.example", cat_id),
        )
    conn.commit()
    conn.close()
    rule_engine.reload_rules()

    removed = rule_engine.set_category_enabled(cat_id, enabled=False)
    assert removed == 100
    assert rule_engine.evaluate("x0.example")[0] == "allow"

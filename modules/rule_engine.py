import fnmatch
import logging
import re
from datetime import UTC, datetime

from modules.database import get_connection

log = logging.getLogger("rule_engine")

DAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def domain_matches(domain, pattern, rule_type):
    if rule_type == "exact":
        return domain == pattern
    elif rule_type == "wildcard":
        return fnmatch.fnmatch(domain, pattern)
    elif rule_type == "regex":
        if not pattern:
            return False
        try:
            return re.fullmatch(pattern, domain) is not None
        except re.error:
            return False
    return False


def _parse_days(raw: str) -> set[int]:
    out = set()
    for tok in (raw or "").split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        if tok in DAY_NAMES:
            out.add(DAY_NAMES[tok])
        else:
            try:
                n = int(tok)
            except ValueError:
                continue
            if 0 <= n <= 6:
                out.add(n)
    return out


def is_rule_active(rule, now=None):
    if not rule["enabled"]:
        return False
    now = now or datetime.now(UTC)
    days = rule["days_of_week"]
    if days:
        allowed = _parse_days(days)
        if allowed and now.weekday() not in allowed:
            return False
    start = rule["time_start"]
    end = rule["time_end"]
    if start and end:
        current = now.strftime("%H:%M")
        if not (start <= current <= end):
            return False
    return True


def _compile_rule(row):
    r = dict(row)
    if r["type"] == "regex":
        try:
            r["_compiled"] = re.compile(r["pattern"])
        except re.error as e:
            log.warning("dropping invalid regex rule %r: %s", r["pattern"], e)
            return None
    return r


class RuleEngine:
    def __init__(self, db_path):
        self.db_path = db_path

        self._exact: dict[str, dict] = {}
        self._wildcard: list[dict] = []
        self._regex: list[dict] = []

        self._wl_exact: set[str] = set()
        self._wl_wildcard: list[dict] = []
        self._wl_regex: list[dict] = []

        self.reload_rules()

    def reload_rules(self):
        log.info("reloading rules from %s", self.db_path)
        conn = get_connection(self.db_path)
        try:
            rules = conn.execute("""
                SELECT r.*, c.name AS category_name
                FROM rules r
                LEFT JOIN categories c ON r.category_id = c.id
                WHERE r.enabled = 1
                """).fetchall()
            wl = conn.execute("SELECT * FROM whitelist").fetchall()
        finally:
            conn.close()

        self._exact.clear()
        self._wildcard.clear()
        self._regex.clear()
        self._wl_exact.clear()
        self._wl_wildcard.clear()
        self._wl_regex.clear()

        for row in rules:
            r = _compile_rule(row)
            if r is None:
                continue
            self._add_to_cache(r)

        for row in wl:
            w = _compile_rule(row)
            if w is None:
                continue
            self._add_to_whitelist_cache(w)

        log.info(
            "loaded %d rules (%d exact, %d wildcard, %d regex), " "%d whitelist",
            len(self._exact) + len(self._wildcard) + len(self._regex),
            len(self._exact),
            len(self._wildcard),
            len(self._regex),
            len(self._wl_exact) + len(self._wl_wildcard) + len(self._wl_regex),
        )

    def add_rule(self, rule_id: int) -> None:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                """
                SELECT r.*, c.name AS category_name
                FROM rules r
                LEFT JOIN categories c ON r.category_id = c.id
                WHERE r.id = ? AND r.enabled = 1
                """,
                (rule_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return
        r = _compile_rule(row)
        if r is not None:
            self._add_to_cache(r)

    def remove_rules_by_pattern(self, pattern: str) -> int:
        removed = 0

        if pattern in self._exact:
            del self._exact[pattern]
            removed += 1

        before = len(self._wildcard)
        self._wildcard = [r for r in self._wildcard if r["pattern"] != pattern]
        removed += before - len(self._wildcard)

        before = len(self._regex)
        self._regex = [r for r in self._regex if r["pattern"] != pattern]
        removed += before - len(self._regex)

        return removed

    def set_category_enabled(self, category_id: int, enabled: bool) -> int:

        if enabled:
            self.reload_rules()
            return -1

        removed = 0

        to_remove = [
            p for p, r in self._exact.items() if r.get("category_id") == category_id
        ]
        for p in to_remove:
            del self._exact[p]
            removed += 1

        before = len(self._wildcard)
        self._wildcard = [
            r for r in self._wildcard if r.get("category_id") != category_id
        ]
        removed += before - len(self._wildcard)

        before = len(self._regex)
        self._regex = [r for r in self._regex if r.get("category_id") != category_id]
        removed += before - len(self._regex)

        return removed

    def _add_to_cache(self, rule: dict) -> None:
        t = rule["type"]
        if t == "exact":
            self._exact[rule["pattern"]] = rule
        elif t == "wildcard":
            self._wildcard.append(rule)
        elif t == "regex":
            self._regex.append(rule)

    def _add_to_whitelist_cache(self, wl: dict) -> None:
        t = wl["type"]
        if t == "exact":
            self._wl_exact.add(wl["pattern"])
        elif t == "wildcard":
            self._wl_wildcard.append(wl)
        elif t == "regex":
            self._wl_regex.append(wl)

    def is_whitelisted(self, domain: str) -> bool:
        d = domain.lower()
        if d in self._wl_exact:
            return True
        for w in self._wl_wildcard:
            if fnmatch.fnmatch(d, w["pattern"]):
                return True
        for w in self._wl_regex:
            if w["_compiled"].fullmatch(d) is not None:
                return True
        return False

    def evaluate(self, domain, client=None, now=None, process_info=None):
        d = domain.lower()

        if self.is_whitelisted(d):
            return ("allow", None)

        rule = self._exact.get(d)
        if rule is not None and is_rule_active(rule, now):
            return (rule["action"], rule)

        for rule in self._wildcard:
            if not is_rule_active(rule, now):
                continue
            if fnmatch.fnmatch(d, rule["pattern"]):
                return (rule["action"], rule)

        for rule in self._regex:
            if not is_rule_active(rule, now):
                continue
            if rule["_compiled"].fullmatch(d) is not None:
                return (rule["action"], rule)

        return ("allow", None)

    @property
    def rule_count(self) -> int:
        return len(self._exact) + len(self._wildcard) + len(self._regex)

    @property
    def whitelist_count(self) -> int:
        return len(self._wl_exact) + len(self._wl_wildcard) + len(self._wl_regex)

    def all_rules(self):
        yield from self._exact.values()
        yield from self._wildcard
        yield from self._regex

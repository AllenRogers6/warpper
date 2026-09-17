import fnmatch
import re
from datetime import UTC, datetime

from modules.database import get_connection


def domain_matches(domain, pattern, rule_type):
    if rule_type == "exact":
        return domain == pattern
    elif rule_type == "wildcard":
        return fnmatch.fnmatch(domain, pattern)
    elif rule_type == "regex":
        try:
            return re.search(pattern, domain) is not None
        except re.error:
            return False
    return False


def is_rule_active(rule, now=None):
    if not rule["enabled"]:
        return False
    now = now or datetime.now(UTC)
    days = rule["days_of_week"]
    if days:
        allowed_days = [int(d) for d in days.split(",") if d.strip()]
        if now.weekday() not in allowed_days:
            return False
    start = rule["time_start"]
    end = rule["time_end"]
    if start and end:
        current = now.strftime("%H:%M")
        if not (start <= current <= end):
            return False
    return True


class RuleEngine:
    def __init__(self, db_path):
        self.db_path = db_path
        self.rules_cache = []
        self.whitelist_cache = []
        self.reload_rules()

    def reload_rules(self):
        conn = get_connection(self.db_path)
        # Load rules with category name
        query = """
            SELECT r.*, c.name as category_name
            FROM rules r
            LEFT JOIN categories c ON r.category_id = c.id
            WHERE r.enabled = 1
        """
        self.rules_cache = [dict(row) for row in conn.execute(query).fetchall()]
        self.whitelist_cache = [
            dict(row) for row in conn.execute("SELECT * FROM whitelist").fetchall()
        ]
        conn.close()

    def is_whitelisted(self, domain):
        for wl in self.whitelist_cache:
            if domain_matches(domain, wl["pattern"], wl["type"]):
                return True
        return False

    def evaluate(self, domain, client=None, now=None, process_info=None):
        if self.is_whitelisted(domain):
            return ("allow", None)

        for rule in self.rules_cache:
            if not is_rule_active(rule, now):
                continue
            if not domain_matches(domain, rule["pattern"], rule["type"]):
                continue
            if rule["action"] == "block":
                return ("block", rule)
            if rule["action"] == "redirect" and rule["redirect_ip"]:
                return ("redirect", rule)
            if rule["action"] == "allow":
                return ("allow", rule)
        return ("allow", None)

import sqlite3

from modules.database import get_connection
from modules.ipc import ControlError


class ControlHandlers:
    def __init__(self, db_path, engine, logger):
        self.db_path = db_path
        self.engine = engine
        self.logger = logger

    async def ping(self):
        return {"pong": True, "rules": len(self.engine.rules_cache)}

    async def check(self, domain):
        action, rule = self.engine.evaluate(domain)
        return {
            "domain": domain,
            "action": action,
            "rule": _rule_dict(rule) if rule else None,
        }

    async def list(self, limit=None):
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                "SELECT id, pattern, type, action, redirect_ip, "
                "time_start, time_end, days_of_week, enabled, category_id "
                "FROM rules ORDER BY id"
            ).fetchall()
            whitelist = conn.execute("SELECT pattern, type FROM whitelist").fetchall()
        finally:
            conn.close()
        rules = [dict(r) for r in rows]
        if limit:
            rules = rules[:limit]
        return {"rules": rules, "whitelist": [dict(r) for r in whitelist]}

    async def block(
        self,
        pattern,
        type="exact",
        time_start=None,
        time_end=None,
        days_of_week=None,
        redirect_ip=None,
    ):
        return await self._add_rule(
            pattern,
            type,
            "block" if redirect_ip is None else "redirect",
            time_start,
            time_end,
            days_of_week,
            redirect_ip,
        )

    async def allow(
        self, pattern, type="exact", time_start=None, time_end=None, days_of_week=None
    ):
        return await self._add_rule(
            pattern,
            type,
            "allow",
            time_start,
            time_end,
            days_of_week,
            None,
        )

    async def _add_rule(self, pattern, mtype, action, t0, t1, days, redirect_ip):
        if not pattern:
            raise ControlError("pattern is required")
        if mtype not in ("exact", "wildcard", "regex"):
            raise ControlError(f"invalid type: {mtype}")
        conn = get_connection(self.db_path)
        try:
            cur = conn.execute(
                "INSERT INTO rules (pattern, type, action, redirect_ip, "
                "time_start, time_end, days_of_week, enabled) "
                "VALUES (?,?,?,?,?,?,?,1)",
                (pattern, mtype, action, redirect_ip, t0, t1, days),
            )
            conn.commit()
            rule_id = cur.lastrowid
        except sqlite3.IntegrityError as e:
            raise ControlError(f"insert failed: {e}")
        finally:
            conn.close()
        self.engine.reload_rules()
        self.logger.info(f"rule added: id={rule_id} {action} {pattern}")
        return {"id": rule_id}

    async def unblock(self, pattern):
        conn = get_connection(self.db_path)
        try:
            cur = conn.execute(
                "DELETE FROM rules WHERE pattern = ?",
                (pattern,),
            )
            conn.commit()
            removed = cur.rowcount
        finally:
            conn.close()
        self.engine.reload_rules()
        self.logger.info(f"unblocked {pattern}: {removed} rule(s) removed")
        return {"removed": removed}

    async def whitelist(self, pattern, type="exact"):
        if type not in ("exact", "wildcard", "regex"):
            raise ControlError(f"invalid type: {type}")
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                "INSERT INTO whitelist (pattern, type) VALUES (?,?)",
                (pattern, type),
            )
            conn.commit()
        except sqlite3.IntegrityError as e:
            raise ControlError(f"insert failed: {e}")
        finally:
            conn.close()
        self.engine.reload_rules()
        self.logger.info(f"whitelist added: {pattern}")
        return {"pattern": pattern}

    async def unwhitelist(self, pattern):
        conn = get_connection(self.db_path)
        try:
            cur = conn.execute(
                "DELETE FROM whitelist WHERE pattern = ?",
                (pattern,),
            )
            conn.commit()
            removed = cur.rowcount
        finally:
            conn.close()
        self.engine.reload_rules()
        return {"removed": removed}

    async def reload(self):
        self.engine.reload_rules()
        self.logger.info("rules reloaded via IPC")
        return {"rules": len(self.engine.rules_cache)}


def _rule_dict(row):
    if row is None:
        return None
    return {
        k: row[k]
        for k in (
            "id",
            "pattern",
            "type",
            "action",
            "redirect_ip",
            "time_start",
            "time_end",
            "days_of_week",
        )
        if k in row
    }

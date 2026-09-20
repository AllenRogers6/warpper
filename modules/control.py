import os
import sqlite3
import time
from pathlib import Path

from modules.database import get_connection
from modules.firewall import FirewallError
from modules.ipc import ControlError


def _parse_duration(s: str):
    from datetime import timedelta

    if not s or len(s) < 2:
        return None
    unit = s[-1].lower()
    try:
        n = int(s[:-1])
    except ValueError:
        return None
    if unit == "s":
        return timedelta(seconds=n)
    if unit == "m":
        return timedelta(minutes=n)
    if unit == "h":
        return timedelta(hours=n)
    if unit == "d":
        return timedelta(days=n)
    return None


class ControlHandlers:
    def __init__(
        self, db_path, engine, firewall, logger, proxy, config, started_at=None
    ):
        self.db_path = db_path
        self.engine = engine
        self.firewall = firewall
        self.logger = logger
        self.proxy = proxy
        self.config = config
        self.started_at = started_at if started_at is not None else time.time()

    def _count_rows(self, table):
        from modules.database import get_connection

        conn = get_connection(self.db_path)
        try:
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        finally:
            conn.close()

    def _block_set_size(self):
        import subprocess

        try:
            r = subprocess.run(
                [
                    "nft",
                    "list",  # TODO: ADD JSON OUTPUT
                    "set",
                    self.firewall.family,
                    self.firewall.table,
                    self.firewall.block_set,
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if r.returncode != 0:
                return 0
            count = 0
            in_elements = False
            for line in r.stdout.splitlines():
                if "elements" in line or "{" in line:
                    in_elements = True
                if in_elements and line.strip() and not line.strip().endswith("}"):
                    count += line.count(",") + 1
            return count
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return 0

    async def ping(self):
        return {"pong": True, "rules": self.engine.rule_count}

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
            if "rules.pattern" in str(e) or "idx_rules_pattern_type" in str(e):
                raise ControlError(f"rule already exists for pattern: {pattern}")
            raise ControlError(f"insert failed: {e}")
        finally:
            conn.close()

        self.engine.add_rule(rule_id)
        self.logger.info(f"rule added: id={rule_id} {action} {pattern}")
        return {"id": rule_id}

    async def unblock(self, pattern):
        conn = get_connection(self.db_path)
        try:
            cur = conn.execute("DELETE FROM rules WHERE pattern = ?", (pattern,))
            conn.commit()
            removed = cur.rowcount
        finally:
            conn.close()

        self.engine.remove_rules_by_pattern(pattern)
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

    async def firewall_status(self):
        if self.firewall is None:
            return {"available": False, "enabled": False}
        return {
            "available": True,
            "enabled": self.firewall.enabled,
            "applied": self.firewall.is_applied(),
            "table": self.firewall.table,
            "block_set": self.firewall.block_set,
        }

    async def firewall_enable(self):
        if self.firewall is None:
            raise ControlError("firewall module not loaded")
        if self.firewall.enabled:
            return {"enabled": True, "changed": False}
        try:
            self.firewall.apply()
        except (FirewallError, OSError) as e:
            raise ControlError(f"failed to enable: {e}")
        return {"enabled": True, "changed": True}

    async def firewall_disable(self):
        if self.firewall is None:
            raise ControlError("firewall module not loaded")
        if not self.firewall.enabled:
            return {"enabled": False, "changed": False}
        try:
            self.firewall.remove()
        except (FirewallError, OSError) as e:
            raise ControlError(f"failed to disable: {e}")
        return {"enabled": False, "changed": True}

    async def categories_list(self):
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute("""
                SELECT c.id, c.name,
                    COUNT(r.id) AS total,
                    SUM(CASE WHEN r.enabled = 1 THEN 1 ELSE 0 END) AS active
                FROM categories c
                LEFT JOIN rules r ON r.category_id = c.id
                GROUP BY c.id, c.name
                ORDER BY c.name
            """).fetchall()
        finally:
            conn.close()
        return {"categories": [dict(r) for r in rows]}

    async def categories_enable(self, name):
        return await self._set_category_enabled(name, True)

    async def categories_disable(self, name):
        return await self._set_category_enabled(name, False)

    async def _set_category_enabled(self, name, enabled):
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT id FROM categories WHERE name=?", (name,)
            ).fetchone()
            if row is None:
                raise ControlError(f"unknown category: {name}")
            cat_id = row["id"]

            cur = conn.execute(
                "UPDATE rules SET enabled=? WHERE category_id=?",
                (1 if enabled else 0, cat_id),
            )
            conn.commit()
            count = cur.rowcount
        finally:
            conn.close()

        self.engine.set_category_enabled(cat_id, enabled)
        self.logger.info(
            "category %s %s: %d rule(s) updated",
            name,
            "enabled" if enabled else "disabled",
            count,
        )
        return {"category": name, "enabled": enabled, "rules_updated": count}

    async def update(self, categories=None):
        import asyncio

        from modules.updater import update_blocklists

        loop = asyncio.get_running_loop()
        try:
            summary = await loop.run_in_executor(
                None, update_blocklists, self.db_path, categories
            )
        except Exception as e:  # noqa: BLE001
            raise ControlError(f"update failed: {e}")

        self.engine.reload_rules()
        self.logger.info("blocklists updated: %s", summary)
        return {"updated": summary, "total_rules": self.engine.rule_count}

    async def status(self):
        db = Path(self.db_path)
        db_size = db.stat().st_size if db.exists() else 0
        query_count = self._count_rows("query_log")

        rules_count = self.engine.rule_count
        whitelist_count = self.engine.whitelist_count

        return {
            "pid": os.getpid(),
            "uptime_seconds": int(time.time() - self.started_at),
            "config_path": self.config["_meta"]["source"],
            "db_path": str(db),
            "db_size_bytes": db_size,
            "query_count": query_count,
            "rules_active": rules_count,
            "whitelist_count": whitelist_count,
            "firewall": {
                "enabled": self.firewall.enabled if self.firewall else False,
                "applied": self.firewall.is_applied() if self.firewall else False,
                "table": (
                    f"{self.firewall.family} {self.firewall.table}"
                    if self.firewall
                    else None
                ),
                "block_set": self.firewall.block_set if self.firewall else None,
                "blocked_ips": self._block_set_size() if self.firewall else 0,
            },
            "upstreams": self.config.get("general", "upstream_dns", fallback="").split(
                ","
            ),
            "listen": f"{self.config.get('proxy', 'listen_host', fallback='127.0.0.1')}:"
            f"{self.config.get('proxy', 'listen_port', fallback='15353')}",
            "cache": self.proxy.cache.stats() if self.proxy else None,
        }

    async def flush_cache(self):
        self.proxy.cache.clear()
        return {"cleared": True}

    async def logs(self, tail=50, domain=None, since=None, action=None):
        from datetime import UTC, datetime

        clauses = []
        params = []

        if domain:
            clauses.append("(domain = ? OR domain LIKE ?)")
            params.extend([domain, f"%.{domain}"])

        if action:
            clauses.append("action = ?")
            params.append(action)

        if since:
            delta = _parse_duration(since)
            if delta is None:
                raise ControlError(f"invalid duration: {since!r}")
            cutoff = (datetime.now(UTC) - delta).strftime("%Y-%m-%d %H:%M:%S")
            clauses.append("timestamp >= ?")
            params.append(cutoff)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT timestamp, client, domain, action, rule_id
            FROM query_log
            {where}
            ORDER BY id DESC
            LIMIT ?
        """
        params.append(int(tail))

        from modules.database import get_connection

        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()

        return {"entries": [dict(r) for r in rows]}

    async def reload(self):
        self.engine.reload_rules()
        self.logger.info("rules reloaded via IPC")
        return {"rules": self.engine.rule_count}


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

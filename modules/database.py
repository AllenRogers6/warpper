import logging
import sqlite3

log = logging.getLogger("database")

LATEST_VERSION = 2


def get_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate_0_to_1(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('exact','wildcard','regex')),
            category_id INTEGER,
            action TEXT NOT NULL CHECK(action IN ('block','allow','redirect')),
            redirect_ip TEXT,
            time_start TEXT,
            time_end TEXT,
            days_of_week TEXT,
            enabled INTEGER DEFAULT 1,
            FOREIGN KEY(category_id) REFERENCES categories(id)
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            pattern TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('exact','wildcard','regex'))
        );

        CREATE TABLE IF NOT EXISTS query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client TEXT,
            domain TEXT,
            action TEXT,
            rule_id INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_rules_pattern ON rules(pattern);
        CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
        CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);
    """)

    for cat in ("ads", "trackers", "malware", "social", "adult", "gambling"):
        conn.execute("INSERT OR IGNORE INTO categories (name) VALUES (?)", (cat,))


def _migrate_1_to_2(conn):
    conn.execute("""
        DELETE FROM rules
        WHERE id NOT IN (
            SELECT MIN(id) FROM rules GROUP BY pattern, type
        )
    """)
    conn.execute("CREATE UNIQUE INDEX idx_rules_pattern_type ON rules(pattern, type)")


MIGRATIONS = {
    1: _migrate_0_to_1,
    2: _migrate_1_to_2,
}


def _current_version(conn) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _set_version(conn, version: int) -> None:
    assert isinstance(version, int)
    conn.execute(f"PRAGMA user_version = {version}")


def init_db(db_path: str) -> None:
    conn = get_connection(db_path)
    try:
        current = _current_version(conn)
        if current == LATEST_VERSION:
            log.debug("db already at version %d", current)
            return

        if current > LATEST_VERSION:
            raise RuntimeError(
                f"database schema version {current} is newer than this "
                f"build supports ({LATEST_VERSION}). "
                f"Upgrade warpperd, or use a matching version."
            )

        log.info("migrating db from version %d to %d", current, LATEST_VERSION)
        for v in range(current + 1, LATEST_VERSION + 1):
            migration = MIGRATIONS.get(v)
            if migration is None:
                raise RuntimeError(f"no migration registered for version {v}")

            log.info("applying migration %d", v)
            try:
                migration(conn)
                _set_version(conn, v)
                conn.commit()
            except Exception:
                conn.rollback()
                log.exception("migration %d failed, rolled back", v)
                raise

        log.info("db migrated to version %d", LATEST_VERSION)
    finally:
        conn.close()

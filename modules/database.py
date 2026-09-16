import sqlite3
import os

SCHEMA = """
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
"""


def get_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path):
    conn = get_connection(db_path)
    conn.executescript(SCHEMA)
    default_categories = ["ads", "trackers", "malware", "social", "adult", "gambling"]
    for cat in default_categories:
        conn.execute("INSERT OR IGNORE INTO categories (name) VALUES (?)", (cat,))
    conn.commit()
    conn.close()

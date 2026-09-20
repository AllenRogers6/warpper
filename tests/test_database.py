import sqlite3

from modules.database import LATEST_VERSION, get_connection, init_db


def test_init_db_on_fresh_file(tmp_path):
    db = str(tmp_path / "fresh.db")
    init_db(db)
    conn = get_connection(db)
    try:
        v = conn.execute("PRAGMA user_version").fetchone()[0]
        assert v == LATEST_VERSION
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "rules" in tables
        assert "whitelist" in tables
        assert "query_log" in tables
    finally:
        conn.close()


def test_init_db_is_idempotent(tmp_path):
    db = str(tmp_path / "idem.db")
    init_db(db)
    init_db(db)
    init_db(db)
    conn = get_connection(db)
    try:
        v = conn.execute("PRAGMA user_version").fetchone()[0]
        assert v == LATEST_VERSION
    finally:
        conn.close()


def test_init_db_rejects_future_version(tmp_path):
    db = str(tmp_path / "future.db")
    conn = sqlite3.connect(db)
    conn.execute(f"PRAGMA user_version = {LATEST_VERSION + 5}")
    conn.commit()
    conn.close()

    import pytest

    with pytest.raises(RuntimeError, match="newer than this build"):
        init_db(db)


def test_migration_1_to_2_adds_unique_constraint(tmp_path):
    import sqlite3

    from modules.database import LATEST_VERSION, get_connection, init_db

    assert LATEST_VERSION == 2

    db = str(tmp_path / "m.db")
    init_db(db)

    conn = get_connection(db)
    try:
        conn.execute(
            "INSERT INTO rules (pattern, type, action, enabled) "
            "VALUES ('foo.example', 'exact', 'block', 1)"
        )
        conn.commit()

        import pytest

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO rules (pattern, type, action, enabled) "
                "VALUES ('foo.example', 'exact', 'block', 1)"
            )
            conn.commit()
    finally:
        conn.close()


def test_migration_1_to_2_dedupes_existing_rows(tmp_path):
    import sqlite3

    from modules.database import get_connection, init_db

    db = str(tmp_path / "old.db")

    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
        CREATE TABLE rules (
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
        CREATE TABLE whitelist (
            pattern TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('exact','wildcard','regex'))
        );
        CREATE TABLE query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client TEXT,
            domain TEXT,
            action TEXT,
            rule_id INTEGER
        );
        PRAGMA user_version = 1;
    """)
    for _ in range(3):
        conn.execute(
            "INSERT INTO rules (pattern, type, action, enabled) "
            "VALUES ('dupe.example', 'exact', 'block', 1)"
        )
    conn.execute(
        "INSERT INTO rules (pattern, type, action, enabled) "
        "VALUES ('keep.example', 'exact', 'block', 1)"
    )
    conn.commit()
    conn.close()

    init_db(db)

    conn = get_connection(db)
    try:
        v = conn.execute("PRAGMA user_version").fetchone()[0]
        assert v == 2

        rows = conn.execute(
            "SELECT pattern, COUNT(*) FROM rules GROUP BY pattern, type"
        ).fetchall()
        d = {r[0]: r[1] for r in rows}
        assert d == {"dupe.example": 1, "keep.example": 1}

        import pytest

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO rules (pattern, type, action, enabled) "
                "VALUES ('dupe.example', 'exact', 'block', 1)"
            )
            conn.commit()
    finally:
        conn.close()

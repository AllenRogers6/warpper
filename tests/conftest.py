import sqlite3
import tempfile
from pathlib import Path

import pytest

from modules.database import init_db


class FakeLogger:
    def __init__(self):
        self.records = []
        self.messages = []

    def _emit(self, level, msg, *a, **kw):
        self.messages.append((level, msg % a if a else msg))

    def debug(self, msg, *a, **kw):
        self._emit("debug", msg, *a, **kw)

    def info(self, msg, *a, **kw):
        self._emit("info", msg, *a, **kw)

    def warning(self, msg, *a, **kw):
        self._emit("warning", msg, *a, **kw)

    def error(self, msg, *a, **kw):
        self._emit("error", msg, *a, **kw)

    def critical(self, msg, *a, **kw):
        self._emit("critical", msg, *a, **kw)

    def exception(self, msg, *a, **kw):
        self._emit("exception", msg, *a, **kw)

    def record(self, client, domain, action, rule_id=None):
        self.records.append((client, domain, action, rule_id))


@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / "warpper.db"
    init_db(str(db))
    return str(db)


@pytest.fixture
def logger():
    return FakeLogger()


@pytest.fixture
def rule_engine(tmp_db):
    from modules.rule_engine import RuleEngine

    return RuleEngine(tmp_db)


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    cfg = tmp_path / "warpper.conf"
    monkeypatch.setenv("WARPPER_CONFIG", str(cfg))
    return cfg

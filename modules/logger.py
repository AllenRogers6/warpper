import logging
import sqlite3
from modules.database import get_connection


class QueryLogger:
    def __init__(self, db_path, name="dnsproxy", level=logging.INFO):
        self.db_path = db_path
        self._log = logging.getLogger(name)
        if not self._log.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            )
            self._log.addHandler(handler)
        self._log.setLevel(level)

    def debug(self, msg, *a, **kw):
        return self._log.debug(msg, *a, **kw)

    def info(self, msg, *a, **kw):
        return self._log.info(msg, *a, **kw)

    def warning(self, msg, *a, **kw):
        return self._log.warning(msg, *a, **kw)

    def error(self, msg, *a, **kw):
        return self._log.error(msg, *a, **kw)

    def critical(self, msg, *a, **kw):
        return self._log.critical(msg, *a, **kw)

    def exception(self, msg, *a, **kw):
        return self._log.exception(msg, *a, **kw)

    def record(self, client, domain, action, rule_id=None):
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                "INSERT INTO query_log (client, domain, action, rule_id) "
                "VALUES (?,?,?,?)",
                (client, domain, action, rule_id),
            )
            conn.commit()
        finally:
            conn.close()

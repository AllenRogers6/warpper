import logging
import urllib.error
import urllib.request

from modules.database import get_connection

log = logging.getLogger("updater")

BLOCKLIST_URLS = {
    "ads": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ],
    "malware": [
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    ],
    "trackers": [
        "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
    ],
    "social": [
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt",
    ],
}


def download_blocklist(url: str):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            for line in response:
                line = line.decode().strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                domain = parts[1] if len(parts) >= 2 else parts[0]
                domain = domain.strip()
                if domain and not domain.startswith("#"):
                    yield domain
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.error("failed to download %s: %s", url, e)


def update_blocklists(db_path: str, categories: list[str] | None = None) -> dict:
    if categories is None:
        categories = list(BLOCKLIST_URLS.keys())

    conn = get_connection(db_path)
    summary = {}
    try:
        conn.execute("BEGIN")
        for category in categories:
            urls = BLOCKLIST_URLS.get(category)
            if urls is None:
                log.warning("unknown category: %s", category)
                continue

            row = conn.execute(
                "SELECT id FROM categories WHERE name=?", (category,)
            ).fetchone()
            if row:
                cat_id = row[0]
                conn.execute("DELETE FROM rules WHERE category_id=?", (cat_id,))
            else:
                cur = conn.execute(
                    "INSERT INTO categories (name) VALUES (?)", (category,)
                )
                cat_id = cur.lastrowid

            count = 0
            for url in urls:
                for domain in download_blocklist(url):
                    conn.execute(
                        "INSERT OR IGNORE INTO rules "
                        "(pattern, type, category_id, action, enabled) "
                        "VALUES (?, 'exact', ?, 'block', 1)",
                        (domain, cat_id),
                    )
                    count += 1

            summary[category] = count
            log.info("updated %s: %d domains", category, count)

        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

    return summary

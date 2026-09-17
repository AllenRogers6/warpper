import logging
import urllib.error
import urllib.request

from modules.database import get_connection

logger = logging.getLogger(__name__)

BLOCKLIST_URLS = {
    "ads": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://adaway.org/hosts.txt",
    ],
    "malware": [
        "https://mirror1.malwaredomains.com/files/justdomains",
    ],
    "trackers": [
        "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
    ],
    "social": [
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt",
    ],
}


def download_blocklist(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            for line in response:
                line = line.decode().strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
                else:
                    domain = parts[0]
                domain = domain.strip()
                if domain and not domain.startswith("#"):
                    yield domain
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        logger.error(f"Failed to download {url}: {e}")


def update_blocklists(db_path):
    conn = get_connection(db_path)
    for category in BLOCKLIST_URLS:
        cat_id = conn.execute(
            "SELECT id FROM categories WHERE name=?", (category,)
        ).fetchone()
        if cat_id:
            conn.execute("DELETE FROM rules WHERE category_id=?", (cat_id[0],))
    for category, urls in BLOCKLIST_URLS.items():
        cat_id = conn.execute(
            "SELECT id FROM categories WHERE name=?", (category,)
        ).fetchone()
        if not cat_id:
            cat_id = conn.execute(
                "INSERT INTO categories (name) VALUES (?)", (category,)
            ).lastrowid
        else:
            cat_id = cat_id[0]
        for url in urls:
            for domain in download_blocklist(url):
                conn.execute(
                    "INSERT INTO rules (pattern, type, category_id, action, enabled) VALUES (?,?,?,?,?)",
                    (domain, "exact", cat_id, "block", 1),
                )
    conn.commit()
    conn.close()
    logger.info("Blocklists updated.")

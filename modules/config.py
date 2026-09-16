import configparser
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "warpper.conf")

DEFAULTS = {
    "general": {
        "host": "127.0.0.1",
        "sinkhole_ip": "0.0.0.0",
        "upstream_dns": "1.1.1.1,8.8.8.8",
        "enable_proxy": "false",
        "enable_firewall": "false",
        "db_path": "data/warpper.db",
        "log_level": "info",
    },
    "proxy": {
        "listen_port": "15353",  # temporarily change to high port for dev
        "ca_cert_path": "certs",
    },
    "firewall": {
        "nft_table": "inet warpper",
        "block_set": "blocked_ips",
    },
}


def load_config():
    config = configparser.ConfigParser()
    config.read_dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    return config


def get_db_path(config):
    db_path = config.get("general", "db_path")
    if not os.path.isabs(db_path):
        db_path = os.path.join(BASE_DIR, db_path)
    return db_path


def get_ca_cert_path(config):
    ca_cert = config.get("proxy", "ca_cert_path")
    if not os.path.isabs(ca_cert):
        ca_cert = os.path.join(BASE_DIR, ca_cert)
    return ca_cert

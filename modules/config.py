import configparser
import os
import sys
from pathlib import Path

CONFIG_PATH = Path("/etc") / "warpper" / "warpper.conf"
STATE_DIR = Path("/var/lib") / "warpper"
SOCKET_PATH = Path("/run/warpperd.sock")

DEFAULTS = {
    "general": {
        "sinkhole_ip": "0.0.0.0",
        "upstream_dns": "1.1.1.1,8.8.8.8",
        "enable_proxy": "false",
        "enable_firewall": "false",
        "db_path": str(STATE_DIR / "warpper.db"),
        "log_level": "info",
    },
    "proxy": {
        "listen_host": "127.0.0.1",
        "listen_port": "15353",
        "ca_cert_path": str(STATE_DIR / "certs"),
        "cache_size": "4096",
        "cache_max_ttl": "300",
    },
    "firewall": {
        "nft_family": "inet",
        "nft_table": "warpper",
        "block_set": "blocked_ips",
    },
}


def config_path() -> Path:
    if env := os.environ.get("WARPPER_CONFIG"):
        return Path(env)
    return CONFIG_PATH


def ensure_dirs() -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE_DIR / "certs").mkdir(parents=True, exist_ok=True, mode=0o700)

    CONFIG_PATH.parent.chmod(0o755)
    STATE_DIR.chmod(0o700)
    (STATE_DIR / "certs").chmod(0o700)


def ensure_config(process: str) -> configparser.ConfigParser:
    ensure_dirs()

    path = config_path()
    if not path.is_file():
        cfg = configparser.ConfigParser()
        cfg.read_dict(DEFAULTS)

        with path.open("w") as f:
            f.write("# Warpper auto-generated default configuration file\n")
            f.write(
                "# Please refer to the Warpper documentation for more information on how to configure Warpper.\n"
            )
            cfg.write(f)

        path.chmod(0o600)

        print(f"{process}: wrote default config to {path}", file=sys.stderr)

    return load_config()


def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict(DEFAULTS)
    path = config_path()
    if path.is_file():
        cfg.read(path)
    cfg["_meta"] = {"source": str(path) if path.is_file() else "<built-in defaults>"}
    return cfg


def write_default_config(overwrite: bool = False) -> Path:
    path = config_path()
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists")

    cfg = configparser.ConfigParser()
    cfg.read_dict(DEFAULTS)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        f.write("# Warpper default configuration file\n")
        f.write(
            "# Please refer to the Warpper documentation for more information on how to configure Warpper.\n"
        )
        cfg.write(f)

    path.chmod(0o600)
    return path

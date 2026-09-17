#!/usr/bin/env python3
"""warpperd — DNS filter daemon."""

import asyncio
import logging
import signal
import sys
from pathlib import Path

from modules.cert import generate_ca
from modules.config import get_db_path, load_config
from modules.control import ControlHandlers
from modules.database import init_db
from modules.dns_proxy import DNSProxy
from modules.ipc import ControlServer, socket_path
from modules.logger import QueryLogger
from modules.rule_engine import RuleEngine


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def parse_upstreams(raw: str) -> list[tuple[str, int]]:
    """'1.1.1.1,8.8.8.8:5353' -> [('1.1.1.1', 53), ('8.8.8.8', 5353)]"""
    out = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            host, port = entry.rsplit(":", 1)
            out.append((host.strip(), int(port)))
        else:
            out.append((entry, 53))
    if not out:
        raise ValueError("general.upstream_dns is empty")
    return out


def ensure_ca(ca_dir: str) -> None:
    """Only generate the CA if it's missing — regenerating breaks trust."""
    path = Path(ca_dir) / "ca.pem"
    if path.exists():
        logging.getLogger("dnsproxy").info(f"CA present at {path}")
        return
    logging.getLogger("dnsproxy").info(f"generating CA at {path}")
    generate_ca(ca_dir)


def make_firewall_hook(firewall):
    """Returns a callback for DNSProxy.on_resolve, or None if firewall is off."""
    if firewall is None:
        return None

    def hook(client_ip: str, qname: str, ips: list[str]) -> None:
        # Firewall decides what to do with the resolved IPs. The proxy
        # only tells it *what* was resolved, not what to allow/block.
        firewall.observe(client_ip, qname, ips)

    return hook


async def main() -> int:
    config = load_config()
    setup_logging(config.get("general", "log_level", fallback="info"))
    log = logging.getLogger("warpperd")

    db_path = get_db_path(config)
    init_db(db_path)

    ensure_ca(config.get("proxy", "ca_cert_path", fallback="certs"))

    upstreams = parse_upstreams(
        config.get("general", "upstream_dns", fallback="1.1.1.1,8.8.8.8")
    )

    logger = QueryLogger(
        db_path,
        level=config.get("general", "log_level", fallback="info").upper(),
    )
    rule_engine = RuleEngine(db_path)
    rule_engine.reload_rules()

    # --- firewall (optional) ---
    firewall = None
    if config.getboolean("general", "enable_firewall", fallback=False):
        from modules.firewall import Firewall

        firewall = Firewall(
            nft_table=config.get("firewall", "nft_table", fallback="inet warpper"),
            block_set=config.get("firewall", "block_set", fallback="blocked_ips"),
            logger=logger,
        )
        firewall.apply()

    # --- DNS proxy ---
    dns_proxy = DNSProxy(
        rule_engine=rule_engine,
        logger=logger,
        upstreams=upstreams,
        sinkhole=config.get("general", "sinkhole_ip", fallback="0.0.0.0"),
        host=config.get("proxy", "listen_host", fallback="127.0.0.1"),
        port=config.getint("proxy", "listen_port", fallback=5353),
        on_resolve=make_firewall_hook(firewall),
    )

    # --- IPC control socket ---
    control = ControlHandlers(db_path, rule_engine, logger)
    server = ControlServer(
        path=socket_path(),
        handlers={
            "ping": control.ping,
            "check": control.check,
            "list": control.list,
            "block": control.block,
            "allow": control.allow,
            "unblock": control.unblock,
            "whitelist": control.whitelist,
            "unwhitelist": control.unwhitelist,
            "reload": control.reload,
        },
        logger=logging.getLogger("ipc"),
        group="warpper",
    )

    # --- signal handling BEFORE anything that can block ---
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    # --- start everything ---
    exit_code = 0
    try:
        await server.start()
    except Exception:
        log.exception("failed to start control socket")
        return 1

    try:
        await dns_proxy.start()
    except Exception:
        log.exception("failed to start DNS proxy")
        await server.stop()
        return 1

    log.info("warpperd started")

    # --- wait for shutdown ---
    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    log.info("shutting down")

    # --- teardown, in reverse order ---
    try:
        await dns_proxy.close()
    except Exception:
        log.exception("error closing DNS proxy")
        exit_code = 1

    try:
        await server.stop()
    except Exception:
        log.exception("error closing control socket")
        exit_code = 1

    if firewall is not None:
        try:
            firewall.remove()
        except Exception:
            log.exception("error removing firewall rules")
            exit_code = 1

    return exit_code


def cli() -> None:
    """Sync entry point for the `warpperd` console script."""
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)


def _run() -> None:
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    _run()

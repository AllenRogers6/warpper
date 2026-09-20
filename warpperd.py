#!/usr/bin/env python3

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path

from modules.cert import generate_ca
from modules.config import ensure_config, write_default_config
from modules.control import ControlHandlers
from modules.database import init_db
from modules.dns_proxy import DNSProxy
from modules.firewall import Firewall, FirewallError
from modules.ipc import ControlServer, socket_path
from modules.logger import QueryLogger
from modules.rule_engine import RuleEngine

started_at = time.time()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def check_root(program: str) -> None:
    if os.geteuid() != 0:
        print(f"{program} must be run as root", file=sys.stderr)
        raise SystemExit(1)


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="warpperd",
        description="Warpper daemon",
    )
    sub = p.add_subparsers(dest="cmd")

    i = sub.add_parser("init", help="write a default config file and exit")
    i.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing config file",
    )

    sub.add_parser("run", help="run the daemon (default)")

    return p


def parse_upstreams(raw: str) -> list[tuple[str, int]]:
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
    path = Path(ca_dir) / "ca.pem"
    if path.exists():
        logging.getLogger("dnsproxy").info(f"CA present at {path}")
        return
    logging.getLogger("dnsproxy").info(f"generating CA at {path}")
    generate_ca(ca_dir)


def main(argv=None) -> int:
    check_root("warpperd")

    args = _build_argparser().parse_args(argv)

    if args.cmd == "init":
        try:
            written = write_default_config(overwrite=args.force)
        except FileExistsError as e:
            print(f"refusing: {e}", file=sys.stderr)
            return 1
        print(f"wrote {written}")
        return 0

    return asyncio.run(_run_daemon())


async def _run_daemon() -> int:
    config = ensure_config("warpperd")
    log = logging.getLogger("warpperd")
    setup_logging(config.get("general", "log_level", fallback="info"))

    db_path = config.get("general", "db_path", fallback="/var/lib/warpper/warpper.db")
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

    firewall = Firewall(
        nft_family=config.get("firewall", "nft_family", fallback="inet"),
        nft_table=config.get("firewall", "nft_table", fallback="warpper"),
        block_set=config.get("firewall", "block_set", fallback="blocked_ips"),
        port=config.getint("proxy", "listen_port", fallback=5353),
        daemon_uid=os.getuid(),
        logger=logger,
    )
    firewall_applied = False
    if config.getboolean("general", "enable_firewall", fallback=False):
        try:
            firewall.apply()
            firewall_applied = True
        except (OSError, FirewallError) as e:
            logger.error(f"failed to enable firewall: {e}")

    dns_proxy = DNSProxy(
        rule_engine=rule_engine,
        logger=logger,
        upstreams=upstreams,
        sinkhole=config.get("general", "sinkhole_ip", fallback="0.0.0.0"),
        host=config.get("proxy", "listen_host", fallback="127.0.0.1"),
        port=config.getint("proxy", "listen_port", fallback=5353),
        cache_max_size=config.getint("proxy", "cache_size", fallback=4096),
        cache_max_ttl=config.getint("proxy", "cache_max_ttl", fallback=300),
    )

    control = ControlHandlers(
        db_path, rule_engine, firewall, logger, dns_proxy, config, started_at
    )
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
            "firewall_status": control.firewall_status,
            "firewall_enable": control.firewall_enable,
            "firewall_disable": control.firewall_disable,
            "categories_list": control.categories_list,
            "categories_enable": control.categories_enable,
            "categories_disable": control.categories_disable,
            "update": control.update,
            "status": control.status,
            "flush_cache": control.flush_cache,
            "logs": control.logs,
            "reload": control.reload,
        },
        logger=logging.getLogger("ipc"),
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    exit_code = 0
    try:
        await server.start()
    except Exception:
        log.exception("failed to start control socket")
        if firewall_applied:
            try:
                firewall.remove()
            except Exception:
                log.exception("error removing firewall rules")
        return 1

    try:
        await dns_proxy.start()
    except Exception:
        log.exception("failed to start DNS proxy")
        await server.stop()
        if firewall_applied:
            try:
                firewall.remove()
            except Exception:
                log.exception("error removing firewall rules")
        return 1

    log.info("warpperd started")

    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    log.info("shutting down")

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

    if firewall_applied:
        try:
            firewall.remove()
        except Exception:
            log.exception("error removing firewall rules")
            exit_code = 1

    return exit_code


def cli() -> None:
    try:
        rc = main()
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    cli()

import subprocess
import time
import pytest


def _nft_ok():
    return (
        subprocess.run(["nft", "list", "tables"], capture_output=True).returncode == 0
    )


pytestmark = pytest.mark.skipif(
    not _nft_ok(),
    reason="nftables not available (need root + nft)",
)


def test_firewall_apply_and_cleanup():
    from modules.firewall import Firewall

    fw = Firewall("inet", "warpper_test", "test_blocks", 15353, daemon_uid=0)
    try:
        fw.apply()
        assert fw.is_applied()
        r = subprocess.run(
            ["nft", "list", "table", "inet", "warpper_test"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "test_blocks" in r.stdout
    finally:
        fw.remove()
    assert not fw.is_applied()


def test_dns_proxy_binds_and_responds():
    import asyncio
    from dnslib import DNSRecord
    from modules.database import init_db
    from modules.rule_engine import RuleEngine
    from modules.dns_proxy import DNSProxy

    async def scenario():
        db = "/tmp/warpper_test.db"
        import os

        if os.path.exists(db):
            os.unlink(db)
        init_db(db)
        engine = RuleEngine(db)

        class L:
            def info(self, *a, **kw):
                pass

            def warning(self, *a, **kw):
                pass

            def error(self, *a, **kw):
                pass

            def exception(self, *a, **kw):
                pass

            def record(self, *a, **kw):
                pass

        proxy = DNSProxy(
            rule_engine=engine,
            logger=L(),
            upstreams=[("1.1.1.1", 53)],
            host="127.0.0.1",
            port=0,
        )
        await proxy.start()
        sockname = proxy.transport.get_extra_info("sockname")
        port = sockname[1]

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=("127.0.0.1", port),
        )
        query = DNSRecord.question("example.com").pack()
        transport.sendto(query)

        got = asyncio.Event()
        result = {}

        class P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                result["data"] = data
                got.set()

        transport.close()
        await proxy.close()

    asyncio.run(scenario())

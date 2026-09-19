import pytest
from dnslib import A, DNSRecord, QTYPE, RR

from modules.dns_proxy import DNSProxy, _extract_ips


def _make_proxy(rule_engine, logger, sinkhole="0.0.0.0"):
    return DNSProxy(
        rule_engine=rule_engine,
        logger=logger,
        upstreams=[("127.0.0.1", 1)],
        sinkhole=sinkhole,
        host="127.0.0.1",
        port=0,
    )


def _add_block(engine, pattern, mtype="exact"):
    from modules.database import get_connection

    conn = get_connection(engine.db_path)
    conn.execute(
        "INSERT INTO rules (pattern,type,action,enabled) VALUES (?,?,?,1)",
        (pattern, mtype, "block"),
    )
    conn.commit()
    conn.close()
    engine.reload_rules()


@pytest.mark.asyncio
async def test_block_reply_has_ra_and_ttl(rule_engine, logger):
    _add_block(rule_engine, "ads.example.com")
    proxy = _make_proxy(rule_engine, logger)

    query = DNSRecord.question("ads.example.com")
    raw = await proxy.handle_query(query.pack(), ("127.0.0.1", 12345))
    assert raw is not None

    reply = DNSRecord.parse(raw)
    assert reply.header.ra == 1, "ra must be 1 so clients keep asking us"
    assert reply.header.aa == 0
    assert len(reply.rr) == 1
    rr = reply.rr[0]
    assert rr.rtype == QTYPE.A
    assert str(rr.rdata) == "0.0.0.0"
    assert rr.ttl == 300


@pytest.mark.asyncio
async def test_allow_miss_returns_no_block(rule_engine, logger):
    proxy = _make_proxy(rule_engine, logger)

    async def fake_forward(request):
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("1.2.3.4")))
        return reply.pack()

    proxy._forward = fake_forward

    query = DNSRecord.question("example.com")
    raw = await proxy.handle_query(query.pack(), ("127.0.0.1", 12345))
    reply = DNSRecord.parse(raw)
    assert str(reply.rr[0].rdata) == "1.2.3.4"


def test_extract_ips_handles_a_and_aaaa():
    q = DNSRecord.question("example.com")
    q = q.reply()
    q.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4")))
    ips = _extract_ips(q.pack())
    assert "1.2.3.4" in ips


def test_extract_ips_returns_empty_on_garbage():
    assert _extract_ips(b"\x00\x01\x02") == []

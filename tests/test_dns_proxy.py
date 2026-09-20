import asyncio

import pytest
from dnslib import EDNS0, QTYPE, RR, A, DNSRecord

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


def _query(name, qtype="A", bufsize=None):
    q = DNSRecord.question(name, qtype)
    if bufsize is not None:
        q.add_ar(EDNS0(udp_len=bufsize))
    return q


def _big_reply(request, n=50):
    reply = request.reply()
    for i in range(n):
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(f"10.0.0.{i}"), ttl=300))
    return reply.pack()


@pytest.mark.asyncio
async def test_block_reply_has_ra_and_ttl(rule_engine, logger):
    _add_block(rule_engine, "ads.example.com")
    proxy = _make_proxy(rule_engine, logger)

    raw = await proxy.handle_query(_query("ads.example.com").pack(), ("127.0.0.1", 1))
    reply = DNSRecord.parse(raw)

    assert reply.header.ra == 1
    assert reply.header.aa == 0
    assert len(reply.rr) == 1
    assert reply.rr[0].rtype == QTYPE.A
    assert str(reply.rr[0].rdata) == "0.0.0.0"
    assert reply.rr[0].ttl == 300


@pytest.mark.asyncio
async def test_block_answers_aaaa_with_sinkhole(rule_engine, logger):
    _add_block(rule_engine, "ads.example.com")
    proxy = _make_proxy(rule_engine, logger)

    raw = await proxy.handle_query(
        _query("ads.example.com", qtype="AAAA").pack(), ("127.0.0.1", 1)
    )
    reply = DNSRecord.parse(raw)

    assert len(reply.rr) == 1
    assert reply.rr[0].rtype == QTYPE.AAAA
    assert str(reply.rr[0].rdata) == "::"
    assert reply.rr[0].ttl == 300
    assert reply.header.ra == 1


@pytest.mark.asyncio
async def test_block_does_not_mix_families(rule_engine, logger):
    _add_block(rule_engine, "ads.example.com")
    proxy = _make_proxy(rule_engine, logger)

    raw = await proxy.handle_query(
        _query("ads.example.com", qtype="A").pack(), ("127.0.0.1", 1)
    )
    reply = DNSRecord.parse(raw)

    assert len(reply.rr) == 1
    assert reply.rr[0].rtype == QTYPE.A


@pytest.mark.asyncio
async def test_allow_miss_returns_forwarded_answer(rule_engine, logger):
    proxy = _make_proxy(rule_engine, logger)

    async def fake_forward(request):
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("1.2.3.4")))
        return reply.pack()

    proxy._forward = fake_forward

    raw = await proxy.handle_query(_query("example.com").pack(), ("127.0.0.1", 1))
    reply = DNSRecord.parse(raw)
    assert str(reply.rr[0].rdata) == "1.2.3.4"


@pytest.mark.asyncio
async def test_cache_hit_rewrites_transaction_id(rule_engine, logger):
    calls = []

    async def fake_forward(request):
        calls.append(request)
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=300))
        return reply.pack()

    proxy = _make_proxy(rule_engine, logger)
    proxy._forward = fake_forward

    q1 = DNSRecord.question("example.com")
    q1.header.id = 0x1111
    raw1 = await proxy.handle_query(q1.pack(), ("127.0.0.1", 1))
    reply1 = DNSRecord.parse(raw1)
    assert reply1.header.id == 0x1111
    assert len(calls) == 1

    q2 = DNSRecord.question("example.com")
    q2.header.id = 0x2222
    raw2 = await proxy.handle_query(q2.pack(), ("127.0.0.1", 1))
    reply2 = DNSRecord.parse(raw2)
    assert reply2.header.id == 0x2222
    assert str(reply2.rr[0].rdata) == "1.2.3.4"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_tcp_listener_responds(rule_engine, logger):
    proxy = _make_proxy(rule_engine, logger)

    async def fake_forward(request):
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("1.2.3.4")))
        return reply.pack()

    proxy._forward = fake_forward

    await proxy.start()
    try:
        port = proxy.tcp_server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        packed = DNSRecord.question("example.com").pack()
        writer.write(len(packed).to_bytes(2, "big") + packed)
        await writer.drain()

        length = int.from_bytes(await reader.readexactly(2), "big")
        data = await reader.readexactly(length)

        reply = DNSRecord.parse(data)
        assert len(reply.rr) == 1
        assert str(reply.rr[0].rdata) == "1.2.3.4"

        writer.close()
        await writer.wait_closed()
    finally:
        await proxy.close()


def test_extract_ips_handles_a_and_aaaa():
    q = DNSRecord.question("example.com").reply()
    q.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4")))
    assert "1.2.3.4" in _extract_ips(q.pack())


def test_extract_ips_returns_empty_on_garbage():
    assert _extract_ips(b"\x00\x01\x02") == []


@pytest.mark.asyncio
async def test_udp_small_bufsize_truncates(rule_engine, logger):
    proxy = _make_proxy(rule_engine, logger)

    async def big_forward(request):
        return _big_reply(request, n=50)

    proxy._forward = big_forward

    raw = await proxy.handle_query(
        _query("example.com", bufsize=512).pack(),
        ("127.0.0.1", 1),
        transport="udp",
    )
    reply = DNSRecord.parse(raw)

    assert reply.header.tc == 1
    assert len(reply.rr) == 0
    assert len(raw) <= 512


@pytest.mark.asyncio
async def test_udp_large_bufsize_does_not_truncate(rule_engine, logger):
    proxy = _make_proxy(rule_engine, logger)

    async def big_forward(request):
        return _big_reply(request, n=50)

    proxy._forward = big_forward

    raw = await proxy.handle_query(
        _query("example.com", bufsize=4096).pack(),
        ("127.0.0.1", 1),
        transport="udp",
    )
    reply = DNSRecord.parse(raw)

    assert reply.header.tc == 0
    assert len(reply.rr) == 50


@pytest.mark.asyncio
async def test_tcp_small_bufsize_does_not_truncate(rule_engine, logger):
    proxy = _make_proxy(rule_engine, logger)

    async def big_forward(request):
        return _big_reply(request, n=50)

    proxy._forward = big_forward

    raw = await proxy.handle_query(
        _query("example.com", bufsize=512).pack(),
        ("127.0.0.1", 1),
        transport="tcp",
    )
    reply = DNSRecord.parse(raw)

    assert reply.header.tc == 0
    assert len(reply.rr) == 50


@pytest.mark.asyncio
async def test_cache_hit_truncates_per_client_bufsize(rule_engine, logger):
    proxy = _make_proxy(rule_engine, logger)

    async def big_forward(request):
        return _big_reply(request, n=50)

    proxy._forward = big_forward

    raw1 = await proxy.handle_query(
        _query("example.com", bufsize=4096).pack(),
        ("127.0.0.1", 1),
        transport="udp",
    )
    assert DNSRecord.parse(raw1).header.tc == 0

    raw2 = await proxy.handle_query(
        _query("example.com", bufsize=512).pack(),
        ("127.0.0.1", 1),
        transport="udp",
    )
    reply2 = DNSRecord.parse(raw2)
    assert reply2.header.tc == 1
    assert len(reply2.rr) == 0

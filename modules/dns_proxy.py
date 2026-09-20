import asyncio
import socket
import struct

import psutil
from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSError, DNSHeader, DNSRecord

from modules.cache import ResponseCache

_DNS_PARSE_ERRORS = (DNSError, ValueError, IndexError, struct.error)


def get_port_holders(port: int):
    holders = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr and conn.laddr.port == port:
            if conn.type == socket.SOCK_STREAM and conn.status != psutil.CONN_LISTEN:
                continue
            holders.append(conn)
    return holders


def _response_min_ttl(response_bytes: bytes) -> int | None:
    try:
        response = DNSRecord.parse(response_bytes)
    except _DNS_PARSE_ERRORS:
        return None
    ttls = [rr.ttl for rr in response.rr if rr.ttl is not None]
    return min(ttls) if ttls else None


def _rewrite_transaction_id(response_bytes: bytes, new_id: int) -> bytes:
    if len(response_bytes) < 2:
        return response_bytes
    return new_id.to_bytes(2, "big") + response_bytes[2:]


def _client_bufsize(request: DNSRecord) -> int:
    for rr in request.ar or []:
        if rr.rtype != QTYPE.OPT:
            continue
        try:
            n = int(rr.rclass)
            if n > 0:
                return max(512, n)
        except (AttributeError, TypeError, ValueError):
            pass
    return 512


def _truncate_response(response_bytes: bytes, max_size: int) -> bytes:
    if len(response_bytes) <= max_size:
        return response_bytes

    try:
        parsed = DNSRecord.parse(response_bytes)
    except _DNS_PARSE_ERRORS:
        return response_bytes

    reply = DNSRecord(
        DNSHeader(
            id=parsed.header.id,
            qr=1,
            opcode=parsed.header.opcode,
            aa=0,
            tc=1,
            rd=parsed.header.rd,
            ra=1,
            rcode=parsed.header.rcode,
        ),
        q=parsed.q,
    )
    return reply.pack()


def _strip_opt(response_bytes: bytes) -> bytes:
    try:
        response = DNSRecord.parse(response_bytes)
    except _DNS_PARSE_ERRORS:
        return response_bytes

    if not response.ar:
        return response_bytes

    kept = [rr for rr in response.ar if rr.rtype != QTYPE.OPT]
    if len(kept) == len(response.ar):
        return response_bytes

    response.ar = kept
    return response.pack()


class DNSForwardProtocol(asyncio.DatagramProtocol):
    def __init__(self, request, loop):
        self.request = request
        self.loop = loop
        self.future = loop.create_future()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x1)
            except OSError:
                print("SO_MARK not supported")
        transport.sendto(self.request.pack())

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)
        self.transport.close()

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.future.done():
            self.future.set_exception(exc or ConnectionError("upstream closed"))


class DNSServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy):
        self.proxy = proxy
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data, addr):
        response = await self.proxy.handle_query(data, addr, transport="udp")
        if response and self.transport is not None:
            try:
                self.transport.sendto(response, addr)
            except OSError:
                pass


class TCPDNSServerProtocol(asyncio.Protocol):
    def __init__(self, proxy):
        self.proxy = proxy
        self.transport = None
        self.buffer = b""
        self.expected = None
        self._tasks: set[asyncio.Task] = set()

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

    def data_received(self, data):
        self.buffer += data
        while True:
            if self.expected is None:
                if len(self.buffer) < 2:
                    return
                self.expected = int.from_bytes(self.buffer[:2], "big")
                self.buffer = self.buffer[2:]
            if len(self.buffer) < self.expected:
                return
            message = self.buffer[: self.expected]
            self.buffer = self.buffer[self.expected :]
            self.expected = None
            task = asyncio.create_task(self._handle(message))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _handle(self, message):
        peer = self.transport.get_extra_info("peername")
        client_addr = (peer[0], peer[1]) if peer else ("0.0.0.0", 0)
        response = await self.proxy.handle_query(message, client_addr, transport="tcp")
        if response is None or self.transport is None:
            return
        try:
            length = len(response).to_bytes(2, "big")
            self.transport.write(length + response)
        except OSError:
            pass

    def connection_lost(self, exc):
        self.transport = None


class DNSProxy:
    def __init__(
        self,
        rule_engine,
        logger,
        upstreams,
        sinkhole="0.0.0.0",
        sinkhole_v6="::",
        host="0.0.0.0",
        port=15353,
        upstream_timeout=10.0,
        cache_max_size=4096,
        cache_max_ttl=300,
    ):
        self.rule_engine = rule_engine
        self.logger = logger
        self.upstreams = list(upstreams)
        self.sinkhole = sinkhole
        self.sinkhole_v6 = sinkhole_v6
        self.host = host
        self.port = port
        self.upstream_timeout = upstream_timeout
        self.cache = ResponseCache(max_size=cache_max_size, max_ttl=cache_max_ttl)

        self.tcp_server = None
        self.transport = None
        self._stopped = asyncio.Event()
        self._loop = None

    async def start(self):
        self._loop = asyncio.get_running_loop()

        try:
            self.transport, _ = await self._loop.create_datagram_endpoint(
                lambda: DNSServerProtocol(self),
                local_addr=(self.host, self.port),
                reuse_port=True,
            )
        except PermissionError:
            raise RuntimeError(
                f"cannot bind {self.host}:{self.port}/udp — permission denied"
            )
        except OSError as e:
            if e.errno == 98:
                holders = get_port_holders(self.port)
                who = (
                    ", ".join(f"{c.pid or '?'}({c.laddr})" for c in holders)
                    or "unknown"
                )
                raise RuntimeError(f"{self.host}:{self.port}/udp already in use: {who}")
            raise

        try:
            self.tcp_server = await self._loop.create_server(
                lambda: TCPDNSServerProtocol(self),
                host=self.host,
                port=self.port,
                reuse_address=True,
            )
        except OSError as e:
            self.transport.close()
            raise RuntimeError(f"cannot bind {self.host}:{self.port}/tcp: {e}")

        self.logger.info(f"DNS proxy listening on {self.host}:{self.port} (UDP + TCP)")

    async def serve_forever(self):
        await self._stopped.wait()

    def stop(self):
        self._stopped.set()

    async def close(self):
        self.stop()
        await self._stopped.wait()
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        if self.tcp_server is not None:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            self.tcp_server = None
        self.logger.info("DNS proxy stopped")

    async def handle_query(self, data, client_addr, transport="udp"):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".").lower()
            client_ip = client_addr[0]

            action, rule = self.rule_engine.evaluate(qname, client_ip)
            rule_id = rule["id"] if rule else None

            if action in ("block", "redirect"):
                v4 = (
                    rule["redirect_ip"]
                    if action == "redirect" and rule and rule.get("redirect_ip")
                    else self.sinkhole
                )
                v6 = self.sinkhole_v6

                reply = request.reply(ra=1, aa=0)

                qtype = request.q.qtype
                if qtype in (QTYPE.A, QTYPE.ANY):
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(v4), ttl=300))
                if qtype in (QTYPE.AAAA, QTYPE.ANY):
                    reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(v6), ttl=300))

                self.logger.record(client_ip, qname, action, rule_id)
                self.logger.info(f"{client_ip} {qname} {action} → {v4}/{v6}")
                return reply.pack()

            qtype = request.q.qtype
            cache_key = (qname, qtype)
            cached = self.cache.get(cache_key)
            if cached is not None:
                rewritten = _rewrite_transaction_id(cached, request.header.id)
                if transport == "udp":
                    bufsize = _client_bufsize(request)
                    rewritten = _truncate_response(rewritten, bufsize)
                self.logger.record(client_ip, qname, "cached", rule_id)
                self.logger.debug("cache hit: %s/%s", qname, QTYPE[qtype])
                return rewritten

            response = await self._forward(request)
            if response is None:
                reply = request.reply()
                reply.header.rcode = RCODE.SERVFAIL
                reply.header.aa = 0
                reply.header.ra = 1
                self.logger.record(client_ip, qname, "servfail", rule_id)
                return reply.pack()

            ttl = _response_min_ttl(response)
            if ttl is not None and ttl > 0:
                cached_response = _strip_opt(response)
                self.cache.put(cache_key, cached_response, ttl)

            if transport == "udp":
                bufsize = _client_bufsize(request)
                response = _truncate_response(response, bufsize)

            self.logger.record(client_ip, qname, "allow", rule_id)
            self.logger.info(f"{client_ip} {qname} allow")
            return response

        except Exception:
            self.logger.exception(f"Error handling query from {client_addr}")
            return None

    async def _forward_tcp(self, request, upstream, timeout=5.0):
        host, port = upstream
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except (TimeoutError, OSError) as e:
            self.logger.warning("TCP connect to %s:%s failed: %s", host, port, e)
            return None

        try:
            packed = request.pack()
            writer.write(len(packed).to_bytes(2, "big") + packed)
            await writer.drain()

            try:
                length_bytes = await asyncio.wait_for(
                    reader.readexactly(2), timeout=timeout
                )
            except asyncio.IncompleteReadError:
                return None
            length = int.from_bytes(length_bytes, "big")
            if length == 0 or length > 65535:
                return None

            try:
                data = await asyncio.wait_for(
                    reader.readexactly(length), timeout=timeout
                )
            except asyncio.IncompleteReadError:
                return None
            return data
        except (TimeoutError, OSError) as e:
            self.logger.warning("TCP forward to %s:%s failed: %s", host, port, e)
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _forward(self, request):
        last_exc = None
        for upstream in self.upstreams:
            response = await self._forward_udp_single(request, upstream)
            if response is None:
                continue

            try:
                parsed = DNSRecord.parse(response)
            except _DNS_PARSE_ERRORS:
                return response

            if parsed.header.tc:
                self.logger.debug(
                    "truncated response from %s:%s for %s, retrying over TCP",
                    upstream[0],
                    upstream[1],
                    request.q.qname,
                )
                tcp = await self._forward_tcp(request, upstream)
                if tcp is not None:
                    return tcp
            return response

        self.logger.error("all upstreams failed: %s", last_exc)
        return None

    async def _forward_udp_single(self, request, upstream):
        try:
            transport, protocol = await self._loop.create_datagram_endpoint(
                lambda: DNSForwardProtocol(request, self._loop),
                remote_addr=upstream,
            )
            try:
                return await asyncio.wait_for(
                    protocol.future, timeout=self.upstream_timeout
                )
            finally:
                transport.close()
        except (TimeoutError, OSError) as e:
            self.logger.warning(
                "upstream %s:%s failed for %s: %s: %r",
                upstream[0],
                upstream[1],
                request.q.qname,
                type(e).__name__,
                e,
            )
            return None


def _extract_ips(response_bytes):
    try:
        response = DNSRecord.parse(response_bytes)
    except (DNSError, struct.error, IndexError):
        return []
    ips = []
    for rr in response.rr:
        if rr.rtype in (QTYPE.A, QTYPE.AAAA):
            ips.append(str(rr.rdata))
    return ips

import asyncio
import socket
import struct

import psutil
from dnslib import QTYPE, RR, A, DNSError, DNSRecord


def get_port_holders(port: int):
    holders = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr and conn.laddr.port == port:
            if conn.type == socket.SOCK_STREAM and conn.status != psutil.CONN_LISTEN:
                continue
            holders.append(conn)
    return holders


class DNSForwardProtocol(asyncio.DatagramProtocol):
    def __init__(self, request, loop):
        self.request = request
        self.loop = loop
        self.future = loop.create_future()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
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
        response = await self.proxy.handle_query(data, addr)
        if response and self.transport is not None:
            try:
                self.transport.sendto(response, addr)
            except OSError:
                pass


class DNSProxy:
    def __init__(
        self,
        rule_engine,
        logger,
        upstreams,
        sinkhole="0.0.0.0",
        host="127.0.0.1",
        port=15353,
        upstream_timeout=10.0,
        on_resolve=None,
    ):
        self.rule_engine = rule_engine
        self.logger = logger
        self.upstreams = list(upstreams)
        self.sinkhole = sinkhole
        self.host = host
        self.port = port
        self.upstream_timeout = upstream_timeout
        self.on_resolve = on_resolve

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
                f"cannot bind {self.host}:{self.port} — permission denied. "
                f"Either run as root, grant CAP_NET_BIND_SERVICE, "
                f"or use a port >= 1024."
            )
        except OSError as e:
            if e.errno == 98:
                holders = get_port_holders(self.port)
                who = (
                    ", ".join(f"{c.pid or '?'}({c.laddr})" for c in holders)
                    or "unknown"
                )
                raise RuntimeError(f"{self.host}:{self.port} already in use by: {who}")
            raise

        self.logger.info(f"DNS proxy listening on {self.host}:{self.port}")

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
        self.logger.info("DNS proxy stopped")

    async def handle_query(self, data, client_addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".").lower()
            client_ip = client_addr[0]

            action, rule = self.rule_engine.evaluate(qname, client_ip)
            rule_id = rule["id"] if rule else None

            if action in ("block", "redirect"):
                ip = (
                    rule["redirect_ip"]
                    if action == "redirect" and rule and rule.get("redirect_ip")
                    else self.sinkhole
                )

                reply = request.reply()
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip)))
                reply.header.aa = 0
                reply.header.ra = 0
                self.logger.record(client_ip, qname, action, rule_id)
                self.logger.info(f"{client_ip} {qname} {action} → {ip}")
                return reply.pack()

            response = await self._forward(request)
            if response is None:
                return None

            if self.on_resolve is not None:
                try:
                    ips = _extract_ips(response)
                    if ips:
                        self.on_resolve(client_ip, qname, ips)
                except Exception:
                    self.logger.exception(f"on_resolve callback failed for {qname}")

            self.logger.record(client_ip, qname, "allow", rule_id)
            self.logger.info(f"{client_ip} {qname} allow")
            return response

        except Exception:
            self.logger.exception(f"Error handling query from {client_addr}")
            return None

    async def _forward(self, request):
        last_exc = None
        for upstream in self.upstreams:
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
            except (OSError, TimeoutError) as e:
                last_exc = e
                self.logger.warning(f"upstream {upstream[0]}:{upstream[1]} failed: {e}")
                continue

        self.logger.error(f"all upstreams failed: {last_exc}")
        return None


def _extract_ips(response_bytes):
    try:
        response = DNSRecord.parse(response_bytes)
    except (DNSError, struct.error, IndexError):
        return []
    ips = []
    for rr in response.rr:
        if rr.rtype == QTYPE.A or rr.rtype == QTYPE.AAAA:
            ips.append(str(rr.rdata))
    return ips

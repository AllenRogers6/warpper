import asyncio
import json
import os
import socket
import struct
from pathlib import Path

PROTOCOL_VERSION = 1
DEFAULT_SOCKET = "/run/warpperd.sock"


def socket_path() -> Path:
    if env := os.environ.get("WARPPERD_SOCKET"):
        return Path(env)
    return Path("/run/warpperd.sock")


class ControlError(Exception):
    """Exception raised when a control command fails."""


class ControlServer:
    def __init__(
        self,
        path: Path,
        handlers: dict,
        logger,
    ):
        self.path = Path(path)
        self.handlers = handlers
        self.logger = logger
        self.server: asyncio.AbstractServer | None = None

    async def start(self):
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError as e:
                raise RuntimeError(f"cannot remove stale socket {self.path}: {e}")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.path),
        )

        os.chmod(self.path, 0o600)

        self.logger.info(f"control socket listening on {self.path}")

    async def stop(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    async def _handle_client(self, reader, writer):
        peer_pid = None
        try:
            peer_pid = self._peer_credentials(writer)
        except (OSError, struct.error, AttributeError):
            self.logger.warning("cannot determine peer credentials")

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    req = json.loads(line)
                except json.JSONDecodeError as e:
                    await self._reply(writer, ok=False, error=f"bad json: {e}")
                    continue

                if req.get("v") != PROTOCOL_VERSION:
                    await self._reply(
                        writer, ok=False, error="unsupported protocol version"
                    )
                    continue

                cmd = req.get("cmd")
                args = req.get("args") or {}
                handler = self.handlers.get(cmd)
                if handler is None:
                    await self._reply(writer, ok=False, error=f"unknown command: {cmd}")
                    continue

                try:
                    result = await handler(**args)
                    await self._reply(writer, ok=True, result=result)
                except ControlError as e:
                    await self._reply(writer, ok=False, error=str(e))
                except TypeError as e:
                    await self._reply(writer, ok=False, error=f"bad args: {e}")
                except Exception as e:
                    self.logger.exception(f"handler {cmd} failed (peer pid={peer_pid})")
                    await self._reply(writer, ok=False, error=str(e))
        except (ConnectionResetError, BrokenPipeError):
            self.logger.warning("connection reset by peer")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ConnectionError):
                self.logger.warning("cannot close connection")

    @staticmethod
    def _peer_credentials(writer) -> int | None:
        sock = writer.get_extra_info("socket")
        if sock is None:
            return None
        try:
            import struct

            creds = sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, _, _ = struct.unpack("3i", creds)
            return pid
        except (OSError, AttributeError):
            return None

    @staticmethod
    async def _reply(writer, *, ok: bool, result=None, error=None):
        msg = {"v": PROTOCOL_VERSION, "ok": ok}
        if ok:
            msg["result"] = result
        else:
            msg["error"] = error
        writer.write(json.dumps(msg).encode() + b"\n")
        await writer.drain()


class ControlClient:
    def __init__(self, path: Path | None = None, timeout: float = 5.0):
        self.path = path or socket_path()
        self.timeout = timeout

    def call(self, cmd: str, timeout: float | None = None, **args):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout if timeout is not None else self.timeout)
            sock.connect(str(self.path))
        except FileNotFoundError:
            raise ControlError(f"daemon not running (no socket at {self.path})")
        except (ConnectionRefusedError, PermissionError) as e:
            raise ControlError(f"cannot connect to {self.path}: {e}")

        try:
            req = {"v": PROTOCOL_VERSION, "cmd": cmd, "args": args}
            sock.sendall(json.dumps(req).encode() + b"\n")
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ControlError("daemon closed connection")
                buf += chunk
            line, _, _ = buf.partition(b"\n")
            resp = json.loads(line)
        finally:
            sock.close()

        if not resp.get("ok"):
            raise ControlError(resp.get("error", "unknown error"))
        return resp.get("result")

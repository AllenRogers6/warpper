import json

import pytest

from modules.ipc import PROTOCOL_VERSION


def test_protocol_version_is_int():
    assert isinstance(PROTOCOL_VERSION, int)


def test_reply_serializes_ok():
    msg = {"v": PROTOCOL_VERSION, "ok": True, "result": {"pong": True}}
    line = json.dumps(msg).encode() + b"\n"
    parsed = json.loads(line.split(b"\n")[0])
    assert parsed["ok"] is True
    assert parsed["result"]["pong"] is True


def test_reply_serializes_error():
    msg = {"v": PROTOCOL_VERSION, "ok": False, "error": "boom"}
    line = json.dumps(msg).encode() + b"\n"
    parsed = json.loads(line.split(b"\n")[0])
    assert parsed["ok"] is False
    assert parsed["error"] == "boom"

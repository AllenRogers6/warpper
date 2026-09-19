import subprocess
import types

from modules.firewall import Firewall


def _fake_run_factory(store):
    def fake_run(self, *args, check=True):
        store.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    return fake_run


def test_redirect_chain_exempts_daemon_uid(logger):
    fw = Firewall(
        nft_family="inet",
        nft_table="warpper",
        block_set="blocked_ips",
        port=15353,
        daemon_uid=0,
        logger=logger,
    )
    calls = []
    fw._run = types.MethodType(_fake_run_factory(calls), fw)

    fw._create_redirect_chain()

    rule_calls = [c for c in calls if "rule" in c]
    assert rule_calls, "no rules were added"

    first_rule = rule_calls[0]
    assert "skuid" in first_rule
    assert "0" in first_rule
    assert "return" in first_rule

    assert any(
        "udp" in c and "dport" in c and "53" in c and "redirect" in c
        for c in rule_calls
    ), "no udp redirect rule"


def test_apply_is_idempotent(logger):
    fw = Firewall("inet", "warpper", "blocked_ips", 15353, daemon_uid=0, logger=logger)
    calls = []
    fw._run = types.MethodType(_fake_run_factory(calls), fw)

    fw.apply()
    n = len(calls)
    assert n > 0

    fw.apply()
    assert len(calls) == n, "apply() is not idempotent"


def test_observe_ignores_invalid_ips(logger):
    fw = Firewall("inet", "warpper", "blocked_ips", 15353, daemon_uid=0, logger=logger)
    fw.enabled = True
    calls = []
    fw._run = types.MethodType(_fake_run_factory(calls), fw)

    fw.observe("client", "example.com", ["1.2.3.4", "not-an-ip", "::1"])

    assert len(calls) == 2
    assert any("1.2.3.4" in c for c in calls)
    assert any("::1" in c for c in calls)

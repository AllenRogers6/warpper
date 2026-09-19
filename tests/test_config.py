import configparser
from pathlib import Path

from modules.config import DEFAULTS, config_path, load_config


def test_shipped_config_matches_defaults():
    shipped = configparser.ConfigParser()
    shipped_path = Path(__file__).parent.parent / "config" / "warpper.conf"
    assert shipped_path.is_file(), f"missing shipped config: {shipped_path}"
    shipped.read(shipped_path)

    for section, keys in DEFAULTS.items():
        assert shipped.has_section(section), f"shipped config missing [{section}]"
        for key in keys:
            assert shipped.has_option(
                section, key
            ), f"shipped config missing [{section}] {key}"

    for section in shipped.sections():
        assert (
            section in DEFAULTS
        ), f"shipped config has section [{section}] not in DEFAULTS"
        for key in shipped[section]:
            assert (
                key in DEFAULTS[section]
            ), f"shipped config has [{section}] {key} not in DEFAULTS"


def test_load_config_no_file_uses_defaults(config_file):
    assert not config_file.exists()
    cfg = load_config()
    assert cfg.get("general", "upstream_dns") == "1.1.1.1,8.8.8.8"
    assert cfg.get("proxy", "listen_port") == "15353"
    assert cfg["_meta"]["source"] == "<built-in defaults>"


def test_load_config_with_file_reports_source(config_file):
    config_file.write_text("[general]\nupstream_dns = 9.9.9.9\n")
    cfg = load_config()
    assert cfg["_meta"]["source"] == str(config_file)


def test_load_config_overrides_defaults(config_file):
    config_file.write_text(
        "[general]\n" "upstream_dns = 9.9.9.9\n" "log_level = debug\n"
    )
    cfg = load_config()
    assert cfg.get("general", "upstream_dns") == "9.9.9.9"
    assert cfg.get("general", "log_level") == "debug"
    assert cfg.get("proxy", "listen_port") == "15353"


def test_config_path_respects_env(monkeypatch, tmp_path):
    custom = tmp_path / "custom.conf"
    monkeypatch.setenv("WARPPER_CONFIG", str(custom))
    assert config_path() == custom

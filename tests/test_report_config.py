import json

from domainscriptor import report as report_mod
from domainscriptor.config import load_config, write_sample_config, Config


FINDINGS = [
    {"id": 1, "protocol": "SMB", "ip_hostname": "10.0.0.5", "toolname": "nxc",
     "timestamp": "2024-01-01T12:00:00", "data": [{"message": "signing not required"}]},
    {"id": 2, "protocol": "KERBEROS", "ip_hostname": "10.0.0.5", "toolname": "kerbrute",
     "timestamp": "2024-01-01T12:05:00", "data": [{"username": "jdoe@corp.local"}]},
    {"id": 3, "protocol": "LDAP", "ip_hostname": "10.0.0.6", "toolname": "nxc",
     "timestamp": "2024-01-01T12:10:00", "data": []},
]


def test_report_json_roundtrip():
    out = report_mod.render("json", FINDINGS)
    payload = json.loads(out)
    assert payload["stats"]["total_findings"] == 3
    assert payload["stats"]["hosts"] == 2
    assert payload["stats"]["by_tool"] == {"kerbrute": 1, "nxc": 2}


def test_report_markdown_contains_hosts_and_tools():
    md = report_mod.render("markdown", FINDINGS, ai_analysis="Some AI text")
    assert "# Domainscriptor Report" in md
    assert "10.0.0.5" in md and "10.0.0.6" in md
    assert "KI-Analyse" in md
    assert "Some AI text" in md


def test_report_html_escapes_content():
    evil = [{"id": 1, "protocol": "SMB", "ip_hostname": "<script>alert(1)</script>",
             "toolname": "nxc", "timestamp": "t", "data": [{"k": "<b>x</b>"}]}]
    out = report_mod.render("html", evil)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_report_invalid_format():
    try:
        report_mod.render("pdf", FINDINGS)
        assert False
    except ValueError as e:
        assert "pdf" in str(e)


def test_write_report(tmp_path):
    path = report_mod.write_report("markdown", FINDINGS, tmp_path)
    assert path.exists()
    assert path.read_text(encoding="utf-8").startswith("# Domainscriptor Report")


def test_config_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.delenv("DOMAINSCRIPTOR_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = load_config(path=tmp_path / "does_not_exist.toml")
    assert cfg.web.port == 5000
    assert cfg.paths.targets_file == "targets.txt"


def test_config_loads_toml_and_env_override(tmp_path, monkeypatch):
    cfg_file = tmp_path / "domainscriptor.toml"
    cfg_file.write_text(
        "[web]\nport = 8080\nhost = \"0.0.0.0\"\n[paths]\nloot_dir = \"beute\"\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DOMAINSCRIPTOR_WEB_PORT", "9999")
    cfg = load_config(path=cfg_file)
    assert cfg.web.host == "0.0.0.0"
    assert cfg.paths.loot_dir == "beute"
    assert cfg.web.port == 9999  # env override wins over file


def test_config_path_helper(tmp_path):
    cfg = Config()
    cfg.paths.work_dir = str(tmp_path)
    assert cfg.path("targets_file") == (tmp_path / "targets.txt").resolve()


def test_write_sample_config(tmp_path):
    p = write_sample_config(tmp_path / "sub" / "cfg.toml")
    assert p.exists()
    assert "[paths]" in p.read_text(encoding="utf-8")

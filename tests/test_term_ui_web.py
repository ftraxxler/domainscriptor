from domainscriptor import term_ui as tui
from domainscriptor import web
from domainscriptor import report
from domainscriptor.engine import Engine


# ── term_ui: detach-key parsing ───────────────────────────────────────────────

def test_parse_key_spec_ctrl():
    assert tui.parse_key_spec("ctrl-g") == b"\x07"
    assert tui.parse_key_spec("ctrl-a") == b"\x01"
    assert tui.parse_key_spec("ctrl-b") == b"\x02"


def test_parse_key_spec_single_char_and_fallback():
    assert tui.parse_key_spec("q") == b"q"
    assert tui.parse_key_spec("") == b"\x07"          # default Ctrl-G
    assert tui.parse_key_spec("nonsense") == b"\x07"  # default Ctrl-G


def test_key_display():
    assert tui.key_display("ctrl-g") == "Ctrl-G"
    assert tui.key_display("q") == "Q"
    assert tui.key_display("") == "Ctrl-G"


def test_color_force_flags():
    assert tui.color("x", "red", force=False) == "x"
    assert tui.color("x", "green", force=True) == "\033[32mx\033[0m"
    assert tui.color("x", force=True) == "x"  # no styles -> unchanged


def test_status_tag_contains_marker():
    # color may be stripped depending on tty, but the marker is always present
    assert "[+]" in tui.status_tag(True)
    assert "[-]" in tui.status_tag(False)


# ── web: readable data rendering ──────────────────────────────────────────────

def test_render_shares_marks_admin():
    html = str(web._render_data("SMB-SHARES", [
        {"name": "Public", "share_type": "Disk", "comment": ""},
        {"name": "C$", "share_type": "Disk", "comment": "Default share"},
    ]))
    assert "Public" in html and "C$" in html
    assert "tag-adm" in html          # C$ flagged administrative
    assert html.count("tag-adm") == 1  # Public is not


def test_render_loot_counts_hits():
    html = str(web._render_data("SMB-LOOT", [
        {"share": "Pub", "remote_path": "a.txt", "size": 1,
         "matches": [{"pattern": "password_assignment"}]},
        {"share": "Pub", "remote_path": "b.log", "size": 2, "matches": []},
    ]))
    assert "1 hit(s)" in html
    assert "tag-dim" in html  # the no-match row


def test_render_diff_matrix():
    html = str(web._render_data("SMB-DIFF", [
        {"user": "alice", "shares": {"Pub": {"access": "OK", "files": ["x"]},
                                     "Sec": {"access": "DENIED", "files": []}}},
        {"user": "bob", "shares": {"Pub": {"access": "OK", "files": ["x", "y"]}}},
    ]))
    assert "alice" in html and "bob" in html
    assert "OK (1)" in html and "OK (2)" in html
    assert "DENIED" in html


def test_render_data_escapes_html():
    html = str(web._render_data("SMB-SHARES", [
        {"name": "<script>", "share_type": "Disk", "comment": "x&y"},
    ]))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_render_generic_fallback_for_flat_dicts():
    html = str(web._render_data("WHATEVER", [{"a": 1, "b": 2}]))
    assert "<table" in html and ">a<" in html and ">1<" in html


def test_render_data_empty_is_blank():
    assert str(web._render_data("SMB-SHARES", [])) == ""


# ── engine: subnet / range expansion for list_shares ──────────────────────────

def _bare_engine():
    return Engine.__new__(Engine)  # no __init__: we only exercise pure helpers


def test_expand_range_dotted_and_shorthand():
    assert Engine._expand_range("10.0.0.1-10.0.0.3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert Engine._expand_range("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert Engine._expand_range("10.0.0.5-10.0.0.1") == []  # descending -> empty


def test_expand_target_cidr():
    eng = _bare_engine()
    assert eng._expand_target("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert eng._expand_target("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_target_passthrough_host():
    eng = _bare_engine()
    assert eng._expand_target("dc01.corp.local") == ["dc01.corp.local"]
    assert eng._expand_target("10.0.0.9") == ["10.0.0.9"]
    assert eng._expand_target("") == []


def test_render_shares_access_tags():
    html = str(web._render_data("SMB-SHARES", [
        {"name": "Pub", "share_type": "Disk", "comment": "", "access": "READ"},
        {"name": "C$", "share_type": "Disk", "comment": "", "access": "READ,WRITE"},
        {"name": "No", "share_type": "Disk", "comment": "", "access": "NO ACCESS"},
    ]))
    assert "<th>Access</th>" in html
    assert "tag-rw" in html and "READ,WRITE" in html
    assert "tag-deny" in html and "NO ACCESS" in html


def test_render_shares_no_access_column_when_absent():
    html = str(web._render_data("SMB-SHARES", [
        {"name": "Pub", "share_type": "Disk", "comment": ""},
    ]))
    assert "<th>Access</th>" not in html


def test_collect_shares_dedupes_latest_per_host_share():
    findings = [
        {"protocol": "SMB-SHARES", "ip_hostname": "10.0.0.5", "timestamp": "2026-10-22T09:00",
         "data": [{"name": "Pub", "share_type": "Disk", "access": "READ", "comment": ""}]},
        {"protocol": "SMB-SHARES", "ip_hostname": "10.0.0.5", "timestamp": "2026-10-22T11:00",
         "data": [{"name": "Pub", "share_type": "Disk", "access": "READ,WRITE", "comment": ""}]},
        {"protocol": "SMB", "ip_hostname": "10.0.0.5", "timestamp": "x", "data": [{"ignored": 1}]},
    ]
    rows = report._collect_shares(findings)
    assert len(rows) == 1
    assert rows[0]["access"] == "READ,WRITE"  # later timestamp wins
    assert "_ts" not in rows[0]


def test_report_includes_share_section():
    findings = [{"protocol": "SMB-SHARES", "ip_hostname": "10.0.0.5",
                 "toolname": "list_shares", "timestamp": "2026-10-22T10:00",
                 "data": [{"name": "C$", "share_type": "Disk",
                           "access": "READ,WRITE", "comment": "Default"}]}]
    assert "SMB Shares" in report.build_markdown(findings)
    html = report.build_html(findings)
    assert "Zugriffsrechte" in html and "acc-rw" in html


def test_excluded_shares_from_config():
    from domainscriptor.config import get_config
    eng = _bare_engine()
    eng.config = get_config()
    excl = eng._excluded_shares()
    assert "IPC$" in excl
    # comma-separated, case-insensitive
    eng.config.tools.share_exclude = "ipc$, print$ ,NETLOGON"
    assert eng._excluded_shares() == {"IPC$", "PRINT$", "NETLOGON"}


def test_build_share_matrix_merges_and_flags_diff():
    entries = [
        {"protocol": "SMB-DIFF", "ip_hostname": "10.0.0.5", "timestamp": "2026-10-22T09:00",
         "data": [
             {"user": "alice", "shares": {"Pub": {"access": "OK", "files": ["a", "b"]},
                                          "HR": {"access": "DENIED", "files": []}}},
             {"user": "bob", "shares": {"Pub": {"access": "OK", "files": ["a"]},
                                        "HR": {"access": "OK", "files": ["x"]}}},
         ]},
        {"protocol": "SMB-SHARES", "ip_hostname": "10.0.0.5", "timestamp": "2026-10-22T10:00",
         "data": [{"name": "Pub", "share_type": "Disk", "access": "READ,WRITE", "comment": "p"}]},
        {"protocol": "SMB-SHARES", "ip_hostname": "10.0.0.9", "timestamp": "2026-10-22T10:00",
         "data": [{"name": "C$", "share_type": "Disk", "access": "READ", "comment": ""}]},
    ]
    blocks, users = web._build_share_matrix(entries)
    assert [b["host"] for b in blocks] == ["10.0.0.5", "10.0.0.9"]
    assert "list_shares" in users and "alice" in users and "bob" in users
    html = str(blocks[0]["table_html"])
    # HR differs (DENIED vs OK), Pub differs (file sets differ) -> both flagged
    assert html.count("srow differs") == 2
    assert "data-user=\"alice\"" in html


def test_build_share_matrix_empty():
    blocks, users = web._build_share_matrix([])
    assert blocks == [] and users == []


def test_matrix_cell_variants():
    assert "tag-dim" in web._matrix_cell(None)
    assert "tag-rw" in web._matrix_cell({"access": "READ,WRITE", "count": None})
    cell = web._matrix_cell({"access": "READ", "count": 3})
    assert "tag-ok" in cell and "3 Dateien" in cell
    assert "tag-deny" in web._matrix_cell({"access": "DENIED", "count": 0})


def test_prune_empty_dirs(tmp_path):
    nested = tmp_path / "loot" / "share" / "sub"
    nested.mkdir(parents=True)
    (tmp_path / "loot" / "share" / "keep.txt").write_text("x")
    Engine._prune_empty_dirs(tmp_path / "loot")
    assert not nested.exists()                       # empty dirs gone
    assert (tmp_path / "loot" / "share" / "keep.txt").exists()  # non-empty kept

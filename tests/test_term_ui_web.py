from domainscriptor import term_ui as tui
from domainscriptor import web
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


def test_prune_empty_dirs(tmp_path):
    nested = tmp_path / "loot" / "share" / "sub"
    nested.mkdir(parents=True)
    (tmp_path / "loot" / "share" / "keep.txt").write_text("x")
    Engine._prune_empty_dirs(tmp_path / "loot")
    assert not nested.exists()                       # empty dirs gone
    assert (tmp_path / "loot" / "share" / "keep.txt").exists()  # non-empty kept

from domainscriptor.engine import _is_valid_target
from domainscriptor.smb_loot import is_interesting, search_credentials
from domainscriptor.automations import get_ldap_security_commands, get_smb_security_commands


def test_valid_targets():
    assert _is_valid_target("10.0.0.5")
    assert _is_valid_target("10.0.0.0/24")
    assert _is_valid_target("10.0.0.1-10.0.0.50")
    assert _is_valid_target("dc01.corp.local")


def test_invalid_targets_block_argument_injection():
    assert not _is_valid_target("--gen-relay-list")
    assert not _is_valid_target("-x whoami")
    assert not _is_valid_target("10.0.0.5; rm -rf /")
    assert not _is_valid_target("")


def test_smb_loot_interesting():
    assert is_interesting("web.config", "config")
    assert is_interesting("notes.txt", "txt")
    assert is_interesting("passwords.unknownext", None)
    assert not is_interesting("image.png", "png")


def test_smb_loot_credential_detection():
    text = "username=admin\npassword=Secret123\napi_key: abcd1234"
    hits = search_credentials(text)
    labels = {h["pattern"] for h in hits}
    assert "password_assignment" in labels
    assert "api_key" in labels


def test_ldap_automation_has_no_zerologon_mislabel():
    # Regression: 'asreproasting' darf nicht mit module=zerologon laufen.
    cmds = get_ldap_security_commands()
    for c in cmds:
        if c["vuln"] == "asreproasting":
            assert c["parameters"].get("module") != "zerologon"


def test_automation_commands_shape():
    for c in get_smb_security_commands() + get_ldap_security_commands():
        assert "vuln" in c and "parameters" in c and "creds_required" in c

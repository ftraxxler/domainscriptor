from domainscriptor.adapters_registry.adapters.kerbrute import KerbruteAdapter
from domainscriptor.adapters_registry.adapters.secretsdump import SecretsdumpAdapter
from domainscriptor.adapters_registry.adapters.nxc import parse_nxc_line


def test_kerbrute_userenum_parse():
    out = """
    2024/01/01 12:00:00 >  Using KDC(s):
    [+] VALID USERNAME:\t jdoe@corp.local
    [+] VALID USERNAME:\t admin@corp.local
    [*] done
    """
    adapter = KerbruteAdapter()
    adapter.used_domain = "corp.local"
    result = adapter.parse_output(out)
    # Ein CanonicalDataModel pro Domain
    assert len(result) == 1
    data = result[0].data
    users = {d["username"] for d in data}
    assert users == {"jdoe@corp.local", "admin@corp.local"}
    assert all(d["kind"] == "valid_user" for d in data)
    assert result[0].protocol == "KERBEROS"


def test_kerbrute_passwordspray_parse():
    out = "[+] jdoe@corp.local:Summer2024!   -> VALID CREDENTIALS"
    adapter = KerbruteAdapter()
    adapter.used_domain = "corp.local"
    result = adapter.parse_output(out)
    data = result[0].data
    assert data[0]["kind"] == "valid_credential"
    assert data[0]["password"] == "Summer2024!"


def test_kerbrute_build_command_passwordspray_requires_password():
    adapter = KerbruteAdapter()
    try:
        adapter.build_command(mode="passwordspray", domain="corp.local", userlist="u.txt")
        assert False, "should raise"
    except Exception as e:
        assert "password" in str(e).lower()


def test_secretsdump_ntlm_parse():
    out = """
    Impacket v0.11
    [*] Dumping Domain Credentials
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    corp.local\\jdoe:1104:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
    """
    adapter = SecretsdumpAdapter()
    adapter.used_target = "10.0.0.1"
    result = adapter.parse_output(out)
    assert len(result) == 1
    data = result[0].data
    accounts = {d["account"]: d for d in data}
    assert "Administrator" in accounts
    assert accounts["Administrator"]["rid"] == "500"
    assert accounts["Administrator"]["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert result[0].protocol == "SECRETS"


def test_secretsdump_empty_returns_empty_list():
    adapter = SecretsdumpAdapter()
    adapter.used_target = "10.0.0.1"
    assert adapter.parse_output("nothing here") == []


def test_secretsdump_build_command_identity():
    adapter = SecretsdumpAdapter()
    cmd = adapter.build_command(target="10.0.0.1", domain="corp.local",
                                username="admin", password="Pass123")
    assert cmd[0] == "impacket-secretsdump"
    assert cmd[1] == "corp.local/admin:Pass123@10.0.0.1"


def test_nxc_line_parse():
    line = "SMB         10.0.0.5        445    DC01             [*] Windows 10 x64 (name:DC01) (domain:corp.local)"
    entry = parse_nxc_line(line)
    assert entry is not None
    assert entry.ip == "10.0.0.5"
    assert entry.port == 445
    assert entry.hostname == "DC01"


def test_certipy_find_parse():
    from domainscriptor.adapters_registry.adapters.certipy import (
        CertipyAdapter, parse_certipy_find,
    )
    out = """
Certificate Templates
  0
    Template Name                       : ESC1-Template
    Display Name                        : ESC1 Template
    [!] Vulnerabilities
      ESC1                              : 'CORP.LOCAL\\\\Domain Users' can enroll, enrollee supplies subject
  1
    Template Name                       : WebServer
    [!] Vulnerabilities
      ESC4                              : 'CORP.LOCAL\\\\Domain Users' has dangerous permissions
"""
    findings = parse_certipy_find(out)
    escs = {(f.esc, f.template) for f in findings}
    assert ("ESC1", "ESC1-Template") in escs
    assert ("ESC4", "WebServer") in escs

    adapter = CertipyAdapter()
    adapter.used_target = "10.0.0.1"
    result = adapter.normalizer(findings)
    assert len(result) == 1
    assert result[0].protocol == "ADCS"
    assert result[0].toolname == "certipy"


def test_certipy_build_command_identity_and_flags():
    from domainscriptor.adapters_registry.adapters.certipy import CertipyAdapter
    adapter = CertipyAdapter()
    cmd = adapter.build_command(
        target="10.0.0.1", domain="corp.local", username="admin", password="pw",
    )
    assert cmd[:2] == ["certipy-ad", "find"]
    assert "admin@corp.local" in cmd
    assert "-dc-ip" in cmd and "10.0.0.1" in cmd
    assert "-stdout" in cmd and "-vulnerable" in cmd


def test_certipy_build_command_requires_creds():
    from domainscriptor.adapters_registry.adapters.certipy import CertipyAdapter
    adapter = CertipyAdapter()
    try:
        adapter.build_command(target="10.0.0.1", username="admin")
        assert False, "should raise without password/hashes"
    except Exception:
        pass

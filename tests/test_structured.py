from domainscriptor.data.canonical_db import CanonicalDB, CanonicalDataModel
from domainscriptor.data.db_reader import DBReader
from domainscriptor.data.structured_mapper import map_canonical
from domainscriptor.data.models import Category, Severity, SecretType


def _cdm(protocol, host, tool, data):
    return CanonicalDataModel(protocol, host, tool, "2024-01-01T00:00:00", data)


def test_mapper_secretsdump_produces_credentials():
    cdm = _cdm("SECRETS", "10.0.0.1", "secretsdump", [
        {"account": "CORP\\Administrator", "kind": "ntlm", "rid": "500",
         "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
         "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
    ])
    host, findings, creds = map_canonical(cdm)
    assert len(creds) == 1
    assert creds[0].secret_type == SecretType.NT_HASH
    assert creds[0].domain == "CORP"
    assert creds[0].username == "Administrator"
    assert findings[0].category == Category.CRED
    assert findings[0].severity == Severity.CRITICAL


def test_mapper_nxc_extracts_host_and_severity():
    msg = "[*] Windows 10 x64 (name:DC01) (domain:corp.local) (signing:False)"
    cdm = _cdm("SMB", "10.0.0.5", "nxc", [
        {"protocol": "SMB", "ip": "10.0.0.5", "port": 445, "hostname": "DC01", "message": msg},
    ])
    host, findings, creds = map_canonical(cdm)
    assert host.domain == "corp.local"
    assert host.hostname == "DC01"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].category == Category.VULN


def test_mapper_kerbrute_credential_vs_user():
    cdm = _cdm("KERBEROS", "corp.local", "kerbrute", [
        {"username": "jdoe@corp.local", "domain": "corp.local", "kind": "valid_user"},
        {"username": "svc@corp.local", "domain": "corp.local",
         "kind": "valid_credential", "password": "Summer2024!"},
    ])
    host, findings, creds = map_canonical(cdm)
    assert len(creds) == 1
    assert creds[0].secret_type == SecretType.PASSWORD
    assert any(f.category == Category.RECON for f in findings)


def test_mapper_unknown_tool_falls_back():
    cdm = _cdm("TCP", "10.0.0.9", "mystery", [{"foo": "bar"}])
    host, findings, creds = map_canonical(cdm)
    assert findings[0].category == Category.RECON
    assert creds == []


def test_db_roundtrip_and_dedup(tmp_path):
    db_path = tmp_path / "t.db"
    db = CanonicalDB(str(db_path))
    db.init_database()

    cdm = _cdm("SECRETS", "10.0.0.1", "secretsdump", [
        {"account": "CORP\\Administrator", "kind": "ntlm", "rid": "500",
         "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
         "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
    ])
    host, findings, creds = map_canonical(cdm)
    # Zweimal einfügen -> Dedup muss greifen
    db.insert_structured(host, findings, creds)
    db.insert_structured(host, findings, creds)
    db.close()

    reader = DBReader(str(db_path))
    assert len(reader.get_hosts()) == 1
    assert len(reader.get_credentials()) == 1
    assert len(reader.get_findings()) == 1
    assert reader.get_findings(severity="critical")
    assert reader.get_findings(category="VULN") == []
    reader.close()


def test_migrate_adds_structured_tables(tmp_path):
    # Simuliert eine alte DB nur mit canonical_data/pentest_config.
    db_path = tmp_path / "old.db"
    db = CanonicalDB(str(db_path))
    db.init_database()
    db.conn.execute("DROP TABLE hosts")
    db.conn.execute("DROP TABLE findings")
    db.conn.execute("DROP TABLE credentials")
    db.conn.commit()
    db.close()

    db2 = CanonicalDB(str(db_path))
    db2.migrate()  # muss die Tabellen nachrüsten
    host, findings, creds = map_canonical(
        _cdm("SMB", "10.0.0.5", "nxc", [{"message": "x (name:A) (domain:d)"}])
    )
    db2.insert_structured(host, findings, creds)
    db2.close()

    reader = DBReader(str(db_path))
    assert len(reader.get_hosts()) == 1
    reader.close()

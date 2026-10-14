"""Leitet aus einem rohen ``CanonicalDataModel`` die strukturierten Entitäten
(Host, Findings, Credentials) ab.

Die Zuordnung erfolgt pro Tool (``toolname``). Für unbekannte Tools greift ein
generischer Fallback, sodass niemals Daten verloren gehen – nur die Qualität der
Kategorisierung/Severity variiert.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from domainscriptor.data.canonical_db import CanonicalDataModel
from domainscriptor.data.models import (
    HostModel, FindingModel, CredentialModel, Category, Severity, SecretType,
)

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_NXC_NAME_RE = re.compile(r"\(name:(?P<name>[^)]+)\)", re.IGNORECASE)
_NXC_DOMAIN_RE = re.compile(r"\(domain:(?P<domain>[^)]+)\)", re.IGNORECASE)
_NXC_OS_RE = re.compile(r"\[\*\]\s*(?P<os>.+?)\s*\(name:", re.IGNORECASE)

MapResult = Tuple[HostModel, List[FindingModel], List[CredentialModel]]


def _truncate(text: str, n: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _host_from(cdm: CanonicalDataModel) -> HostModel:
    ident = cdm.ip_hostname or "(unknown)"
    is_ip = bool(_IPV4_RE.match(ident))
    return HostModel(
        identifier=ident,
        ip=ident if is_ip else None,
        hostname=None if is_ip else ident,
    )


def _nxc_severity(message: str) -> Severity:
    msg = message.lower()
    if "pwn3d!" in msg or "vulnerable" in msg:
        return Severity.HIGH
    if "signing:false" in msg.replace(" ", "") or "smbv1:true" in msg.replace(" ", ""):
        return Severity.MEDIUM
    if "[-]" in msg or "status_" in msg or "failure" in msg:
        return Severity.INFO
    return Severity.LOW


# ── Per-Tool-Handler ─────────────────────────────────────────────────────────

def _handle_nxc(cdm, host) -> MapResult:
    findings: List[FindingModel] = []
    for item in cdm.data:
        message = str(item.get("message", "")).strip()
        if not message:
            continue
        m = _NXC_DOMAIN_RE.search(message)
        if m:
            host.domain = m.group("domain").strip()
        m = _NXC_NAME_RE.search(message)
        if m and not host.hostname:
            host.hostname = m.group("name").strip()
        m = _NXC_OS_RE.search(message)
        if m:
            host.os = m.group("os").strip()

        sev = _nxc_severity(message)
        category = Category.VULN if sev.rank >= Severity.MEDIUM.rank else Category.RECON
        findings.append(FindingModel(
            host=host.identifier, category=category, title=_truncate(message),
            severity=sev, protocol=cdm.protocol, tool=cdm.toolname, evidence=item,
        ))
    return host, findings, []


def _handle_secretsdump(cdm, host) -> MapResult:
    creds: List[CredentialModel] = []
    for item in cdm.data:
        account = str(item.get("account", ""))
        domain = account.split("\\")[0] if "\\" in account else ""
        user = account.split("\\")[-1]
        if item.get("kind") == "ntlm" and item.get("nt_hash"):
            creds.append(CredentialModel(
                username=user, domain=domain, secret_type=SecretType.NT_HASH,
                secret_value=item["nt_hash"], source_tool=cdm.toolname, host=host.identifier,
            ))
        elif item.get("kind") == "kerberos_key" and item.get("key"):
            creds.append(CredentialModel(
                username=user, domain=domain, secret_type=SecretType.AES_KEY,
                secret_value=item["key"], source_tool=cdm.toolname, host=host.identifier,
            ))
    findings = [FindingModel(
        host=host.identifier, category=Category.CRED,
        title=f"secretsdump: {len(creds)} secret(s) dumped",
        severity=Severity.CRITICAL if creds else Severity.INFO,
        protocol=cdm.protocol, tool=cdm.toolname, evidence={"count": len(creds)},
    )] if creds else []
    return host, findings, creds


def _handle_kerbrute(cdm, host) -> MapResult:
    findings: List[FindingModel] = []
    creds: List[CredentialModel] = []
    for item in cdm.data:
        user = str(item.get("username", ""))
        domain = str(item.get("domain", ""))
        if item.get("kind") == "valid_credential" and item.get("password"):
            creds.append(CredentialModel(
                username=user, domain=domain, secret_type=SecretType.PASSWORD,
                secret_value=item["password"], source_tool=cdm.toolname, host=host.identifier,
            ))
            findings.append(FindingModel(
                host=host.identifier, category=Category.CRED,
                title=f"Valid credentials: {user}", severity=Severity.HIGH,
                protocol=cdm.protocol, tool=cdm.toolname, evidence=item,
            ))
        else:
            findings.append(FindingModel(
                host=host.identifier, category=Category.RECON,
                title=f"Valid username: {user}", severity=Severity.LOW,
                protocol=cdm.protocol, tool=cdm.toolname, evidence=item,
            ))
    return host, findings, creds


def _handle_responder(cdm, host) -> MapResult:
    findings: List[FindingModel] = []
    for item in cdm.data:
        kind = str(item.get("kind", ""))
        if kind == "NTLMV2":
            findings.append(FindingModel(
                host=host.identifier, category=Category.CRED,
                title=f"NTLMv2 hash captured from {item.get('ip')} "
                      f"(user {item.get('username') or '?'})",
                severity=Severity.HIGH, protocol=cdm.protocol, tool=cdm.toolname, evidence=item,
            ))
        else:
            findings.append(FindingModel(
                host=host.identifier, category=Category.RECON,
                title=f"{kind} poisoning: {item.get('name') or ''}".strip(),
                severity=Severity.INFO, protocol=cdm.protocol, tool=cdm.toolname, evidence=item,
            ))
    return host, findings, []


def _handle_smbloot(cdm, host) -> MapResult:
    findings: List[FindingModel] = []
    for item in cdm.data:
        has_matches = bool(item.get("matches"))
        findings.append(FindingModel(
            host=host.identifier,
            category=Category.CRED if has_matches else Category.SHARE,
            title=f"Loot: {item.get('remote_path', '?')}"
                  + (f" ({len(item['matches'])} credential match(es))" if has_matches else ""),
            severity=Severity.HIGH if has_matches else Severity.INFO,
            protocol=cdm.protocol, tool=cdm.toolname, evidence=item,
        ))
    return host, findings, []


def _handle_smbclient(cdm, host) -> MapResult:
    shares = [i for i in cdm.data if "share_type" in i]
    files = [i for i in cdm.data if "share_type" not in i]
    findings: List[FindingModel] = []
    for s in shares:
        findings.append(FindingModel(
            host=host.identifier, category=Category.SHARE,
            title=f"Share: {s.get('name')} ({s.get('share_type')})",
            severity=Severity.INFO, protocol=cdm.protocol, tool=cdm.toolname, evidence=s,
        ))
    if files:
        findings.append(FindingModel(
            host=host.identifier, category=Category.SHARE,
            title=f"{len(files)} file(s) listed", severity=Severity.INFO,
            protocol=cdm.protocol, tool=cdm.toolname, evidence={"count": len(files)},
        ))
    return host, findings, []


def _handle_nslookup(cdm, host) -> MapResult:
    findings: List[FindingModel] = []
    for item in cdm.data:
        if item.get("ip"):
            host.ip = host.ip or item["ip"]
        findings.append(FindingModel(
            host=host.identifier, category=Category.RECON,
            title=f"DNS {item.get('record_type', '')}: "
                  f"{item.get('hostname', '')} -> {item.get('ip', '')}".strip(),
            severity=Severity.INFO, protocol=cdm.protocol, tool=cdm.toolname, evidence=item,
        ))
    return host, findings, []


def _handle_bloodhound(cdm, host) -> MapResult:
    host.domain = host.domain or cdm.ip_hostname
    collected = cdm.data[0].get("collected", {}) if cdm.data else {}
    finding = FindingModel(
        host=host.identifier, category=Category.AD,
        title=f"BloodHound collection ({len(collected)} object type(s))",
        severity=Severity.INFO, protocol=cdm.protocol, tool=cdm.toolname,
        evidence=cdm.data[0] if cdm.data else {},
    )
    return host, [finding], []


def _handle_default(cdm, host) -> MapResult:
    findings = [FindingModel(
        host=host.identifier, category=Category.RECON,
        title=f"{cdm.toolname}: {cdm.protocol} result ({len(cdm.data)} item(s))",
        severity=Severity.INFO, protocol=cdm.protocol, tool=cdm.toolname,
        evidence={"items": cdm.data[:20]},
    )] if cdm.data else []
    return host, findings, []


_HANDLERS = {
    "nxc": _handle_nxc,
    "secretsdump": _handle_secretsdump,
    "kerbrute": _handle_kerbrute,
    "responder": _handle_responder,
    "smbloot": _handle_smbloot,
    "smbclient": _handle_smbclient,
    "nslookup": _handle_nslookup,
    "bloodhound-ce": _handle_bloodhound,
}


def map_canonical(cdm: CanonicalDataModel) -> MapResult:
    """Wandelt ein CanonicalDataModel in (Host, Findings, Credentials)."""
    host = _host_from(cdm)
    handler = _HANDLERS.get((cdm.toolname or "").lower(), _handle_default)
    return handler(cdm, host)

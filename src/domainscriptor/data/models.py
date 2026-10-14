"""Typisiertes (strukturiertes) Datenmodell.

Ergänzt das rohe ``canonical_data``-Log um normalisierte Entitäten:
Hosts, Findings und Credentials. Die Modelle werden mit pydantic validiert und
am Schreib-Rand (DBWriter) aus den ``CanonicalDataModel``-Objekten abgeleitet.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order[self.value]


class Category(str, Enum):
    RECON = "RECON"
    VULN = "VULN"
    MISCONFIG = "MISCONFIG"
    CRED = "CRED"
    SHARE = "SHARE"
    AD = "AD"


class SecretType(str, Enum):
    PASSWORD = "password"
    NT_HASH = "nt_hash"
    LM_HASH = "lm_hash"
    AES_KEY = "aes_key"
    TICKET = "ticket"


class HostModel(BaseModel):
    identifier: str                      # roher ip_hostname-Wert (Upsert-Schlüssel)
    ip: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    domain: Optional[str] = None


class FindingModel(BaseModel):
    host: str                            # Host-Identifier
    category: Category
    title: str
    severity: Severity = Severity.INFO
    protocol: str = ""
    tool: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)


class CredentialModel(BaseModel):
    username: str
    secret_type: SecretType
    secret_value: str
    domain: str = ""
    source_tool: str = ""
    host: Optional[str] = None
    valid: bool = True

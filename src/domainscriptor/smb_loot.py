"""Pure parsing/regex helpers for hunting credential-bearing documents on SMB shares."""
import re
import zipfile
from pathlib import Path
from typing import List, Optional, Pattern, Tuple

INTERESTING_EXTENSIONS = {
    "txt", "ini", "cfg", "conf", "config", "xml", "json", "yml", "yaml",
    "ps1", "psm1", "bat", "cmd", "vbs", "rdp", "csv", "log",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
    "kdbx", "psafe3", "sql", "env",
}

TEXT_EXTENSIONS = {
    "txt", "ini", "cfg", "conf", "config", "xml", "json", "yml", "yaml",
    "ps1", "psm1", "bat", "cmd", "vbs", "rdp", "csv", "log", "sql", "env",
}

OOXML_EXTENSIONS = {"docx", "xlsx", "pptx"}

INTERESTING_NAME_RE = re.compile(
    r"(password|passwort|kennwort|credential|secret|vault|backup|unattend|sysprep"
    r"|web\.config|\.git-credentials)",
    re.IGNORECASE,
)

CREDENTIAL_PATTERNS: List[Tuple[str, Pattern]] = [
    ("password_assignment", re.compile(r"(pass(?:wor[dt])?|pwd|kennwort)\s*[:=]\s*\S+", re.IGNORECASE)),
    ("api_key", re.compile(r"(api[_-]?key|secret[_-]?key|token)\s*[:=]\s*\S+", re.IGNORECASE)),
    ("connection_string", re.compile(r"(Data Source|Server)\s*=.*(Password|Pwd)\s*=", re.IGNORECASE)),
    ("private_key_block", re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("ntlm_hash", re.compile(r"\b[0-9a-f]{32}:[0-9a-f]{32}\b", re.IGNORECASE)),
]


def is_interesting(name: str, extension: Optional[str]) -> bool:
    if extension and extension.lower() in INTERESTING_EXTENSIONS:
        return True
    return bool(INTERESTING_NAME_RE.search(name))


def extract_text(path: Path, extension: Optional[str]) -> Optional[str]:
    ext = (extension or "").lower()
    try:
        if ext in TEXT_EXTENSIONS:
            return path.read_text(encoding="utf-8", errors="ignore")
        if ext in OOXML_EXTENSIONS:
            texts = []
            with zipfile.ZipFile(path) as zf:
                for member in zf.namelist():
                    if member.endswith(".xml") and (
                        "document" in member or "sharedStrings" in member or "slide" in member
                    ):
                        texts.append(zf.read(member).decode("utf-8", errors="ignore"))
            return "\n".join(texts) if texts else None
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def search_credentials(text: str, context: int = 40) -> List[dict]:
    findings = []
    for label, pattern in CREDENTIAL_PATTERNS:
        for m in pattern.finditer(text):
            start = max(0, m.start() - context)
            end = min(len(text), m.end() + context)
            snippet = text[start:end].replace("\n", " ").strip()
            findings.append({"pattern": label, "snippet": snippet})
    return findings

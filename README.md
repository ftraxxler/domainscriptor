# DomainScriptor

> Ein CLI-Framework, das ausgewählte Active-Directory-Pentest-Werkzeuge unter einer Oberfläche vereint. Automatisiert Prüfungen, normalisiert Ergebnisse in einer zentralen Datenbank und bietet KI-gestützte Analyse und Befehlsvorschläge.

![DomainScriptor](image.png)

---

## Unterstützte Tools

Jedes Tool ist über einen eigenen Adapter angebunden und wird beim Start automatisch erkannt (fehlt das Binary, wird der Adapter deaktiviert, siehe `showadapters`).

| Adapter-Name | Tool / Binary |
|--------------|----------------|
| `responder` | Responder |
| `smbexec` | impacket-smbexec |
| `smbclient` | smbclient |
| `ntlmrelayx` | impacket-ntlmrelayx |
| `nxc` | NetExec (nxc) |
| `proxychains` | proxychains4 |
| `nmap` | nmap |
| `nslookup` | nslookup |
| `bloodhound-ce` | bloodhound-ce-python |
| `kerbrute` | kerbrute (User-Enum / Password-Spray) |
| `secretsdump` | impacket-secretsdump (NTLM-Hashes / Kerberos-Keys) |

---

## Inhalt

- [Unterstützte Tools](#unterstützte-tools)
- [Installation](#installation)
- [Konfiguration](#konfiguration)
  - [Tool-Konfiguration](#tool-konfiguration)
  - [KI-Anbindung (.env)](#ki-anbindung-env)
- [Start](#start)
- [Befehle](#befehle)
- [Shortcuts](#shortcuts)
- [KI-Assistent](#ki-assistent)
- [Beispiele](#beispiele)

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Konfiguration

### Tool-Konfiguration

Für Responder und ntlmrelayx müssen vor dem ersten Einsatz folgende Einstellungen angepasst werden.

**`/etc/responder/Responder.conf`** — SMB und HTTP deaktivieren, damit ntlmrelayx diese Ports nutzen kann:

```ini
SMB  = Off
HTTP = Off
```

**`/etc/proxychains4.conf`** — Port für SOCKS-Proxy auf 1080 setzen:

```ini
socks4  127.0.0.1 1080
```

### KI-Anbindung (.env)

Domainscriptor unterstützt drei KI-Anbieter für den integrierten Assistenten. Eine `.env`-Datei im Arbeitsverzeichnis reicht aus — kein Export von Umgebungsvariablen nötig.

```ini
# Aktiven Anbieter wählen: openrouter | anthropic | openai
AI_PROVIDER=anthropic

# Anthropic
ANTHROPIC_API_KEY=sk-ant-...
# ANTHROPIC_MODEL=claude-haiku-4-5-20251001   # optional, das ist der Standard

# OpenRouter
# OPENROUTER_API_KEY=sk-or-...
# OPENROUTER_MODEL=anthropic/claude-haiku-4-5

# OpenAI
# OPENAI_API_KEY=sk-...
# OPENAI_MODEL=gpt-4o-mini
```

> Manuell gesetzte Umgebungsvariablen haben immer Vorrang vor der `.env`-Datei.

### Konfigurationsdatei (TOML)

Ausgabepfade, Web-UI, KI-Provider und Tool-Einstellungen lassen sich zentral über eine
TOML-Datei steuern. Eine Beispieldatei erzeugst du mit:

```bash
domainscriptor config init          # schreibt ./domainscriptor.toml
domainscriptor config show          # zeigt die effektiv geladene Konfiguration
```

Suchreihenfolge: `DOMAINSCRIPTOR_CONFIG` (Pfad) → `./domainscriptor.toml` → `~/.config/domainscriptor/config.toml`.

```toml
[paths]
work_dir       = "."        # Basis für targets.txt, loot/, reports/, ...
db_dir         = "."
loot_dir       = "loot"
report_dir     = "reports"

[web]
enabled = true
host    = "127.0.0.1"
port    = 5000

[ai]
provider = "openrouter"      # openrouter | anthropic | openai
model    = ""                 # leer = Provider-Default

[tools]
responder_log   = "/usr/share/responder/logs/Responder-Session.log"
default_timeout = 300
```

> Reihenfolge der Priorität: Defaults < TOML-Datei < Umgebungsvariablen.
> Da sich Domainscriptor per `sudo` auf Root eskaliert, ist die projekt-lokale
> `./domainscriptor.toml` (oder `DOMAINSCRIPTOR_CONFIG`) zuverlässiger als `~/.config`.

### Report-Export

Die gesammelten Findings lassen sich jederzeit als Bericht exportieren:

```
report                      → Markdown-Report nach reports/ (Zeitstempel-Name)
report html                 → HTML-Report (dunkles Theme, eigenständige Datei)
report json out.json        → JSON-Export unter eigenem Pfad
report markdown --ai        → Markdown inkl. KI-Analyse der Findings
```

---

## Start

```bash
domainscriptor start
```

Beim ersten Start wird abgefragt:
- Ob initiale Zugangsdaten (Domain, User, Passwort) hinterlegt werden sollen
- Der Ziel-IP-Bereich (wird in `targets.txt` gespeichert)
- Name der Datenbank (oder Auswahl einer bestehenden)

---

## Befehle

Alle Befehle werden innerhalb der interaktiven Shell (`domainscriptor start`) ausgeführt. Tab-Completion ist verfügbar.

| Befehl | Beschreibung |
|--------|-------------|
| `help [adapter]` | Allgemeine Hilfe oder Adapter-spezifische Hilfe |
| `version [adapter]` | Version von Domainscriptor oder eines Adapters |
| `showadapters` | Alle registrierten und verfügbaren Adapter anzeigen |
| `showprocesses` | Laufende Hintergrundprozesse anzeigen |
| `stopprocess <name>` | Hintergrundprozess beenden |
| `runcommand <adapter> [param=wert ...]` | Befehl über einen bestimmten Adapter ausführen |
| `fetch [byIp\|byProtocol\|byToolname\|search] [wert]` | Daten aus der Datenbank abrufen |
| `settings [add\|delete <id>\|default <id>]` | Zugangsdaten verwalten |
| `targets` | Konfigurierte Ziel-IPs anzeigen |
| `relayable` | Relayable Hosts aus `smb_relayable.txt` anzeigen |
| `shortcuts <shortcut> [proxy]` | Vordefinierte Befehlssequenzen ausführen |
| `ai <suggest\|analyze>` | KI-Assistent: Vorschläge oder Schwachstellenanalyse |
| `report [markdown\|html\|json] [pfad] [--ai]` | Findings als Bericht exportieren (optional mit KI-Analyse) |
| `config [show\|init]` | Effektive Konfiguration anzeigen oder Beispiel-Config schreiben |

### fetch

Liest normalisierte Ergebnisse aus der SQLite-Datenbank.

```
fetch                        → alle Roh-Einträge (canonical_data)
fetch byIp 192.168.0.1       → nach IP filtern
fetch byProtocol SMB         → nach Protokoll filtern
fetch byToolname nxc         → nach Tool filtern
fetch search zerologon       → Volltextsuche
fetch hosts                  → entdeckte Hosts (IP, Hostname, OS, Domain)
fetch findings [severity]    → priorisierte Findings (optional nach Severity gefiltert)
fetch creds                  → gefundene/zurückgewonnene Zugangsdaten
```

### Datenmodell

Jedes Ergebnis wird roh als JSON in `canonical_data` protokolliert (Audit-Log) **und**
zusätzlich automatisch in normalisierte Tabellen überführt:

- **`hosts`** — pro Host eindeutig (IP/Hostname), mit OS und Domain, dedupliziert.
- **`findings`** — kategorisiert (`RECON`/`VULN`/`MISCONFIG`/`CRED`/`SHARE`/`AD`) und mit
  Severity (`info`…`critical`); dedupliziert pro (Host, Tool, Protokoll, Titel).
- **`credentials`** — gefundene Secrets (`password`/`nt_hash`/`aes_key`/…) mit Quelle und Host.

Diese Struktur speist die priorisierte Ansicht in `fetch findings`, den Report-Export und
die KI-Analyse. Bestehende Datenbanken werden beim Start automatisch migriert.

### settings

Speichert Zugangsdaten für automatisierte Checks (Domain, User, Passwort).

```
settings                     → aktuelle Einträge anzeigen
settings add                 → neuen Eintrag hinzufügen
settings delete <id>         → Eintrag löschen
settings default <id>        → Eintrag als Default für automatisierte Checks setzen
```

Gibt es mehrere Einträge, wird ohne explizites Setzen eines Defaults der erste Eintrag verwendet. Der aktive Default ist in der `settings`-Ausgabe mit `*` markiert.

---

## Shortcuts

Vordefinierte Befehlssequenzen für häufige Prüfungen.

| Shortcut | Beschreibung |
|----------|-------------|
| `shortcuts get_relayable` | Welche Hosts sind SMB-relayable? → `smb_relayable.txt` |
| `shortcuts get_dc` | Domaincontroller suchen → `dc_ips.txt` (via nxc oder nslookup-Fallback) |
| `shortcuts smb_check [proxy]` | Vollständiger SMB-Sicherheitscheck (11 Prüfungen). Bei der IP-Abfrage kann auch `all` eingegeben werden, um gegen alle Ziele in `targets.txt` zu testen |
| `shortcuts ldap_check [proxy]` | Vollständiger LDAP-Sicherheitscheck (10 Prüfungen). Bei der IP-Abfrage kann auch `all` eingegeben werden, um gegen alle Ziele in `targets.txt` zu testen |
| `shortcuts hunt_creds` | SMB-Shares nach Credential-tragenden Dateien durchsuchen und herunterladen |
| `shortcuts diff_shares` | Share-/Datei-Sichtbarkeit zwischen gespeicherten Usern vergleichen |
| `shortcuts collect_ad` | AD-Daten via bloodhound-ce-python sammeln (Computer, User, Gruppen, GPOs, ...) |

`smb_check` und `ldap_check` führen die Checks strukturiert mit Kopfzeilen aus:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [1/11] [SMB] Zerologon  (no auth)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SMB scan complete — 11 checks run against 192.168.1.5
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**SMB-Checks:** Zerologon, NoPAC, PrintNightmare, SMBGhost, NTLM-Reflection, GPP-Autologin, GPP-Password, Password-Policy, Coerce+, Null Session, Guest Logon

**LDAP-Checks:** ASREPRoasting, User-Descriptions, User-Passwords, Unix-Passwords, ADCS, Domain Trusts, LAPS, LDAP-Signing, Machine-Quota

---

## KI-Assistent

Benötigt einen konfigurierten Anbieter in der `.env` (siehe [KI-Anbindung](#ki-anbindung-env)).

```
ai suggest      → KI schlägt konkrete nächste Domainscriptor-Befehle vor
ai analyze      → KI analysiert alle DB-Findings auf Schwachstellen und Angriffspfade
```

Die KI bekommt als Kontext: verfügbare Adapter, gesammelte Findings aus der DB und die konfigurierte Zieldomain.

---

## Beispiele

**SMB-Share auflisten**
```
runcommand smbclient target=192.168.1.10 share=SYSVOL username=user password=pass command=ls
```

**LDAP-Signing prüfen**
```
runcommand nxc protocol=ldap target=192.168.1.5 module=ldap-checker
```

**Responder starten**
```
runcommand responder interface=eth0 extra_args=-w
```

**ntlmrelayx starten**
```
runcommand ntlmrelayx target_file=smb_relayable.txt
```

**Relayable Hosts ermitteln und direkt SMB-Check durchführen**
```
shortcuts get_relayable
shortcuts smb_check
```

**Domaincontroller suchen (mit Fallback auf nslookup)**
```
shortcuts get_dc
```

**Nmap-Scan**
```
runcommand nmap target=192.168.1.0/24 ports=445,389,88 service_detection=true
```

**KI-Analyse nach einem Scan**
```
shortcuts smb_check
ai analyze
```



*by Fabian Traxler*

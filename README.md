# DomainScriptor



## Installieren

```bash
python -m venv .venv # Wird empfohlen
source .venv/bin/activate
pip install -e .
```

![DomainScriptor Version](image.png)

Start des Domainscriptors:
```bash
domainscriptor start
```

#### Notwendige Tool Konfiguration

Für die Verwendung von Responder und ntlmrelayx müssen folgende Einstellungen angepasst werden
In /etc/responder/Responder.conf müssen SMB und HTTP abgedreht werden

```bash
; Servers to start
SMB      = Off
HTTP     = Off
```

Für die Verwendung von Proxychains mit ntlmrelay muss der Port in /etc/proxychains4.conf auf 1080 angepasst werden
```bash
socks4  127.0.0.1 1080
```

Für folgende Versionen wurden Tests durchgeführt
- Ntlmrelayx - v0.14.0.dev
- Nxc - 1.5.1
- Responder 3.2.2.0
- smbclient - 4.23.6-Debian-4.23.6+dfsg-1+b1
- smbexec - v0.14.0.dev0

Ein Kali Linux 2026.1 hat diese Versionen derzeit bereits installiert

### Befehle

#### help
Zeigt die allgemeine Hilfe oder die Hilfe zu einem bestimmten Befehl an. Wenn ein Adaptername angegeben wird, wird die Hilfe für die Befehle und Optionen dieses Adapters angezeigt.

#### version

Gibt die Versionsnummer von Domainscriptor aus. Wenn ein Adaptername angegeben wird, werden zusätzlich die Versionsinformationen dieses Adapters angezeigt, sofern verfügbar.

#### showadapters
Listet alle registrierten Adapter auf, einschließlich Name, Typ und aktuellem Status (aktiviert/deaktiviert).

#### showprocesses
Zeigt die von Domainscriptor gestarteten Hintergrundprozesse an.

#### stopprocesses
Beendet einen Hintergrundprozess anhand seines Namens. Mit der Prozessübersicht können die gültigen Namen eingesehen werden.

#### runcommand
Führt einen Befehl innerhalb eines bestimmten Adapters aus. Damit lassen sich adapter-spezifische Aktionen ausführen, ohne einen vollständigen Workflow zu starten.

#### fetch
Ruft Daten von Adaptern ab und speichert sie in der Datenbank (z. B. Erkennungen/Ergebnisse). Dies wird in der Regel nach dem Start oder nach dem Ausführen von Adapter-Befehlen verwendet.
- Ohne Parameter liefert alle Einträge aus der Datenbank
- "byIp" filtert nach einer bestimmten IP zb. "192.168.0.1"
- "byProtocol" filtert nach einem bestimmten Protokoll zb. "SMB"
- "byToolname" filtert nach einem bestimmten Toolnamen zb. "nxc"
- "search" ermöglicht eine Volltextsuche in den Daten

#### settings
Es ist möglich vordefinierte Einstellungen zu hinterlegen: Domain, Username und Passwort.
- Ohne Parameter liefert die aktuellen Einstellungen
- "add" ermöglicht es neue Einträge hinzuzufügen
- "delete" ermöglicht es unter angabe der ID einen Eintrag zu löschen


#### shortcuts
Diese sollen häufige Befehle vereinfach und beschleunigen
- "get_relayable" schaut welche targets relayable sind und speichert die Resultate in smb_relayable.txt
  - target.txt mit Scope notwendig
- "get_dc" sucht die Domaincontroller in einem Netzwerk und speichert sie in dc_ips.txt
- "smb_check" führt mehrere Befehle gegen die selbe IP durch die das Ziel auf klassische Sicherheitslücken in SMB überprüft
- "ldap_check" führt mehrere Befehle gegen die selbe IP durch die das Ziel auf klassische Sicherheitslücken in LDAP überprüft



### Beispiel Befehle

SMB-Share ls Abfrage

```bash
runcommand smbclient target=127.0.0.1 share=SHARE username=test password=test command=ls
```

Check for LDAP signing

```bash
runcommand nxc protocol=ldap target=192.168.3.5 module=ldap-checker username=username password='passwort'
```


Starte Responder

```bash
runcommand responder interface=eth0 extra_args=-w
```

Starte ntlmrelayx
```bash
runcommand ntlmrelayx target_file=targets.txt
```

Get SMB relayable hosts

```bash
shortcuts get_relayable
```


Check SMB security

```bash
shortcuts smb_check
```




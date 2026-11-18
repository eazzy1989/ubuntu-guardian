# Ubuntu Guardian

[![Python](https://github.com/eazzy1989/ubuntu-guardian/actions/workflows/python-lint.yml/badge.svg)](https://github.com/eazzy1989/ubuntu-guardian/actions/workflows/python-lint.yml)

Server-Monitoring für Ubuntu mit Telegram-Bot: Der Guardian überwacht Ressourcen, Dienste, Netzwerk und Sicherheit eines Linux-Servers, schickt bei Problemen Alarme aufs Handy und lässt sich komplett über Telegram-Buttons bedienen – inklusive APT-Updates.

Entstanden als Homelab-Projekt, um meinen eigenen Ubuntu-Server unter Proxmox ohne zusätzliche Monitoring-Infrastruktur (Zabbix, Grafana o. Ä.) im Blick zu behalten.

## Funktionen

**Überwachung**
- CPU, RAM, Load und Festplattenbelegung mit Warn- und Kritisch-Schwellen
- systemd-Dienste: Status, ausgefallene Units, Timer, Flapping-Erkennung (Dienst startet ständig neu)
- Netzwerk: Internet- und DNS-Test, Ping/TCP-Checks (Router, eigene Hosts), Wechsel der öffentlichen IP
- TLS-Zertifikate: Restlaufzeit je Host
- SMART-Werte und Temperaturen der Festplatten
- Sicherheit: ausstehende Sicherheitsupdates, Neustart erforderlich, Livepatch-Status
- Docker-Container (optional) und Proxmox-VMs/Backups über die Proxmox-API (optional)
- Gesamtzustand als **Health-Score**

**Alarmierung**
- Alarme erst nach anhaltender Überschreitung (keine Fehlalarme bei kurzen Spitzen)
- Entwarnung, sobald ein Problem behoben ist – mit Dauer des Ausfalls
- Cooldowns und Erinnerungen gegen Alarm-Spam
- Warteschlange: Nachrichten werden nachgeschickt, wenn Telegram kurzzeitig nicht erreichbar war

**Bedienung über Telegram**
- Menü mit Buttons: Home, Status, Host, Netzwerk, Dienste, Updates, Diagnose, Logs
- APT-Updates direkt aus dem Chat installieren, mit Fortschrittsanzeige
- Befehle als Fallback: `/menu` `/status` `/updates` `/services` `/failed` `/disk` `/network` `/security` `/ping` `/temps` `/smart` `/docker` `/logs [n]` `/help`

**Sicherheit**
- Bedienung nur für freigegebene Telegram-User-IDs, mit Rate-Limit
- Tokens und Schlüssel werden in Logs automatisch geschwärzt
- Alle Zugangsdaten liegen in einer `.env`, nicht im Code

## Guardian API (optional)

`api/main.py` stellt Systemdaten zusätzlich als kleine HTTP-API bereit (FastAPI, nur `127.0.0.1`):

| Endpunkt | Funktion |
|---|---|
| `GET /health` | Lebenszeichen |
| `GET /status` | CPU, RAM, Disk, Netzwerk-Traffic |
| `GET /services` | Status der Dienste |
| `POST /services/{name}/restart` | Dienst neu starten – nur mit `X-API-Key` und nur für freigegebene Dienste |
| `GET /disk` | Festplattenbelegung |
| `GET /updates` | verfügbare Updates |

## Installation

Voraussetzungen: Ubuntu 22.04/24.04, Python 3.10+, ein Telegram-Bot (Token über [@BotFather](https://t.me/BotFather)).

```bash
sudo git clone https://github.com/eazzy1989/ubuntu-guardian.git /opt/ubuntu-guardian
cd /opt/ubuntu-guardian
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt
sudo cp .env.example .env
sudo nano .env          # Token, Chat-IDs und Schwellwerte eintragen
sudo chmod 600 .env
```

Als Dienst starten:

```bash
sudo cp systemd/ubuntu-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ubuntu-guardian
journalctl -u ubuntu-guardian -f
```

Für die API zusätzlich `sudo venv/bin/pip install -r api/requirements.txt` und `systemd/ubuntu-guardian-api.service` einrichten.

## Konfiguration

Alle Einstellungen stehen in `.env` – siehe [`.env.example`](.env.example). Die wichtigsten:

| Variable | Bedeutung |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Token des Bots |
| `TELEGRAM_CHAT_IDS` | Empfänger der Alarme |
| `ALLOWED_TELEGRAM_USER_IDS` | Wer den Bot bedienen darf |
| `WATCH_SERVICES` | Dienste, deren Ausfall alarmiert wird |
| `CPU_/RAM_/DISK_WARN`, `…_CRIT` | Schwellwerte in Prozent |
| `CERT_HOSTS` | Hosts für die Zertifikatsprüfung |
| `EXTRA_TCP_CHECKS` | weitere Hosts als `host:port` |
| `PROXMOX_*` | optionale Proxmox-Anbindung per API-Token |

## Hinweise

- Der Dienst läuft als `root`, weil APT-Updates, SMART-Werte und `systemctl` Root-Rechte benötigen. Deshalb ist die Bedienung auf freigegebene User-IDs beschränkt.
- Die API lauscht nur auf `127.0.0.1`. Für Zugriff von außen gehört sie hinter einen Reverse Proxy mit Authentifizierung.

## Tech-Stack

Python · Telegram Bot API · systemd · APT · smartctl · FastAPI · psutil · Proxmox VE API

## Lizenz

[MIT](LICENSE)

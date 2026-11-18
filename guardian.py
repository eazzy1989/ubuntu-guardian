import re
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

_APT_INSTALL_LOCK = threading.Lock()

import requests
from dotenv import load_dotenv

BASE_DIR = Path(os.getenv("GUARDIAN_BASE_DIR", Path(__file__).resolve().parent))
LOG_DIR = BASE_DIR / "logs"
STATE_FILE = BASE_DIR / "state.json"
LOG_FILE = LOG_DIR / "guardian.log"

load_dotenv(BASE_DIR / ".env")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_IDS = [x.strip() for x in os.getenv("TELEGRAM_CHAT_IDS", "").split(",") if x.strip()]
HOST_LABEL = os.getenv("HOST_LABEL", "Ubuntu Guardian").strip()

# Proxmox Monitoring (optional)
PROXMOX_ENABLED = os.getenv("PROXMOX_ENABLED", "false").strip().lower() == "true"
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "").strip()
PROXMOX_PORT = int(os.getenv("PROXMOX_PORT", "8006"))
PROXMOX_USER = os.getenv("PROXMOX_USER", "root").strip()
PROXMOX_REALM = os.getenv("PROXMOX_REALM", "pam").strip()
PROXMOX_TOKEN_NAME = os.getenv("PROXMOX_TOKEN_NAME", "guardian").strip()
PROXMOX_TOKEN_UUID = os.getenv("PROXMOX_TOKEN_UUID", "").strip()
PROXMOX_NODE = os.getenv("PROXMOX_NODE", "proxmox").strip()

# Zusätzliche Dienste anhand von Namensbestandteilen erkennen (kommagetrennt)
SERVICE_KEYWORDS = tuple(k.strip().lower() for k in os.getenv("SERVICE_KEYWORDS", "bot,guardian").split(",") if k.strip())
# Zusätzliche TCP-Checks im Format host:port,host:port (z. B. NAS oder Hypervisor)
EXTRA_TCP_CHECKS = [x.strip() for x in os.getenv("EXTRA_TCP_CHECKS", "").split(",") if x.strip()]
ROUTER_IP_FALLBACK = os.getenv("ROUTER_IP", "192.168.1.1").strip()

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL_SECONDS", "240"))
POLL_INTERVAL = int(os.getenv("TELEGRAM_POLL_INTERVAL_SECONDS", "15"))
# Proxmox Monitoring (optional)
SLOW_CHECK_INTERVAL = int(os.getenv("SLOW_CHECK_INTERVAL_SECONDS", "1800"))
WAN_IP_TTL_SECONDS = int(os.getenv("WAN_IP_TTL_SECONDS", "21600"))
RATE_LIMIT_SECONDS = float(os.getenv("RATE_LIMIT_SECONDS", "1.0"))

RAM_WARN = int(os.getenv("RAM_WARN", "80"))
RAM_CRIT = int(os.getenv("RAM_CRIT", "90"))
CPU_WARN = int(os.getenv("CPU_WARN", "75"))
CPU_CRIT = int(os.getenv("CPU_CRIT", "90"))
DISK_WARN = int(os.getenv("DISK_WARN", "80"))
DISK_CRIT = int(os.getenv("DISK_CRIT", "90"))

WATCH_SERVICES = [s.strip() for s in os.getenv("WATCH_SERVICES", "").split(",") if s.strip()]
CERT_HOSTS = [s.strip() for s in os.getenv("CERT_HOSTS", "").split(",") if s.strip()]
# Alle IDs als Strings vergleichen (vorher int vs. str -> der Fallback
# auf CHAT_IDS hat niemanden mehr autorisiert).
ALLOWED_IDS = [x.strip() for x in os.getenv("ALLOWED_TELEGRAM_USER_IDS", "").split(",") if x.strip()]
if not ALLOWED_IDS and CHAT_IDS:
    ALLOWED_IDS = CHAT_IDS.copy()  # Fallback zu CHAT_IDS
# ALARM_COOLDOWN_MINUTES = 10  # Ausfall muss 10 Min dauern bevor Alarm
ENABLE_DOCKER = os.getenv("ENABLE_DOCKER", "false").lower() == "true"

LOG_DIR.mkdir(parents=True, exist_ok=True)

_SECRET_PATTERNS = [re.compile(r"\d{6,12}:[A-Za-z0-9_-]{30,}")]


def redact(text):
    s = str(text)
    for pattern in _SECRET_PATTERNS:
        s = pattern.sub("<BOT_TOKEN>", s)
    return s


class RedactingFilter(logging.Filter):
    """Schwärzt den Bot-Token in jeder Logzeile (auch in Tracebacks).

    Vorher landete der Token über requests-Fehlermeldungen
    (".../bot<TOKEN>/getUpdates") hundertfach im Log und konnte über
    die Telegram-Logansicht angezeigt werden.
    """

    def filter(self, record):
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


logger = logging.getLogger("ubuntu_guardian")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)

# Dieser Host hat kein IPv6-Routing (siehe telegram_api_online). Statt
# socket.getaddrinfo zur Laufzeit global umzubiegen (Race mit den anderen
# Threads), wird urllib3 einmalig auf IPv4 festgelegt.
if os.getenv("FORCE_IPV4", "true").strip().lower() == "true":
    try:
        import urllib3.util.connection as _u3conn
        _u3conn.HAS_IPV6 = False
    except Exception:
        pass

STATE_LOCK = threading.RLock()
STATE = {}


def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        class Dummy:
            stdout = ""
            stderr = str(e)
            returncode = 1
        return Dummy()


def load_state_from_disk():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def get_current_snapshot():
    return STATE.get("snapshot")


def init_state():
    global STATE
    with STATE_LOCK:
        STATE = load_state_from_disk()


def persist_state_locked():
    # Atomar schreiben: ein Absturz/Stromausfall beim Schreiben hätte vorher
    # state.json zerstört -> alle Zustände (Alarme, Menüs, Offsets) verloren.
    tmp = STATE_FILE.with_name(f".{STATE_FILE.name}.{threading.get_ident()}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(STATE, fh, indent=2, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


def state_get(key=None, default=None):
    with STATE_LOCK:
        if key is None:
            return json.loads(json.dumps(STATE))
        return STATE.get(key, default)


def state_set(key, value):
    with STATE_LOCK:
        STATE[key] = value
        persist_state_locked()


def state_update(mutator):
    with STATE_LOCK:
        result = mutator(STATE)
        persist_state_locked()
        return result


def tg_api(method, data=None):
    try:
        post_data = {k: v for k, v in (data or {}).items() if k != "_retried"}
        r = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
            data=post_data,
            timeout=20,
        )
        try:
            payload = r.json()
        except Exception:
            payload = {"ok": False, "raw": r.text[:300]}
        if payload.get("ok"):
            logger.debug("Telegram %s status=%s", method, r.status_code)
        else:
            desc = str(payload.get("description", ""))
            harmless = ("message is not modified" in desc or "query is too old" in desc
                        or "message to delete not found" in desc)
            (logger.info if harmless else logger.warning)(
                "Telegram %s status=%s fehlgeschlagen: %s", method, r.status_code, desc or payload
            )
            # Flood-Limit: einmal nach retry_after erneut versuchen
            retry_after = int(((payload.get("parameters") or {}).get("retry_after")) or 0)
            if r.status_code == 429 and 0 < retry_after <= 30 and not (data or {}).get("_retried"):
                time.sleep(retry_after)
                return tg_api(method, dict(data or {}, _retried=True))
        return payload
    except Exception as e:
        msg = str(e)
        if method == "answerCallbackQuery" and ("query is too old" in msg or "query ID is invalid" in msg):
            logger.info("Telegram %s ignoriert: %s", method, msg)
            return {"ok": False, "ignored": True, "description": msg}
        logger.warning("Telegram %s Fehler: %s", method, e)
        return {"ok": False, "description": redact(e)}


def html_escape(text):
    text = "" if text is None else str(text)
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )


def mdv2_escape(text):
    if text is None:
        return ""
    text = str(text)
    for ch in ['\\', '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']:
        text = text.replace(ch, '\\' + ch)
    return text


def mdv2_code(text):
    if text is None:
        text = ""
    text = str(text).replace("\\", "\\\\").replace("`", "\\`")
    return f"`{text}`"


def alert_latency_icon(latency_ms):
    if latency_ms is None:
        return "⚪"
    try:
        latency_ms = float(latency_ms)
    except Exception:
        return "⚪"
    if latency_ms < 100:
        return "🟢"
    if latency_ms <= 500:
        return "🟡"
    return "🔴"


def alert_sep():
    return "━━━━━━━━━━━━━━"


def alert_title(icon, title):
    return f"{icon} *{mdv2_escape(title)}*"


def alert_field(label, value):
    return f"*{mdv2_escape(label)}:* {value}"


def alert_block(icon, title, lines):
    return f"{alert_title(icon, title)}\n\n" + "\n".join(lines) + f"\n\n{alert_sep()}"


_SEND_LOCAL = threading.local()
OUTBOX_MAX_AGE = 24 * 3600
OUTBOX_MAX_ENTRIES = 100


def _send_one(chat_id, text, reply_markup=None, parse_mode=None):
    data = {"chat_id": chat_id, "text": text}
    if parse_mode:
        data["parse_mode"] = parse_mode
    if reply_markup:
        data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    result = tg_api("sendMessage", data)
    # Formatierungsfehler: als Klartext senden statt den Alarm zu verlieren
    if (not result.get("ok")) and parse_mode and "parse entities" in str(result.get("description", "")).lower():
        data.pop("parse_mode", None)
        data["text"] = re.sub(r"\\([_*\[\]()~`>#+\-=|{}.!])", r"\1", text)
        result = tg_api("sendMessage", data)
    return result


def send_telegram(text, reply_markup=None, parse_mode=None, queue_on_failure=True):
    """Sendet an alle CHAT_IDS.

    Vorher verhinderte ein globales Flag "Rekursion" – sendeten zwei Threads
    gleichzeitig (Monitor + Update-Worker), wurde eine Nachricht verworfen.
    Jetzt: Schutz nur gegen echte Rekursion im selben Thread; nicht
    zustellbare Nachrichten landen in der Outbox und werden nachgeliefert.
    """
    if getattr(_SEND_LOCAL, "active", False):
        logger.warning("send_telegram Rekursion verhindert")
        return {"ok": False, "description": "send_telegram Rekursion verhindert"}

    if not CHAT_IDS:
        logger.warning("CHAT_IDS fehlt – Telegram Versand übersprungen")
        return {"ok": False, "description": "CHAT_IDS fehlt"}

    results = []
    _SEND_LOCAL.active = True
    try:
        for chat_id in CHAT_IDS:
            try:
                result = _send_one(chat_id, text, reply_markup, parse_mode)
            except Exception as e:
                logger.error("Telegram error for %s: %s", chat_id, e)
                result = {"ok": False, "description": str(e)}
            results.append(result)
            if queue_on_failure and not result.get("ok"):
                outbox_add(chat_id, text, reply_markup, parse_mode)
    finally:
        _SEND_LOCAL.active = False

    ok = bool(results) and all(r.get("ok") for r in results)
    return {"ok": ok, "results": results}


def outbox_add(chat_id, text, reply_markup=None, parse_mode=None):
    def mut(s):
        box = s.setdefault("outbox", [])
        box.append({
            "chat_id": str(chat_id), "text": text, "reply_markup": reply_markup,
            "parse_mode": parse_mode, "created_ts": int(time.time()),
        })
        del box[:-OUTBOX_MAX_ENTRIES]
    state_update(mut)
    logger.warning("Nachricht an %s nicht zustellbar – in Outbox gespeichert", chat_id)


def outbox_flush():
    """Liefert Nachrichten nach, die z. B. während eines Internet-Ausfalls
    entstanden sind. Stoppt beim ersten Fehler (Verbindung noch weg)."""
    box = list(state_get("outbox", []) or [])
    if not box:
        return 0
    now = int(time.time())
    delivered, keep = 0, []
    for idx, item in enumerate(box):
        if now - int(item.get("created_ts", now)) > OUTBOX_MAX_AGE:
            logger.warning("Outbox: Nachricht verworfen (älter als 24 h)")
            continue
        stamp = datetime.fromtimestamp(item.get("created_ts", now)).strftime("%d.%m. %H:%M")
        pm = item.get("parse_mode")
        prefix = f"⏱ Verspätet zugestellt \\(Ereignis {mdv2_escape(stamp)}\\)\n\n" if pm == "MarkdownV2" else f"⏱ Verspätet zugestellt (Ereignis {stamp})\n\n"
        res = _send_one(item["chat_id"], prefix + item.get("text", ""), item.get("reply_markup"), pm)
        if res.get("ok"):
            delivered += 1
        else:
            keep = [i for i in box[idx:] if now - int(i.get("created_ts", now)) <= OUTBOX_MAX_AGE]
            break

    def mut(s):
        current = s.get("outbox", []) or []
        added = current[len(box):]  # während des Flush hinzugekommen
        s["outbox"] = keep + added
    state_update(mut)
    if delivered:
        logger.info("Outbox: %s verspätete Nachricht(en) zugestellt", delivered)
    return delivered


def edit_telegram_message(chat_id, message_id, text, reply_markup=None, parse_mode=None):
    data = {"chat_id": chat_id, "message_id": message_id, "text": text}
    if parse_mode:
        data["parse_mode"] = parse_mode
    if reply_markup is not None:
        data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    return tg_api("editMessageText", data)


def delete_telegram_message(chat_id, message_id):
    return tg_api("deleteMessage", {"chat_id": chat_id, "message_id": message_id})


def answer_callback_query(callback_query_id, text=None):
    data = {"callback_query_id": callback_query_id}
    if text:
        data["text"] = text
    return tg_api("answerCallbackQuery", data)


def telegram_get_updates(offset=None, timeout=30):
    params = {
        "timeout": timeout,
        "allowed_updates": json.dumps(["message", "callback_query"]),
    }
    if offset is not None:
        params["offset"] = offset
    try:
        r = requests.get(
            f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
            params=params,
            timeout=timeout + 10,
        )
        payload = r.json()
        count = len(payload.get("result", [])) if isinstance(payload, dict) else -1
        logger.info("Telegram getUpdates status=%s offset=%s count=%s", r.status_code, offset, count)
        if r.status_code != 200:
            logger.warning("Telegram getUpdates HTTP Fehler: status=%s body=%s", r.status_code, payload)
        elif not payload.get("ok", False):
            logger.warning("Telegram getUpdates API Fehler: %s", payload)
        return payload if isinstance(payload, dict) else {"ok": False, "result": []}
    except Exception as e:
        # Netzwerkfehler sind erwartbar (Ausfall, Telegram 5xx) – ohne Traceback
        # loggen; vorher füllten Tracebacks die 5 MB Log in ~2 Wochen.
        logger.warning("Telegram getUpdates Fehler: %s", e)
        return {"ok": False, "result": []}


def get_updates():
    r = run(["/usr/lib/update-notifier/apt-check"])
    raw = (r.stdout or "") + (r.stderr or "")
    first = raw.strip().splitlines()[0] if raw.strip() else "0;0"
    parts = first.split(";")
    updates = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    security = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return updates, security


def get_reboot_required():
    """
    Erkennt einen ausstehenden Neustart zuverlässig.

    True wenn:
    1. Ubuntu den offiziellen reboot-required Marker gesetzt hat oder
    2. ein neuerer installierter Kernel vorhanden ist als der aktuell laufende.
    """
    # Offizieller Ubuntu-Reboot-Marker
    if Path("/var/run/reboot-required").exists():
        return True

    # Kernelvergleich:
    # Aktiver Kernel
    current = run(["uname", "-r"]).stdout.strip()
    if not current:
        return False

    try:
        current_version = current.removeprefix("6.8.0-").removesuffix("-generic")
        current_num = int(current_version)
    except (ValueError, AttributeError):
        current_num = None

    if current_num is None:
        return False

    # Installierte Kernel unter /boot
    installed = []
    for kernel in Path("/boot").glob("vmlinuz-*"):
        name = kernel.name.removeprefix("vmlinuz-")

        if not name.endswith("-generic"):
            continue

        try:
            version = name.removeprefix("6.8.0-").removesuffix("-generic")
            installed.append(int(version))
        except ValueError:
            continue

    return bool(installed and max(installed) > current_num)


def get_livepatch_status():
    if shutil.which("pro"):
        r = run(["pro", "status"])
        text = ((r.stdout or "") + (r.stderr or "")).lower()
        if "livepatch" in text and "enabled" in text:
            return "Aktiv"
    if shutil.which("canonical-livepatch"):
        r = run(["canonical-livepatch", "status"])
        text = ((r.stdout or "") + (r.stderr or "")).lower()
        if "server check-in: succeeded" in text or "patch state: ✓" in text:
            return "Aktiv"
    return "Inaktiv"


def parse_os_release():
    data = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
    except Exception:
        pass
    return data


def get_hostname():
    return socket.gethostname()


def get_kernel():
    return run(["uname", "-r"]).stdout.strip() or "unbekannt"


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unbekannt"
    finally:
        s.close()


def get_network_interfaces():
    result = []
    r = run(["ip", "-o", "-4", "addr", "show"])
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            iface = parts[1]
            ip_cidr = parts[3]
            result.append({"iface": iface, "ip": ip_cidr})
    return result


def get_uptime():
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        if days > 0:
            return f"{days} Tage"
        if hours > 0:
            return f"{hours} Std"
        return f"{minutes} Min"
    except Exception:
        return "unbekannt"


def get_ram_percent():
    lines = Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
    mem = {}
    for line in lines:
        key, value = line.split(":")
        mem[key] = int(value.strip().split()[0])
    total = mem.get("MemTotal", 1)
    available = mem.get("MemAvailable", 0)
    used = total - available
    return round((used / total) * 100), total // 1024, used // 1024


def get_cpu_percent():
    def read_cpu():
        parts = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:]))
        idle = parts[3] + parts[4]
        total = sum(parts)
        return idle, total

    idle1, total1 = read_cpu()
    time.sleep(1)
    idle2, total2 = read_cpu()
    idle = idle2 - idle1
    total = total2 - total1
    if total <= 0:
        return 0
    return round((1 - idle / total) * 100)


def get_load_average():
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            parts = f.read().split()
        return parts[0], parts[1], parts[2]
    except Exception:
        return "?", "?", "?"


def get_cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore").splitlines():
            if "model name" in line:
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unbekannt"


def get_cpu_cores():
    r = run(["nproc"])
    out = (r.stdout or "").strip()
    return out or "unbekannt"


def get_disk_info():
    usage = shutil.disk_usage("/")
    total = round(usage.total / (1024**3), 1)
    used = round(usage.used / (1024**3), 1)
    free = round(usage.free / (1024**3), 1)
    percent = round((usage.used / usage.total) * 100)
    return percent, total, used, free


def level_for(value, warn, crit):
    if value >= crit:
        return "Kritisch"
    if value >= warn:
        return "Warnung"
    return "Normal"


def internet_probe(url):
    try:
        r = requests.get(url, timeout=5)
        return r.ok
    except Exception:
        return False


def internet_online():
    targets = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = [ex.submit(internet_probe, t) for t in targets]
        for f in as_completed(futures):
            try:
                if f.result():
                    return True
            except Exception:
                pass
    return False


def proxmox_api(path, method="GET", data=None):
    if not PROXMOX_ENABLED:
        return None
    try:
        import requests
        base = f"https://{PROXMOX_HOST}:{PROXMOX_PORT}/api2/json"
        if PROXMOX_TOKEN_UUID:
            headers = {"Authorization": f"PVEAPIToken=root@pam!{PROXMOX_TOKEN_NAME}={PROXMOX_TOKEN_UUID}"}
        else:
            return None
        url = base + path
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            return r.json().get("data")
        return None
    except Exception:
        return None

def check_proxmox():
    result = {"proxmox_api_ok": False, "vms_changed": [], "backups_failed": []}
    if not PROXMOX_ENABLED:
        return result
    try:
        node_status = proxmox_api(f"/nodes/{PROXMOX_NODE}/status")
        if node_status is None:
            result["proxmox_api_ok"] = False
            return result
        result["proxmox_api_ok"] = True

        vms = proxmox_api(f"/nodes/{PROXMOX_NODE}/qemu") or []
        for vm in vms:
            vmid = vm.get("vmid")
            status = vm.get("status")
            if status != "running":
                result["vms_changed"].append({"type": "qemu", "vmid": vmid, "status": status})

        tasks = proxmox_api(f"/nodes/{PROXMOX_NODE}/tasks") or []
        from datetime import datetime, timedelta
        now = datetime.now()
        for task in tasks:
            if task.get("type") != "vzdump":
                continue
            endtime = task.get("endtime", 0)
            if endtime and now - datetime.fromtimestamp(endtime) > timedelta(hours=24):
                continue
            if task.get("status") != "OK":
                result["backups_failed"].append({"vmid": task.get("upid", "").split(":")[1], "status": task.get("status")})
    except Exception:
        pass
    return result

def telegram_api_online():
    """Telegram API connectivity check (IPv4 wird global über FORCE_IPV4 erzwungen)."""
    if not BOT_TOKEN:
        return False
    try:
        r = requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe", timeout=10)
        return r.status_code == 200
    except Exception as e:
        logger.warning("Telegram API check failed: %s", e)
        return False


def dns_test():
    """
    DNS health check.

    Only IPv4 resolution is relevant for this host because IPv6 transport
    is not available. gethostbyname() therefore deliberately tests IPv4 DNS.
    """
    try:
        socket.gethostbyname("api.telegram.org")
        return True
    except Exception as e:
        logger.warning("DNS check failed: %s", e)
        return False


def run_ping(host, timeout=2, label=None):
    host = str(host or "").strip()
    target = str(label or host)

    if not host:
        return {"target": target, "ok": False, "latency_ms": None}

    cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
    r = run(cmd, timeout=timeout + 2)

    out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
    if getattr(r, "returncode", 1) != 0:
        return {"target": target, "ok": False, "latency_ms": None}

    latency_ms = None
    for marker in ("time=", "Zeit="):
        if marker in out:
            try:
                tail = out.split(marker, 1)[1]
                num = tail.split()[0].replace("ms", "").strip()
                latency_ms = float(num)
                break
            except Exception:
                latency_ms = None

    return {"target": target, "ok": True, "latency_ms": latency_ms}


def tcp_check(host, port, timeout=2):
    try:
        import socket
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            latency = (time.time() - start) * 1000.0
            return {"ok": True, "latency_ms": latency, "host": f"{host}:{port}"}
    except Exception:
        return {"ok": False, "latency_ms": None, "host": f"{host}:{port}"}


def parallel_pings():
    hosts = ["1.1.1.1", "8.8.8.8", "api.telegram.org"]
    results = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        future_map = {ex.submit(run_ping, h): h for h in hosts}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                results[host] = future.result()
            except Exception:
                results[host] = {"ok": False, "latency_ms": None}
    return results


def get_cert_expiry_days(host):
    """Restlaufzeit des TLS-Zertifikats in Tagen (ohne Shell/openssl-Aufruf).

    Vorher: `bash -lc "echo | openssl s_client -connect {host}:443 ..."` –
    der Hostname aus .env wurde ungeprüft in eine Shell eingesetzt.
    """
    import ssl
    host = str(host or "").strip()
    port = 443
    if ":" in host:
        host, _, port_s = host.rpartition(":")
        port = int(port_s) if port_s.isdigit() else 443
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        logger.warning("Ungültiger CERT_HOSTS-Eintrag ignoriert")
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        expiry_ts = ssl.cert_time_to_seconds(cert["notAfter"])
        return max(0, int((expiry_ts - time.time()) // 86400))
    except ssl.SSLCertVerificationError as e:
        logger.warning("Zertifikat %s ungültig: %s", host, e)
        return 0
    except Exception as e:
        logger.info("Zertifikat %s nicht prüfbar: %s", host, e)
        return None


def get_docker_summary():
    if not ENABLE_DOCKER or not shutil.which("docker"):
        return {"enabled": False, "running": 0, "total": 0, "names": []}
    r = run(["docker", "ps", "--format", "{{.Names}}"])
    running = [x for x in (r.stdout or "").splitlines() if x.strip()]
    r2 = run(["docker", "ps", "-a", "--format", "{{.Names}}"])
    total = [x for x in (r2.stdout or "").splitlines() if x.strip()]
    return {"enabled": True, "running": len(running), "total": len(total), "names": running}

def get_security_summary():
    def lines(cmd, limit=5):
        r = run(["bash", "-lc", cmd], timeout=20)
        out = (r.stdout or "").strip().splitlines()
        return [x.strip() for x in out if x.strip()][:limit]

    failed_ssh = lines("journalctl -u ssh --since '24 hours ago' --no-pager 2>/dev/null | grep -Ei 'Failed password|authentication failure|Invalid user' | tail -n 5")
    sudo_events = lines("journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep -E 'sudo:|COMMAND=' | tail -n 5")
    recent_logins = lines("last -n 5 -i 2>/dev/null | sed '/^wtmp begins/d'")
    failed_logins = lines("lastb -n 5 -i 2>/dev/null | sed '/^btmp begins/d'")
    lastlog_lines = lines("lastlog -t 30 2>/dev/null | head -n 6")

    return {
        "failed_ssh": failed_ssh,
        "sudo_events": sudo_events,
        "recent_logins": recent_logins,
        "failed_logins": failed_logins,
        "lastlog": lastlog_lines,
    }

def get_smart_summary():
    if not shutil.which("smartctl"):
        return {"available": False, "devices": []}

    devices = []
    scan = run(["bash", "-lc", "smartctl --scan 2>/dev/null | awk '{print $1}'"])
    for dev in [x.strip() for x in (scan.stdout or "").splitlines() if x.strip()]:
        info = {"device": dev, "health": "unbekannt", "temperature": None, "reallocated": None, "pending": None}

        r_health = run(["smartctl", "-H", dev], timeout=20)
        text_h = (r_health.stdout or "") + (r_health.stderr or "")
        if "PASSED" in text_h:
            info["health"] = "PASSED"
        elif "FAILED" in text_h:
            info["health"] = "FAILED"

        r_all = run(["smartctl", "-A", dev], timeout=20)
        text = (r_all.stdout or "") + (r_all.stderr or "")
        for line in text.splitlines():
            line_s = line.strip()
            if "Temperature_Celsius" in line_s or "Temperature_Internal" in line_s:
                try:
                    info["temperature"] = int(line_s.split()[-1])
                except Exception:
                    pass
            if "Reallocated_Sector_Ct" in line_s:
                try:
                    info["reallocated"] = int(line_s.split()[-1])
                except Exception:
                    pass
            if "Current_Pending_Sector" in line_s:
                try:
                    info["pending"] = int(line_s.split()[-1])
                except Exception:
                    pass
        devices.append(info)
    return {"available": True, "devices": devices}

def get_temperatures():
    temps = {}
    base = Path("/sys/class/thermal")
    if base.exists():
        for zone in base.glob("thermal_zone*"):
            try:
                tfile = zone / "temp"
                typefile = zone / "type"
                if tfile.exists():
                    raw = int(tfile.read_text().strip())
                    c = round(raw / 1000, 1) if raw > 1000 else round(float(raw), 1)
                    name = typefile.read_text().strip() if typefile.exists() else zone.name
                    temps[name] = c
            except Exception:
                continue
    return temps


def get_service_states():
    states = {}

    watched_services = [svc for svc in WATCH_SERVICES if svc]

    # Alle installierten Service-Units ermitteln.
    # Dadurch können auch passive/oneshot Services mit zugehörigem
    # Timer angezeigt werden, ohne sie für Alarmzwecke zu überwachen.
    r_units = run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
        timeout=30,
    )

    discovered = set(watched_services)

    for line in (r_units.stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue

        name = parts[0]

        if not name.endswith(".service"):
            continue

        # Explizit überwachte Services immer aufnehmen.
        if name in watched_services:
            discovered.add(name)
            continue

        # Eigene Services unter /etc/systemd/system automatisch erkennen.
        r_cat = run(["systemctl", "cat", name], timeout=15)
        unit_text = r_cat.stdout or ""

        if "/etc/systemd/system/" in unit_text:
            discovered.add(name)
            continue

        # Zusätzlich bekannte Anwendungs-Service-Namen erkennen.
        lname = name.lower()
        keywords = SERVICE_KEYWORDS

        if any(k in lname for k in keywords):
            discovered.add(name)

    for svc in sorted(discovered):
        r_en = run(["systemctl", "is-enabled", svc], timeout=10)
        enabled = (r_en.stdout or "").strip() or "unknown"

        r_ac = run(["systemctl", "is-active", svc], timeout=10)
        active = (r_ac.stdout or "").strip() or "unknown"

        r_type = run(
            ["systemctl", "show", "-p", "Type", "--value", svc],
            timeout=10,
        )
        service_type = (r_type.stdout or "").strip() or "unknown"

        is_oneshot = service_type == "oneshot"

        # Nur explizit überwachte Services werden für Ausfallalarme
        # als dauerhaft zu überwachende Services markiert.
        watched = svc in watched_services and not is_oneshot

        states[svc] = {
            "active": active,
            "enabled": enabled,
            "type": service_type,
            "watched": watched,
        }

    # Alle Services übernehmen, die durch einen systemd-Timer
    # aktiviert werden. get_timers_map() liefert die zuverlässige
    # Zuordnung TIMER -> ACTIVATES-Service.
    timer_map = get_timers_map()

    for activates in timer_map:
        if activates.endswith(".service"):
            discovered.add(activates)

    for svc in sorted(discovered):
        if svc in states:
            continue

        r_en = run(["systemctl", "is-enabled", svc], timeout=10)
        enabled = (r_en.stdout or "").strip() or "unknown"

        r_ac = run(["systemctl", "is-active", svc], timeout=10)
        active = (r_ac.stdout or "").strip() or "unknown"

        r_type = run(
            ["systemctl", "show", "-p", "Type", "--value", svc],
            timeout=10,
        )
        service_type = (r_type.stdout or "").strip() or "unknown"

        states[svc] = {
            "active": active,
            "enabled": enabled,
            "type": service_type,
            "watched": False,
        }

    return states

def get_failed_units():
    r = run(["systemctl", "--failed", "--no-legend", "--plain"])
    units = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        units.append(line.split()[0])
    return sorted(set(units))



def get_timers_map():
    timers = {}

    r = run(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], timeout=30)
    timer_units = []

    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        for token in parts:
            if token.endswith(".timer"):
                timer_units.append(token)
                break

    for timer_unit in sorted(set(timer_units)):
        rr = run([
            "systemctl", "show", timer_unit,
            "--property=Id",
            "--property=NextElapseUSecRealtime",
            "--property=NextElapseUSecMonotonic",
            "--property=LastTriggerUSec",
            "--property=Result",
            "--property=Unit",
        ], timeout=20)

        data = {}
        for line in (rr.stdout or "").splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()

        activates = data.get("Unit", "").strip()
        if not activates:
            continue

        next_run = data.get("NextElapseUSecRealtime", "").strip()
        last_run = data.get("LastTriggerUSec", "").strip()

        timers[activates] = {
            "timer": data.get("Id", timer_unit).strip(),
            "next": next_run,
            "left": "",
            "last": last_run,
            "result": data.get("Result", "").strip(),
        }

    return timers


def get_wan_ip_fresh():
    services = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
    with ThreadPoolExecutor(max_workers=3) as ex:
        future_map = {ex.submit(requests.get, url, timeout=8): url for url in services}
        for future in as_completed(future_map):
            try:
                r = future.result()
                if r.ok:
                    ip = r.text.strip()
                    if ip:
                        return ip
            except Exception:
                pass
    return "unbekannt"


def color_for_health(score):
    if score >= 95:
        return "🟢"
    if score >= 75:
        return "🟡"
    if score >= 50:
        return "🟠"
    return "🔴"


def health_score(snapshot):
    score = 100
    if snapshot["security_updates"] > 0:
        score -= 25
    if snapshot["updates"] > 0:
        score -= 10
    if snapshot["reboot_required"]:
        score -= 15
    if not snapshot.get("internet_online", True):
        score -= 25
    if not snapshot.get("telegram_online", True):
        score -= 15
    if not snapshot.get("dns_ok", True):
        score -= 10
    if snapshot["ram"] >= RAM_CRIT:
        score -= 15
    elif snapshot["ram"] >= RAM_WARN:
        score -= 8
    if snapshot["cpu"] >= CPU_CRIT:
        score -= 15
    elif snapshot["cpu"] >= CPU_WARN:
        score -= 8
    if snapshot["disk_percent"] >= DISK_CRIT:
        score -= 20
    elif snapshot["disk_percent"] >= DISK_WARN:
        score -= 10
    bad_services = [k for k, v in snapshot["services"].items() if v.get("watched") and v.get("active") != "active"]
    score -= min(len(bad_services) * 10, 30)
    return max(0, min(100, score))



def build_fast_snapshot(prev_snapshot=None):
    prev_snapshot = prev_snapshot or {}
    updates, security = get_updates()
    reboot_required = get_reboot_required()
    os_data = parse_os_release()
    ram_percent, ram_total_mb, ram_used_mb = get_ram_percent()
    disk_percent, disk_total_gb, disk_used_gb, disk_free_gb = get_disk_info()
    load1, load5, load15 = get_load_average()
    services = get_service_states()
    failed_units = get_failed_units()

    snapshot = {
        "host": HOST_LABEL,
        "hostname": get_hostname(),
        "ubuntu": os_data.get("PRETTY_NAME", "Ubuntu"),
        "ubuntu_version": os_data.get("VERSION_ID", "unbekannt"),
        "kernel": get_kernel(),
        "cpu_model": get_cpu_model(),
        "cpu_cores": get_cpu_cores(),
        "ram_total_mb": ram_total_mb,
        "ram_used_mb": ram_used_mb,
        "updates": updates,
        "security_updates": security,
        "reboot_required": reboot_required,
        "livepatch": get_livepatch_status(),
        "ram": ram_percent,
        "cpu": get_cpu_percent(),
        "disk_percent": disk_percent,
        "disk_total_gb": disk_total_gb,
        "disk_used_gb": disk_used_gb,
        "disk_free_gb": disk_free_gb,
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "uptime": get_uptime(),
        "local_ip": get_local_ip(),
        "interfaces": get_network_interfaces(),
        "services": services,
        "failed_units": failed_units,
        "last_check": datetime.now().strftime("%d.%m.%Y • %H:%M"),
        "timestamp": int(time.time()),
    }
    # ============================================================
    # LIVE NETWORK STATUS
    # Diese Werte werden BEI JEDEM normalen Guardian-Check
    # neu ermittelt. Sie dürfen NICHT aus dem 30-Minuten-Slow-
    # Snapshot übernommen werden.
    # ============================================================
    snapshot["internet_online"] = internet_online()
    snapshot["telegram_online"] = telegram_api_online()
    snapshot["dns_ok"] = dns_test()
    snapshot["pings"] = build_live_ping_results(snapshot)

    # ============================================================
    # SLOW DATA
    # Diese Werte werden weiterhin aus dem Slow-Snapshot übernommen.
    # ============================================================
    slow = prev_snapshot.get("slow", {})
    snapshot["slow"] = slow
    snapshot["wan_ip"] = slow.get(
        "wan_ip",
        prev_snapshot.get("wan_ip", "unbekannt")
    )
    snapshot["docker"] = slow.get(
        "docker",
        prev_snapshot.get(
            "docker",
            {"enabled": False, "running": 0, "total": 0, "names": []}
        )
    )
    snapshot["temperatures"] = slow.get(
        "temperatures",
        prev_snapshot.get("temperatures", {})
    )
    snapshot["smart"] = slow.get("smart", prev_snapshot.get("smart", {"available": False, "devices": []}))
    snapshot["security"] = slow.get("security", prev_snapshot.get("security", {}))
    snapshot["timers"] = get_timers_map()

    snapshot["ram_level"] = level_for(snapshot["ram"], RAM_WARN, RAM_CRIT)
    snapshot["cpu_level"] = level_for(snapshot["cpu"], CPU_WARN, CPU_CRIT)
    snapshot["disk_level"] = level_for(snapshot["disk_percent"], DISK_WARN, DISK_CRIT)
    snapshot["health"] = health_score(snapshot)
    snapshot["health_color"] = color_for_health(snapshot["health"])
    return snapshot


def build_live_ping_results(snapshot):
    """
    Live-Netzwerkdiagnose für jeden normalen Guardian-Check.

    Diese Werte werden bewusst NICHT im Slow-Snapshot gecacht.
    """
    try:
        return parallel_pings()
    except Exception as e:
        logger.warning("Live-Pingprüfung fehlgeschlagen: %s", e)
        return {}


def build_ping_checks(snapshot):
    checks = []

    def add_host(host, label=None):
        host = str(host or "").strip()
        if not host:
            return
        target = label or host
        checks.append(run_ping(host, label=target))

    def add_tcp(host, port):
        host = str(host or "").strip()
        if not host:
            return
        checks.append(tcp_check(host, int(port)))

    add_host("1.1.1.1")
    add_host("8.8.8.8")
    add_host("api.telegram.org")

    router_ip = snapshot.get("router_ip") or ROUTER_IP_FALLBACK
    local_ip = snapshot.get("local_ip")
    add_host(router_ip)
    if local_ip:
        add_host(local_ip)

    for entry in EXTRA_TCP_CHECKS:
        host, _, port = entry.rpartition(":")
        if host and port.isdigit():
            add_tcp(host, int(port))
    # Lokale Guardian-Dienste dynamisch erkennen.
    # Alle aktuell auf 8780-8799 lauschenden TCP-Ports werden geprüft.
    try:
        r = run(["ss", "-lnt"], timeout=5)

        local_ports = set()

        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue

            local_address = parts[3]

            try:
                port = int(local_address.rsplit(":", 1)[1])
            except (ValueError, IndexError):
                continue

            if 8780 <= port <= 8799:
                local_ports.add(port)

        for port in sorted(local_ports):
            add_tcp("127.0.0.1", port)

    except Exception:
        pass

    seen = set()
    unique = []
    for item in checks:
        target = str(item.get("target") or item.get("host") or item.get("name") or "")
        if not target or target in seen:
            continue
        seen.add(target)
        unique.append(item)

    return unique


def build_slow_snapshot(prev_snapshot=None, force=False):
    prev_snapshot = prev_snapshot or {}
    prev_slow = prev_snapshot.get("slow", {})
    now = int(time.time())

    local_ip = get_local_ip()
    last_local_ip = prev_snapshot.get("local_ip")
    wan_cache_ok = (
        prev_slow.get("wan_ip")
        and prev_slow.get("wan_ip_checked_at")
        and (now - int(prev_slow["wan_ip_checked_at"]) < WAN_IP_TTL_SECONDS)
        and local_ip == last_local_ip
        and not force
    )

    wan_ip = prev_slow.get("wan_ip", "unbekannt") if wan_cache_ok else get_wan_ip_fresh()

    certs = {}
    for host in CERT_HOSTS:
        certs[host] = get_cert_expiry_days(host)

    return {
        "wan_ip": wan_ip,
        "wan_ip_checked_at": now,
        "internet_online": internet_online(),
        "telegram_online": telegram_api_online(),
        "dns_ok": dns_test(),
        "pings": parallel_pings(),
        "docker": get_docker_summary(),
        "temperatures": get_temperatures(),
        "smart": get_smart_summary(),
        # fehlte bisher -> Zertifikatsüberwachung war wirkungslos
        "certs": certs,
        "checked_at": now,
    }


def merge_snapshot_with_slow(snapshot, slow):
    snapshot = dict(snapshot)
    snapshot["slow"] = slow

    # ============================================================
    # NETZWERK IST LIVE-DATEN
    # Niemals aus dem Slow-Snapshot überschreiben.
    # ============================================================
    snapshot["internet_online"] = bool(
        snapshot.get("internet_online", True)
    )
    snapshot["telegram_online"] = bool(
        snapshot.get("telegram_online", True)
    )
    snapshot["dns_ok"] = bool(
        snapshot.get("dns_ok", True)
    )

    # Live-Pingdaten ebenfalls behalten.
    snapshot["pings"] = snapshot.get("pings", {})

    # ============================================================
    # SLOW DATA
    # ============================================================
    snapshot["wan_ip"] = slow.get(
        "wan_ip",
        snapshot.get("wan_ip", "unbekannt")
    )
    snapshot["docker"] = slow.get(
        "docker",
        snapshot.get(
            "docker",
            {"enabled": False, "running": 0, "total": 0, "names": []}
        )
    )
    snapshot["temperatures"] = slow.get("temperatures", snapshot.get("temperatures", {}))
    snapshot["smart"] = slow.get("smart", snapshot.get("smart", {"available": False, "devices": []}))
    snapshot["certs"] = slow.get("certs", snapshot.get("certs", {}))
    snapshot["health"] = health_score(snapshot)
    snapshot["health_color"] = color_for_health(snapshot["health"])
    return snapshot


def overall_status(snapshot):
    issues = []

    if snapshot.get("internet_online") is False:
        issues.append("internet")

    if snapshot.get("disk_percent", 0) >= DISK_CRIT:
        issues.append("disk")

    if snapshot.get("cpu", 0) >= CPU_CRIT:
        issues.append("cpu")

    if snapshot.get("security_updates", 0) > 0:
        issues.append("security_updates")

    services = snapshot.get("services", {})
    relevant_down = []

    for name in WATCH_SERVICES:
        if not name:
            continue

        info = services.get(name, {})
        active = info.get("active", "unknown") if isinstance(info, dict) else str(info or "unknown")
        enabled = info.get("enabled", "unknown") if isinstance(info, dict) else "unknown"

        if active == "inactive" or enabled in ("static", "indirect", "masked"):
            continue

        if active in ("failed", "activating", "deactivating", "reloading"):
            relevant_down.append(name)
        elif active != "active" and enabled == "enabled":
            relevant_down.append(name)

    if relevant_down:
        issues.append("services")

    if issues:
        return "🔴 Status: Kritisch"

    if snapshot.get("security_updates", 0) > 0 or snapshot.get("updates", 0) > 0 or snapshot.get("reboot_required"):
        return "🟡 Status: Wartung empfohlen"

    return "🟢 Status: Alles ok"

def format_services(snapshot):
    services = snapshot.get("services", {})
    timers = snapshot.get("timers", {}) or {}
    watched = [svc for svc in WATCH_SERVICES if svc]

    def is_custom_service(name):
        # Guardian niemals selbst in der Service-Übersicht anzeigen.
        if name in ("ubuntu-guardian.service", "snap.canonical-livepatch.canonical-livepatchd.service"):
            return False

        # Explizit überwachte eigene Dienste immer anzeigen.
        if name in watched or name == "ssh.service":
            return True

        # Eigene systemd-Units liegen typischerweise hier.
        r = run(["systemctl", "cat", name], timeout=15)
        out = r.stdout or ""

        if "/etc/systemd/system/" in out:
            return True

        # Zusätzliche Erkennung eigener Dienste anhand des Namens.
        lname = name.lower()
        keywords = SERVICE_KEYWORDS

        return any(k in lname for k in keywords)

    def classify(active, enabled, has_timer):
        if active == "active":
            return ("AKTIV", "🟢", 0)

        if active in ("activating", "reloading"):
            return ("STARTET", "🟡", 1)

        if has_timer or enabled in ("static", "indirect"):
            return ("PASSIV", "🟡", 1)

        if active == "inactive" and enabled == "disabled":
            return ("AUS", "🟡", 1)

        if active == "inactive" and enabled == "enabled":
            return ("OFFLINE", "🔴", 2)

        if active in ("failed", "deactivating"):
            return ("FEHLER", "🔴", 2)

        return (str(active).upper()[:8], "🔴", 2)

    def timer_hint(service_name):
        # get_timers_map() ist nach Service-Name indiziert:
        #   "backup.service" -> {"timer": "backup.timer", ...}
        t = timers.get(service_name, {}) or {}

        nxt = t.get("next")
        left = t.get("left")
        last = t.get("last")

        if nxt:
            txt = str(nxt).replace(" +", " ").strip()

            # Zeit aus systemd-Ausgabe extrahieren.
            m = re.search(r"(\d{2}:\d{2})(?::\d{2})?", txt)
            if m:
                return m.group(1)

            # Falls keine Uhrzeit vorhanden ist, Datum/Angabe kurz anzeigen.
            if txt not in ("", "n/a", "NA", "unknown"):
                return txt[:20]

        if left:
            txt = str(left).strip()
            if txt not in ("", "n/a", "NA", "unknown"):
                return f"in {txt}"

        if last:
            txt = str(last).replace(" +", " ").strip()
            m = re.search(r"(\d{2}:\d{2})(?::\d{2})?", txt)
            if m:
                return f"zuletzt {m.group(1)}"

        return "geplant"

    rows = []

    for name in services.keys():
        if not name.endswith(".service"):
            continue

        # Nur relevante eigene/custom Services anzeigen.
        if not is_custom_service(name):
            continue

        info = services.get(name, {})
        active = info.get("active", "unknown") if isinstance(info, dict) else "unknown"
        enabled = info.get("enabled", "unknown") if isinstance(info, dict) else "unknown"

        # Timer-Zuordnung erfolgt über den Service-Namen.
        has_timer = name in timers

        state, icon, group = classify(active, enabled, has_timer)

        detail = timer_hint(name) if state == "PASSIV" else ""

        short = name.replace(".service", "")
        rows.append((group, short.lower(), icon, short, state, detail))

    rows.sort(key=lambda x: (x[0], x[1]))

    active_rows = [r for r in rows if r[4] == "AKTIV"]
    passive_rows = [r for r in rows if r[4] in ("PASSIV", "STARTET", "AUS")]
    critical_rows = [r for r in rows if r[4] in ("OFFLINE", "FEHLER")]

    lines = [
        f"Aktiv:{len(active_rows)} Passiv:{len(passive_rows)} Krit:{len(critical_rows)}",
        "",
    ]

    def append_group(title, items):
        if not items:
            return

        lines.append(title)

        for _, _, icon, short, state, detail in items:
            if title == "PASSIV":
                label = (icon + " " + short)[:26]
                lines.append(f"{label:<26} {detail}")
            else:
                lines.append(f"{icon} {short}")

        lines.append("")

    if not rows:
        lines.append("Keine relevanten Dienste gefunden")
    else:
        append_group("AKTIV", active_rows)
        append_group("PASSIV", passive_rows)
        append_group("KRITISCH", critical_rows)

        while lines and lines[-1] == "":
            lines.pop()

    return "🛠 Services\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(lines)) + "</pre>"

def format_security(snapshot):
    sec = snapshot.get("security") or {}

    failed_ssh = sec.get("failed_ssh") or []
    sudo_events = sec.get("sudo_events") or []
    recent_logins = sec.get("recent_logins") or []
    failed_logins = sec.get("failed_logins") or []
    lastlog_lines = sec.get("lastlog") or []

    lines = [
        f"SSH:{len(failed_ssh)}  Sudo:{len(sudo_events)}  Fail:{len(failed_logins)}",
        "",
    ]

    def block(title, items, empty_text, limit=4):
        lines.append(title)
        if items:
            lines.extend(f" • {x}" for x in items[:limit])
        else:
            lines.append(f" • {empty_text}")
        lines.append("")

    block("SSH-Fehler 24h", failed_ssh, "Keine auffälligen SSH-Fehler")
    block("Sudo 24h", sudo_events, "Keine sudo-Aktivität")
    block("Erfolgreiche Logins", recent_logins, "Keine Login-Historie")
    block("Fehlversuche", failed_logins, "Keine fehlgeschlagenen Logins")
    block("Lastlog 30 Tage", lastlog_lines, "Keine Lastlog-Daten")

    while lines and lines[-1] == "":
        lines.pop()

    table = ["BEREICH                WERT"]
    for line in lines:
        text = line.strip()
        if not text:
            continue

        if ":" in text:
            label, value = text.split(":", 1)
            table.append(f"{label[:22]:<22} {value.strip()}")
        else:
            table.append(f"Security               {text[:48]}")

    return "🔐 Security\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(table)) + "</pre>"

def format_docker(snapshot):
    d = snapshot.get("docker", {"enabled": False, "running": 0, "total": 0, "names": []})
    if not d["enabled"]:
        return "Docker-Monitoring deaktiviert oder Docker nicht installiert"
    names = ", ".join(d["names"]) if d["names"] else "-"
    return f"🐳 Docker\n────────────────────────────────\n\nLaufend: {d['running']}/{d['total']}\nContainer: {names}"


def format_logs(limit=20):
    if not LOG_FILE.exists():
        return "📜 Logs\n\n<pre>Keine Logs vorhanden</pre>"
    try:
        limit = max(1, min(int(limit), 300))
    except Exception:
        limit = 20

    lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
    skip_tokens = [
        # Erfolgreiche Telegram-API-Aufrufe
        "Telegram getUpdates status=200",
        "Telegram editMessageText status=200 payload=",
        "Telegram sendMessage status=200 payload=",
        "Telegram answerCallbackQuery status=200 payload=",
        "Telegram deleteMessage status=200 payload=",
        "payload={'ok': True, 'result': {'message_id':",

        # Erwartete Meldungen beim Bedienen des Telegram-Menüs
        "Telegram edit übersprungen: message is not modified",
    ]

    filtered = []
    for line in lines:
        if any(tok in line for tok in skip_tokens):
            continue

        # Telegram meldet HTTP 400, wenn Nachricht und Menü unverändert sind.
        if (
            "Telegram editMessageText status=400" in line
            and "message is not modified" in line
        ):
            continue

        filtered.append(line)

    tail = filtered[-limit:]
    body = [f"LOGS ({len(tail)}/{limit})", ""]

    if tail:
        body.extend(tail)
    else:
        body.append("Keine relevanten Logzeilen")

    text = "\n".join(body)
    if len(text) > 3900:
        text = text[-3900:]

    return "📜 Logs\n────────────────────────────────\n\n<pre>" + html_escape(text) + "</pre>"

def format_help():
    body = (
        "Nutze die Buttons für Home, Status, Host, Netzwerk, Updates und Diagnose.\n\n"
        "Fallback\n"
        "/menu /status /updates /services\n"
        "/disk /network /logs /logs 100 /help"
    )
    return "📘 Hilfe\n────────────────────────────────\n\n<pre>" + html_escape(body) + "</pre>"



def format_failed_services(snapshot):
    r = run(["systemctl", "--failed", "--no-legend", "--plain"], timeout=20)
    lines = [line.strip() for line in (r.stdout or "").splitlines() if line.strip()]
    if not lines:
        return "🔄 Dienste\n\nKeine fehlgeschlagenen Dienste."
    out = ["🔄 Dienste\n", "Fehlgeschlagene Units:\n"]
    for line in lines[:20]:
        parts = line.split()
        unit = parts[0] if len(parts) > 0 else "?"
        load = parts[1] if len(parts) > 1 else "?"
        active = parts[2] if len(parts) > 2 else "?"
        sub = parts[3] if len(parts) > 3 else "?"
        out.append(f"❌ {unit}: {load}/{active}/{sub}")
    return "\n".join(out)

def bot_service_summary(snapshot):
    services = snapshot.get("services", {})
    names = [svc for svc in WATCH_SERVICES if svc]

    names = sorted(set(names))
    total = len(names)
    active = 0

    for name in names:
        info = services.get(name, {})

        if isinstance(info, dict):
            if info.get("active") == "active":
                active += 1
        else:
            if str(info or "") == "active":
                active += 1

    return active, total

def format_critical(snapshot):
    issues = []

    services = snapshot.get("services", {})
    recovery = []

    for name in WATCH_SERVICES:
        if not name:
            continue

        info = services.get(name, {})
        active = info.get("active", "unknown") if isinstance(info, dict) else str(info or "unknown")

        if active != "active":
            issues.append(f"{name}: {active}")

            if active == "inactive":
                recovery.append(f"Aktion: restart {name}")
            else:
                recovery.append(f"Prüfen: status {name}")

    if snapshot.get("internet_online") is False:
        issues.append("Netzwerk: Offline")

    if snapshot.get("disk_percent", 0) >= DISK_CRIT:
        issues.append(f"Speicher: {snapshot.get('disk_percent')} %")

    if snapshot.get("cpu", 0) >= CPU_CRIT:
        issues.append(f"CPU: {snapshot.get('cpu')} %")

    if snapshot.get("security_updates", 0) > 0:
        issues.append(f"Security Updates: {snapshot.get('security_updates')}")

    if not issues:
        return "🩺 Diagnose\n────────────────────────────────\n\n<pre>Keine kritischen Probleme.</pre>"

    lines = [
        f"Kritische Punkte: {len(issues)}",
        "",
        "AKTUELL",
    ]

    for item in issues[:6]:
        lines.append(f"• {item}")

    if recovery:
        restart_units = []
        check_units = []

        for item in recovery:
            if item.startswith("Aktion: restart "):
                restart_units.append(item.replace("Aktion: restart ", "", 1))
            elif item.startswith("Prüfen: status "):
                check_units.append(item.replace("Prüfen: status ", "", 1))

        if restart_units:
            lines.append("• Aktion: restart " + ", ".join(restart_units[:4]))
        if check_units:
            lines.append("• Prüfen: status " + ", ".join(check_units[:3]))

    if len(issues) > 6:
        lines.append(f"• … und {len(issues) - 6} weitere")

    return "🩺 Diagnose\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(lines)) + "</pre>"

def format_certs(snapshot):
    pass

def _pretty_kv_block(data, empty_text="Keine Daten"):
    if not data:
        return empty_text
    if isinstance(data, str):
        return data
    if isinstance(data, list):
        lines = []
        for item in data:
            if isinstance(item, dict):
                name = item.get("name") or item.get("device") or item.get("host") or "Eintrag"
                parts = []
                for k, v in item.items():
                    if k in ("name", "device", "host"):
                        continue
                    parts.append(f"{k}: {v}")
                lines.append(f"{name} — " + (", ".join(parts) if parts else "OK"))
            else:
                lines.append(str(item))
        return "\n".join(lines) if lines else empty_text
    if isinstance(data, dict):
        return "\n".join(f"{k}: {v}" for k, v in data.items()) or empty_text
    return str(data)


def format_smart(snapshot):
    smart = snapshot.get("smart", {}) or {}

    if not smart:
        return "💿 SMART\n────────────────────────────────\n\n<pre>Keine SMART-Daten</pre>"

    devices = smart.get("devices", []) if isinstance(smart, dict) else []
    available = smart.get("available", False) if isinstance(smart, dict) else False

    lines = [
        "SMART                STATUS",
        f"{'Verfügbar':<20} {('Ja' if available else 'Nein'):<10}",
    ]

    if devices:
        lines.append(f"{'Geräte':<20} {len(devices):<10}")
        lines.append("")
        lines.append(f"{'Device':<12} {'Health':<12} {'Temp':<8} {'Info':<10}")
        for dev in devices[:10]:
            device = str(dev.get("device", "?"))[:12]
            health = str(dev.get("health", dev.get("status", "unbekannt")))[:12]
            temp = dev.get("temp", dev.get("temperature", "n/a"))
            temp_text = str(temp)[:8]
            info = []
            if dev.get("model"):
                info.append(str(dev.get("model"))[:10])
            elif dev.get("serial"):
                info.append(str(dev.get("serial"))[:10])
            lines.append(f"{device:<12} {health:<12} {temp_text:<8} {(' '.join(info))[:10]:<10}")
    else:
        lines.append(f"{'Geräte':<20} 0")
        lines.append("")
        lines.append("Keine SMART-Geräte gefunden")

    return "💿 SMART\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(lines)) + "</pre>"

def format_temps(snapshot):
    temps = snapshot.get("temperatures") or snapshot.get("thermal") or snapshot.get("temp") or {}
    temp_text = "n/a"
    if isinstance(temps, dict) and temps:
        first_val = next(iter(temps.values()))
        if isinstance(first_val, dict):
            cur = first_val.get("current", first_val.get("temp", first_val.get("value", "n/a")))
            temp_text = f"{cur} °C"
        else:
            temp_text = f"{first_val} °C"

    smart = snapshot.get("smart", {}) or {}
    smart_lines = []
    if smart.get("available") and smart.get("devices"):
        for dev in smart.get("devices", [])[:6]:
            device = dev.get("device", "?")
            health = dev.get("health", "unbekannt")
            smart_lines.append(f"• {device}: {health}")
    else:
        smart_lines.append("Kein SMART oder nicht verfügbar")

    zfs_text = "Kein ZFS oder nicht verfügbar"

    table = [
        "HOST",
        "----------------------",
        f"Hostname   : {snapshot.get('hostname', 'unbekannt')}",
        f"Kernel     : {snapshot.get('kernel', 'unbekannt')}",
        f"CPU Modell : {snapshot.get('cpu_model', 'unbekannt')}",
        f"CPU Kerne  : {snapshot.get('cpu_cores', 'unbekannt')}",
        f"Reboot     : {'Ja' if snapshot.get('reboot_required') else 'Nein'}",
        f"CPU        : {snapshot.get('cpu', 'n/a')} %",
        f"RAM        : {snapshot.get('ram', 'n/a')} %",
        f"RootFS     : {snapshot.get('disk_percent', 'n/a')} % ({snapshot.get('disk_used_gb', 'n/a')}G/{snapshot.get('disk_total_gb', 'n/a')}G)",
        f"Load       : {snapshot.get('load1', 'n/a')} / {snapshot.get('load5', 'n/a')} / {snapshot.get('load15', 'n/a')}",
        f"Temp       : {temp_text}",
        f"Uptime     : {snapshot.get('uptime', 'unbekannt')}",
        "",
        "SMART",
        *smart_lines,
        "",
        "ZFS",
        zfs_text,
        "",
        f"Check      : {snapshot.get('last_check', 'unbekannt')}",
    ]

    return "🖥 Host\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(table)) + "</pre>"

def format_network(snapshot):
    local_ip = snapshot.get("local_ip") or snapshot.get("ip") or "unbekannt"
    public_ip = snapshot.get("public_ip") or snapshot.get("wan_ip") or "unbekannt"
    router_ip = snapshot.get("router_ip") or "unbekannt"
    dns_ok = snapshot.get("dns_ok")
    internet_online = snapshot.get("internet_online")
    telegram_online = snapshot.get("telegram_online")

    interfaces = snapshot.get("interfaces") or {}
    if isinstance(interfaces, dict):
        iface_items = list(interfaces.items())
    elif isinstance(interfaces, list):
        iface_items = []
        for item in interfaces:
            if isinstance(item, dict):
                name = item.get("name") or item.get("iface") or item.get("interface") or "?"
                iface_items.append((name, item))
    else:
        iface_items = []

    ok_bits = []
    ok_bits.append("Internet: Ja" if internet_online else "Internet: Nein")
    ok_bits.append("DNS: Ja" if dns_ok else "DNS: Nein")
    ok_bits.append("Telegram: Ja" if telegram_online else "Telegram: Nein")

    lines = [
        "NETZWERK",
        "",
        "LAGE",
        " • " + " | ".join(ok_bits),
        "",
        "HOST",
        f" • LAN: {local_ip}",
        f" • WAN: {public_ip}",
        f" • Router: {router_ip}",
    ]

    if iface_items:
        lines.extend(["", "INTERFACES"])
        for name, info in iface_items[:8]:
            if isinstance(info, dict):
                addr = info.get("ip") or info.get("addr") or info.get("address") or info.get("ipv4") or "-"
                state = info.get("state") or info.get("status") or info.get("operstate") or "-"
                mac = info.get("mac") or info.get("ether") or ""
                row = f" • {name}: {addr}"
                if state and state != "-":
                    row += f" ({state})"
                if mac:
                    row += f" [{mac}]"
                lines.append(row)
            else:
                lines.append(f" • {name}: {info}")

    return "🌐 Netzwerk\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(lines)) + "</pre>"

def format_home(snapshot):
    bots_active, bots_total = bot_service_summary(snapshot)

    table = [
        "STATUS                 WERT",
        f"{snapshot.get('health_color', '🟢')} Status              {overall_status(snapshot).replace('🟢 ', '').replace('🟡 ', '').replace('🔴 ', '')}",
        f"💚 Health              {snapshot['health']} %",
        f"🤖 Bots                {bots_active}/{bots_total} aktiv",
        f"📦 Updates             {snapshot['updates']}",
        f"🔒 Security            {snapshot['security_updates']}",
        f"🌐 Netzwerk            {'Online' if snapshot.get('internet_online', False) else 'Offline'}",
        f"💾 Speicher            {snapshot['disk_percent']} %",
        f"🖥 CPU                 {snapshot['cpu']} %",
        f"📦 APT                 {snapshot.get('apt_auto', 'Unbekannt')}",
        f"🖧 Host                {snapshot.get('host', snapshot.get('hostname', '-'))}",
        "",
        f"Snapshot              {snapshot.get('last_check', 'unbekannt')}",
    ]

    return "🤖 Ubuntu Guardian\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(table)) + "</pre>"


def format_status(snapshot):
    table = [
        "BEREICH                WERT",
        f"Health                 {snapshot['health']} %",
        f"Updates                {snapshot['updates']}",
        f"Security               {snapshot['security_updates']}",
        f"Reboot                 {'Ja' if snapshot['reboot_required'] else 'Nein'}",
        f"Host                   {snapshot['hostname']}",
        f"Kernel                 {snapshot['kernel']}",
        f"Livepatch              {snapshot['livepatch']}",
        f"Uptime                 {snapshot['uptime']}",
        f"RAM                    {snapshot['ram']} % ({snapshot['ram_level']})",
        f"CPU                    {snapshot['cpu']} % ({snapshot['cpu_level']})",
        f"Load Avg               {snapshot['load1']} / {snapshot['load5']} / {snapshot['load15']}",
        f"Speicher               {snapshot['disk_percent']} % ({snapshot['disk_level']})",
        f"RootFS                 {snapshot['disk_used_gb']}G / {snapshot['disk_free_gb']}G frei",
        f"Internet               {'Online' if snapshot.get('internet_online', False) else 'Offline'}",
        f"Telegram               {'Erreichbar' if snapshot.get('telegram_online', False) else 'Nicht erreichbar'}",
        f"DNS                    {'OK' if snapshot.get('dns_ok', False) else 'Fehler'}",
        f"LAN-IP                 {snapshot['local_ip']}",
        f"WAN-IP                 {snapshot.get('wan_ip', 'unbekannt')}",
    ]

    return (
        f"🤖 {snapshot['host']}\n"
        "────────────────────────────────\n\n"
        "<pre>" + html_escape("\n".join(table)) + "</pre>"
    )


def format_apt(snapshot):
    import subprocess

    def run(cmd):
        try:
            out = subprocess.check_output(
                cmd,
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=4
            )
            return out.strip()
        except Exception:
            return ""

    def tail_lines(path, n=5):
        txt = run(f"tail -n {n} {path} 2>/dev/null")
        return [line for line in txt.splitlines() if line.strip()]

    apt_daily = run("systemctl is-enabled apt-daily.timer")
    apt_upgrade = run("systemctl is-enabled apt-daily-upgrade.timer")

    auto_cfg = run(
        "grep -hE 'APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)' "
        "/etc/apt/apt.conf.d/20auto-upgrades "
        "/etc/apt/apt.conf.d/* 2>/dev/null | tail -n 2"
    )

    hist_lines = tail_lines("/var/log/apt/history.log", 6)
    ulog_lines = tail_lines(
        "/var/log/unattended-upgrades/unattended-upgrades.log",
        6
    )

    auto_state = (
        "Aktiv"
        if (
            ('enabled' in apt_daily or 'static' in apt_daily or 'generated' in apt_daily)
            and
            ('enabled' in apt_upgrade or 'static' in apt_upgrade or 'generated' in apt_upgrade)
        )
        else "Teilweise/Aus"
    )

    table = [
        "BEREICH                WERT",
        f"Auto-Updates           {auto_state}",
        f"Verfügbare Updates     {snapshot.get('updates', 0)}",
        f"Security Updates       {snapshot.get('security_updates', 0)}",
        f"apt-daily.timer        {apt_daily or 'unbekannt'}",
        f"apt-daily-upgrade      {apt_upgrade or 'unbekannt'}",
    ]

    if auto_cfg:
        for line in auto_cfg.splitlines():
            table.append(f"Konfiguration          {line}")

    if hist_lines:
        table.append("")
        table.append("APT-HISTORY")
        for line in hist_lines:
            table.append(f"History                {line}")

    if ulog_lines:
        table.append("")
        table.append("UNATTENDED")
        for line in ulog_lines:
            table.append(f"Upgrade                {line}")

    return (
        "📦 APT\n"
        "────────────────────────────────\n\n"
        "<pre>" + html_escape("\n".join(table)) + "</pre>"
    )

def build_menu(view="home", snapshot=None):
    if view == "updates" and snapshot:
        available = int(snapshot.get("updates", 0) or 0)
        if available > 0:
            # Installationsbutton oben vor das normale Menü setzen.
            return {
                "inline_keyboard": [
                    [
                        {
                            "text": "📦 Updates installieren",
                            "callback_data": "updates:install",
                        }
                    ],
                    *[
                        [
                            {"text": "🏠 Start", "callback_data": "home"},
                            {"text": "📊 Status", "callback_data": "status"},
                            {"text": "🖥 Host", "callback_data": "temps"},
                        ],
                        [
                            {"text": "🛠 Services", "callback_data": "services"},
                            {"text": "💾 Disk", "callback_data": "disk"},
                            {"text": "🌐 Netz", "callback_data": "network"},
                        ],
                        [
                            {"text": "📦 Updates", "callback_data": "updates"},
                            {"text": "⚙️ Auto", "callback_data": "apt"},
                            {"text": "🔐 Security", "callback_data": "security"},
                        ],
                        [
                            {"text": "💿 SMART", "callback_data": "smart"},
                            {"text": "📜 Logs", "callback_data": "logs"},
                            {"text": "🩺 Kritisch", "callback_data": "critical"},
                        ],
                        [
                            {"text": "📜 Hilfe", "callback_data": "help"},
                            {"text": "🔄 Refresh", "callback_data": f"refresh:{view}"},
                            {"text": "🏓 Ping", "callback_data": "ping"},
                        ],
                    ]
                ]
            }

    return {
        "inline_keyboard": [
            [
                {"text": "🏠 Start", "callback_data": "home"},
                {"text": "📊 Status", "callback_data": "status"},
                {"text": "🖥 Host", "callback_data": "temps"},
            ],
            [
                {"text": "🛠 Services", "callback_data": "services"},
                {"text": "💾 Disk", "callback_data": "disk"},
                {"text": "🌐 Netz", "callback_data": "network"},
            ],
            [
                {"text": "📦 Updates", "callback_data": "updates"},
                {"text": "⚙️ Auto", "callback_data": "apt"},
                {"text": "🔐 Security", "callback_data": "security"},
            ],
            [
                {"text": "💿 SMART", "callback_data": "smart"},
                {"text": "📜 Logs", "callback_data": "logs"},
                {"text": "🩺 Kritisch", "callback_data": "critical"},
            ],
            [
                {"text": "📜 Hilfe", "callback_data": "help"},
                {"text": "🔄 Refresh", "callback_data": f"refresh:{view}"},
                {"text": "🏓 Ping", "callback_data": "ping"},
            ],
        ]
    }



def snapshot_time_text(snapshot):
    value = snapshot.get("last_check", "unbekannt")
    return str(value or "unbekannt")

def append_snapshot_time(text, snapshot):
    ts = snapshot_time_text(snapshot)
    if "</pre>" in text:
        return text.replace("</pre>", f"\n\nSnapshot: {html_escape(ts)}</pre>", 1)
    return text + f"\n\nSnapshot: {ts}"


def format_ping(snapshot):
    checks = snapshot.get("ping_checks") or snapshot.get("ping") or []
    last_check = snapshot.get("last_check", "n/a")

    if not checks:
        body = [
            "Ziel                 Status   Latenz",
            "Keine Daten          -        -",
            "",
            f"Snapshot: {last_check}",
        ]
        return "🏓 Ping\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(body)) + "</pre>"

    def status_text(item):
        if not item.get("ok"):
            return "DOWN"
        latency = item.get("latency_ms")
        try:
            ms = int(round(float(latency)))
        except Exception:
            return "OK"
        if ms < 80:
            return "SEHR GUT"
        if ms < 200:
            return "GUT"
        if ms < 800:
            return "LANGSAM"
        return "KRITISCH"

    def latency_text(item):
        latency = item.get("latency_ms")
        if latency is None:
            return "n/a"
        try:
            return f"{int(round(float(latency)))} ms"
        except Exception:
            return str(latency)[:10]

    lines = [
        "Ziel                 Status   Latenz",
    ]

    for item in checks[:20]:
        host = str(
            item.get("target")
            or item.get("host")
            or item.get("name")
            or item.get("label")
            or item.get("ip")
            or "?"
        )[:20]
        lines.append(f"{host:<20} {status_text(item):<8} {latency_text(item):<10}")

    lines.append("")
    lines.append(f"Snapshot: {last_check}")

    return "🏓 Ping\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(lines)) + "</pre>"

def render_view(name, snapshot=None, arg=None):
    snapshot = snapshot or get_current_snapshot() or build_fast_snapshot({})
    if name == "home":
        return format_home(snapshot)
    if name == "status":
        return format_status(snapshot)
    if name == "updates":
        available = int(snapshot.get("updates", 0) or 0)
        security = int(snapshot.get("security_updates", 0) or 0)

        table = [
            "BEREICH                WERT",
            f"Pakete                 {available}",
            f"Security               {security}",
            f"Livepatch              {snapshot.get('livepatch', 'Unbekannt')}",
            f"Reboot nötig           {'Ja' if snapshot.get('reboot_required') else 'Nein'}",
        ]

        return "📦 Updates\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(table)) + "</pre>"
    if name == "services":
        return format_services(snapshot)
    if name == "disk":
        lines = [
            "SPEICHER             WERTE",
            f"{'Belegt':<10} {str(snapshot.get('disk_percent', 'n/a')) + ' %':<18}",
            f"{'Status':<10} {str(snapshot.get('disk_level', 'Unbekannt'))[:18]:<18}",
            f"{'Gesamt':<10} {str(snapshot.get('disk_total_gb', 'n/a')) + ' GB':<18}",
            f"{'Used':<10} {str(snapshot.get('disk_used_gb', 'n/a')) + ' GB':<18}",
            f"{'Frei':<10} {str(snapshot.get('disk_free_gb', 'n/a')) + ' GB':<18}",
        ]
        return "💽 Speicher\n────────────────────────────────\n\n<pre>" + html_escape("\n".join(lines)) + "</pre>"
    if name == "network":
        return format_network(snapshot)
    if name == "ping":
        # Ping immer live ausführen, nicht aus dem letzten Snapshot lesen.
        try:
            live_checks = build_ping_checks(snapshot)
            live_snapshot = dict(snapshot)
            live_snapshot["ping"] = live_checks
            live_snapshot["ping_checks"] = live_checks
            live_snapshot["last_check"] = time.strftime("%Y-%m-%d %H:%M:%S")
            return format_ping(live_snapshot)
        except Exception as e:
            logger.exception("Live-Ping fehlgeschlagen: %s", e)
            return format_ping(snapshot)
    if name == "temps":
        return append_snapshot_time(format_temps(snapshot), snapshot)
    if name == "smart":
        return append_snapshot_time(format_smart(snapshot), snapshot)
    if name == "apt":
        return append_snapshot_time(format_apt(snapshot), snapshot)
    if name == "logs":
        return format_logs(arg or 20)
    if name == "security":
        return append_snapshot_time(format_security(snapshot), snapshot)
    if name == "critical":
        return append_snapshot_time(format_critical(snapshot), snapshot)
    if name == "help":
        return append_snapshot_time(format_help(), snapshot)
    return format_home(snapshot)


def delete_message_safe(chat_id, message_id):
    try:
        delete_telegram_message(chat_id, message_id)
    except Exception:
        pass


def get_menu_for_chat(chat_id):
    """Menü-Nachricht je Chat (vorher eine globale -> Account A und B
    haben sich gegenseitig das Menü 'weggenommen')."""
    menus = state_get("menu_messages", {}) or {}
    entry = menus.get(str(chat_id))
    if entry:
        return {"chat_id": str(chat_id), "message_id": entry.get("message_id")}
    legacy = state_get("menu_message", {}) or {}
    if str(legacy.get("chat_id", "")) == str(chat_id):
        return legacy
    return {}


def set_menu_for_chat(chat_id, message_id, view):
    def mut(s):
        s.setdefault("menu_messages", {})[str(chat_id)] = {"message_id": message_id, "view": view}
        s["menu_view"] = view
    state_update(mut)


def notify_other_admins(origin_chat_id, text):
    """Kritische Aktionen (Updates, Neustart) auch den anderen Accounts melden."""
    for cid in CHAT_IDS:
        if str(cid) != str(origin_chat_id):
            _send_one(cid, text, parse_mode="HTML")


def actor_name(user):
    user = user or {}
    return html_escape(str(user.get("first_name") or user.get("username") or user.get("id") or "unbekannt")[:40])


def upsert_menu_message(chat_id, text, view="home"):
    menu = get_menu_for_chat(chat_id)
    snapshot = get_current_snapshot() or {}
    reply_markup = build_menu(view=view, snapshot=snapshot)

    if str(menu.get("chat_id", "")) == str(chat_id) and menu.get("message_id"):
        edited = edit_telegram_message(chat_id, menu["message_id"], text, reply_markup=reply_markup, parse_mode="HTML")

        if edited.get("ok"):
            set_menu_for_chat(chat_id, menu["message_id"], view)
            return menu["message_id"]

        desc = (edited.get("description") or "").lower()
        if "message is not modified" in desc:
            logger.info("Telegram edit übersprungen: message is not modified")
            set_menu_for_chat(chat_id, menu["message_id"], view)
            return menu["message_id"]

    sent = tg_api(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": json.dumps(reply_markup, ensure_ascii=False),
        },
    )
    if sent.get("ok"):
        message_id = sent["result"]["message_id"]
        set_menu_for_chat(chat_id, message_id, view)
        return message_id
    return None


def history_push(metric, value, keep=12):
    def mut(s):
        hist = s.setdefault("metric_history", {})
        arr = hist.setdefault(metric, [])
        arr.append({"ts": int(time.time()), "value": value})
        if len(arr) > keep:
            del arr[:-keep]
    state_update(mut)

def history_get(metric):
    with STATE_LOCK:
        return list((STATE.get("metric_history", {}) or {}).get(metric, []))

def sustained_above(metric, threshold, needed=3):
    vals = [x.get("value", 0) for x in history_get(metric)]
    if len(vals) < needed:
        return False
    return all(isinstance(v, (int, float)) and v >= threshold for v in vals[-needed:])

def sustained_below(metric, threshold, needed=3):
    vals = [x.get("value", 0) for x in history_get(metric)]
    if len(vals) < needed:
        return False
    return all(isinstance(v, (int, float)) and v < threshold for v in vals[-needed:])



def record_service_change(name, status, keep=12):
    now = int(time.time())
    def mut(s):
        svc_hist = s.setdefault("service_history", {})
        arr = svc_hist.setdefault(name, [])
        arr.append({"ts": now, "status": status})
        if len(arr) > keep:
            del arr[:-keep]
    state_update(mut)

def service_active_value(status):
    if isinstance(status, dict):
        return str(status.get("active", "unknown"))
    return str(status or "unknown")



def recent_service_flaps(name, seconds=1800):
    now = int(time.time())
    state = load_state_from_disk()
    arr = state.get("service_history", {}).get(name, [])
    arr = [x for x in arr if now - int(x.get("ts", 0)) <= seconds]
    if len(arr) < 4:
        return 0
    changes = 0
    prev = None
    for item in arr:
        cur = item.get("status")
        if prev is not None and cur != prev:
            changes += 1
        prev = cur
    return changes

ALERT_COOLDOWNS = {
    "service_down": 1800,
    "service_flap": 3600,
}

_last_alert_sent = {}

_last_diag_sent = {}


def should_send_alert(kind, name):
    now = time.time()
    key = (kind, name)
    cooldown = ALERT_COOLDOWNS.get(kind, 1800)
    last = _last_alert_sent.get(key, 0)
    if now - last < cooldown:
        return False
    _last_alert_sent[key] = now
    return True


DIAGNOSTIC_HINTS = {
    "NameError": {
        "title": "NameError",
        "cause": "Eine Funktion oder Variable ist nicht definiert.",
        "path": "guardian.py",
        "command": 'grep -n "def should_send_alert\\|should_send_alert(" guardian.py',
        "next": "Definition von should_send_alert oberhalb von compare_and_alert ergänzen.",
    },
    "KeyError": {
        "title": "KeyError",
        "cause": "Ein Dictionary-Schlüssel fehlt.",
        "path": "guardian.py / Konfiguration / Snapshot-Daten",
        "command": 'grep -n "get(\\\".*\\\")\\|\\[.*\\]" guardian.py',
        "next": "Statt direktem Zugriff .get(...) verwenden oder den Schlüssel sicher setzen.",
    },
    "AttributeError": {
        "title": "AttributeError",
        "cause": "Ein Objekt hat das verwendete Attribut oder die Methode nicht.",
        "path": "guardian.py",
        "command": "grep -n '\\.' guardian.py | tail -n 40",
        "next": "Objekttyp und Attributnamen prüfen, ggf. isinstance(...) absichern.",
    },
    "FileNotFoundError": {
        "title": "FileNotFoundError",
        "cause": "Eine Datei oder ein Pfad existiert nicht oder wurde falsch angegeben.",
        "path": ".env / Konfigurationsdatei / betroffener Dateipfad",
        "command": "pwd && ls -la && find . -maxdepth 2 -type f | sort",
        "next": "Pfad prüfen und ggf. Konfigurationswert korrigieren.",
    },
    "PermissionError": {
        "title": "PermissionError",
        "cause": "Dem Bot fehlt die Berechtigung für Datei oder Dienst.",
        "path": "Betroffene Datei, systemd-Service oder Verzeichnis",
        "command": "ls -l <pfad> && sudo systemctl status <dienst> -l --no-pager",
        "next": "Rechte oder Service-User prüfen.",
    },
    "TimeoutError": {
        "title": "TimeoutError",
        "cause": "Ein Netzwerk- oder API-Aufruf hat zu lange gedauert.",
        "path": "Telegram/API-Aufruf oder externer Request",
        "command": "journalctl -u ubuntu-guardian.service -n 80 --no-pager",
        "next": "Timeout-Werte prüfen und einmalig retryen.",
    },
    "telegram": {
        "title": "Telegram/HTTP",
        "cause": "Der Bot konnte Telegram oder einen HTTP-Endpunkt nicht rechtzeitig erreichen.",
        "path": "send_telegram(...) / Requests",
        "command": "journalctl -u ubuntu-guardian.service -n 80 --no-pager",
        "next": "Netzwerk, Token und Timeout prüfen.",
    },
    "systemctl": {
        "title": "systemctl",
        "cause": "Ein Systemdienst ist fehlgeschlagen oder flapped.",
        "path": "/etc/systemd/system/<dienst>.service",
        "command": "systemctl status <dienst> -l --no-pager && journalctl -u <dienst> -n 80 --no-pager",
        "next": "Dienststatus und Logs prüfen.",
    },
}

def diagnose_hint(exc_text):
    text = str(exc_text or "")
    low = text.lower()

    if "NameError" in text and "should_send_alert" in text:
        h = DIAGNOSTIC_HINTS["NameError"]
    elif "KeyError" in text:
        h = DIAGNOSTIC_HINTS["KeyError"]
    elif "AttributeError" in text:
        h = DIAGNOSTIC_HINTS["AttributeError"]
    elif "TimeoutError" in text:
        h = DIAGNOSTIC_HINTS["TimeoutError"]
    elif "telegram" in low or "http" in low or "request timeout" in low:
        h = DIAGNOSTIC_HINTS["telegram"]
    elif "PermissionError" in text or "permission denied" in low:
        h = DIAGNOSTIC_HINTS["PermissionError"]
    elif "FileNotFoundError" in text or "No such file" in text:
        h = DIAGNOSTIC_HINTS["FileNotFoundError"]
    elif "systemctl" in low:
        h = DIAGNOSTIC_HINTS["systemctl"]
    else:
        return (
            "🛠 Diagnose\n\n"
            f"Problem: {type(exc_text).__name__ if not isinstance(exc_text, str) else (text.split(':', 1)[0] if ':' in text else 'Unbekannter Fehler')}\n"
            f"Ursache: {text.split(':', 1)[1].strip() if isinstance(exc_text, str) and ':' in text else 'Bitte Logausgabe prüfen'}\n"
            "Pfad: guardian.py\n"
            "Befehl: journalctl -u ubuntu-guardian.service -n 80 --no-pager"
        )

    return (
        f"🛠 Diagnose\n\n"
        f"Problem: {h['title']}\n"
        f"Ursache: {h['cause']}\n"
        f"Pfad: {h['path']}\n"
        f"Befehl: {h['command']}\n"
        f"Nächster Schritt: {h['next']}"
    )


LEVEL_REMINDER_SECONDS = int(os.getenv("ALERT_REMINDER_SECONDS", str(6 * 3600)))


def _fmt_duration(seconds):
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours} Std. {minutes} Min."
    if minutes:
        return f"{minutes} Min. {secs} Sek."
    return f"{secs} Sek."


def level_transition(down_states, key, level, now):
    """Zustandsautomat für Schwellwert-Alarme.

    level: 0 = normal, 1 = Warnung, 2 = kritisch
    Rückgabe: "alert" (neu/eskaliert), "reminder", "recovery" oder None.
    """
    state_key = f"lvl_{key}"
    entry = down_states.get(state_key) or {}
    prev = int(entry.get("level", 0) or 0)

    if level <= 0:
        if prev > 0:
            down_states.pop(state_key, None)
            return "recovery"
        return None

    if level > prev:
        down_states[state_key] = {"level": level, "since": entry.get("since", now), "last_sent": now}
        return "alert"

    if level < prev:
        # Entschärfung (kritisch -> Warnung): Zustand anpassen, nicht erneut melden
        entry["level"] = level
        down_states[state_key] = entry
        return None

    if now - float(entry.get("last_sent", now)) >= LEVEL_REMINDER_SECONDS:
        entry["last_sent"] = now
        down_states[state_key] = entry
        return "reminder"
    return None


def compare_and_alert(old, new):
    alerts = []
    import time
    now = time.time()
    
    # Down-States tracken (wann ging etwas erstmals down)
    down_states = state_get("down_states", {})
    ALARM_DELAY = 300  # 5 Minuten in Sekunden
    
    # WAN-IP
    if old.get("wan_ip") and new.get("wan_ip") and new.get("wan_ip") != "unbekannt":
        if old.get("wan_ip") != new.get("wan_ip"):
            history_push("wan_ip_seq", new.get("wan_ip"))
            seq = [x.get("value") for x in history_get("wan_ip_seq")]
            if len(seq) >= 3 and all(x == seq[-1] for x in seq[-3:]):
                alerts.append(alert_block("🟡", "WAN-IP geändert", [
                    alert_field("Host", mdv2_code(HOST_LABEL)),
                    alert_field("Alt", mdv2_code(old.get("wan_ip"))),
                    alert_field("Neu", mdv2_code(new.get("wan_ip"))),
                ]))
    
    # =========================================================
    # NETZWERK-ALARME
    # - Ausfall erst nach ALARM_DELAY
    # - pro Ausfall genau EIN Alarm
    # - bei Wiederherstellung Zustand zurücksetzen
    # - danach bereit für den nächsten Ausfall
    # =========================================================

    # ---------------------------------------------------------
    # INTERNET
    # ---------------------------------------------------------
    if new.get("internet_online") is False:
        down_key = "internet"
        alert_key = "internet_alerted"

        if down_key not in down_states:
            down_states[down_key] = now

        first_down = down_states[down_key]

        if now - first_down >= ALARM_DELAY and not down_states.get(alert_key):
            alerts.append(alert_block("🔴", "Internet offline", [
                alert_field("Host", mdv2_code(HOST_LABEL)),
                alert_field("Status", mdv2_escape("Nicht erreichbar")),
            ]))
            down_states[alert_key] = now

    else:
        if down_states.get("internet_alerted"):
            _dur = _fmt_duration(now - float(down_states.get("internet", now)))
            alerts.append(alert_block("🟢", "Internet wieder verfügbar", [
                alert_field("Host", mdv2_code(HOST_LABEL)),
                alert_field("Ausfallzeit", mdv2_escape(_dur)),
            ]))
        down_states.pop("internet", None)
        down_states.pop("internet_alerted", None)

    # ---------------------------------------------------------
    # TELEGRAM API
    # ---------------------------------------------------------
    if new.get("telegram_online") is False:
        down_key = "telegram"
        alert_key = "telegram_alerted"

        if down_key not in down_states:
            down_states[down_key] = now

        first_down = down_states[down_key]

        if now - first_down >= ALARM_DELAY and not down_states.get(alert_key):
            alerts.append(alert_block("🔴", "Telegram API nicht erreichbar", [
                alert_field("Host", mdv2_code(HOST_LABEL)),
                alert_field("Status", mdv2_escape("Nicht erreichbar")),
            ]))
            down_states[alert_key] = now

    else:
        if down_states.get("telegram_alerted"):
            _dur = _fmt_duration(now - float(down_states.get("telegram", now)))
            alerts.append(alert_block("🟢", "Telegram API wieder verfügbar", [
                alert_field("Host", mdv2_code(HOST_LABEL)),
                alert_field("Ausfallzeit", mdv2_escape(_dur)),
            ]))
        down_states.pop("telegram", None)
        down_states.pop("telegram_alerted", None)

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------
    if new.get("dns_ok") is False:
        down_key = "dns"
        alert_key = "dns_alerted"

        if down_key not in down_states:
            down_states[down_key] = now

        first_down = down_states[down_key]

        if now - first_down >= ALARM_DELAY and not down_states.get(alert_key):
            alerts.append(alert_block("🟡", "DNS-Störung erkannt", [
                alert_field("Host", mdv2_code(HOST_LABEL)),
                alert_field("Status", mdv2_escape("DNS-Auflösung fehlgeschlagen")),
            ]))
            down_states[alert_key] = now

    else:
        if down_states.get("dns_alerted"):
            _dur = _fmt_duration(now - float(down_states.get("dns", now)))
            alerts.append(alert_block("🟢", "DNS-Auflösung wieder verfügbar", [
                alert_field("Host", mdv2_code(HOST_LABEL)),
                alert_field("Ausfallzeit", mdv2_escape(_dur)),
            ]))
        down_states.pop("dns", None)
        down_states.pop("dns_alerted", None)
    
    # Reboot required
    # Persistent: Auch wenn der Guardian erst NACH dem Update startet,
    # wird der offene Neustart einmalig per Telegram gemeldet.
    if new.get("reboot_required"):
        if not down_states.get("reboot_required_alerted"):
            alerts.append(alert_block("🟡", "Neustart erforderlich", [
                alert_field("Host", mdv2_code(HOST_LABEL)),
                alert_field(
                    "Status",
                    mdv2_escape("Systemneustart nach Updates erforderlich"),
                ),
                alert_field(
                    "Kernel",
                    mdv2_code(new.get("kernel", "unbekannt")),
                ),
            ]))
            down_states["reboot_required_alerted"] = now
    else:
        # Neustart wurde durchgeführt bzw. ist nicht mehr erforderlich.
        down_states.pop("reboot_required_alerted", None)
    
    # Services überwachen:
    # - ausschließlich WATCH_SERVICES
    # - Ausfall erst nach ALARM_DELAY
    # - pro Ausfall genau 1 Alarm
    # - bei Wiederherstellung genau 1 Recovery-Meldung
    # - danach bereit für den nächsten Ausfall

    old_services = old.get("services", {})
    new_services = new.get("services", {})

    for svc, status in new_services.items():
        # Nur explizit konfigurierte WATCH_SERVICES überwachen.
        if svc not in WATCH_SERVICES:
            continue

        if not isinstance(status, dict):
            continue

        new_active = status.get("active", "unknown")
        new_enabled = status.get("enabled", "unknown")

        old_status = old_services.get(svc)

        # Beim ersten bekannten Zustand niemals alarmieren.
        if old_status is None:
            if new_active != "active":
                down_states.setdefault(f"svc_{svc}", now)
            continue

        old_active = (
            old_status.get("active", "unknown")
            if isinstance(old_status, dict)
            else str(old_status or "unknown")
        )

        # Zustand protokollieren.
        if old_status != status:
            record_service_change(svc, status)

        down_key = f"svc_{svc}"
        alert_key = f"svc_alerted_{svc}"

        # ---------------------------------------------------------
        # RECOVERY: vorher offline, jetzt wieder aktiv
        # ---------------------------------------------------------
        if old_active != "active" and new_active == "active":

            # Nur dann Recovery melden, wenn dieser Ausfall
            # tatsächlich bereits als Alarm gemeldet wurde.
            if down_states.get(alert_key):
                first_down = down_states.get(down_key)

                offline_text = "unbekannt"
                if first_down:
                    try:
                        duration = max(0, int(now - float(first_down)))
                        minutes, seconds = divmod(duration, 60)

                        if minutes:
                            offline_text = f"{minutes} Min."
                            if seconds:
                                offline_text += f" {seconds} Sek."
                        else:
                            offline_text = f"{seconds} Sek."
                    except Exception:
                        offline_text = "unbekannt"

                alerts.append(alert_block("🟢", "Dienst wieder online", [
                    alert_field("Dienst", mdv2_code(svc)),
                    alert_field("Status", mdv2_escape("active")),
                    alert_field("Ausfallzeit", mdv2_escape(offline_text)),
                    alert_field(
                        "Wiederhergestellt",
                        mdv2_escape(datetime.now().strftime("%H:%M")),
                    ),
                ]))

            # Für den nächsten Ausfall zurücksetzen.
            down_states.pop(down_key, None)
            down_states.pop(alert_key, None)
            continue

        # ---------------------------------------------------------
        # AKTIV: nichts zu tun
        # ---------------------------------------------------------
        if new_active == "active":
            # Kein alter Alarmzustand vorhanden.
            down_states.pop(down_key, None)
            down_states.pop(alert_key, None)
            continue

        # ---------------------------------------------------------
        # AUSFALL BEGINNT
        # ---------------------------------------------------------
        if old_active == "active" and new_active != "active":
            down_states[down_key] = now
            down_states.pop(alert_key, None)
            continue

        # ---------------------------------------------------------
        # AUSFALL DAUERT AN
        # ---------------------------------------------------------
        first_down = down_states.get(down_key)

        if first_down is None:
            down_states[down_key] = now
            first_down = now

        # Nach ALARM_DELAY genau EINEN Alarm senden.
        if now - first_down >= ALARM_DELAY:
            if not down_states.get(alert_key):
                alerts.append(alert_block("🔴", "Dienst offline", [
                    alert_field("Dienst", mdv2_code(svc)),
                    alert_field("Status", mdv2_escape(new_active)),
                    alert_field("Enabled", mdv2_escape(str(new_enabled))),
                ]))

                down_states[alert_key] = True

    # =========================================================
    # SCHWELLWERT-ALARME (Disk, CPU, RAM, Zertifikate, SMART)
    # Vorher: Alarm in JEDEM Zyklus (alle 4 min) solange überschritten,
    # CPU-Alarm nie (falscher Schlüssel "cpu_percent"), Zertifikat- und
    # SMART-Alarme nie (Daten wurden nicht in den Snapshot übernommen).
    # Jetzt: Alarm bei Eintritt/Eskalation, Erinnerung alle
    # LEVEL_REMINDER_SECONDS, Entwarnung bei Normalisierung.
    # =========================================================
    def level_alert(key, level, title_warn, title_crit, fields, recovery_title, recovery_fields):
        action = level_transition(down_states, key, level, now)
        if action in ("alert", "reminder"):
            icon = "🔴" if level >= 2 else "🟡"
            title = title_crit if level >= 2 else title_warn
            if action == "reminder":
                title = f"{title} (besteht weiterhin)"
            alerts.append(alert_block(icon, title, fields))
        elif action == "recovery":
            alerts.append(alert_block("🟢", recovery_title, recovery_fields))

    # Speicher (DISK) – ändert sich langsam, kein Mehrfach-Nachweis nötig
    new_disk = new.get("disk_percent", 0) or 0
    disk_level = 2 if new_disk >= DISK_CRIT else 1 if new_disk >= DISK_WARN else 0
    level_alert(
        "disk", disk_level, "Speicher-Warnung", "Speicher kritisch",
        [alert_field("Host", mdv2_code(HOST_LABEL)), alert_field("Verwendung", mdv2_escape(f"{new_disk}%"))],
        "Speicher wieder normal",
        [alert_field("Host", mdv2_code(HOST_LABEL)), alert_field("Verwendung", mdv2_escape(f"{new_disk}%"))],
    )

    # CPU – 3 Messungen in Folge, damit kurze Spitzen keinen Alarm auslösen
    new_cpu = new.get("cpu", new.get("cpu_percent", 0)) or 0
    history_push("cpu", new_cpu)
    if sustained_above("cpu", CPU_CRIT, needed=3):
        cpu_level = 2
    elif sustained_above("cpu", CPU_WARN, needed=3):
        cpu_level = 1
    elif new_cpu < CPU_WARN:
        cpu_level = 0
    else:
        cpu_level = (down_states.get("lvl_cpu") or {}).get("level", 0)
    level_alert(
        "cpu", cpu_level, "CPU erhöht", "CPU kritisch",
        [alert_field("Host", mdv2_code(HOST_LABEL)), alert_field("CPU", mdv2_escape(f"{new_cpu}%"))],
        "CPU wieder normal",
        [alert_field("Host", mdv2_code(HOST_LABEL)), alert_field("CPU", mdv2_escape(f"{new_cpu}%"))],
    )

    # RAM – Historie wie bisher (3 Messungen)
    new_ram = new.get("ram", 0) or 0
    history_push("ram", new_ram)
    if sustained_above("ram", RAM_CRIT, needed=3):
        ram_level = 2
    elif sustained_above("ram", RAM_WARN, needed=3):
        ram_level = 1
    elif new_ram < RAM_WARN:
        ram_level = 0
    else:
        ram_level = (down_states.get("lvl_ram") or {}).get("level", 0)
    level_alert(
        "ram", ram_level, "RAM erhöht", "RAM kritisch",
        [alert_field("Host", mdv2_code(HOST_LABEL)), alert_field("RAM", mdv2_escape(f"{new_ram}%"))],
        "RAM wieder normal",
        [alert_field("Host", mdv2_code(HOST_LABEL)), alert_field("RAM", mdv2_escape(f"{new_ram}%"))],
    )

    # Zertifikate (je Host)
    for host, days in (new.get("certs", {}) or {}).items():
        if days is None:
            continue
        cert_level = 2 if days <= 7 else 1 if days <= 30 else 0
        level_alert(
            f"cert_{host}", cert_level, "Zertifikat läuft bald ab", "Zertifikat läuft in Kürze ab",
            [alert_field("Host", mdv2_code(host)), alert_field("Tage", mdv2_escape(str(days)))],
            "Zertifikat erneuert",
            [alert_field("Host", mdv2_code(host)), alert_field("Tage", mdv2_escape(str(days)))],
        )

    # SMART (je Gerät) – aus den tatsächlich gesammelten Gerätedaten
    for dev in ((new.get("smart") or {}).get("devices") or []):
        name = str(dev.get("device", "?"))
        failed = str(dev.get("health", "")).upper() == "FAILED"
        pending = int(dev.get("pending") or 0)
        realloc = int(dev.get("reallocated") or 0)
        smart_level = 2 if failed else 1 if (pending or realloc) else 0
        level_alert(
            f"smart_{name}", smart_level, "SMART-Auffälligkeit", "SMART-Fehler erkannt",
            [
                alert_field("Gerät", mdv2_code(name)),
                alert_field("Health", mdv2_escape(str(dev.get("health", "?")))),
                alert_field("Pending", mdv2_escape(str(pending))),
                alert_field("Reallocated", mdv2_escape(str(realloc))),
            ],
            "SMART wieder unauffällig",
            [alert_field("Gerät", mdv2_code(name))],
        )

    

    # ------------------------------------------------------------
    # Netzwerk-Recovery-Flags zurücksetzen.
    # Dadurch kann ein späterer echter Ausfall wieder alarmiert
    # werden, aber ein bestehender Ausfall erzeugt keinen Spam.
    # ------------------------------------------------------------
    if new.get("internet_online"):
        down_states.pop("internet", None)
        down_states.pop("internet_alerted", None)

    if new.get("telegram_online"):
        down_states.pop("telegram", None)
        down_states.pop("telegram_alerted", None)

    if new.get("dns_ok"):
        down_states.pop("dns", None)
        down_states.pop("dns_alerted", None)

    # Down-States speichern
    state_set("down_states", down_states)
    
    return alerts

def authorized_chat_and_user(chat_id, user_id):
    """Fail-closed: ohne konfigurierte IDs ist niemand berechtigt."""
    if not CHAT_IDS or not ALLOWED_IDS:
        return False
    if str(chat_id) not in CHAT_IDS:
        return False
    if str(user_id) not in ALLOWED_IDS:
        return False
    return True


_RATE_LAST = {}
_RATE_LOCK = threading.Lock()


def rate_limited(user_id):
    # Nur im Speicher: vorher wurde für jede Eingabe die komplette state.json geschrieben
    now = time.time()
    with _RATE_LOCK:
        last = _RATE_LAST.get(str(user_id), 0.0)
        if now - last < RATE_LIMIT_SECONDS:
            return True
        _RATE_LAST[str(user_id)] = now
        return False


def refresh_snapshot(force_slow=False):
    old_snapshot = state_get("snapshot", {})
    fast = build_fast_snapshot(old_snapshot)

    slow = old_snapshot.get("slow", {})
    last_slow = int(slow.get("checked_at", 0)) if slow else 0
    need_slow = force_slow or (int(time.time()) - last_slow >= SLOW_CHECK_INTERVAL)

    if need_slow:
        slow = build_slow_snapshot(fast, force=force_slow)

    merged = merge_snapshot_with_slow(fast, slow)

    def mut(s):
        s["snapshot"] = merged

    state_update(mut)
    return merged, old_snapshot


def process_command_text(text):
    parts = text.strip().split()
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else None

    if cmd in ("/start", "/menu"):
        return ("home", None)
    if cmd == "/status":
        return ("status", None)
    if cmd == "/updates":
        return ("updates", None)
    if cmd == "/reboot":
        return ("reboot", None)
    if cmd == "/services":
        return ("services", None)
    if cmd == "/failed":
        return ("failed", None)
    if cmd == "/disk":
        return ("disk", None)
    if cmd == "/network":
        return ("network", None)
    if cmd == "/security":
        return ("security", None)
    if cmd == "/ping":
        return ("ping", None)
    if cmd == "/temps":
        return ("temps", None)
    if cmd == "/smart":
        return ("smart", None)
    if cmd == "/docker":
        return ("docker", None)
    if cmd == "/logs":
        return ("logs", arg or 20)
    if cmd == "/help":
        return ("help", None)
    return (None, None)


def install_apt_updates(timeout=1800):
    """Führt einen vollständigen Ubuntu-Upgrade-Lauf nach Telegram-Bestätigung durch."""

    lock_paths = [
        "/var/lib/dpkg/lock-frontend",
        "/var/lib/dpkg/lock",
        "/var/lib/apt/lists/lock",
    ]

    lock = run(
        ["fuser", "-v", *lock_paths],
        timeout=10,
    )

    if lock.returncode == 0 and (lock.stdout or "").strip():
        return {
            "success": False,
            "stage": "lock",
            "output": (lock.stdout or "").strip(),
        }

    update = run(
        ["apt-get", "update"],
        timeout=600,
    )

    update_output = ((update.stdout or "") + (update.stderr or "")).strip()

    if update.returncode != 0:
        return {
            "success": False,
            "stage": "apt-update",
            "output": update_output,
        }

    configure = run(
        ["dpkg", "--configure", "-a"],
        timeout=300,
    )

    configure_output = (
        (configure.stdout or "") + (configure.stderr or "")
    ).strip()

    if configure.returncode != 0:
        return {
            "success": False,
            "stage": "dpkg-configure",
            "output": configure_output,
        }

    fix = run(
        [
            "apt-get",
            "-f",
            "install",
            "-y",
            "-o",
            "Dpkg::Options::=--force-confold",
        ],
        timeout=600,
    )

    fix_output = ((fix.stdout or "") + (fix.stderr or "")).strip()

    if fix.returncode != 0:
        return {
            "success": False,
            "stage": "apt-fix",
            "output": fix_output,
        }

    upgrade = run(
        [
            "apt-get",
            "full-upgrade",
            "-y",
            "-o",
            "APT::Get::Always-Include-Phased-Updates=true",
            "-o",
            "Dpkg::Options::=--force-confold",
        ],
        timeout=timeout,
    )

    upgrade_output = ((upgrade.stdout or "") + (upgrade.stderr or "")).strip()

    if upgrade.returncode != 0:
        return {
            "success": False,
            "stage": "apt-full-upgrade",
            "output": upgrade_output,
        }

    verify = run(
        [
                "apt-get",
                "-s",
                "-o",
                "APT::Get::Always-Include-Phased-Updates=true",
                "full-upgrade",
            ],
        timeout=300,
    )

    verify_output = ((verify.stdout or "") + (verify.stderr or "")).strip()

    if verify.returncode != 0:
        return {
            "success": False,
            "stage": "apt-verify",
            "output": verify_output,
        }

    # Falls APT Updates wegen Phasing zurückhält, die noch
    # aktualisierbaren Pakete gezielt installieren.
    pending = []
    for line in verify_output.splitlines():
        if line.startswith("Inst "):
            parts = line.split()
            if len(parts) >= 2:
                pending.append(parts[1])

    if pending:
        phased_install = run(
            [
                "apt-get",
                "install",
                "-y",
                "-o",
                "APT::Get::Always-Include-Phased-Updates=true",
                "-o",
                "Dpkg::Options::=--force-confold",
                *pending,
            ],
            timeout=timeout,
        )

        phased_output = (
            (phased_install.stdout or "")
            + (phased_install.stderr or "")
        ).strip()

        if phased_install.returncode != 0:
            return {
                "success": False,
                "stage": "apt-phased",
                "output": phased_output,
            }

        verify = run(
            [
                "apt-get",
                "-s",
                "-o",
                "APT::Get::Always-Include-Phased-Updates=true",
                "full-upgrade",
            ],
            timeout=300,
        )

        verify_output = (
            (verify.stdout or "") + (verify.stderr or "")
        ).strip()

    if not any(
        line.startswith("0 upgraded")
        for line in verify_output.splitlines()
    ):
        return {
            "success": False,
            "stage": "apt-verify",
            "output": (
                "Nach dem Upgrade sind möglicherweise noch Pakete offen.\n\n"
                + verify_output
            ),
        }

    combined_output = (
        "=== APT UPDATE ===\n"
        + update_output[-1500:]
        + "\n\n=== DPKG CONFIGURE ===\n"
        + configure_output[-1000:]
        + "\n\n=== APT FIX ===\n"
        + fix_output[-1000:]
        + "\n\n=== FULL-UPGRADE ===\n"
        + upgrade_output[-3000:]
        + "\n\n=== ABSCHLUSSPRÜFUNG ===\n"
        + verify_output[-1500:]
    )

    return {
        "success": True,
        "stage": "complete",
        "output": combined_output,
    }

def _apt_update_worker(chat_id, message_id):
    try:
        result = install_apt_updates()

        if result.get("success"):
            output = result.get("output") or "Keine Ausgabe."
            reboot_needed = get_reboot_required()

            if reboot_needed:
                body = (
                    "📦 Updates\n\n"
                    "✅ Installation erfolgreich abgeschlossen.\n\n"
                    "<pre>"
                    + html_escape(output[-3000:])
                    + "</pre>\n\n"
                    "⚠️ Ein Neustart ist erforderlich."
                )
                menu = {
                    "inline_keyboard": [
                        [
                            {
                                "text": "🔄 Jetzt neu starten",
                                "callback_data": "updates:reboot",
                            }
                        ],
                        [
                            {
                                "text": "⬅️ Später",
                                "callback_data": "updates:reboot_cancel",
                            }
                        ],
                    ]
                }
            else:
                body = (
                    "📦 Updates\n\n"
                    "✅ Installation erfolgreich abgeschlossen.\n\n"
                    "<pre>"
                    + html_escape(output[-3500:])
                    + "</pre>\n\n"
                    "ℹ️ Kein Neustart erforderlich."
                )
                menu = build_menu(view="updates")
        else:
            output = result.get("output") or "Keine Ausgabe."
            stage = result.get("stage", "unbekannt")
            body = (
                "📦 Updates\n\n"
                "❌ Installation fehlgeschlagen.\n\n"
                f"Phase: {html_escape(str(stage))}\n\n"
                "<pre>"
                + html_escape(output[-3500:])
                + "</pre>"
            )
            menu = build_menu(view="updates")

        snapshot, _ = refresh_snapshot(force_slow=False)

        edit_telegram_message(
            chat_id,
            message_id,
            body,
            reply_markup=menu,
            parse_mode="HTML",
        )

    except Exception as exc:
        logger.exception("APT-Update-Worker fehlgeschlagen")

        edit_telegram_message(
            chat_id,
            message_id,
            "📦 Updates\n\n"
            "❌ Unerwarteter Fehler:\n\n"
            f"<pre>{html_escape(str(exc))}</pre>",
            reply_markup=build_menu(view="updates"),
            parse_mode="HTML",
        )

    finally:
        _APT_INSTALL_LOCK.release()



_REFRESH_LOCK = threading.Lock()


def _refresh_worker(chat_id, message_id, view, arg=None):
    try:
        with _REFRESH_LOCK:  # parallele Refreshes beider Accounts nicht doppelt rechnen
            snapshot, _ = refresh_snapshot(force_slow=True)
        text = render_view(view, snapshot=snapshot, arg=arg)
        result = edit_telegram_message(
            chat_id, message_id, text,
            reply_markup=build_menu(view=view, snapshot=snapshot), parse_mode="HTML",
        )
        if result.get("ok"):
            set_menu_for_chat(chat_id, message_id, view)
    except Exception as e:
        logger.exception("Refresh-Worker Fehler: %s", e)


def bot_loop():
    if not BOT_TOKEN:
        logger.warning("BOT_TOKEN fehlt")
        return

    while True:
        try:
            offset = state_get("telegram_offset") or 0
            data = telegram_get_updates(offset=offset, timeout=30)

            if data.get("ok"):
                for item in data.get("result", []):
                    offset = int(item.get("update_id", 0)) + 1
                    state_set("telegram_offset", offset)

                    if "callback_query" in item:
                        cq = item["callback_query"]
                        msg = cq.get("message", {})
                        chat = msg.get("chat", {})
                        user = cq.get("from", {})
                        chat_id = str(chat.get("id", ""))
                        user_id = str(user.get("id", ""))
                        action = (cq.get("data") or "").strip().lower()

                        if not authorized_chat_and_user(chat_id, user_id):
                            answer_callback_query(cq["id"], "Nicht erlaubt")
                            continue

                        if rate_limited(user_id):
                            answer_callback_query(cq["id"], "Bitte kurz warten")
                            continue

                        # Updates: Installation nur nach ausdrücklicher Bestätigung.
                        if action == "updates:install":
                            snapshot = get_current_snapshot() or refresh_snapshot(force_slow=False)[0]
                            available, security = get_updates()

                            if available <= 0:
                                answer_callback_query(cq["id"], "Keine Updates verfügbar")
                                continue

                            confirm_text = (
                                "📦 Updates installieren\n\n"
                                "<pre>"
                                f"Verfügbare Updates: {available}\n"
                                f"Security-Updates:    {security}\n\n"
                                "Der Server wird NICHT automatisch neu gestartet."
                                "</pre>"
                            )

                            confirm_menu = {
                                "inline_keyboard": [
                                    [
                                        {
                                            "text": "✅ Ja, installieren",
                                            "callback_data": "updates:confirm",
                                        }
                                    ],
                                    [
                                        {
                                            "text": "⬅️ Zurück",
                                            "callback_data": "updates:cancel",
                                        }
                                    ],
                                ]
                            }

                            answer_callback_query(cq["id"], "Bestätigung erforderlich")
                            edit_telegram_message(
                                chat_id,
                                msg.get("message_id"),
                                confirm_text,
                                reply_markup=confirm_menu,
                                parse_mode="HTML",
                            )
                            continue

                        if action == "updates:cancel":
                            answer_callback_query(cq["id"], "Abgebrochen")

                            snapshot = get_current_snapshot() or refresh_snapshot(force_slow=False)[0]
                            text = render_view("updates", snapshot=snapshot)

                            edit_telegram_message(
                                chat_id,
                                msg.get("message_id"),
                                text,
                                reply_markup=build_menu(view="updates"),
                                parse_mode="HTML",
                            )
                            continue

                        if action == "updates:reboot_cancel":
                            answer_callback_query(cq["id"], "Neustart verschoben")

                            snapshot = get_current_snapshot() or refresh_snapshot(force_slow=False)[0]
                            text = render_view("updates", snapshot=snapshot)

                            edit_telegram_message(
                                chat_id,
                                msg.get("message_id"),
                                text,
                                reply_markup=build_menu(view="updates"),
                                parse_mode="HTML",
                            )
                            continue

                        if action == "updates:reboot":
                            # Zweite Sicherheitsprüfung unmittelbar vor dem Reboot.
                            if not get_reboot_required():
                                answer_callback_query(
                                    cq["id"],
                                    "Kein Neustart mehr erforderlich",
                                )
                                snapshot = get_current_snapshot() or refresh_snapshot(force_slow=False)[0]
                                text = render_view("updates", snapshot=snapshot)
                                edit_telegram_message(
                                    chat_id,
                                    msg.get("message_id"),
                                    text,
                                    reply_markup=build_menu(view="updates"),
                                    parse_mode="HTML",
                                )
                                continue

                            answer_callback_query(
                                cq["id"],
                                "Neustart wird durchgeführt",
                            )

                            menu_id = msg.get("message_id")

                            edit_telegram_message(
                                chat_id,
                                menu_id,
                                "🔄 Neustart wird durchgeführt ...\n\n"
                                "Der Ubuntu-Server fährt jetzt kontrolliert herunter.",
                                reply_markup={"inline_keyboard": []},
                                parse_mode="HTML",
                            )

                            notify_other_admins(
                                chat_id,
                                f"ℹ️ {html_escape(HOST_LABEL)}: Neustart wurde von {actor_name(user)} ausgelöst.",
                            )

                            threading.Thread(
                                target=lambda: run(
                                    ["systemctl", "reboot"],
                                    timeout=10,
                                ),
                                daemon=True,
                                name="system-reboot-worker",
                            ).start()
                            continue

                        if action == "updates:confirm":
                            if not _APT_INSTALL_LOCK.acquire(blocking=False):
                                answer_callback_query(cq["id"], "Installation läuft bereits")
                                continue

                            available, security = get_updates()

                            if available <= 0:
                                _APT_INSTALL_LOCK.release()
                                answer_callback_query(cq["id"], "Keine Updates mehr verfügbar")
                                continue

                            answer_callback_query(cq["id"], "Installation gestartet")

                            menu_id = msg.get("message_id")

                            edit_telegram_message(
                                chat_id,
                                menu_id,
                                "📦 Updates installieren\n\n"
                                f"⏳ {available} Update(s) werden installiert ...\n\n"
                                "Bitte warten.\n"
                                "Kein automatischer Reboot.",
                                reply_markup={"inline_keyboard": []},
                                parse_mode="HTML",
                            )

                            notify_other_admins(
                                chat_id,
                                f"ℹ️ {html_escape(HOST_LABEL)}: Installation von {available} Update(s) "
                                f"wurde von {actor_name(user)} gestartet.",
                            )

                            threading.Thread(
                                target=_apt_update_worker,
                                args=(chat_id, menu_id),
                                daemon=True,
                                name="apt-update-worker",
                            ).start()
                            continue

                        answer_callback_query(cq["id"])

                        current_view = "home"
                        arg = None
                        force_refresh = False

                        if action.startswith("refresh:"):
                            current_view = action.split(":", 1)[1] or "home"
                            force_refresh = True
                        else:
                            current_view = action

                        if force_refresh:
                            # Refresh (inkl. langsamer Checks) im Hintergrund, damit
                            # der Bot für beide Accounts sofort bedienbar bleibt.
                            threading.Thread(
                                target=_refresh_worker,
                                args=(chat_id, msg.get("message_id"), current_view, arg),
                                daemon=True,
                                name=f"refresh-{current_view}",
                            ).start()
                            continue
                        snapshot = get_current_snapshot() or refresh_snapshot(force_slow=False)[0]

                        text = render_view(current_view, snapshot=snapshot, arg=arg)
                        menu_id = msg.get("message_id")
                        result = edit_telegram_message(chat_id, menu_id, text, reply_markup=build_menu(view=current_view, snapshot=snapshot), parse_mode="HTML")

                        if result.get("ok"):
                            set_menu_for_chat(chat_id, menu_id, current_view)
                        elif "message is not modified" in str(result.get("description", "")).lower():
                            pass
                        else:
                            upsert_menu_message(chat_id, text, view=current_view)
                        continue

                    msg = item.get("message", {})
                    chat = msg.get("chat", {})
                    user = msg.get("from", {})
                    text = (msg.get("text") or "").strip()
                    chat_id = str(chat.get("id", ""))
                    user_id = str(user.get("id", ""))
                    message_id = msg.get("message_id")

                    if not authorized_chat_and_user(chat_id, user_id):
                        continue

                    if rate_limited(user_id):
                        if message_id:
                            delete_message_safe(chat_id, message_id)
                        continue

                    allowed_commands = {
                        "/start", "/menu", "/home", "/status", "/updates", "/reboot", "/security",
                        "/services", "/disk", "/network", "/smart", "/logs",
                        "/ping", "/help", "/critical", "/apt"
                    }

                    if text:
                        cmd = text.split()[0].lower()
                        if not text.startswith("/") or cmd not in allowed_commands:
                            if message_id:
                                delete_message_safe(chat_id, message_id)
                            continue

                    if text.startswith("/"):
                        logger.info("Telegram command empfangen: chat_id=%s user_id=%s text=%s", chat_id, user_id, text)

                        cmd = text.split()[0].lower()

                        if cmd == "/reboot":
                            if not get_reboot_required():
                                tg_api(
                                    "sendMessage",
                                    {
                                        "chat_id": chat_id,
                                        "text": "ℹ️ Kein Neustart erforderlich.",
                                        "parse_mode": "HTML",
                                    },
                                )
                                continue

                            reboot_menu = {
                                "inline_keyboard": [
                                    [
                                        {
                                            "text": "🔄 Ja, jetzt neu starten",
                                            "callback_data": "updates:reboot",
                                        }
                                    ],
                                    [
                                        {
                                            "text": "⬅️ Abbrechen",
                                            "callback_data": "updates:reboot_cancel",
                                        }
                                    ],
                                ]
                            }

                            tg_api(
                                "sendMessage",
                                {
                                    "chat_id": chat_id,
                                    "text": (
                                        "⚠️ <b>Neustart erforderlich</b>\n\n"
                                        "Der Ubuntu-Server hat ein ausstehendes "
                                        "System-Update bzw. Kernel-Upgrade.\n\n"
                                        "Soll der Server jetzt kontrolliert "
                                        "neu gestartet werden?"
                                    ),
                                    "reply_markup": json.dumps(
                                        reboot_menu,
                                        ensure_ascii=False,
                                    ),
                                    "parse_mode": "HTML",
                                },
                            )
                            continue

                        view, arg = process_command_text(text)
                        if view:
                            snapshot = get_current_snapshot() or refresh_snapshot(force_slow=False)[0]
                            reply = render_view(view, snapshot=snapshot, arg=arg)

                            if view == "home":
                                menu = get_menu_for_chat(chat_id)
                                old_message_id = menu.get("message_id")

                                if old_message_id:
                                    delete_message_safe(chat_id, old_message_id)

                                sent = tg_api("sendMessage", {"chat_id": chat_id, "text": reply, "reply_markup": json.dumps(build_menu(view=view), ensure_ascii=False), "parse_mode": "HTML"})
                                if sent.get("ok") and sent.get("result", {}).get("message_id"):
                                    set_menu_for_chat(chat_id, sent["result"]["message_id"], view)
                            else:
                                upsert_menu_message(chat_id, reply, view=view)

                            logger.info("Telegram command verarbeitet: view=%s", view)
                            if message_id:
                                delete_message_safe(chat_id, message_id)
                              # User-Befehle nach Verarbeitung löschen

                state_set("telegram_offset", offset)

        except Exception as e:
            logger.exception("Bot loop Fehler: %s", e)
            time.sleep(max(1, POLL_INTERVAL))
            continue

        # Long-Polling wartet bereits serverseitig; eine zusätzliche Pause von
        # POLL_INTERVAL (15 s) hat jeden zweiten Tastendruck verzögert.
        if not data.get("ok"):
            time.sleep(max(1, POLL_INTERVAL))


def monitor_loop():
    logger.info("Monitor loop gestartet")
    while True:
        try:
            # Ausstehende Nachrichten (z. B. nach Internet-Ausfall) nachliefern
            try:
                outbox_flush()
            except Exception as e:
                logger.warning("Outbox-Flush Fehler: %s", e)

            new_snapshot, _ = refresh_snapshot(force_slow=False)
            # Eigener Vergleichsstand des Monitors: Ein manueller Refresh über
            # Telegram überschreibt "snapshot" – würde der Monitor damit
            # vergleichen, gingen Statuswechsel (z. B. Dienst-Ausfall) verloren.
            old_snapshot = state_get("alert_baseline") or state_get("snapshot", {}) or {}
            alerts = compare_and_alert(old_snapshot, new_snapshot)
            state_set("alert_baseline", new_snapshot)
            for alert in alerts:
                if "Neustart erforderlich" in alert:
                    reboot_menu = {
                        "inline_keyboard": [
                            [
                                {
                                    "text": "🔄 Jetzt neu starten",
                                    "callback_data": "updates:reboot",
                                }
                            ],
                            [
                                {
                                    "text": "⏰ Später",
                                    "callback_data": "updates:reboot_cancel",
                                }
                            ],
                        ]
                    }

                    send_telegram(
                        alert,
                        reply_markup=reboot_menu,
                        parse_mode="MarkdownV2",
                    )
                else:
                    send_telegram(
                        alert,
                        parse_mode="MarkdownV2",
                    )

            logger.info("Check abgeschlossen")
        except Exception as e:
            logger.exception("Monitor loop Fehler: %s", e)
            kind = f"{type(e).__name__}:{e}"
            now = time.time()
            last = _last_diag_sent.get(kind, 0)
            if now - last >= 300:
                _last_diag_sent[kind] = now
                send_telegram(diagnose_hint(f"{type(e).__name__}: {e}"))
        time.sleep(CHECK_INTERVAL)


def main():
    init_state()
    t1 = threading.Thread(target=monitor_loop, daemon=True)
    t2 = threading.Thread(target=bot_loop, daemon=True)
    t1.start()
    t2.start()
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()

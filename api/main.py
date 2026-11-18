"""
Ubuntu Guardian API
Stellt System-Informationen als HTTP-API bereit
"""
from fastapi import FastAPI, HTTPException, Header
import hmac
import os
import re
import psutil
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Ubuntu Guardian API")

# Absicherung des Restart-Endpunkts (abwärtskompatibel):
# * Dienstname muss ein gültiger systemd-Unit-Name sein (keine Optionen wie "--help")
# * GUARDIAN_API_RESTART_ALLOW (kommagetrennt) begrenzt, welche Dienste neu
#   gestartet werden dürfen. Leer = wie bisher alle (mit Warnung im Log).
# * GUARDIAN_API_KEY gesetzt -> Header "X-API-Key" ist Pflicht.
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]{0,200}$")
RESTART_ALLOW = {x.strip() for x in os.getenv("GUARDIAN_API_RESTART_ALLOW", "").split(",") if x.strip()}
API_KEY = os.getenv("GUARDIAN_API_KEY", "").strip()
if not RESTART_ALLOW:
    logger.warning("GUARDIAN_API_RESTART_ALLOW nicht gesetzt – Restart für alle Dienste erlaubt")
if not API_KEY:
    logger.warning("GUARDIAN_API_KEY nicht gesetzt – API ohne Authentifizierung (nur 127.0.0.1)")


def _check_restart_allowed(service_name: str, x_api_key: str | None) -> str:
    if API_KEY and not hmac.compare_digest(str(x_api_key or ""), API_KEY):
        raise HTTPException(status_code=401, detail="Nicht autorisiert")
    if not _UNIT_RE.match(service_name or ""):
        raise HTTPException(status_code=400, detail="Ungültiger Dienstname")
    unit = service_name if "." in service_name else f"{service_name}.service"
    if RESTART_ALLOW and unit not in RESTART_ALLOW and service_name not in RESTART_ALLOW:
        raise HTTPException(status_code=403, detail="Dienst nicht freigegeben")
    return unit


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/status")
async def get_status():
    """Systemstatus (CPU, RAM, Disk)"""
    try:
        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        # Netzwerk Stats
        net = psutil.net_io_counters()
        
        return {
            "cpu_percent": cpu,
            "ram_percent": ram,
            "disk_percent": disk,
            "network": {
                "bytes_sent": net.bytes_sent,
                "bytes_recv": net.bytes_recv
            },
            "status": "ok",
            "message": "Ubuntu online"
        }
    except Exception as e:
        logger.error(f"Status Fehler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/services")
async def get_services():
    """Systemd Services Liste"""
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        services = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[0]
                    # Status ist typischerweise das 4. Feld
                    status_field = parts[3] if len(parts) > 3 else "unknown"
                    is_active = "active" in status_field.lower()
                    
                    services.append({
                        "name": name,
                        "status": status_field,
                        "active": is_active,
                        "description": " ".join(parts[4:]) if len(parts) > 4 else ""
                    })
        
        return services
    except Exception as e:
        logger.error(f"Services Fehler: {e}")
        return []


@app.post("/services/{service_name}/restart")
async def restart_service(service_name: str, x_api_key: str | None = Header(default=None)):
    """Service neustarten"""
    service_name = _check_restart_allowed(service_name, x_api_key)
    try:
        # First check if service exists (status liefert 3 für "inactive" -> ok)
        check = subprocess.run(
            ["systemctl", "status", "--", service_name],
            capture_output=True,
            timeout=5
        )
        
        if check.returncode not in (0, 3):
            raise HTTPException(status_code=404, detail=f"Service {service_name} nicht gefunden")
        
        # Restart
        result = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "--", service_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return {"success": True, "service": service_name, "message": "Service neu gestartet"}
        else:
            raise HTTPException(status_code=500, detail=result.stderr)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Timeout beim Neustart")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Restart Fehler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/disk")
async def get_disk():
    """Disk Usage"""
    try:
        disk = psutil.disk_usage('/')
        return {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/updates")
async def get_updates():
    """Verfügbare Updates"""
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable", "-q"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Zähle Updates (erste Zeile ist Header)
        lines = result.stdout.strip().split('\n')
        update_count = len(lines) - 1 if len(lines) > 1 else 0
        
        return {
            "count": update_count,
            "status": "ok" if update_count == 0 else "updates_available"
        }
    except Exception as e:
        logger.error(f"Updates Fehler: {e}")
        return {"count": 0, "error": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)


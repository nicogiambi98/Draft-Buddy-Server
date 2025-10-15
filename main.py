import os
import shutil
import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging

from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
import jwt
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # Fallback if not available; scheduler will be disabled

# Minimal, ephemeral-friendly server_old for Railway
# Stores one SQLite file per manager_id under STORAGE_DIR (may be ephemeral on Railway)
# Endpoints:
# - GET /health
# - POST /auth/login {username, password, remember}
# - POST /db/upload (Authorization: Bearer <token>) multipart/form-data file
# - GET  /db/download (Authorization: Bearer <token>)
# - GET  /public/{manager_id}/snapshot.sqlite (public read-only)
# - GET  /public/{manager_id}/version (public metadata)
#
# Notes:
# - This keeps a super simple in-memory user list by default; override via env vars.
# - Designed for simplicity: manager controls when to upload, players read snapshot.

STORAGE_DIR = os.getenv("STORAGE_DIR", "./storage")
JWT_SECRET = os.getenv("JWT_SECRET", "draftbuddyclandestini!")
# Users are now loaded exclusively from a file named users.txt located next to this script.
# Format for entries: "user1:pass1@id1" with entries separated by commas or newlines.
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.txt")
ALGORITHM = "HS256"

os.makedirs(STORAGE_DIR, exist_ok=True)

# Load and parse users from users.txt (no plaintext defaults in source)
USERS = {}
_raw_users = ""
if os.path.exists(USERS_FILE):
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            _raw_users = f.read()
    except Exception as e:
        logging.getLogger("draftbuddy").warning("Failed to read users.txt: %s", e)
else:
    logging.getLogger("draftbuddy").warning("users.txt not found at %s. Create server/users.txt with entries username:password@manager_id", USERS_FILE)

parts = []
if _raw_users:
    # Support either comma-separated or newline-separated definitions
    for chunk in _raw_users.replace("\n", ",").split(","):
        s = chunk.strip()
        if s:
            parts.append(s)

for part in parts:
    # format username:password@manager_id
    try:
        creds, manager_id = part.split("@", 1)
        username, password = creds.split(":", 1)
        USERS[username] = {"password": password, "manager_id": manager_id}
    except ValueError:
        logging.getLogger("draftbuddy").warning("Skipping invalid users.txt entry: %s", part)

if not USERS:
    logging.getLogger("draftbuddy").warning("No users configured. Add entries to server/users.txt (username:password@manager_id). Login will fail until configured.")

# Configure simple logging to stdout
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
logger = logging.getLogger("draftbuddy")

app = FastAPI(title="Draft Buddy Minimal Server", version="0.1.0")

# ----- Weekly backup scheduler (Europe/Rome, Thursdays at 02:00) -----

def _seconds_until_next_thu_2am_rome() -> float:
    """Return seconds until the next Thursday 02:00 in Europe/Rome timezone."""
    if ZoneInfo is None:
        return 7 * 24 * 3600.0  # Fallback: a week
    rome = ZoneInfo("Europe/Rome")
    now_rome = datetime.now(rome)
    # Monday=0 ... Sunday=6; Thursday=3
    target_wd = 3
    days_ahead = (target_wd - now_rome.weekday()) % 7
    target_date = (now_rome.date() + timedelta(days=days_ahead))
    target_dt = datetime.combine(target_date, datetime.min.time()).replace(hour=2, tzinfo=rome)
    if target_dt <= now_rome:
        target_dt = target_dt + timedelta(days=7)
    return max(1.0, (target_dt - now_rome).total_seconds())


def _perform_backups():
    """Create timestamped backups for each primary .sqlite DB, keep last 2 backups per DB."""
    if not os.path.isdir(STORAGE_DIR):
        return
    rome = ZoneInfo("Europe/Rome") if ZoneInfo else None
    ts = datetime.now(rome).strftime("%Y%m%d_%H%M%S") if rome else datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    for fname in os.listdir(STORAGE_DIR):
        # primary DBs are <manager_id>.sqlite; ignore public snapshot files
        if not fname.endswith(".sqlite"):
            continue
        if fname.endswith(".snapshot.sqlite"):
            continue
        full = os.path.join(STORAGE_DIR, fname)
        if not os.path.isfile(full):
            continue
        name = fname[:-len(".sqlite")]  # strip extension
        backup_name = f"{name}-{ts}.sqlite"
        backup_path = os.path.join(STORAGE_DIR, backup_name)
        try:
            shutil.copyfile(full, backup_path)
            size = os.path.getsize(backup_path)
            logger.info("Backup created: %s (%d bytes)", backup_path, size)
        except Exception as e:
            logger.error("Failed to create backup for %s: %s", full, e)
            continue
        # Retention: keep only the last 2 backups for this DB
        try:
            backups = []
            prefix = f"{name}-"
            for f in os.listdir(STORAGE_DIR):
                if f.startswith(prefix) and f.endswith(".sqlite") and not f.endswith(".snapshot.sqlite"):
                    ts_str = f[len(prefix):-len(".sqlite")]
                    backups.append((ts_str, os.path.join(STORAGE_DIR, f)))
            # sort by timestamp string; format ensures lexical order == chronological order
            backups.sort(key=lambda x: x[0])
            # keep last two
            old = backups[:-2]
            for _, path in old:
                try:
                    os.remove(path)
                    logger.info("Old backup removed: %s", path)
                except Exception as e:
                    logger.warning("Failed to remove old backup %s: %s", path, e)
        except Exception as e:
            logger.warning("Backup retention failed for %s: %s", name, e)


def _backup_loop():
    if os.getenv("DISABLE_BACKUPS"):
        logger.info("Backups disabled via DISABLE_BACKUPS env var")
        return
    if ZoneInfo is None:
        logger.warning("zoneinfo not available; scheduled backups disabled")
        return
    while True:
        try:
            secs = _seconds_until_next_thu_2am_rome()
            try:
                rome = ZoneInfo("Europe/Rome")
                next_when = datetime.now(rome) + timedelta(seconds=secs)
                logger.info("Next DB backup scheduled at %s Europe/Rome (in %.0f seconds)", next_when.strftime("%Y-%m-%d %H:%M:%S"), secs)
            except Exception:
                logger.info("Next DB backup in %.0f seconds", secs)
            time.sleep(secs)
            _perform_backups()
        except Exception as e:
            logger.error("Backup loop error: %s", e)
            time.sleep(60)

# Start background backup thread on import
try:
    t = threading.Thread(target=_backup_loop, name="db-backup-scheduler", daemon=True)
    t.start()
except Exception as _e:
    logger.warning("Failed to start backup thread: %s", _e)


class LoginBody(BaseModel):
    username: str
    password: str
    remember: bool = True


@app.get("/health")
def health():
    return {"status": "ok", "time": time.time()}


@app.post("/auth/login")
def auth_login(body: LoginBody):
    user = USERS.get(body.username)
    if not user or user["password"] != body.password:
        logger.info("Login failed for user=%s", getattr(body, 'username', '?'))
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Determine role: any username starting with "manager" (case-insensitive) is a manager; others are guests
    try:
        uname = (body.username or "").strip().lower()
    except Exception:
        uname = ""
    role = "manager" if uname.startswith("manager") else "guest"
    exp_days = 90 if body.remember else 1
    exp = datetime.now(timezone.utc) + timedelta(days=exp_days)
    token = jwt.encode({
        "sub": user["manager_id"],
        "role": role,
        "exp": int(exp.timestamp()),
    }, JWT_SECRET, algorithm=ALGORITHM)
    logger.info("Login ok user=%s role=%s manager_id=%s", getattr(body, 'username', '?'), role, user["manager_id"])
    return {"access_token": token, "exp": int(exp.timestamp()), "manager_id": user["manager_id"], "role": role}


def _require_manager_token(authorization: Optional[str]) -> str:
    if not authorization:
        logger.warning("Missing Authorization header")
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        token = authorization
    else:
        if scheme.lower() != "bearer":
            logger.warning("Wrong auth scheme: %s", scheme)
            raise HTTPException(status_code=401, detail="Use Bearer token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except Exception as e:
        logger.warning("Invalid token: %s", e)
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("role") != "manager":
        logger.warning("Forbidden: role=%s", payload.get("role"))
        raise HTTPException(status_code=403, detail="Forbidden")
    return payload.get("sub")


@app.post("/db/upload")
def db_upload(file: UploadFile = File(...), authorization: Optional[str] = Header(default=None)):
    manager_id = _require_manager_token(authorization)
    dest = os.path.join(STORAGE_DIR, f"{manager_id}.sqlite")
    tmp = dest + ".tmp"
    with open(tmp, "wb") as out:
        shutil.copyfileobj(file.file, out)
    size_bytes = 0
    try:
        size_bytes = os.path.getsize(tmp)
    except Exception:
        pass
    os.replace(tmp, dest)
    # Also refresh public snapshot copy
    public_path = os.path.join(STORAGE_DIR, f"{manager_id}.snapshot.sqlite")
    shutil.copyfile(dest, public_path)
    # Write a tiny version metadata file
    version_path = os.path.join(STORAGE_DIR, f"{manager_id}.version")
    version_ts = int(time.time())
    with open(version_path, "w", encoding="utf-8") as f:
        f.write(str(version_ts))
    logger.info("Upload ok manager_id=%s size=%s dest=%s public=%s version=%s", manager_id, size_bytes, dest, public_path, version_ts)
    return {
        "status": "ok",
        "manager_id": manager_id,
        "size_bytes": size_bytes,
        "stored": os.path.basename(dest),
        "public_snapshot": os.path.basename(public_path),
        "version": version_ts
    }


@app.get("/db/download")
def db_download(authorization: Optional[str] = Header(default=None)):
    manager_id = _require_manager_token(authorization)
    path = os.path.join(STORAGE_DIR, f"{manager_id}.sqlite")
    if not os.path.exists(path):
        logger.info("Download 404 manager_id=%s path=%s (no db yet)", manager_id, path)
        raise HTTPException(status_code=404, detail=f"No DB uploaded yet for {manager_id}")
    try:
        size_bytes = os.path.getsize(path)
    except Exception:
        size_bytes = None
    logger.info("Download ok manager_id=%s path=%s size=%s", manager_id, path, size_bytes)
    return FileResponse(path, filename=f"{manager_id}.sqlite", media_type="application/octet-stream")


@app.get("/public/{manager_id}/snapshot.sqlite")
def public_snapshot(manager_id: str):
    path = os.path.join(STORAGE_DIR, f"{manager_id}.snapshot.sqlite")
    if not os.path.exists(path):
        logger.info("Public snapshot 404 manager_id=%s path=%s", manager_id, path)
        raise HTTPException(status_code=404, detail=f"Public snapshot not found for {manager_id}")
    try:
        size_bytes = os.path.getsize(path)
    except Exception:
        size_bytes = None
    logger.info("Public snapshot ok manager_id=%s path=%s size=%s", manager_id, path, size_bytes)
    return FileResponse(path, filename=f"{manager_id}.sqlite", media_type="application/octet-stream")


@app.get("/public/{manager_id}/version")
def public_version(manager_id: str):
    version_path = os.path.join(STORAGE_DIR, f"{manager_id}.version")
    if not os.path.exists(version_path):
        logger.info("Version for %s not found, returning 0", manager_id)
        return PlainTextResponse("0", media_type="text/plain")
    with open(version_path, "r", encoding="utf-8") as f:
        v = f.read().strip()
    logger.info("Version for %s = %s", manager_id, v)
    return PlainTextResponse(v, media_type="text/plain")


# Root helpful message
@app.get("/")
def root(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "status": "ok",
        "health": f"{base}/health",
        "login": f"{base}/auth/login",
        "upload": f"{base}/db/upload",
        "download": f"{base}/db/download",
        "public_example": f"{base}/public/default/snapshot.sqlite",
    })


if __name__ == "__main__":
    # Allow running this file directly: python server/main.py
    # Host/port can be specified via environment variables:
    #   HOST (default 0.0.0.0)
    #   PORT or SERVER_PORT (default 8000)
    import uvicorn
    _host = os.getenv("HOST", "0.0.0.0")
    _port = 80
    uvicorn.run(app, host=_host, port=_port)

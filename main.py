import os
import shutil
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
import jwt

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
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
# Comma-separated list of users: "user1:pass1@id1,user2:pass2@id2"
USERS_ENV = os.getenv("USERS", "manager:password@default")
ALGORITHM = "HS256"

os.makedirs(STORAGE_DIR, exist_ok=True)

# Parse users from env
USERS = {}
for part in [p.strip() for p in USERS_ENV.split(",") if p.strip()]:
    # format username:password@manager_id
    try:
        creds, manager_id = part.split("@", 1)
        username, password = creds.split(":", 1)
        USERS[username] = {"password": password, "manager_id": manager_id}
    except ValueError:
        # Fallback: treat the whole thing as username with default
        USERS[part] = {"password": "password", "manager_id": part}

app = FastAPI(title="Draft Buddy Minimal Server", version="0.1.0")


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
        raise HTTPException(status_code=401, detail="Invalid credentials")
    exp_days = 90 if body.remember else 1
    exp = datetime.now(timezone.utc) + timedelta(days=exp_days)
    token = jwt.encode({
        "sub": user["manager_id"],
        "role": "manager",
        "exp": int(exp.timestamp()),
    }, JWT_SECRET, algorithm=ALGORITHM)
    return {"access_token": token, "exp": int(exp.timestamp()), "manager_id": user["manager_id"]}


def _require_manager_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        token = authorization
    else:
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Use Bearer token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("role") != "manager":
        raise HTTPException(status_code=403, detail="Forbidden")
    return payload.get("sub")


@app.post("/db/upload")
def db_upload(file: UploadFile = File(...), authorization: Optional[str] = Header(default=None)):
    manager_id = _require_manager_token(authorization)
    dest = os.path.join(STORAGE_DIR, f"{manager_id}.sqlite")
    tmp = dest + ".tmp"
    with open(tmp, "wb") as out:
        shutil.copyfileobj(file.file, out)
    os.replace(tmp, dest)
    # Also refresh public snapshot copy
    public_path = os.path.join(STORAGE_DIR, f"{manager_id}.snapshot.sqlite")
    shutil.copyfile(dest, public_path)
    # Write a tiny version metadata file
    version_path = os.path.join(STORAGE_DIR, f"{manager_id}.version")
    with open(version_path, "w", encoding="utf-8") as f:
        f.write(str(int(time.time())))
    return {"status": "ok", "manager_id": manager_id}


@app.get("/db/download")
def db_download(authorization: Optional[str] = Header(default=None)):
    manager_id = _require_manager_token(authorization)
    path = os.path.join(STORAGE_DIR, f"{manager_id}.sqlite")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="No DB uploaded yet")
    return FileResponse(path, filename=f"{manager_id}.sqlite", media_type="application/octet-stream")


@app.get("/public/{manager_id}/snapshot.sqlite")
def public_snapshot(manager_id: str):
    path = os.path.join(STORAGE_DIR, f"{manager_id}.snapshot.sqlite")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path, filename=f"{manager_id}.sqlite", media_type="application/octet-stream")


@app.get("/public/{manager_id}/version")
def public_version(manager_id: str):
    version_path = os.path.join(STORAGE_DIR, f"{manager_id}.version")
    if not os.path.exists(version_path):
        return PlainTextResponse("0", media_type="text/plain")
    with open(version_path, "r", encoding="utf-8") as f:
        return PlainTextResponse(f.read().strip(), media_type="text/plain")


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

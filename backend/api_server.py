import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt

# ----------------------------
# Config (reuse your env vars)
# ----------------------------
APP_USER = os.getenv("APP_USER", "")
APP_PASS = os.getenv("APP_PASS", "")

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_SUPER_SECRET")
JWT_ALG = "HS256"
TOKEN_EXPIRE_MIN = int(os.getenv("TOKEN_EXPIRE_MIN", "240"))

app = FastAPI(title="Zabbix-AI API (Sidecar)")

# React dev server CORS friendly


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class LoginReq(BaseModel):
    username: str
    password: str

class LoginResp(BaseModel):
    token: str

class AskReq(BaseModel):
    message: str

# Auth helpers
def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid/expired token")

def require_auth(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1].strip()
    return verify_token(token)

# Routes
@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/login", response_model=LoginResp)
def login(body: LoginReq):
    if not APP_USER or not APP_PASS:
        raise HTTPException(status_code=500, detail="APP_USER/APP_PASS not set on server")
    if body.username != APP_USER or body.password != APP_PASS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_token(body.username)}

@app.post("/api/ask")
def ask(body: AskReq, authorization: Optional[str] = Header(default=None)):
    user = require_auth(authorization)

    return {
        "answer": f"Authenticated as {user.get('sub')}. You said: {body.message}",
        "user": user.get("sub"),
    }











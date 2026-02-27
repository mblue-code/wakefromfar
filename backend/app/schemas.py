from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int


class HostOut(BaseModel):
    id: str
    name: str
    mac: str
    group_name: str | None = None
    broadcast: str | None = None
    subnet_cidr: str | None = None
    udp_port: int = 9


class WakeResponse(BaseModel):
    ok: bool
    sent_to: str
    timestamp: datetime


class AdminUserCreate(BaseModel):
    username: str
    password: str = Field(min_length=8)
    role: str = Field(pattern="^(admin|user)$")


class AdminHostCreate(BaseModel):
    id: str | None = None
    name: str
    mac: str
    group_name: str | None = None
    broadcast: str | None = None
    subnet_cidr: str | None = None
    udp_port: int = Field(default=9, ge=1, le=65535)
    interface: str | None = None

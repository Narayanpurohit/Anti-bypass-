"""Pydantic request models used by admin endpoints."""
from typing import Optional
from pydantic import BaseModel

class AddURL(BaseModel):
    label: str
    target_url: str
    captcha_enabled: bool = True
    expiry_hours: Optional[int] = None
    password: str

class ToggleURL(BaseModel):
    token: str
    active: bool
    password: str

class DeleteURL(BaseModel):
    token: str
    password: str

class BlockIPBody(BaseModel):
    ip: str
    reason: str = ""
    password: str

class UnblockIPBody(BaseModel):
    ip: str
    password: str

class SetShortenerConfig(BaseModel):
    shortener_url: str
    shortener_api_key: str
    enabled: bool = True
    password: str

class ClearShortenerConfig(BaseModel):
    password: str

class CreateAPIKey(BaseModel):
    label: str
    password: str

class DeleteAPIKey(BaseModel):
    key: str
    password: str

class ToggleAPIKey(BaseModel):
    key: str
    active: bool
    password: str
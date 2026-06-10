from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from db import create_api_key, get_api_key, log_request
from typing import Optional
import time

router = APIRouter()


class RegisterIn(BaseModel):
    email: EmailStr


class RegisterOut(BaseModel):
    api_key: str


@router.post("/register", response_model=RegisterOut, include_in_schema=True)
async def register(body: RegisterIn, request: Request):
    key = await create_api_key(body.email)
    await log_request(key, "/register", body.email, 0)
    return {"api_key": key}


async def get_api_key_dependency(request: Request):
    # Use lowercase header lookup; Starlette/FastAPI normalizes header keys to lowercase
    x_api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if not x_api_key:
        raise HTTPException(status_code=401, detail={"error": "Missing API key", "detail": "X-API-Key header required"})
    data = await get_api_key(x_api_key)
    if not data or not data.get("is_active"):
        raise HTTPException(status_code=401, detail={"error": "Invalid API key", "detail": "Key not found or inactive"})
    return x_api_key

"""Authentication endpoints: POST /auth/login, GET /auth/me."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.deps import require_admin
from app.models import LoginRequest, MeResponse, TokenResponse
from app.ratelimit import LOGIN_LIMIT, limiter, resolve_annotations
from app.security import create_access_token, verify_admin_credentials

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT)
@resolve_annotations
async def login(request: Request, response: Response, body: LoginRequest) -> TokenResponse:
    settings = request.app.state.settings
    if not verify_admin_credentials(body.username, body.password, settings.admin_user, settings.admin_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(body.username, settings.secret_key, settings.token_expire_minutes)
    return TokenResponse(access_token=token)


@router.get("/auth/me", response_model=MeResponse)
async def me(username: str = Depends(require_admin)) -> MeResponse:
    return MeResponse(username=username)

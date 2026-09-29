"""
AI Markets SSO: the marketplace API (ai-marketplace-api `POST /v1/openwebui/launch`)
sends the buyer to `https://{userId}.openwebui.aimarkets.vn/api/v1/aimarkets/sso?ticket=...`.

Ticket = base64url(JSON payload) + "." + base64url(HMAC-SHA256(secret, "aimr.v1.openwebui." + payload)),
payload = {v: 1, rt: "openwebui", uid, name, email, exp (ms), jti}. The secret is
OPENWEBUI_SSO_SECRET (or AIMARKETS_RUNTIME_SSO_SECRET) and must match the marketplace API.

Every buyer gets their own non-admin account keyed by `oauth.aimarkets.sub = uid`.
"""

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from open_webui.env import WEBUI_AUTH_COOKIE_SAME_SITE, WEBUI_AUTH_COOKIE_SECURE
from open_webui.events import EVENTS, publish_event
from open_webui.internal.db import get_async_session
from open_webui.models.auths import Auths
from open_webui.models.config import Config
from open_webui.models.users import Users
from open_webui.utils.auth import create_token, get_password_hash
from open_webui.utils.groups import apply_default_group_assignment
from open_webui.utils.misc import parse_duration
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

router = APIRouter()

RUNTIME = 'openwebui'
PROVIDER = 'aimarkets'
USER_ID_RE = re.compile(r'^[a-f0-9]{24}$')
MAX_TICKET_LEN = 4096
EMAIL_DOMAIN = os.environ.get('AIMARKETS_SSO_EMAIL_DOMAIN', 'users.aimarkets.vn').strip() or 'users.aimarkets.vn'

_used_jti: dict[str, float] = {}
_used_lock = threading.Lock()


def _secret() -> str:
    return (os.environ.get('OPENWEBUI_SSO_SECRET') or os.environ.get('AIMARKETS_RUNTIME_SSO_SECRET') or '').strip()


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _verify(ticket: str) -> dict | None:
    secret = _secret()
    raw = (ticket or '').strip()
    if not secret or not raw or len(raw) > MAX_TICKET_LEN:
        return None
    parts = raw.split('.')
    if len(parts) != 2:
        return None
    payload, sig = parts
    expected = hmac.new(
        secret.encode('utf-8'),
        f'aimr.v1.{RUNTIME}.{payload}'.encode('utf-8'),
        hashlib.sha256,
    ).digest()
    try:
        got = _b64url_decode(sig)
        data = json.loads(_b64url_decode(payload).decode('utf-8'))
    except Exception:
        return None
    if not hmac.compare_digest(got, expected):
        return None
    if not isinstance(data, dict) or data.get('v') != 1 or data.get('rt') != RUNTIME:
        return None
    uid = str(data.get('uid') or '').lower()
    exp = data.get('exp')
    if not USER_ID_RE.match(uid) or not isinstance(exp, (int, float)) or exp < time.time() * 1000:
        return None
    data['uid'] = uid
    return data


def _consume_jti(jti: str, exp_ms: float) -> bool:
    """Single-use tickets (per process); returns False when the ticket was already used."""
    now = time.time()
    with _used_lock:
        for key in [k for k, until in _used_jti.items() if until < now]:
            _used_jti.pop(key, None)
        if jti in _used_jti:
            return False
        _used_jti[jti] = exp_ms / 1000 + 60
        return True


def _host_user_id(request: Request) -> str:
    host = (request.headers.get('x-forwarded-host') or request.headers.get('host') or '').split(',')[0]
    label = host.strip().lower().split(':')[0].split('.')[0]
    return label if USER_ID_RE.match(label) else ''


def _clean_name(value, uid: str) -> str:
    name = re.sub(r'[\x00-\x1f<>]', '', str(value or '')).strip()[:80]
    return name or f'AI Markets {uid[-6:]}'


def _error(message: str, status_code: int):
    return JSONResponse(status_code=status_code, content={'detail': message})


@router.get('/sso')
async def aimarkets_sso(request: Request, ticket: str = '', db: AsyncSession = Depends(get_async_session)):
    if not _secret():
        return _error('AI Markets SSO is not configured (OPENWEBUI_SSO_SECRET).', 503)

    data = _verify(ticket)
    if not data:
        return _error('Invalid or expired AI Markets ticket. Launch Open WebUI again from aimarkets.vn.', 401)

    uid = data['uid']
    host_uid = _host_user_id(request)
    if host_uid and host_uid != uid:
        return _error('This AI Markets ticket belongs to another workspace.', 403)

    jti = str(data.get('jti') or '')
    if not jti or not _consume_jti(jti, float(data['exp'])):
        return _error('This AI Markets ticket was already used. Launch Open WebUI again.', 401)

    name = _clean_name(data.get('name'), uid)
    user = await Users.get_user_by_oauth_sub(PROVIDER, uid, db=db)
    if user is None:
        email = f'{uid}@{EMAIL_DOMAIN}'
        user = await Users.get_user_by_email(email, db=db)
        if user is not None:
            if user.role == 'admin':
                return _error('This AI Markets account is reserved.', 403)
            user = await Users.update_user_oauth_by_id(user.id, PROVIDER, uid, db=db) or user
    if user is None:
        user = await Auths.insert_new_auth(
            email=f'{uid}@{EMAIL_DOMAIN}',
            password=await get_password_hash(str(uuid.uuid4())),
            name=name,
            profile_image_url='/user.png',
            role='user',
            oauth={PROVIDER: {'sub': uid}},
            db=db,
        )
        if user is None:
            return _error('Could not create the Open WebUI account.', 500)
        await apply_default_group_assignment(await Config.get('ui.default_group_id'), user.id, db=db)
        await publish_event(
            request,
            EVENTS.USER_CREATED,
            actor=user,
            subject_id=user.id,
            source='oauth',
            data={'role': user.role, 'provider': PROVIDER},
        )
    elif user.role == 'pending':
        await Users.update_user_role_by_id(user.id, 'user', db=db)
        user = await Users.get_user_by_id(user.id, db=db) or user

    expires_delta = parse_duration(await Config.get('auth.jwt_expiry'))
    token = create_token(data={'id': user.id}, expires_delta=expires_delta)
    max_age = int(expires_delta.total_seconds()) if expires_delta else None

    # Relative redirect keeps the buyer on their own {userId}.openwebui host.
    response = RedirectResponse(url='/auth', status_code=303)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.set_cookie(
        key='token',
        value=token,
        httponly=False,  # the /auth page reads it (same as the OAuth callback)
        samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
        secure=WEBUI_AUTH_COOKIE_SECURE,
        **(
            {
                'max_age': max_age,
                'expires': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=max_age),
            }
            if max_age is not None
            else {}
        ),
    )
    await publish_event(
        request,
        EVENTS.AUTH_LOGIN,
        actor=user,
        subject_id=user.id,
        subject_type='user',
        source='oauth',
        data={'auth_method': 'oauth', 'provider': PROVIDER},
    )
    return response

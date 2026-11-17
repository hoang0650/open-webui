"""Shared single-use SSO claims; no process-local fallback across workers/replicas."""
import hashlib
import math
import time


class ReplayStoreUnavailable(Exception):
    pass


async def consume_ticket(jti: str, exp_ms: float, client, now_ms=None) -> bool:
    now = time.time() * 1000 if now_ms is None else now_ms
    if not isinstance(jti, str) or not jti or len(jti) > 256:
        return False
    if not isinstance(exp_ms, (float, int)) or not math.isfinite(exp_ms):
        return False
    ttl = math.ceil((exp_ms - now) / 1000)
    if ttl <= 0 or ttl > 180:
        return False
    if client is None:
        raise ReplayStoreUnavailable('Shared SSO replay store unavailable')
    key = 'aimarkets:openwebui:sso-used:' + hashlib.sha256(jti.encode()).hexdigest()
    try:
        return bool(await client.set(key, '1', nx=True, ex=ttl))
    except Exception as exc:
        raise ReplayStoreUnavailable('Shared SSO replay store unavailable') from exc

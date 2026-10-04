"""
Ponytail coding ruleset for AI Markets chats, fetched from the shared Ponytail
service (PONYTAIL_URL, see ponytail/deploy/DOKPLOY.md) and prepended to the
system message by `process_chat_payload`.

Never raises: an unreachable service serves the last good copy, or nothing.
"""

import asyncio
import logging
import os
import time

import aiohttp

log = logging.getLogger(__name__)

REFRESH_SECONDS = 600
RETRY_SECONDS = 60
TIMEOUT_SECONDS = 3
MODES = {'compact', 'lite', 'full', 'ultra', 'off'}


class PonytailRules:
    def __init__(self, url: str, mode: str = '', clock=time.monotonic):
        requested = (mode or '').strip().lower()
        self.mode = requested if requested in MODES else 'compact'
        self.base = (url or '').strip().rstrip('/')
        self.enabled = bool(self.base) and self.mode != 'off'
        self._clock = clock
        self._text = ''
        self._etag = ''
        self._next_refresh = 0.0
        self._task: asyncio.Task | None = None

    async def _refresh(self) -> None:
        headers = {'If-None-Match': self._etag} if self._etag else {}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)) as session:
                async with session.get(f'{self.base}/v1/rules', params={'mode': self.mode}, headers=headers) as r:
                    if r.status != 304:
                        r.raise_for_status()
                        body = (await r.text()).strip()
                        if body:
                            self._text = body
                            self._etag = r.headers.get('ETag', '')
            self._next_refresh = self._clock() + REFRESH_SECONDS
        except Exception as e:
            log.warning(f'Ponytail rules unavailable from {self.base}: {e}')
            self._next_refresh = self._clock() + RETRY_SECONDS

    async def get(self) -> str:
        if not self.enabled:
            return ''
        if self._clock() >= self._next_refresh and (self._task is None or self._task.done()):
            self._task = asyncio.create_task(self._refresh())
        # Serve the last good copy while revalidating; only the very first fetch waits.
        if not self._text and self._task is not None:
            await asyncio.shield(self._task)
        return self._text


ponytail_rules = PonytailRules(os.environ.get('PONYTAIL_URL', ''), os.environ.get('PONYTAIL_MODE', 'compact'))

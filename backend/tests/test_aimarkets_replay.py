import asyncio
import importlib.util
from pathlib import Path
import unittest
import os
import uuid
import hashlib

spec = importlib.util.spec_from_file_location('aimarkets_replay', Path(__file__).parents[1] / 'open_webui/utils/aimarkets_replay.py')
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


class Client:
    def __init__(self, store):
        self.store = store

    async def set(self, key, value, *, nx, ex):
        assert nx and 0 < ex <= 180
        if key in self.store:
            return None
        self.store[key] = value
        return True


class ReplayTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(os.environ.get('RUN_REDIS_INTEGRATION') == '1', 'CI Redis integration')
    async def test_real_redis_two_connections_reject_replay(self):
        from redis.asyncio import Redis
        clients = [Redis.from_url('redis://127.0.0.1:6379') for _ in range(2)]
        jti = 'ci-' + str(uuid.uuid4())
        key = 'aimarkets:openwebui:sso-used:' + hashlib.sha256(jti.encode()).hexdigest()
        try:
            results = await asyncio.gather(*(replay.consume_ticket(jti, replay.time.time() * 1000 + 120000, clients[i % 2]) for i in range(20)))
            self.assertEqual(sum(results), 1)
        finally:
            await clients[0].delete(key)
            for client in clients:
                await client.aclose()

    async def test_two_replicas_have_exactly_one_winner(self):
        shared = {}
        clients = [Client(shared), Client(shared)]
        results = await asyncio.gather(*(replay.consume_ticket('same-ticket', 120000, clients[i % 2], now_ms=0) for i in range(20)))
        self.assertEqual(sum(results), 1)

    async def test_no_ram_fallback_when_shared_store_is_missing_or_down(self):
        with self.assertRaises(replay.ReplayStoreUnavailable):
            await replay.consume_ticket('valid-ticket', 120000, None, now_ms=0)

        class Broken:
            async def set(self, *args, **kwargs):
                raise ConnectionError('unavailable')

        with self.assertRaises(replay.ReplayStoreUnavailable):
            await replay.consume_ticket('valid-ticket', 120000, Broken(), now_ms=0)

    async def test_invalid_or_expired_claims_do_not_touch_redis(self):
        for jti, exp in [('', 120000), ('x', float('nan')), ('x', 0), ('x', 999999)]:
            self.assertFalse(await replay.consume_ticket(jti, exp, None, now_ms=0))


if __name__ == '__main__':
    unittest.main()

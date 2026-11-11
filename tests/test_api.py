"""HTTP API tests.

These need ``fastapi`` and ``httpx``.  When those packages are not installed the
whole class is skipped, so the standard-library forwarder tests still run with
plain ``python -m unittest``.
"""

import ipaddress
import os
import time
import unittest

try:
    import httpx
    from app.main import app
    _DEPS_OK = True
except Exception:  # pragma: no cover - exercised only without deps
    httpx = None
    app = None
    _DEPS_OK = False

if _DEPS_OK:
    from app.forwarder import DnsForwarder, ForwarderConfig
    from app.test_upstream import TestUpstreamServer, UpstreamConfig, _answer_ip


_ENV_KEYS = (
    "DNS_FORWARDER_HOST", "DNS_FORWARDER_PORT",
    "DNS_QUERY_TIMEOUT_SECONDS", "PUBLIC_DNS_HOST", "PUBLIC_DNS_PORT",
    "DNS_UPSTREAM_LABEL",
)


@unittest.skipUnless(_DEPS_OK, "fastapi/httpx not installed")
class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._old_env = {key: os.environ.get(key) for key in _ENV_KEYS}
        self.upstream = TestUpstreamServer(UpstreamConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            default_ttl=5,
            delay_seconds=0.2,
            wrongq_delay=0.02,
            ooo_window=0.12,
        ))
        await self.upstream.start()
        self.forwarder = DnsForwarder(ForwarderConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            upstream_host="127.0.0.1",
            upstream_port=self.upstream.port,
            timeout=0.6,
            cache_size=200,
        ))
        await self.forwarder.start()
        os.environ["DNS_FORWARDER_HOST"] = "127.0.0.1"
        os.environ["DNS_FORWARDER_PORT"] = str(self.forwarder.listen_port)
        os.environ["DNS_QUERY_TIMEOUT_SECONDS"] = "2.5"
        os.environ["PUBLIC_DNS_HOST"] = "127.0.0.1"
        os.environ["PUBLIC_DNS_PORT"] = "25353"
        os.environ["DNS_UPSTREAM_LABEL"] = "test-upstream"
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        await self.forwarder.close()
        await self.upstream.close()
        for key, value in self._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    async def test_index_page_and_health(self):
        response = await self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("DNS 转发服务", response.text)
        self.assertIn("并发查询", response.text)

        response = await self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    async def test_config_endpoint(self):
        response = await self.client.get("/api/config")
        payload = response.json()
        self.assertEqual(payload["forwarder"]["host"], "127.0.0.1")
        self.assertEqual(payload["forwarder"]["port"], self.forwarder.listen_port)
        self.assertEqual(payload["supported"]["qtype"], "A")
        self.assertFalse(payload["supported"]["edns"])
        self.assertEqual(payload["upstreamLabel"], "test-upstream")

    async def test_single_query_uses_requested_id_and_reports_answer_and_time(self):
        response = await self.client.post("/api/query", json={
            "name": "www.example.test",
            "qid": 0x1234,
        })
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["timedOut"])
        self.assertEqual(payload["query"]["qid"], 0x1234)
        self.assertEqual(payload["response"]["id"], 0x1234)
        self.assertEqual(payload["response"]["rcodeName"], "NOERROR")
        self.assertGreaterEqual(payload["elapsedMs"], 0.0)
        answer = payload["response"]["answers"][0]
        expected = _answer_ip(answer["name"])
        self.assertEqual(answer["data"], expected)
        self.assertEqual(ipaddress.IPv4Address(answer["data"]),
                         ipaddress.IPv4Address(expected))

    async def test_single_query_aliases(self):
        # domain/id spellings are accepted too.
        response = await self.client.post("/api/dns-query", json={
            "domain": "alias.example.test",
            "id": 0x2222,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["response"]["id"], 0x2222)

    async def test_batch_concurrent_same_id_gets_each_own_answer(self):
        names = ["batch-1.example.test", "batch-2.example.test",
                 "batch-3.example.test"]
        response = await self.client.post("/api/query-batch", json={
            "queries": [{"name": name, "qid": 0x7777} for name in names],
        })
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["count"], 3)
        answers = []
        for name, result in zip(names, payload["results"]):
            self.assertTrue(result["ok"])
            self.assertEqual(result["response"]["id"], 0x7777)
            self.assertEqual(result["response"]["question"]["name"],
                             name + ".")
            answer = result["response"]["answers"][0]
            self.assertEqual(answer["data"], _answer_ip(name + "."))
            answers.append(answer["data"])
        self.assertEqual(len(set(answers)), len(answers))

    async def test_timeout_becomes_servfail_visible_to_page(self):
        started = time.perf_counter()
        response = await self.client.post("/api/query", json={
            "name": "drop-api.example.test",
            "qid": 0x5555,
        })
        elapsed = time.perf_counter() - started
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])          # a DNS response did arrive
        self.assertTrue(payload["servfail"])
        self.assertEqual(payload["response"]["id"], 0x5555)
        self.assertEqual(payload["response"]["rcodeName"], "SERVFAIL")
        self.assertEqual(payload["response"]["answers"], [])
        self.assertGreaterEqual(payload["elapsedMs"], 450)
        self.assertLess(elapsed, 2.3)

    async def test_invalid_name_is_http_400(self):
        response = await self.client.post("/api/query", json={
            "name": "bad..name",
            "qid": 1,
        })
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["detail"]["ok"])

        response = await self.client.post("/api/query-batch", json={
            "queries": [{"name": "good.example.test", "qid": 1},
                        {"name": "bad..name", "qid": 2}],
        })
        self.assertEqual(response.status_code, 400)

    async def test_bad_qid_is_validation_error(self):
        response = await self.client.post("/api/query", json={
            "name": "www.example.test",
            "qid": 70000,
        })
        self.assertEqual(response.status_code, 422)

    async def test_ready_checks_end_to_end_chain(self):
        response = await self.client.get("/api/ready")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["answers"])


if __name__ == "__main__":
    unittest.main()

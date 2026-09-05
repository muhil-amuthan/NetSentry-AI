"""
Tests for the FastAPI application shell (Step 4 regression guard).

Step 4 adds data, not endpoints, so these tests simply prove the existing
application still starts and still serves both the health check and the
dashboard. They call the ASGI app directly, which needs no extra dependency;
when ``httpx`` is installed the official ``TestClient`` is used instead.

Run with::

    python -m unittest discover -s tests -t tests
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:  # pragma: no cover - depends on the environment
    from fastapi.testclient import TestClient  # type: ignore

    HAVE_TEST_CLIENT = True
except Exception:  # pragma: no cover - httpx not installed
    TestClient = None  # type: ignore
    HAVE_TEST_CLIENT = False

from app import app  # noqa: E402


def call_asgi(path: str, method: str = "GET") -> Tuple[int, Dict[str, str], bytes]:
    """Drive one request through the ASGI app without an HTTP server."""
    scope: Dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.1"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"localhost:8000"), (b"accept", b"*/*")],
        "client": ("127.0.0.1", 51000),
        "server": ("localhost", 8000),
    }
    messages: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        messages.append(message)

    asyncio.run(app(scope, receive, send))

    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    return int(start["status"]), headers, body


class TestApplicationStartup(unittest.TestCase):
    """7. The existing FastAPI application still starts and serves."""

    def test_app_object_is_importable(self):
        self.assertEqual(app.title, "NetSentry-AI")

    def test_routes_registered(self):
        # API routes: ask the OpenAPI schema, because included routers are not
        # necessarily flattened onto app.routes across FastAPI versions.
        api_paths = set(app.openapi()["paths"])
        self.assertIn("/api/health", api_paths)

        # Static frontend mount.
        mounts = {getattr(route, "path", None) for route in app.routes}
        self.assertTrue("" in mounts or "/" in mounts, f"no static mount: {mounts}")

    def test_health_endpoint(self):
        status, headers, body = call_asgi("/api/health")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("content-type", ""))
        payload = json.loads(body)
        # Health must at least contain status ok and project name; extra fields (version, scenario) are allowed in later steps.
        self.assertEqual(payload.get("status"), "ok")
        self.assertEqual(payload.get("project"), "NetSentry-AI")

    def test_dashboard_still_served(self):
        status, headers, body = call_asgi("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"NetSentry", body)

    def test_frontend_assets_intact(self):
        for name in ("index.html", "app.js", "data.js", "style.css"):
            self.assertTrue(Path("frontend", name).exists(), f"frontend/{name} missing")

    @unittest.skipUnless(HAVE_TEST_CLIENT, "fastapi TestClient needs httpx")
    def test_health_via_test_client(self):  # pragma: no cover - optional path
        with TestClient(app) as client:
            response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")


class TestGeneratorStaysOutOfTheApp(unittest.TestCase):
    """Generator logic lives in src/generator.py, not in the app entry point."""

    def test_app_does_not_contain_generator_logic(self):
        source = Path("app.py").read_text(encoding="utf-8")
        self.assertNotIn("generator", source)
        self.assertNotIn("sample_alerts", source)

    def test_api_module_unchanged_for_step4(self):
        source = Path("src/api.py").read_text(encoding="utf-8")
        self.assertIn("/api/health", source)


if __name__ == "__main__":
    unittest.main()

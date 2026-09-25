import importlib
import json
import os
import unittest

try:
    from fastapi.testclient import TestClient
except ImportError:  # the API is an optional extra
    TestClient = None

from pcapgen import basic_call, pcap


@unittest.skipIf(TestClient is None, "fastapi não instalado (pip install .[api])")
class ApiTests(unittest.TestCase):
    def setUp(self):
        os.environ["SIP_NETWORK_API_TOKEN"] = "segredo"
        os.environ["SIP_NETWORK_MAX_UPLOAD_MB"] = "1"
        import api
        self.api = importlib.reload(api)
        self.client = TestClient(self.api.app)
        self.auth = {"Authorization": "Bearer segredo"}

    def test_health(self):
        self.assertEqual(self.client.get("/health").json()["status"], "ok")

    def test_rejects_missing_token(self):
        r = self.client.post("/v1/analyze", files={"file": ("a.pcap", pcap(basic_call()))})
        self.assertEqual(r.status_code, 401)

    def test_analyze(self):
        r = self.client.post("/v1/analyze", headers=self.auth, files={"file": ("a.pcap", pcap(basic_call()))},
                             data={"thresholds": json.dumps({"pdd_warning_ms": 500})})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["schema_version"], "2.1")
        self.assertEqual(body["kpis"]["calls"]["answered"], 1)
        self.assertTrue(body["calls"][0]["ladder_svg"].startswith("<svg"))
        self.assertNotIn("raw_headers", body["calls"][0]["messages"][0])
        self.assertIn("SIP_HIGH_PDD", {d["code"] for d in body["diagnostics"]})

    def test_limits_and_errors(self):
        big = self.client.post("/v1/analyze", headers=self.auth, files={"file": ("a.pcap", b"\0" * (1024 * 1024 + 1))})
        self.assertEqual(big.status_code, 413)
        bad = self.client.post("/v1/analyze", headers=self.auth, files={"file": ("a.txt", b"not a capture")})
        self.assertEqual(bad.status_code, 422)
        th = self.client.post("/v1/analyze", headers=self.auth, files={"file": ("a.pcap", pcap(basic_call()))},
                              data={"thresholds": '{"nope": 1}'})
        self.assertEqual(th.status_code, 422)


if __name__ == "__main__":
    unittest.main()

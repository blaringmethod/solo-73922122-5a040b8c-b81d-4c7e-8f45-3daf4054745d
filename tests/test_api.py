"""FastAPI 接口测试。"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

GOOD_OLD = '''[
  {"id": 1, "source": "10.0.0.0/8", "destination": "172.16.0.0/12",
   "portRange": [80, 80], "action": "allow"}
]'''
GOOD_NEW = '''[
  {"id": 1, "source": "10.0.0.0/8", "destination": "172.16.0.0/12",
   "portRange": [80, 80], "action": "deny"}
]'''


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_index_page_served():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "防火墙规则变更差分台" in resp.text


def test_analyze_happy_path():
    resp = client.post("/api/analyze", json={"old": GOOD_OLD, "new": GOOD_NEW})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    result = data["result"]
    # allow -> deny：唯一一块新增阻断
    assert result["summary"]["newlyDeniedBlockCount"] == 1
    assert result["summary"]["newlyAllowedBlockCount"] == 0
    blk = result["newlyDenied"][0]
    assert blk["source"]["cidr"] == "10.0.0.0/8"
    assert blk["destination"]["cidr"] == "172.16.0.0/12"
    assert blk["port"]["start"] == 80
    assert blk["oldVerdict"]["action"] == "allow"
    assert blk["newVerdict"]["action"] == "deny"
    assert blk["representativePacket"]["protocol"] == "TCP"


def test_analyze_validation_error_400_with_location():
    bad = '[{"id": 1, "source": "10.0.0.5/24", "destination": "0.0.0.0/0",' \
          ' "portRange": [80], "action": "maybe"}]'
    resp = client.post("/api/analyze", json={"old": GOOD_OLD, "new": bad})
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    fields = {e.get("field") for e in data["errors"]}
    assert {"source", "portRange", "action"} <= fields
    assert all(e["sheet"] == "new" for e in data["errors"])


def test_analyze_json_syntax_error_location():
    resp = client.post("/api/analyze",
                       json={"old": "not json at all", "new": GOOD_NEW})
    assert resp.status_code == 400
    err = resp.json()["errors"][0]
    assert err["sheet"] == "old" and "JSON" in err["message"]


def test_example_endpoint_loadable_and_diff_runs():
    resp = client.get("/api/example")
    assert resp.status_code == 200
    payload = resp.json()
    assert isinstance(payload["old"], list) and isinstance(payload["new"], list)
    # 示例自身必须通过校验并产生结果
    import json
    resp2 = client.post("/api/analyze", json={
        "old": json.dumps(payload["old"]),
        "new": json.dumps(payload["new"]),
    })
    assert resp2.status_code == 200
    body = resp2.json()
    assert body["ok"] is True
    assert body["result"]["summary"]["totalChangedBlockCount"] >= 1


def test_missing_body_field_422():
    resp = client.post("/api/analyze", json={"old": GOOD_OLD})
    assert resp.status_code == 422

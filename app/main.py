"""
FastAPI web application: browser demo page plus a small HTTP -> real UDP query
bridge.

The browser cannot send UDP directly, so every request to ``/api/query`` opens
its own ephemeral UDP socket and sends a genuine DNS packet to the forwarding
service (configured with ``DNS_FORWARDER_HOST`` / ``DNS_FORWARDER_PORT``).  Two
concurrent HTTP requests therefore look like two distinct DNS clients and may
reuse the same transaction ID without interfering with each other.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import socket
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from .dns import (
    DnsFormatError,
    Message,
    Question,
    ResourceRecord,
    build_query,
    make_question,
    parse_message,
    rdata_to_text,
    text_to_labels,
)

LOG = logging.getLogger("dns.web")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="DNS 转发服务 · 并发查询复现台",
    description=(
        "单进程 UDP DNS A/IN 转发服务，带严格上游校验、随机唯一上游 ID、"
        "2 秒超时 SERVFAIL 与最小 TTL 缓存；本页可发起真实并发 UDP 查询。"
    ),
    version="1.0.0",
)

SUPPORTED_SCENARIOS = {
    "normal": "普通域名：返回由域名哈希决定的 198.51.100.x A 记录",
    "same-id": "并发查询 + 相同查询 ID：每个客户端仍须得到自己域名的答案",
    "wrongq": "错误问题包：上游先发问题不匹配的伪造应答，转发器必须忽略并等待正确应答",
    "wrongqr": "QR=0 伪造包：先发不带 QR 的包，转发器必须忽略",
    "wrongsrc": "错误来源包：先从其它源端口发应答，转发器必须忽略",
    "ooo": "倒序应答：并发查询先到后答、后到先答，仍不得串答",
    "delay": "延迟应答：延迟后返回，仍在 2 秒内",
    "drop": "无应答：上游不回复，转发器 2 秒后返回 SERVFAIL",
    "ttlN": "指定 TTL：例如 ttl5；用于观察缓存命中时 TTL 扣减且寿命不延长",
    "cname": "CNAME+A：应答合法但含非 A 记录，不进入缓存",
    "mixed": "混入其它域名 A：应答含非所问域名的答案，不进入缓存",
    "multi": "两条 A 记录：缓存寿命取最小 TTL",
    "trunc": "TC=1：截断应答不进入缓存",
    "nxdomain": "NXDOMAIN：失败应答不进入缓存",
}


# --------------------------------------------------------------------------- #
# Configuration (read per request so deployments/tests can change it)
# --------------------------------------------------------------------------- #
def _env_first(*names: str, default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def forwarder_address() -> tuple[str, int]:
    host = _env_first("DNS_FORWARDER_HOST", "FORWARDER_HOST",
                      default="127.0.0.1") or "127.0.0.1"
    raw_port = _env_first("DNS_FORWARDER_PORT", "FORWARDER_PORT", default="25353")
    try:
        port = int(raw_port)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"DNS_FORWARDER_PORT 不是合法整数：{raw_port!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"DNS_FORWARDER_PORT 超出范围：{port}")
    return host, port


def query_timeout_seconds() -> float:
    raw = _env_first("DNS_QUERY_TIMEOUT_SECONDS", "QUERY_TIMEOUT_SECONDS",
                     default="3.0")
    try:
        value = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"DNS_QUERY_TIMEOUT_SECONDS 不是数字：{raw!r}") from exc
    if value <= 0:
        raise ValueError("DNS_QUERY_TIMEOUT_SECONDS 必须大于 0")
    return value


# --------------------------------------------------------------------------- #
# Request models (accept several common field spellings)
# --------------------------------------------------------------------------- #
class QueryItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str = Field(
        description="要查询的域名",
        validation_alias=AliasChoices("name", "domain", "qname"),
    )
    qid: Optional[int] = Field(
        default=None, ge=0, le=65535,
        description="客户端 DNS 事务 ID（0-65535）；省略时随机生成",
        validation_alias=AliasChoices("qid", "id", "queryId", "query_id"),
    )
    timeout_ms: Optional[int] = Field(
        default=None, ge=1, le=60000,
        description="本次网页端等待时间（毫秒）；默认 3000",
        validation_alias=AliasChoices("timeoutMs", "timeout_ms"),
    )


class BatchRequest(BaseModel):
    queries: list[QueryItem] = Field(..., min_length=1, max_length=256,
                                     description="要并发发起的查询列表")


# --------------------------------------------------------------------------- #
# UDP client used by the HTTP bridge
# --------------------------------------------------------------------------- #
class _UdpClientProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.future: asyncio.Future = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        if not self.future.done():
            self.future.set_exception(exc)


async def _udp_exchange(host: str, port: int, packet: bytes,
                        timeout: float) -> bytes:
    """One real UDP round trip on its own ephemeral socket (one DNS client)."""
    loop = asyncio.get_running_loop()
    protocol = _UdpClientProtocol()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        remote_addr=(host, port),
        family=socket.AF_INET,
    )
    try:
        transport.sendto(packet)
        return await asyncio.wait_for(protocol.future, timeout)
    finally:
        transport.close()


# --------------------------------------------------------------------------- #
# Response serialization
# --------------------------------------------------------------------------- #
def _question_json(question: Question) -> dict:
    return {
        "name": question.name,
        "type": question.qtype,
        "typeName": "A" if question.qtype == 1 else f"TYPE{question.qtype}",
        "class": question.qclass,
        "className": "IN" if question.qclass == 1 else f"CLASS{question.qclass}",
    }


def _rr_json(rr: ResourceRecord) -> dict:
    return {
        "name": rr.name,
        "type": rr.rtype,
        "typeName": rr.type_name,
        "class": rr.rclass,
        "className": rr.class_name,
        "ttl": rr.ttl,
        "data": rdata_to_text(rr),
    }


def _message_json(message: Message) -> dict:
    return {
        "id": message.msg_id,
        "idHex": f"0x{message.msg_id:04x}",
        "rcode": message.rcode,
        "rcodeName": message.rcode_name,
        "flags": {
            "qr": message.qr,
            "aa": message.aa,
            "tc": message.tc,
            "rd": message.rd,
            "ra": message.ra,
        },
        "question": (_question_json(message.questions[0])
                     if message.questions else None),
        "answers": [_rr_json(rr) for rr in message.answers],
        "authorities": [_rr_json(rr) for rr in message.authorities],
        "additionals": [_rr_json(rr) for rr in message.additionals],
    }


def _query_echo(name: str, labels, qid: int) -> dict:
    return {
        "name": name,
        "canonicalName": ".".join(labels) + "." if labels else ".",
        "qid": qid,
        "qidHex": f"0x{qid:04x}",
        "type": "A",
        "class": "IN",
    }


# --------------------------------------------------------------------------- #
# Core query function
# --------------------------------------------------------------------------- #
async def _resolve_one(item: QueryItem) -> dict:
    """
    Validate, send a real UDP query and return a UI-friendly result.

    Network timeout is *not* an HTTP error: it is reported as
    ``{"ok": false, "timedOut": true, ...}``.  A SERVFAIL from the forwarder is
    a valid DNS response and therefore has ``ok=true`` with rcode 2.
    """
    try:
        labels = text_to_labels(item.name)
    except ValueError as exc:
        return {"ok": False, "timedOut": False,
                "query": {"name": item.name},
                "error": f"域名无效：{exc}"}

    qid = item.qid if item.qid is not None else secrets.randbelow(65536)
    question = make_question(labels)
    packet = build_query(qid, labels, question.qtype, question.qclass, rd=True)

    try:
        host, port = forwarder_address()
        timeout = (item.timeout_ms / 1000.0 if item.timeout_ms is not None
                   else query_timeout_seconds())
    except ValueError as exc:
        return {"ok": False, "timedOut": False,
                "query": {"name": item.name, "qid": qid},
                "error": f"服务配置错误：{exc}"}

    started = time.perf_counter()
    try:
        raw = await _udp_exchange(host, port, packet, timeout)
    except (asyncio.TimeoutError, TimeoutError):
        elapsed = (time.perf_counter() - started) * 1000.0
        LOG.warning("web query timeout %s qid=0x%04x after %.0fms",
                    item.name, qid, elapsed)
        return {
            "ok": False,
            "timedOut": True,
            "elapsedMs": round(elapsed, 3),
            "query": _query_echo(item.name, labels, qid),
            "error": f"等待 UDP 应答超时（{timeout:.2f}s）",
        }
    except (OSError, socket.gaierror) as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        return {
            "ok": False,
            "timedOut": False,
            "elapsedMs": round(elapsed, 3),
            "query": _query_echo(item.name, labels, qid),
            "error": f"UDP 通信失败：{exc}",
        }

    elapsed = (time.perf_counter() - started) * 1000.0
    try:
        message = parse_message(raw)
    except DnsFormatError as exc:
        return {
            "ok": False,
            "timedOut": False,
            "elapsedMs": round(elapsed, 3),
            "query": _query_echo(item.name, labels, qid),
            "error": f"收到无法解析的应答：{exc}",
            "rawBytes": len(raw),
        }

    # The web bridge, being a DNS client itself, checks that the response
    # belongs to its query.  This also makes a cross-answer visible in the UI.
    if not message.qr:
        return {
            "ok": False,
            "timedOut": False,
            "elapsedMs": round(elapsed, 3),
            "query": _query_echo(item.name, labels, qid),
            "error": "收到的报文没有 QR 位（不是 DNS 应答）",
            "response": _message_json(message),
        }
    if message.msg_id != qid:
        return {
            "ok": False,
            "timedOut": False,
            "elapsedMs": round(elapsed, 3),
            "query": _query_echo(item.name, labels, qid),
            "error": (f"应答 ID 不匹配：期望 0x{qid:04x}，"
                      f"收到 0x{message.msg_id:04x}（疑似串答）"),
            "response": _message_json(message),
        }
    if len(message.questions) != 1 \
            or not message.questions[0].same_question(question):
        return {
            "ok": False,
            "timedOut": False,
            "elapsedMs": round(elapsed, 3),
            "query": _query_echo(item.name, labels, qid),
            "error": "应答问题与查询不匹配（疑似串答或伪造应答）",
            "response": _message_json(message),
        }

    return {
        "ok": True,
        "timedOut": False,
        "elapsedMs": round(elapsed, 3),
        "query": _query_echo(item.name, labels, qid),
        "response": _message_json(message),
        "servfail": message.rcode == 2,
    }


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/health")
def health() -> dict[str, str]:
    """Cheap liveness check (does not touch the network)."""
    return {"status": "ok"}


@app.get("/api/config")
def get_config() -> dict:
    try:
        host, port = forwarder_address()
        timeout = query_timeout_seconds()
        config_error = None
    except ValueError as exc:  # pragma: no cover - misconfiguration
        host, port, timeout = "127.0.0.1", 25353, 3.0
        config_error = str(exc)

    public_host = _env_first("PUBLIC_DNS_HOST", default=host) or host
    raw_public_port = _env_first("PUBLIC_DNS_PORT", default=str(port))
    try:
        public_port = int(raw_public_port)  # type: ignore[arg-type]
    except (TypeError, ValueError):  # pragma: no cover
        public_port = port

    return {
        "forwarder": {"host": host, "port": port},
        "publicDns": {"host": public_host, "port": public_port},
        "upstreamLabel": _env_first("DNS_UPSTREAM_LABEL", default="") or "",
        "queryTimeoutSeconds": timeout,
        "supported": {
            "questions": 1,
            "qtype": "A",
            "qclass": "IN",
            "edns": False,
        },
        "scenarios": SUPPORTED_SCENARIOS,
        "configError": config_error,
    }


@app.get("/api/ready")
async def ready() -> JSONResponse:
    """End-to-end readiness: a real UDP query through the forwarder/upstream."""
    name = f"ready-{secrets.randbelow(1 << 20)}.probe.test"
    qid = secrets.randbelow(65536)
    result = await _resolve_one(QueryItem(name=name, qid=qid))
    response = result.get("response") or {}
    if not result.get("ok") or response.get("rcode") != 0 \
            or not response.get("answers"):
        return JSONResponse(status_code=503, content={
            "status": "degraded",
            "elapsedMs": result.get("elapsedMs"),
            "error": result.get("error", "forwarder/upstream not answering"),
        })
    return JSONResponse(content={
        "status": "ok",
        "elapsedMs": result.get("elapsedMs"),
        "answers": response.get("answers"),
    })


@app.post("/api/query")
@app.post("/api/dns-query")
@app.post("/api/resolve")
@app.post("/api/dns/query")
@app.post("/query")
@app.post("/resolve")
async def api_query(item: QueryItem) -> dict:
    """Send one real UDP DNS query with the caller-specified transaction ID."""
    try:
        text_to_labels(item.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={
            "ok": False,
            "error": f"域名无效：{exc}",
            "name": item.name,
        })
    return await _resolve_one(item)


@app.post("/api/query-batch")
@app.post("/api/dns-query-batch")
@app.post("/api/dns/query-batch")
@app.post("/query-batch")
async def api_query_batch(request: BatchRequest) -> dict:
    """
    Send all queries concurrently.  Every item gets its own UDP socket, so
    same-ID queries from the browser are independent DNS clients.
    """
    # Validate names up front so a malformed entry does not partially run.
    errors = []
    for index, item in enumerate(request.queries):
        try:
            text_to_labels(item.name)
        except ValueError as exc:
            errors.append({"index": index, "name": item.name,
                           "error": str(exc)})
    if errors:
        raise HTTPException(status_code=400, detail={
            "ok": False,
            "error": "存在无效域名",
            "details": errors,
        })

    results = await asyncio.gather(
        *(_resolve_one(item) for item in request.queries))
    return {"ok": True, "count": len(results), "results": results}


@app.exception_handler(Exception)
def unhandled(_request, exc: Exception) -> JSONResponse:  # pragma: no cover
    LOG.exception("unhandled web error")
    return JSONResponse(status_code=500, content={
        "ok": False,
        "error": f"服务器内部错误：{type(exc).__name__}: {exc}",
    })


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)

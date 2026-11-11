# DNS 转发服务 · 并发查询复现台

内网运维场景用的单进程 UDP DNS 转发器，配套一个浏览器查询页。转发器只接受
**单问题、A / IN、无 EDNS** 的查询，向上游转发时使用**随机且待处理查询中唯一**
的事务 ID，严格校验回包的来源、QR 位与完整问题，2 秒超时返回 `SERVFAIL`，
并只缓存通过全部校验的成功 A 应答。页面通过 HTTP 桥为每个请求新建真实 UDP
套接字，可并发指定域名与客户端 ID，直观复现“同 ID 串答 / 伪造应答 / 倒序回复”。

## 快速启动（Docker Compose）

```bash
docker compose up --build
# 浏览器打开 http://127.0.0.1:8000
```

Compose 提供三个服务，全部在同一个镜像上运行：

| 服务 | 作用 | 宿主机入口 |
| --- | --- | --- |
| `dns-web` | 查询页 + HTTP→真实 UDP 查询桥 | `http://127.0.0.1:8000` |
| `dns-forwarder` | 单进程 UDP 转发器 | `127.0.0.1:25353/udp` → 容器 `25353/udp` |
| `test-upstream` | 可编排的本地实验上游 | `127.0.0.1:25354/udp` → 容器 `25354/udp` |

默认只绑定宿主机回环地址。需要对局域网开放时，把 `docker-compose.yml` 中
`127.0.0.1:8000:8000` 改成 `"8000:8000"`（UDP 端口同理）。

不用浏览器也可以直接用 DNS 客户端验证转发器（宿主机端口 25353）：

```bash
dig @127.0.0.1 -p 25353 www.example.test A
# 没有 dig 时可用标准库：
python3 - <<'PY'
import socket, struct
q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
q += b"\x03www\x07example\x04test\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ("127.0.0.1", 25353))
print(s.recvfrom(4096)[0].hex())
PY
```

## 页面怎么用

1. 每行填写一个域名和一个客户端查询 ID（十进制，或 `0x1234` 形式）。
2. 点 **并发查询**：浏览器对每一行各发一个 `POST /api/query`；后端为每个请求
   新建独立 UDP 套接字（独立源端口），因此即使多行 ID 完全相同，转发器也必须
   分别投递答案。
3. 结果卡片显示：客户端请求 ID、应答 ID、DNS 耗时、HTTP 往返、RCODE、答案
   （A 记录值与 TTL）、标志位（QR/AA/TC/RD/RA）以及原始 JSON。

页面内置场景预设：

| 预设 | 使用的实验域名 | 预期 |
| --- | --- | --- |
| 同 ID 并发 | `sameid-*`，全部同一 ID | 每个卡片得到自己域名的不同 `198.51.100.x` |
| 倒序应答 | `ooo-*` | 上游攒批后按相反顺序回复，仍不串答 |
| 错误问题包 | `wrongq-*` | 上游先发问题不匹配的伪造包再发正确包；页面只显示正确 IP |
| 错误来源包 | `wrongsrc-*` | 上游先从其它源端口发伪造包；被来源校验丢弃 |
| 延迟应答 | `delay-*` | 约 0.6 秒后返回，仍在超时内 |
| 无应答超时 | `drop-*` | 约 2 秒后返回 `SERVFAIL` |
| 缓存 TTL | `ttl5-cache.example.test` | 第二次查询命中缓存：ID 恢复、TTL 按已过秒数扣减 |

**缓存 TTL 演示**：载入“缓存 TTL”预设后点一次“并发查询”，再点第二次。第二次
不会再访问上游，两个不同客户端 ID 都会恢复成各自的 ID；TTL 从 5 递减。连续
多次命中不会延长缓存寿命，超过最小 TTL 后必须重新访问上游。

## 本地上游的可编排行为

`test-upstream` 对普通域名根据域名哈希返回确定的 `198.51.100.x` A 记录，并用
域名标签选择特殊行为：

| 标签 | 行为 |
| --- | --- |
| `drop` | 完全不回复 → 转发器 2 秒后给客户端 `SERVFAIL` |
| `wrongq` | 先发一个**问题不匹配**的伪造应答（含伪造 A），再发正确应答 |
| `wrongqr` | 先发一个 **QR=0** 的包，再发正确应答 |
| `wrongsrc` | 先从**另一个源端口**发伪造应答，再发正确应答 |
| `delay` / `slow` | 延迟 `UPSTREAM_DELAY_SECONDS` 后应答 |
| `ooo` / `reverse` | 把并发查询攒 `UPSTREAM_OOO_WINDOW` 秒，按**倒序**回复 |
| `ttlN`（任意标签内，如 `multi-ttl2`） | 使用 TTL=N |
| `cname` | 返回 CNAME + A（合法，但不满足“答案均为所问域名的 A” → 不缓存） |
| `mixed` | 返回所问域名 A + 另一个域名的 A → 不缓存 |
| `multi` | 返回两条所问域名的 A（TTL 不同）→ 缓存寿命取最小 TTL |
| `trunc` | 返回 `TC=1` → 不缓存 |
| `nxdomain` | 返回 `NXDOMAIN`、无答案 → 不缓存 |

例：`wrongq-x.example.test`、`ooo-1.example.test`、`drop-a.example.test`、
`multi-ttl2.example.test`。

## 关键实现与保证

### 只支持受限查询

* 恰好一个问题，`QTYPE=A`、`QCLASS=IN`；
* 任何 additional 记录（包括 EDNS 的 OPT）都不支持 → `NOTIMP`；
* 问题数不为 1、答案/权威段出现在查询里 → `FORMERR`；
* QR=1 的报文按响应处理为非法输入，直接忽略，避免反射循环。

### 并发不串答

* 每个客户端查询分配一个 **随机 16 位上游 ID**，且在所有待处理查询中唯一；
* 待处理表以上游 ID 为键，值保存**客户端端点 + 客户端原 ID + 完整问题**；
* 两个客户端即使使用相同查询 ID，也各自对应不同的上游 ID，回包分别投递，
  最后把 ID 改回各客户端自己的 ID；
* 倒序或延迟回包只影响到达顺序，不影响归属。

### 回包校验与 2 秒超时

上游包必须同时满足：

1. 源地址与源端口**恰好**等于启动时解析并固定的上游 IPv4 端点；
2. `QR=1`、opcode 为 QUERY；
3. 上游 ID 对应某个待处理查询；
4. 恰好一个问题，且 QNAME（忽略大小写）/QTYPE/QCLASS 与待处理问题完全一致。

任何一条不满足就**忽略该包并继续等待**；直到 2 秒超时，向客户端返回
`SERVFAIL`（保留客户端 ID 与原问题）。只有通过全部校验的包才可能进入缓存。

### 缓存规则

只有同时满足以下条件的应答才缓存：

* 来自已校验的上游回包；
* `RCODE=NOERROR`、`TC=0`；
* 答案段非空，且**每一条**都是 `IN/A`，owner 都是所问域名（忽略大小写）；
* 答案 TTL 至少有一个正值。

缓存键为**忽略大小写的域名**。条目寿命 = 答案集合中的**最小 TTL**。命中时：

* 恢复客户端本次查询的 ID；
* 所有 TTL 减去条目已过整秒数（不会出现负 TTL）；
* 不修改已存条目（因此连续命中绝不延长寿命）。

含 CNAME、混入其它域名、截断、`NXDOMAIN` 或非 A 答案的应答会被正常转发，
但不会进入缓存。

### 单进程

转发器是一个 `asyncio` 事件循环内的单个 UDP 进程，没有多进程 worker；
所有待处理状态只在事件循环线程内访问。网页服务与实验上游是独立进程。

## 配置

### 转发器（`dns-forwarder`）

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `DNS_LISTEN_HOST` | `0.0.0.0` | 监听地址 |
| `DNS_LISTEN_PORT` | `25353` | 监听 UDP 端口 |
| `DNS_UPSTREAM_HOST` | `127.0.0.1` | 上游 IPv4 地址或主机名；启动时解析一次并固定 |
| `DNS_UPSTREAM_PORT` | `25354` | 上游 UDP 端口（固定） |
| `DNS_TIMEOUT_SECONDS` | `2.0` | 上游超时；超时返回 `SERVFAIL` |
| `DNS_CACHE_SIZE` | `1024` | 最大缓存域名数（LRU） |

也支持命令行覆盖，例如：

```bash
python -m app.forwarder \
  --upstream-ip 127.0.0.1 --upstream-port 25354 \
  --listen-port 25353 --timeout 2
```

### 网页服务（`dns-web`）

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `DNS_FORWARDER_HOST` | `127.0.0.1` | 转发器地址 |
| `DNS_FORWARDER_PORT` | `25353` | 转发器 UDP 端口 |
| `DNS_QUERY_TIMEOUT_SECONDS` | `3.0` | 网页端等待时间（应大于转发器的 2 秒） |
| `PUBLIC_DNS_HOST` / `PUBLIC_DNS_PORT` | 同上 | 仅用于页面展示 |

### 实验上游（`test-upstream`）

`UPSTREAM_LISTEN_HOST`、`UPSTREAM_LISTEN_PORT`、`UPSTREAM_TTL`、
`UPSTREAM_DELAY_SECONDS`、`UPSTREAM_WRONGQ_DELAY`、`UPSTREAM_OOO_WINDOW`、
`UPSTREAM_MODE`（全局强制某个场景，如 `wrongq` / `delay` / `ooo` / `drop`；
域名标签场景仍然优先于普通查询）。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 查询页 |
| `GET` | `/api/health` | 存活探针（不访问网络） |
| `GET` | `/api/ready` | 端到端探针：真实 UDP 查询转发器与上游 |
| `GET` | `/api/config` | 转发器地址、支持范围、场景说明 |
| `POST` | `/api/query`（另有 `/api/dns-query`、`/api/resolve`） | 单条真实 UDP 查询 |
| `POST` | `/api/query-batch`（另有 `/api/dns-query-batch`） | 并发多条查询 |

单条请求体：

```json
{"name": "www.example.test", "qid": 4660}
```

`name` 也接受 `domain` / `qname` 别名；`qid` 也接受 `id` / `queryId` 别名，
省略时随机生成。成功响应示例：

```json
{
  "ok": true,
  "timedOut": false,
  "elapsedMs": 2.3,
  "query": {"name": "www.example.test", "canonicalName": "www.example.test.",
            "qid": 4660, "qidHex": "0x1234", "type": "A", "class": "IN"},
  "response": {
    "id": 4660, "rcode": 0, "rcodeName": "NOERROR",
    "flags": {"qr": true, "aa": false, "tc": false, "rd": true, "ra": true},
    "answers": [{"name": "www.example.test.", "typeName": "A",
                 "ttl": 30, "data": "198.51.100.42"}]
  },
  "servfail": false
}
```

转发器返回 `SERVFAIL` 时仍是 `ok=true`、`servfail=true`、`rcode=2`；
网页端自身等待超时则是 `ok=false`、`timedOut=true`。

批量请求体：

```json
{"queries": [{"name": "a.example.test", "qid": 4660},
             {"name": "b.example.test", "qid": 4660}]}
```

每个条目由后端并发执行，且各自使用独立 UDP 套接字。

## 本地直接运行（不用 Docker）

需要三个终端：

```bash
pip install -r requirements.txt

# 1) 实验上游（127.0.0.1:25354）
python -m app.test_upstream

# 2) 转发器（127.0.0.1:25353 -> 上游 127.0.0.1:25354）
python -m app.forwarder

# 3) 网页（http://127.0.0.1:8000，默认连 127.0.0.1:25353）
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## 测试

```bash
pip install -r requirements.txt
pytest
# 或者仅跑不依赖第三方库的转发器/编码测试：
python -m unittest tests.test_dns tests.test_forwarder
```

测试会启动真实的 UDP 上游与转发器，覆盖：

* 正常转发、客户端 ID 恢复、缓存命中与 TTL 扣减/到期；
* 不同客户端使用相同 ID、并发倒序回包不串答；
* 错误问题包、QR=0、错误来源包被忽略；
* 2 秒（测试中缩短）超时 → `SERVFAIL`；
* CNAME、混合 owner、截断、NXDOMAIN 不缓存；
* 多答案缓存以最小 TTL 计寿命且命中不延长；
* AAAA、EDNS、多问题查询不转发；
* HTTP 页面、单条/批量 API 与端到端探针。

## 目录结构

```
.
├── app/
│   ├── dns.py            # 严格 DNS 线格式编解码（无第三方依赖）
│   ├── cache.py          # 最小 TTL / LRU 缓存
│   ├── forwarder.py      # 单进程 UDP 转发器（核心）
│   ├── test_upstream.py  # 可编排本地实验上游
│   ├── main.py           # FastAPI 页面与 HTTP→UDP 桥
│   ├── health_probe.py   # Docker UDP 健康检查
│   └── static/index.html # 浏览器并发查询页（原生 HTML/CSS/JS）
├── tests/
│   ├── test_dns.py
│   ├── test_forwarder.py
│   └── test_api.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── pytest.ini
```

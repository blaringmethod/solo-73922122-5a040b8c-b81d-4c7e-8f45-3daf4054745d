"""
防火墙规则变更精确差分引擎。

规则语义（与需求一一对应）：
  * 仅支持 IPv4、TCP；
  * 每条规则含：唯一编号 id、源 CIDR source、目的 CIDR destination、
    目的端口闭区间 portRange=[low, high]、动作 action ∈ {allow, deny}；
  * 规则按数组顺序匹配，首条命中生效，全部未命中则默认拒绝（DEFAULT DENY）；
  * 每份规则集最多 20 条。

精确性保证（不做任何抽样）：
  在三个维度上收集全部规则边界，把整个流量空间
  (源 IPv4) × (目的 IPv4) × (目的端口 0..65535)
  切分成若干“基本单元”。在每个基本单元内部，任何一条规则要么对整个单元
  全部命中、要么完全不命中，因此单元内每个报文的命中规则编号与动作恒定。
  对所有基本单元计算旧/新命中结果，再把相邻且 (旧命中, 新命中) 完全相同的
  单元贪心合并成长方体区域。输出区域两两互不重叠，且恰好覆盖所有
  旧动作与新动作不一致的流量，没有遗漏、没有重复。

输出块内给出一个具体报文（各区间取最小端点），其命中规则即该整块内任意
报文的命中规则，可直接用于管理员定位。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, AddressValueError, NetmaskValueError
from typing import Any, Optional

MAX_RULES = 20
PORT_MIN = 0
PORT_MAX = 65535
# 默认拒绝的占位规则编号（命中规则索引为 -1 时使用）
DEFAULT_RULE_ID = "DEFAULT-DENY"

_MISSING = object()


class ValidationFailure(Exception):
    """输入校验失败，携带结构化错误列表。"""

    def __init__(self, errors: list[dict[str, Any]]):
        super().__init__("; ".join(e["message"] for e in errors))
        self.errors = errors


@dataclass(frozen=True)
class Rule:
    id: Any
    order: int  # 0-based 在规则集中的位置
    source: IPv4Network
    destination: IPv4Network
    port_low: int
    port_high: int
    action: str  # "allow" / "deny"


# --------------------------------------------------------------------------- #
# 输入校验
# --------------------------------------------------------------------------- #
def _err(sheet: str, rule_index: Optional[int], field: Optional[str],
         message: str, line: Optional[int] = None, col: Optional[int] = None
         ) -> dict[str, Any]:
    e: dict[str, Any] = {"sheet": sheet, "message": message}
    if rule_index is not None:
        e["ruleIndex"] = rule_index  # 1-based，与管理员阅读顺序一致
    if field is not None:
        e["field"] = field
    if line is not None:
        e["line"] = line
    if col is not None:
        e["col"] = col
    return e


def _parse_cidr(value: Any, sheet: str, rule_index: int, field: str,
                errors: list[dict[str, Any]]) -> Optional[IPv4Network]:
    """严格 IPv4 CIDR：必须是字符串、必须带前缀、必须是网络地址（主机位为 0）。"""
    if not isinstance(value, str) or isinstance(value, bool):
        errors.append(_err(sheet, rule_index, field,
                           f"{field} 必须是字符串形式的 IPv4 CIDR，例如 10.0.0.0/24"))
        return None
    text = value.strip()
    if "/" not in text:
        errors.append(_err(sheet, rule_index, field,
                           f"{field} 缺少前缀长度，CIDR 应形如 10.0.0.0/24；"
                           "单个主机请写 a.b.c.d/32，全网请写 0.0.0.0/0"))
        return None
    try:
        network = IPv4Network(text, strict=True)
    except (AddressValueError, NetmaskValueError, ValueError):
        errors.append(_err(sheet, rule_index, field,
                           f"{field} 不是合法的 IPv4 CIDR：{value!r}；"
                           "请使用网络地址（主机位为 0），如 192.168.1.0/24"))
        return None
    if network.version != 4:
        errors.append(_err(sheet, rule_index, field,
                           f"{field} 仅支持 IPv4，不支持 IPv6：{value!r}"))
        return None
    return network


def _parse_port_range(value: Any, sheet: str, rule_index: int,
                      errors: list[dict[str, Any]]) -> Optional[tuple[int, int]]:
    if not isinstance(value, list):
        errors.append(_err(sheet, rule_index, "portRange",
                           "portRange 必须是包含两个整数的闭区间数组，例如 [80, 443]"))
        return None
    if len(value) != 2:
        errors.append(_err(sheet, rule_index, "portRange",
                           f"portRange 必须恰好包含 [下界, 上界] 两个整数，"
                           f"当前包含 {len(value)} 个元素"))
        return None
    low, high = value
    if isinstance(low, bool) or not isinstance(low, int) or isinstance(high, bool) \
            or not isinstance(high, int):
        errors.append(_err(sheet, rule_index, "portRange",
                           "portRange 的两个端点必须是整数（0-65535），"
                           f"当前为 {low!r}, {high!r}"))
        return None
    if not (PORT_MIN <= low <= PORT_MAX and PORT_MIN <= high <= PORT_MAX):
        errors.append(_err(sheet, rule_index, "portRange",
                           f"端口必须在 {PORT_MIN}-{PORT_MAX} 范围内，"
                           f"当前为 [{low}, {high}]"))
        return None
    if low > high:
        errors.append(_err(sheet, rule_index, "portRange",
                           f"portRange 下界不能大于上界，当前为 [{low}, {high}]"))
        return None
    return low, high


def _parse_rule(obj: Any, sheet: str, idx: int, seen_ids: dict[Any, int],
                errors: list[dict[str, Any]]) -> Optional[Rule]:
    if not isinstance(obj, dict):
        errors.append(_err(sheet, idx, None,
                           f"第 {idx} 条规则必须是 JSON 对象，当前是 {type(obj).__name__}"))
        return None

    allowed = {"id", "source", "destination", "portRange", "action"}
    extra = set(obj) - allowed
    for name in sorted(extra):
        errors.append(_err(sheet, idx, name, f"存在不支持的字段 {name!r}，"
                                             f"允许的字段为：{sorted(allowed)}"))

    rule_id = obj.get("id", _MISSING)
    if rule_id is _MISSING:
        errors.append(_err(sheet, idx, "id", "缺少唯一编号字段 id"))
        rule_id = None
    elif isinstance(rule_id, bool) or not isinstance(rule_id, (int, str)):
        errors.append(_err(sheet, idx, "id",
                           f"id 必须是整数或非空字符串，当前为 {rule_id!r}"))
        rule_id = None
    elif isinstance(rule_id, str) and not rule_id.strip():
        errors.append(_err(sheet, idx, "id", "id 不能是空字符串"))
        rule_id = None
    elif rule_id in seen_ids:
        errors.append(_err(sheet, idx, "id",
                           f"id {rule_id!r} 与第 {seen_ids[rule_id]} 条规则重复，"
                           "同一规则集内编号必须唯一"))
        rule_id = None
    else:
        seen_ids[rule_id] = idx

    source = _parse_cidr(obj.get("source", _MISSING), sheet, idx, "source", errors)
    destination = _parse_cidr(obj.get("destination", _MISSING), sheet, idx,
                              "destination", errors)
    ports = _parse_port_range(obj.get("portRange", _MISSING), sheet, idx, errors)

    action = obj.get("action", _MISSING)
    if action is _MISSING:
        errors.append(_err(sheet, idx, "action", "缺少动作字段 action"))
        action = None
    elif action not in ("allow", "deny"):
        errors.append(_err(sheet, idx, "action",
                           f"action 只能是小写的 allow 或 deny，当前为 {action!r}"))
        action = None

    if rule_id is None or source is None or destination is None \
            or ports is None or action is None:
        return None
    return Rule(id=rule_id, order=idx - 1, source=source, destination=destination,
                port_low=ports[0], port_high=ports[1], action=action)


def parse_ruleset(text: str, sheet: str) -> list[Rule]:
    """解析并校验一份规则集文本，失败时抛 ValidationFailure（可能含多条错误）。"""
    errors: list[dict[str, Any]] = []
    if text is None or not text.strip():
        raise ValidationFailure(
            [_err(sheet, None, None, "内容为空，请粘贴 JSON 规则数组；空规则集请写 []")])
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationFailure([_err(sheet, None, None,
                                      f"JSON 语法错误：{exc.msg}",
                                      line=exc.lineno, col=exc.colno)]) from exc

    if not isinstance(data, list):
        raise ValidationFailure(
            [_err(sheet, None, None,
                  f"顶层必须是规则数组（[ ... ]），当前是 {type(data).__name__}")])
    if len(data) > MAX_RULES:
        errors.append(_err(sheet, None, None,
                           f"规则数量为 {len(data)} 条，超过上限 {MAX_RULES} 条"))

    rules: list[Rule] = []
    seen_ids: dict[Any, int] = {}
    for i, obj in enumerate(data[:MAX_RULES], start=1):
        before = len(errors)
        rule = _parse_rule(obj, sheet, i, seen_ids, errors)
        if rule is not None and len(errors) == before:
            rules.append(rule)
    if errors:
        raise ValidationFailure(errors)
    return rules


# --------------------------------------------------------------------------- #
# 边界与基本单元
# --------------------------------------------------------------------------- #
def _interval_bounds(values_lo_hi: list[tuple[int, int]], universe_hi: int
                     ) -> list[tuple[int, int]]:
    """
    用 [low, high] 闭区间的切点构造互不重叠的基本区间（闭区间整数对）。
    规则区间 [a, b] 对应切点 a 与 b+1。
    """
    points = {0, universe_hi + 1}
    for lo, hi in values_lo_hi:
        points.add(lo)
        points.add(hi + 1)
    ordered = sorted(points)
    return [(ordered[i], ordered[i + 1] - 1) for i in range(len(ordered) - 1)]


def _memberships(intervals: list[tuple[int, int]],
                 ranges: list[tuple[int, int]]) -> list[list[int]]:
    """memberships[r] = 命中第 r 条规则的基本区间下标列表。"""
    out: list[list[int]] = []
    for lo, hi in ranges:
        hits = [k for k, (a, b) in enumerate(intervals) if a >= lo and b <= hi]
        out.append(hits)
    return out


def _cell_hit_sets(intervals_count: int, memberships: list[list[int]]
                   ) -> list[frozenset[int]]:
    """反转索引：cell_hits[k] = 在第 k 个基本区间上命中的规则下标集合。"""
    cells: list[set[int]] = [set() for _ in range(intervals_count)]
    for rule_idx, hit_cells in enumerate(memberships):
        for k in hit_cells:
            cells[k].add(rule_idx)
    return [frozenset(s) for s in cells]


def _first_hit(src_cell: frozenset[int],
               dst_cell: frozenset[int], port_cell: frozenset[int]) -> int:
    """按规则顺序返回首条在三个维度同时命中的规则索引；全部未命中返回 -1。"""
    common = src_cell & dst_cell & port_cell
    if not common:
        return -1
    return min(common)


# --------------------------------------------------------------------------- #
# 区域序列化辅助
# --------------------------------------------------------------------------- #
def _ip_str(value: int) -> str:
    return str(IPv4Address(value))


def _aligned_cidr(lo: int, hi: int) -> Optional[str]:
    """若整数闭区间恰好是一个 CIDR 网络，返回其字符串表示；否则 None。"""
    size = hi - lo + 1
    if size <= 0 or (size & (size - 1)) != 0:
        return None
    if lo % size != 0:
        return None
    prefix = 32 - size.bit_length() + 1
    return f"{_ip_str(lo)}/{prefix}"


def _ip_interval_json(lo: int, hi: int) -> dict[str, Any]:
    count = hi - lo + 1
    return {
        "start": _ip_str(lo),
        "end": _ip_str(hi),
        "cidr": _aligned_cidr(lo, hi),
        "addressCount": str(count),
    }


def _hit_json(rule_index: int, rules: list[Rule], action: str) -> dict[str, Any]:
    if rule_index < 0:
        return {"matched": False, "ruleId": DEFAULT_RULE_ID, "ruleOrder": None,
                "action": "deny", "defaultDeny": True}
    rule = rules[rule_index]
    return {"matched": True, "ruleId": rule.id, "ruleOrder": rule.order + 1,
            "action": action, "defaultDeny": False}


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def diff_rulesets(old_rules: list[Rule], new_rules: list[Rule]) -> dict[str, Any]:
    """
    计算两个规则集之间的精确差异，返回可 JSON 序列化的结果：
      blocks: 所有动作发生变化的区域（互不重叠的三维长方体），
              每个块含具体报文参数及旧/新命中规则编号（含默认拒绝标记）。
    """
    # 1) 收集三维边界，构造基本单元
    src_ranges = [(int(r.source.network_address), int(r.source.broadcast_address))
                  for r in old_rules + new_rules]
    dst_ranges = [(int(r.destination.network_address), int(r.destination.broadcast_address))
                  for r in old_rules + new_rules]
    port_ranges = [(r.port_low, r.port_high) for r in old_rules + new_rules]

    src_intervals = _interval_bounds(src_ranges, 2 ** 32 - 1)
    dst_intervals = _interval_bounds(dst_ranges, 2 ** 32 - 1)
    port_intervals = _interval_bounds(port_ranges, PORT_MAX)

    ns, nd, np_ = len(src_intervals), len(dst_intervals), len(port_intervals)

    # 2) 预计算每条规则在各维度上命中的基本区间，避免逐格重复扫描
    old_src_mem = _memberships(src_intervals,
                               [(int(r.source.network_address),
                                 int(r.source.broadcast_address)) for r in old_rules])
    old_dst_mem = _memberships(dst_intervals,
                               [(int(r.destination.network_address),
                                 int(r.destination.broadcast_address)) for r in old_rules])
    old_port_mem = _memberships(port_intervals,
                                [(r.port_low, r.port_high) for r in old_rules])
    new_src_mem = _memberships(src_intervals,
                               [(int(r.source.network_address),
                                 int(r.source.broadcast_address)) for r in new_rules])
    new_dst_mem = _memberships(dst_intervals,
                               [(int(r.destination.network_address),
                                 int(r.destination.broadcast_address)) for r in new_rules])
    new_port_mem = _memberships(port_intervals,
                                [(r.port_low, r.port_high) for r in new_rules])

    # 反转为“每个基本区间命中哪些规则”的集合，供逐格求首条命中
    old_src_cells = _cell_hit_sets(ns, old_src_mem)
    old_dst_cells = _cell_hit_sets(nd, old_dst_mem)
    old_port_cells = _cell_hit_sets(np_, old_port_mem)
    new_src_cells = _cell_hit_sets(ns, new_src_mem)
    new_dst_cells = _cell_hit_sets(nd, new_dst_mem)
    new_port_cells = _cell_hit_sets(np_, new_port_mem)

    # 3) 给每个基本单元打上 (旧命中索引, 新命中索引) 标签，编码为单个 int
    total = ns * nd * np_
    labels = [0] * total
    label_map: dict[tuple[int, int], int] = {}
    label_pairs: list[tuple[int, int]] = []

    def code_for(pair: tuple[int, int]) -> int:
        code = label_map.get(pair)
        if code is None:
            code = len(label_pairs) + 1
            label_map[pair] = code
            label_pairs.append(pair)
        return code

    flat = 0
    for si in range(ns):
        for di in range(nd):
            for pi in range(np_):
                old_hit = _first_hit(old_src_cells[si],
                                     old_dst_cells[di], old_port_cells[pi])
                new_hit = _first_hit(new_src_cells[si],
                                     new_dst_cells[di], new_port_cells[pi])
                labels[flat] = code_for((old_hit, new_hit))
                flat += 1

    # 4) 贪心合并：字典序扫描未处理单元，沿端口→目的→源方向吃掉同标签相邻单元。
    #    同标签意味着旧命中规则与新命中规则（含默认拒绝）完全一致。
    used = bytearray(total)

    def idx(si: int, di: int, pi: int) -> int:
        return (si * nd + di) * np_ + pi

    def idx_used(si: int, di: int, pi: int) -> int:
        return used[idx(si, di, pi)]

    def strip_same(si: int, di: int, p_lo: int, p_hi: int, code: int) -> bool:
        base = idx(si, di, p_lo)
        for k in range(p_hi - p_lo + 1):
            if used[base + k] or labels[base + k] != code:
                return False
        return True

    def slab_same(si: int, d_lo: int, d_hi: int, p_lo: int, p_hi: int,
                  code: int) -> bool:
        for d2 in range(d_lo, d_hi + 1):
            if not strip_same(si, d2, p_lo, p_hi, code):
                return False
        return True

    raw_blocks: list[dict[str, Any]] = []

    for si in range(ns):
        for di in range(nd):
            for pi in range(np_):
                start = idx(si, di, pi)
                if used[start]:
                    continue
                code = labels[start]
                old_hit, new_hit = label_pairs[code - 1]

                old_action = old_rules[old_hit].action if old_hit >= 0 else "deny"
                new_action = new_rules[new_hit].action if new_hit >= 0 else "deny"
                if old_action == new_action:
                    # 动作未变化的单元也标记为已处理，但不输出
                    used[start] = 1
                    continue

                # 端口方向扩展
                p_hi = pi
                while p_hi + 1 < np_ and not idx_used(si, di, p_hi + 1) \
                        and labels[idx(si, di, p_hi + 1)] == code:
                    p_hi += 1
                # 目的方向扩展：要求整段端口条带同标签
                d_hi = di
                while d_hi + 1 < nd:
                    if strip_same(si, d_hi + 1, pi, p_hi, code):
                        d_hi += 1
                    else:
                        break
                # 源方向扩展：要求整个 (目的 × 端口) 切片同标签
                s_hi = si
                while s_hi + 1 < ns:
                    if slab_same(s_hi + 1, di, d_hi, pi, p_hi, code):
                        s_hi += 1
                    else:
                        break

                for s2 in range(si, s_hi + 1):
                    for d2 in range(di, d_hi + 1):
                        base = idx(s2, d2, pi)
                        used[base:base + (p_hi - pi + 1)] = b"\x01" * (p_hi - pi + 1)

                raw_blocks.append({
                    "src": (src_intervals[si][0], src_intervals[s_hi][1]),
                    "dst": (dst_intervals[di][0], dst_intervals[d_hi][1]),
                    "port": (port_intervals[pi][0], port_intervals[p_hi][1]),
                    "oldHit": old_hit,
                    "newHit": new_hit,
                    # 记录数值边界用于确定性排序
                    "_sort": (src_intervals[si][0], dst_intervals[di][0],
                              port_intervals[pi][0]),
                })

    # 5) 序列化：每块取各区间最小端点作为具体报文（块内命中结果恒定）
    raw_blocks.sort(key=lambda b: b["_sort"])
    blocks: list[dict[str, Any]] = []
    for blk in raw_blocks:
        s_lo, s_hi = blk["src"]
        d_lo, d_hi = blk["dst"]
        p_lo, p_hi = blk["port"]
        old_hit, new_hit = blk["oldHit"], blk["newHit"]
        old_action = old_rules[old_hit].action if old_hit >= 0 else "deny"
        new_action = new_rules[new_hit].action if new_hit >= 0 else "deny"

        packet_count = (s_hi - s_lo + 1) * (d_hi - d_lo + 1) * (p_hi - p_lo + 1)
        port_field = (str(p_lo) if p_lo == p_hi else f"{p_lo}-{p_hi}")
        blocks.append({
            "changeType": "newly-allowed" if new_action == "allow" else "newly-denied",
            "source": _ip_interval_json(s_lo, s_hi),
            "destination": _ip_interval_json(d_lo, d_hi),
            "port": {"start": p_lo, "end": p_hi, "label": port_field,
                     "portCount": p_hi - p_lo + 1},
            "packetCount": str(packet_count),
            "representativePacket": {
                "protocol": "TCP",
                "sourceIp": _ip_str(s_lo),
                "destinationIp": _ip_str(d_lo),
                "destinationPort": p_lo,
            },
            "oldVerdict": _hit_json(old_hit, old_rules, old_action),
            "newVerdict": _hit_json(new_hit, new_rules, new_action),
        })

    newly_allowed = [b for b in blocks if b["changeType"] == "newly-allowed"]
    newly_denied = [b for b in blocks if b["changeType"] == "newly-denied"]
    return {
        "summary": {
            "oldRuleCount": len(old_rules),
            "newRuleCount": len(new_rules),
            "newlyAllowedBlockCount": len(newly_allowed),
            "newlyDeniedBlockCount": len(newly_denied),
            "totalChangedBlockCount": len(blocks),
        },
        "newlyAllowed": newly_allowed,
        "newlyDenied": newly_denied,
    }


def analyze(old_text: str, new_text: str) -> dict[str, Any]:
    """供 API 调用的入口：先整体校验（任一输入非法即拒绝并清空结果），再差分。"""
    old_errors: list[dict[str, Any]] = []
    new_errors: list[dict[str, Any]] = []
    try:
        old_rules = parse_ruleset(old_text, "old")
    except ValidationFailure as exc:
        old_rules = []
        old_errors = exc.errors
    try:
        new_rules = parse_ruleset(new_text, "new")
    except ValidationFailure as exc:
        new_rules = []
        new_errors = exc.errors
    if old_errors or new_errors:
        raise ValidationFailure(old_errors + new_errors)
    return diff_rulesets(old_rules, new_rules)

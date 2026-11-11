"""引擎单元测试：校验、首条匹配语义、精确性与区域性质。"""

import random
from ipaddress import IPv4Address, IPv4Network

import pytest

from app.engine import (
    DEFAULT_RULE_ID,
    MAX_RULES,
    Rule,
    ValidationFailure,
    analyze,
    diff_rulesets,
    parse_ruleset,
)


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def make_rule(rid, order, src, dst, plo, phi, action):
    return Rule(id=rid, order=order, source=IPv4Network(src),
                destination=IPv4Network(dst), port_low=plo, port_high=phi,
                action=action)


def ref_hit(rules, sip_int, dip_int, port):
    """参考实现：顺序扫描，首条命中；未命中返回 (-1, deny)。"""
    for r in rules:
        if (int(r.source.network_address) <= sip_int
                <= int(r.source.broadcast_address)
                and int(r.destination.network_address) <= dip_int
                <= int(r.destination.broadcast_address)
                and r.port_low <= port <= r.port_high):
            return r.order, r.action
    return -1, "deny"


def compile_rules(rules):
    """预计算整数边界，供海量枚举点高速复算。"""
    return [(r.order, int(r.source.network_address), int(r.source.broadcast_address),
             int(r.destination.network_address), int(r.destination.broadcast_address),
             r.port_low, r.port_high, r.action) for r in rules]


def ref_hit_fast(compiled, sip_int, dip_int, port):
    for order, slo, shi, dlo, dhi, plo, phi, action in compiled:
        if slo <= sip_int <= shi and dlo <= dip_int <= dhi and plo <= port <= phi:
            return order, action
    return -1, "deny"


def build_diff_point_map(ranges, sip0, dip0, port0, n_ports, dst_stride):
    """
    把输出块覆盖的每个三维点编码为整数键，映射到变化类型。
    若块互不重叠，则每个键只应出现一次（插入时顺带断言）。
    枚举宇宙为连续源地址 × 连续目的地址 × 连续端口窗口，规则块均位于其中。
    键编码与各测试内联编码保持一致：
      key = ((sip-sip0)*dst_stride + (dip-dip0))*n_ports + (port-port0)
    """
    point_map: dict[int, str] = {}
    for slo, shi, dlo, dhi, plo, phi, ctype in ranges:
        for sip in range(slo, shi + 1):
            s_part = (sip - sip0) * dst_stride
            for dip in range(dlo, dhi + 1):
                sd_part = (s_part + (dip - dip0)) * n_ports
                for port in range(plo, phi + 1):
                    key = sd_part + (port - port0)
                    assert key not in point_map, "输出块在该点重叠"
                    point_map[key] = ctype
    return point_map


def ip_int(s):
    return int(IPv4Address(s))


def block_ranges(result):
    out = []
    for sec in ("newlyAllowed", "newlyDenied"):
        for b in result[sec]:
            out.append((
                ip_int(b["source"]["start"]), ip_int(b["source"]["end"]),
                ip_int(b["destination"]["start"]), ip_int(b["destination"]["end"]),
                b["port"]["start"], b["port"]["end"],
                b["changeType"],
            ))
    return out


# --------------------------------------------------------------------------- #
# 输入校验：位置与字段
# --------------------------------------------------------------------------- #
def test_empty_input_rejected():
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset("   ", "old")
    assert ei.value.errors[0]["sheet"] == "old"


def test_json_syntax_error_has_line_and_col():
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset('[{"id": 1,}\n]', "new")
    err = ei.value.errors[0]
    assert err["line"] == 1 and err["col"] is not None
    assert "JSON" in err["message"]


def test_top_level_must_be_array():
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset('{"id": 1}', "old")
    assert "数组" in ei.value.errors[0]["message"]


def test_bad_cidr_reports_rule_and_field():
    text = '[{"id": 1, "source": "10.0.0.5/24", "destination": "8.8.8.8/32",' \
           ' "portRange": [80, 80], "action": "allow"}]'
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset(text, "new")
    err = ei.value.errors[0]
    assert err["ruleIndex"] == 1 and err["field"] == "source"
    assert "网络地址" in err["message"]


def test_missing_prefix_rejected():
    text = '[{"id": 1, "source": "10.0.0.0", "destination": "0.0.0.0/0",' \
           ' "portRange": [80, 80], "action": "allow"}]'
    with pytest.raises(ValidationFailure):
        parse_ruleset(text, "old")


def test_ipv6_rejected():
    text = '[{"id": 1, "source": "::1/128", "destination": "0.0.0.0/0",' \
           ' "portRange": [80, 80], "action": "allow"}]'
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset(text, "old")
    assert "IPv4" in ei.value.errors[0]["message"]


def test_bad_port_range_variants():
    base = '[{"id": 1, "source": "0.0.0.0/0", "destination": "0.0.0.0/0",' \
           ' "portRange": %s, "action": "allow"}]'
    for bad in ("[80]", "[80, 70]", "[-1, 80]", "[0, 70000]", '["80", 81]', "[true, 2]"):
        with pytest.raises(ValidationFailure):
            parse_ruleset(base % bad, "old")


def test_action_and_id_validation_and_duplicate():
    text = '''[
      {"id": 7, "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
       "portRange": [1, 2], "action": "PERMIT"},
      {"id": 7, "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
       "portRange": [1, 2], "action": "allow"},
      {"id": "", "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
       "portRange": [1, 2], "action": "allow"}
    ]'''
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset(text, "new")
    fields = {(e.get("ruleIndex"), e.get("field")) for e in ei.value.errors}
    assert (1, "action") in fields
    assert (2, "id") in fields
    assert (3, "id") in fields


def test_unknown_field_and_missing_field_reported():
    text = '[{"id": 1, "source": "0.0.0.0/0", "destination": "0.0.0.0/0",' \
           ' "portRange": [80, 80], "action": "allow", "priority": 1}]'
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset(text, "old")
    assert ei.value.errors[0]["field"] == "priority"

    text2 = '[{"source": "0.0.0.0/0", "destination": "0.0.0.0/0",' \
            ' "portRange": [80, 80], "action": "allow"}]'
    with pytest.raises(ValidationFailure) as ei2:
        parse_ruleset(text2, "old")
    assert ei2.value.errors[0]["field"] == "id"


def test_too_many_rules():
    rules = [{"id": i, "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
              "portRange": [1, 2], "action": "allow"} for i in range(MAX_RULES + 1)]
    import json
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset(json.dumps(rules), "old")
    assert str(MAX_RULES) in ei.value.errors[0]["message"]


def test_multiple_errors_collected_together():
    text = '[{"id": 1, "source": "bad", "destination": "also-bad",' \
           ' "portRange": [9, 8], "action": "nope"}]'
    with pytest.raises(ValidationFailure) as ei:
        parse_ruleset(text, "old")
    assert len(ei.value.errors) >= 4


# --------------------------------------------------------------------------- #
# 首条匹配与默认拒绝
# --------------------------------------------------------------------------- #
def test_first_match_wins():
    rules = [
        make_rule(1, 0, "0.0.0.0/0", "0.0.0.0/0", 80, 80, "deny"),
        make_rule(2, 1, "10.0.0.0/8", "0.0.0.0/0", 80, 80, "allow"),
    ]
    hit, action = ref_hit(rules, int(IPv4Address("10.1.1.1")),
                          int(IPv4Address("8.8.8.8")), 80)
    assert (hit, action) == (0, "deny")  # 第一条优先，第二条不会生效


def test_empty_ruleset_all_default_deny():
    result = diff_rulesets([], [make_rule(1, 0, "0.0.0.0/0", "0.0.0.0/0",
                                          1, 65535, "allow")])
    # 旧：全部默认拒绝；新：全部放行 → 一块全覆盖区域
    assert result["summary"]["newlyAllowedBlockCount"] == 1
    assert result["summary"]["newlyDeniedBlockCount"] == 0
    blk = result["newlyAllowed"][0]
    assert blk["source"]["start"] == "0.0.0.0"
    assert blk["source"]["end"] == "255.255.255.255"
    assert blk["source"]["cidr"] == "0.0.0.0/0"
    assert blk["port"]["start"] == 1 and blk["port"]["end"] == 65535
    assert blk["oldVerdict"]["defaultDeny"] is True
    assert blk["oldVerdict"]["ruleId"] == DEFAULT_RULE_ID
    assert blk["newVerdict"]["ruleId"] == 1


def test_identical_rulesets_no_diff():
    rules = [make_rule(1, 0, "10.0.0.0/8", "172.16.0.0/12", 80, 443, "allow")]
    result = diff_rulesets(rules, [
        make_rule(1, 0, "10.0.0.0/8", "172.16.0.0/12", 80, 443, "allow")])
    assert result["summary"]["totalChangedBlockCount"] == 0


# --------------------------------------------------------------------------- #
# 内置示例的已知答案
# --------------------------------------------------------------------------- #
def test_builtin_example_expected_blocks():
    from app.example_data import EXAMPLE_OLD, EXAMPLE_NEW
    import json
    result = analyze(json.dumps(EXAMPLE_OLD), json.dumps(EXAMPLE_NEW))

    # 新增放行：旧 102 的 deny 洞被新 202 改为 allow
    allowed = result["newlyAllowed"]
    assert len(allowed) == 1
    a = allowed[0]
    assert a["source"]["cidr"] == "10.1.0.0/16"
    assert a["destination"]["cidr"] == "172.16.5.0/24"
    assert a["port"]["start"] == a["port"]["end"] == 80
    assert a["oldVerdict"]["ruleId"] == 102 and a["oldVerdict"]["action"] == "deny"
    assert a["newVerdict"]["ruleId"] == 202 and a["newVerdict"]["action"] == "allow"
    assert a["representativePacket"]["destinationPort"] == 80

    # 新增阻断三块：205 收紧、104 删除回退默认拒绝、103→203 翻转
    denied = result["newlyDenied"]
    assert len(denied) == 3
    by_key = {(d["source"]["cidr"], d["destination"]["cidr"], d["port"]["start"]): d
              for d in denied}

    d_shrink = by_key[("10.0.0.0/8", "172.16.0.0/12", 1024)]
    assert d_shrink["oldVerdict"]["ruleId"] == 101
    assert d_shrink["newVerdict"]["ruleId"] == 205

    d_default = by_key[("10.0.0.0/8", "192.168.1.0/24", 443)]
    assert d_default["oldVerdict"]["ruleId"] == 104
    assert d_default["newVerdict"]["defaultDeny"] is True
    assert d_default["newVerdict"]["ruleId"] == DEFAULT_RULE_ID

    d_flip = by_key[("192.168.1.0/24", "0.0.0.0/0", 443)]
    assert d_flip["oldVerdict"]["ruleId"] == 103
    assert d_flip["newVerdict"]["ruleId"] == 203


# --------------------------------------------------------------------------- #
# 精确性：受限子空间暴力枚举，逐点核对
# --------------------------------------------------------------------------- #
def test_exhaustive_against_bruteforce():
    old_rules = [
        make_rule(1, 0, "10.0.0.0/24", "192.168.0.0/24", 80, 100, "allow"),
        make_rule(2, 1, "10.0.0.0/25", "192.168.0.0/25", 90, 90, "deny"),
    ]
    new_rules = [
        make_rule(1, 0, "10.0.0.0/24", "192.168.0.0/24", 80, 95, "allow"),
        make_rule(2, 1, "10.0.0.0/25", "192.168.0.0/25", 85, 90, "allow"),
        make_rule(3, 2, "10.0.0.128/25", "192.168.0.0/24", 100, 100, "deny"),
    ]
    result = diff_rulesets(old_rules, new_rules)
    ranges = block_ranges(result)

    old_c = compile_rules(old_rules)
    new_c = compile_rules(new_rules)
    src_net = IPv4Network("10.0.0.0/24")
    dst_net = IPv4Network("192.168.0.0/24")
    port_lo, port_hi = 78, 102
    n_ports = port_hi - port_lo + 1
    sip0 = int(src_net.network_address)
    dip0 = int(dst_net.network_address)
    point_map = build_diff_point_map(ranges, sip0, dip0, port_lo, n_ports, 256)

    matched_diff_points = 0
    sips = [sip0 + i for i in range(256)]
    dips = [dip0 + i for i in range(256)]
    for sip in sips:
        for dip in dips:
            for port in range(port_lo, port_hi + 1):
                _, old_act = ref_hit_fast(old_c, sip, dip, port)
                _, new_act = ref_hit_fast(new_c, sip, dip, port)
                key = ((sip - sip0) * 256 + (dip - dip0)) * n_ports + (port - port_lo)
                if old_act != new_act:
                    # 每个变化点必须恰好落在一个输出块中，且类型正确
                    ctype = point_map.get(key)
                    expect = "newly-allowed" if new_act == "allow" else "newly-denied"
                    assert ctype == expect, (sip, dip, port)
                    matched_diff_points += 1
                else:
                    assert key not in point_map

    # 输出块覆盖的点数与逐点核对到的差异数完全一致（无遗漏、无多余）
    assert len(point_map) == matched_diff_points
    # 覆盖的报文总数必须等于块声明的 packetCount 之和
    declared = sum(int(b["packetCount"])
                   for sec in ("newlyAllowed", "newlyDenied") for b in result[sec])
    assert declared == matched_diff_points


def test_blocks_are_pairwise_disjoint_and_witness_verdict_matches():
    """输出块两两互不重叠；块内代表报文的实际命中编号与块标注一致。"""
    old_rules = [
        make_rule("a", 0, "172.16.0.0/12", "10.0.0.0/8", 1, 1024, "deny"),
        make_rule("b", 1, "172.16.5.0/24", "10.1.0.0/16", 443, 8443, "allow"),
    ]
    new_rules = [
        make_rule("a", 0, "172.16.0.0/12", "10.0.0.0/8", 1, 2048, "allow"),
        make_rule("c", 1, "172.16.5.0/24", "10.1.0.0/16", 443, 8443, "deny"),
    ]
    result = diff_rulesets(old_rules, new_rules)
    ranges = block_ranges(result)

    def overlap1d(a_lo, a_hi, b_lo, b_hi):
        return a_lo <= b_hi and b_lo <= a_hi

    for i in range(len(ranges)):
        for j in range(i + 1, len(ranges)):
            a, b = ranges[i], ranges[j]
            # 两个三维长方体相交，当且仅当三个维度都相交
            intersects = (
                overlap1d(a[0], a[1], b[0], b[1])
                and overlap1d(a[2], a[3], b[2], b[3])
                and overlap1d(a[4], a[5], b[4], b[5]))
            assert not intersects, (a, b)

    # 代表报文（各区间最小端点）独立复算，命中规则编号必须与标注一致
    for sec, rules in (("old", old_rules), ("new", new_rules)):
        blocks = result["newlyAllowed"] + result["newlyDenied"]
        for blk in blocks:
            pkt = blk["representativePacket"]
            sip = int(IPv4Address(pkt["sourceIp"]))
            dip = int(IPv4Address(pkt["destinationIp"]))
            order, action = ref_hit(rules, sip, dip, pkt["destinationPort"])
            verdict = blk["oldVerdict"] if sec == "old" else blk["newVerdict"]
            assert verdict["action"] == action
            if order < 0:
                assert verdict["defaultDeny"] is True and verdict["matched"] is False
            else:
                assert verdict["ruleOrder"] == order + 1
                assert verdict["matched"] is True


# --------------------------------------------------------------------------- #
# 随机性质测试
# --------------------------------------------------------------------------- #
def test_randomized_exhaustive_small_space():
    rng = random.Random(20261111)
    # 所有规则网络均落在两个 /28 宇宙内，边界点全部参与全枚举，无抽样
    pool_s = ["10.0.0.0/28", "10.0.0.0/29", "10.0.0.8/29", "10.0.0.0/30"]
    pool_d = ["192.168.1.0/28", "192.168.1.0/29", "192.168.1.8/29"]
    port_lo, port_hi = 77, 98
    n_ports = port_hi - port_lo + 1
    sip0 = int(IPv4Address("10.0.0.0"))
    dip0 = int(IPv4Address("192.168.1.0"))

    def rand_rules(prefix):
        n = rng.randint(0, 5)
        out = []
        for i in range(n):
            lo = rng.randint(80, 90)
            hi = rng.randint(lo, 95)
            out.append(make_rule(f"{prefix}{i}", i, rng.choice(pool_s),
                                 rng.choice(pool_d), lo, hi,
                                 rng.choice(["allow", "deny"])))
        return out

    for trial in range(20):
        old_rules = rand_rules("o")
        new_rules = rand_rules("n")
        result = diff_rulesets(old_rules, new_rules)
        ranges = block_ranges(result)
        old_c, new_c = compile_rules(old_rules), compile_rules(new_rules)

        # 互不重叠
        def ov(a, b):
            return (a[0] <= b[1] and b[0] <= a[1] and a[2] <= b[3]
                    and b[2] <= a[3] and a[4] <= b[5] and b[4] <= a[5])
        for i in range(len(ranges)):
            for j in range(i + 1, len(ranges)):
                assert not ov(ranges[i], ranges[j])

        # 全枚举（非抽样）：/28 × /28 × 端口窗口内每个点逐点核对
        point_map = build_diff_point_map(ranges, sip0, dip0, port_lo, n_ports, 16)
        diffs = 0
        for sip in range(sip0, sip0 + 16):
            for dip in range(dip0, dip0 + 16):
                for port in range(port_lo, port_hi + 1):
                    _, oa = ref_hit_fast(old_c, sip, dip, port)
                    _, na = ref_hit_fast(new_c, sip, dip, port)
                    key = ((sip - sip0) * 16 + (dip - dip0)) * n_ports \
                        + (port - port_lo)
                    if oa != na:
                        expect = "newly-allowed" if na == "allow" else "newly-denied"
                        assert point_map.get(key) == expect, trial
                        diffs += 1
                    else:
                        assert key not in point_map, trial
        # 无遗漏、无多余；且与块声明报文总数一致
        assert len(point_map) == diffs, trial
        declared = sum(int(b["packetCount"])
                       for sec in ("newlyAllowed", "newlyDenied")
                       for b in result[sec])
        assert declared == diffs, trial


# --------------------------------------------------------------------------- #
# analyze 入口：任一输入非法即整体失败
# --------------------------------------------------------------------------- #
def test_analyze_invalid_input_raises_and_no_partial_result():
    good = '[{"id": 1, "source": "0.0.0.0/0", "destination": "0.0.0.0/0",' \
           ' "portRange": [80, 80], "action": "allow"}]'
    bad = '[{"id": 1, "source": "nope", "destination": "0.0.0.0/0",' \
          ' "portRange": [80, 80], "action": "allow"}]'
    with pytest.raises(ValidationFailure) as ei:
        analyze(good, bad)
    assert any(e["sheet"] == "new" for e in ei.value.errors)


def test_string_ids_and_ports_zero_allowed():
    text = '[{"id": "R-1", "source": "0.0.0.0/0", "destination": "0.0.0.0/0",' \
           ' "portRange": [0, 65535], "action": "deny"}]'
    rules = parse_ruleset(text, "old")
    assert rules[0].id == "R-1"
    assert rules[0].port_low == 0 and rules[0].port_high == 65535

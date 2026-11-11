"""内置“重叠规则”示例：新旧规则集均含互相重叠的 CIDR 与端口区间。

场景（均为首条匹配、默认拒绝语义）：
  * 旧 102 是排在宽放行 101 之前的窄 deny，在放行区里真实“挖洞”；新规则集
    把该洞改为窄 allow（202 仍在最前），对应流量由阻断变放行；
  * 新 205 对宽区域内的端口 1024 单独 deny（排在宽规则 201 前），新增一块阻断；
  * 新 203 把旧 103 对 192.168.1.0/24:443 的放行改为阻断；
  * 旧 104 的放行在新规则集中被整体删除，相关流量退回默认拒绝。
"""

EXAMPLE_OLD = [
    {
        "id": 102,
        "source": "10.1.0.0/16",
        "destination": "172.16.5.0/24",
        "portRange": [80, 80],
        "action": "deny",
    },
    {
        "id": 101,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [1, 1024],
        "action": "allow",
    },
    {
        "id": 103,
        "source": "192.168.1.0/24",
        "destination": "0.0.0.0/0",
        "portRange": [443, 443],
        "action": "allow",
    },
    {
        "id": 104,
        "source": "10.0.0.0/8",
        "destination": "192.168.1.0/24",
        "portRange": [443, 443],
        "action": "allow",
    },
]

EXAMPLE_NEW = [
    {
        "id": 202,
        "source": "10.1.0.0/16",
        "destination": "172.16.5.0/24",
        "portRange": [80, 80],
        "action": "allow",
    },
    {
        "id": 205,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [1024, 1024],
        "action": "deny",
    },
    {
        "id": 201,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [1, 1024],
        "action": "allow",
    },
    {
        "id": 203,
        "source": "192.168.1.0/24",
        "destination": "0.0.0.0/0",
        "portRange": [443, 443],
        "action": "deny",
    },
]

EXAMPLE_PAYLOAD = {"old": EXAMPLE_OLD, "new": EXAMPLE_NEW}

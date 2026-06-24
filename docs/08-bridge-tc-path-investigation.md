# Bridge Traffic Path Investigation

> 调研目的：确定 Marmot 数据面最佳 eBPF TC Hook Point。
> 测试内核：Linux 6.1.0-10-armmp (Debian, ARMv7)
> 测试拓扑：ns-client ↔ br-test ↔ ns-server (netns + veth + bridge)

---

## 1. 候选方案总览

```
方案     位置                     方向         部署复杂度
────     ────                     ────        ────────
A        br0 (bridge device)      ingress     低（1 个 hook）
B        br0 各 slave port        ingress     高（N 个 port）
C        br0                      ingress     clsact = A 的实现机制
D        br0                      egress      低（1 个 hook）
```

---

## 2. 实验数据

### 2.1 TC ingress on br0 测试结果

| 流量类型 | 流量路径 | 是否被捕获 | 是否需要代理 |
|---------|---------|-----------|------------|
| Ping **bridge IP** (192.168.100.1) | routed, local delivery | ✅ **Yes** | No (just for testing) |
| Ping **external** (8.8.8.8) | routed via br0→wlan0 | ✅ **Yes** | ✅ **Yes — MUST capture** |
| Ping **L2 forward** (192.168.100.3) | bridge L2 forwarding | ❌ **No** | ❌ **No — should NOT proxy** |

**证据**：实验显示 `flow_miss=5`，其中 Test A (3 pings) + Test C (2 pings) 共 5 个 ICMP 请求被捕获。Test B (3 pings L2 forward) 未被计数。

### 2.2 各 Hook Point 流量可见性对比

#### 场景 1: LAN client → WAN (核心路径)

```
client → br-slave → [hook?] → bridge RX → routing → wlan0
```

| Hook Point | 可见 | 说明 |
|-----------|------|------|
| br0 ingress | ✅ | Dest MAC = br0 → 进入 bridge net stack → 触发 ingress |
| slave ingress | ✅ | 包到达 slave port 时立即可见 |
| slave egress | ❌ | 包离开 slave port 时（已过 bridge 处理/路由）|
| br0 egress | ❌ | 路由后经 br0 egress 发出？不对，路由后走 wlan0 |
| wlan0 ingress | ❌ | 不在这个路径上 |

#### 场景 2: WAN → LAN client (TProxy 回程)

```
wlan0 → routing → br-slave → [hook?] → client
```

| Hook Point | 可见 | 说明 |
|-----------|------|------|
| br0 ingress | ❌ | 已路由到 slave，不经过 br0 自身 |
| slave ingress | ✅ | 包到达 slave (从 br0 侧) 时可见 |
| br0 egress | ❌ | TProxy socket 直接处理回程 |
| wlan0 ingress | ✅ | 外网包到达时可见 |

#### 场景 3: LAN client ↔ LAN client (L2 bridged)

```
client-A → br-slave-A → bridge FWD → br-slave-B → client-B
```

| Hook Point | 可见 | 说明 |
|-----------|------|------|
| br0 ingress | ❌ | L2 转发不经过 br0 net stack |
| slave ingress | ✅ | 在 slave-A 上可见（入方向）|
| slave egress | ✅ | 在 slave-B 上可见（出方向）|

---

## 3. 路径分析

### 3.1 Linux Bridge 内核处理流程

```
Packet arrives at slave port
        │
        ▼
  [slave ingress qdisc]       ← TC ingress on slave port
        │
        ▼
  bridge processing (FDB lookup, STP)
        │
        ├── Dest MAC = bridge self ──→ [bridge net stack] ──→ routing
        │                                  │
        │                            [bridge ingress qdisc] ← TC ingress on br0
        │                                  │
        │                              IP routing
        │                                  │
        │                            [bridge egress qdisc]  ← TC egress on br0
        │                                  │
        │                              wlan0/WAN
        │
        └── Dest MAC = another port ──→ L2 forward to slave-B
                                              │
                                        [slave-B egress qdisc]
                                              │
                                          client-B
```

### 3.2 TProxy 透明代理所需流量

对于透明代理场景，我们需要捕获的流量是：

```
[LAN client] → [br0] → [routing] → [WAN]
                                    ↓
                              Should go to TProxy first
```

关键路径是 **routing 之前的入方向流量**。此时目标 IP 已知，可以进行分流决策。

---

## 4. 方案对比

### 方案 A: br0 ingress (推荐)

| 维度 | 评价 |
|------|------|
| **可见流量范围** | ✅ 所有路由导向 WAN 的流量（客户端请求）|
| **L2 bridge 流量** | ✅ 正确忽略（不应代理）|
| **本地流量** | ✅ 捕获本机发起的出站流量 |
| **部署复杂度** | 🟢 低 — 单点 attach |
| **性能** | 🟢 最优 — 最早捕获点，减少无效处理 |
| **与 TProxy 兼容性** | ✅ 设置 fwmark → policy route → TProxy |
| **回程流量处理** | TProxy socket 自动处理（无需 eBPF）|

### 方案 B: slave port ingress

| 维度 | 评价 |
|------|------|
| **可见流量范围** | ✅ 所有经过 slave 口的流量（包括 L2 bridge）|
| **L2 bridge 流量** | ❌ 会捕获不应代理的 L2 流量，需要额外过滤 |
| **部署复杂度** | 🔴 高 — 需要遍历所有 slave port 动态 attach/detach |
| **性能** | 🟡 中 — 多端口增加 BPF 程序实例和 map 共享开销 |
| **适用场景** | 需要捕获 L2 桥接流量的场景（Marmot 不需要）|

### 方案 D: br0 egress

| 维度 | 评价 |
|------|------|
| **可见流量范围** | ❌ 仅看到已路由完成的出站流量（错过决策时机）|
| **场景适用性** | ❌ TProxy 需要拦截 routing **之前**的包 |

---

## 5. 性能考量

### 5.1 路径长度对比

```
方案 A (br0 ingress):    slave → bridge RX → [BPF] → routing → wlan0
方案 B (slave ingress):  slave → [BPF] → bridge RX → routing → wlan0
```

方案 A 和 B 的 BPF 执行点几乎相同（相差仅为 bridge 处理之前的若干指令）。

### 5.2 包处理比例

```
实际流量分布（估算）：
  WAN-bound:      ~20%    ← 需要代理/标记
  L2 bridge:      ~70%    ← 不需要处理（方案 A 自动忽略）
  Local/gateway:  ~10%    ← 不需要处理

方案 A：仅 WAN-bound 流量触发 BPF 逻辑
方案 B：100% 流量触发 BPF 逻辑（需要额外过滤 L2 流量）
```

### 5.3 Map 共享复杂度

```
方案 A：单 BPF 实例 → 单组 maps → Conntrack Cache 同步简单
方案 B：N 个 BPF 实例 → 共享 maps → 同步复杂度 × N
```

---

## 6. 生产环境考虑

### 6.1 多 LAN 端口场景

```
典型部署：
  eth0 ── LAN1
  eth1 ── LAN2       ← bridge br0 的 slave ports
  eth2 ── LAN3
  wlan0 ── WAN

推荐方案：
  TC ingress on br0（方案 A）
    └── 捕获所有 LAN→WAN 路由流量
  TC ingress on wlan0（可选扩展）
    └── 捕获网关自身发出的流量
```

### 6.2 内核兼容性

| 内核版本 | TC BPF on bridge | 行为 |
|---------|-----------------|------|
| 5.10+ | ✅ | 稳定 |
| 6.1 (本文测试) | ✅ | 按设计工作 |
| 6.6+ | ✅ TCX 支持 | 性能略优 |

---

## 7. 最终推荐

```
┌─────────────────────────────────────────────────────────┐
│                 最终推荐方案                              │
│                                                         │
│  主 Hook:  TC ingress on br0 (方案 A)                    │
│                                                         │
│  理由：                                                  │
│  1. 捕获 exactly 需要代理的流量（LAN→WAN routed）        │
│  2. 自动忽略 L2 bridge 流量（不需额外过滤）              │
│  3. 单点部署，复杂度最低                                 │
│  4. 性能最优（最早捕获 + 最小无效处理）                   │
│  5. TProxy 兼容性最佳（routing 前设置 fwmark）           │
│                                                         │
│  可选的扩展 Hook:                                        │
│  - TC ingress on wlan0 （网关自身流量代理, 按需）          │
│  - TC ingress on slave ports （如需捕获L2流量, 按需）     │
└─────────────────────────────────────────────────────────┘
```

### 实施建议

```
Phase 1: TC ingress on br0 (已实现, 修复 CIDR byte order bug)
Phase 2: 保持方案不变, 增加 TProxy 接收 fwmark=1 流量
Phase 3: 按需添加 ingress on wlan0 （网关自身流量）
```

> **关键结论**：当前选择 TC ingress on `br0` 是最佳方案。
> CIDR 不命中的问题是 BPF 代码中的 endianness bug，不是架构问题。
> L2 forward 流量不被捕获是正确行为（Marmot 不需要代理这些流量）。

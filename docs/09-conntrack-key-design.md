# Conntrack Fast Path Cache Key Design Analysis

> 工程决策文档 | v1.0 | 2026-06-24
> 目标：评估两种 Fast Path Cache Key 设计，产出明确推荐方案
> 相关子系统：eBPF TC Hook → Flow BPF Map → Conntrack Cache → TProxy

---

## 1. 技术背景与问题定义

### 1.1 当前架构

```
Fast Path (kernel):       Flow BPF Map (HASH, 5-tuple key)
Slow Path (userspace):    Conntrack Cache (Go map, 5-tuple key)
                          → Decision Interface
                          → BPF Map Writeback
```

每经过一次 Slow Path 决策后，结果回写到 Flow BPF Map。后续同 Flow 的包直接走 Fast Path，无需再次进入用户态。

### 1.2 问题：Flow HIT Rate 低

当前使用 **5-tuple key** `(src_ip, src_port, dst_ip, dst_port, proto)`。每个 TCP 连接有唯一的 src_port，导致：

- 每个新建 TCP 连接 → 新的 5-tuple → Flow Cache MISS
- 即使连续请求同一目标（如 `curl http://example.com` 两次），因为内核分配的 src_port 不同，第二次仍然是 MISS
- Flow Cache 的有效命中率**仅限于单 TCP 连接内的多包**（SYN → SYN-ACK → ACK → Data...）
- 对于短连接场景（HTTP/1.0, curl one-shot），实际上 Flow Cache **几乎永不命中**

### 1.3 本质矛盾

```
Session tracking    ≠    Fast path cache

conntrack:      必须精确追踪每个独立连接 → 必须 5-tuple
fast path cache: 加速决策，避免重复走 Slow Path → 可以降维
```

**必须明确区分这两个概念**，否则会陷入“必须 5-tuple”的思维定势。

---

## 2. 5-tuple Key 工作机制分析

### 2.1 定义

```
Key   = {src_ip:u32, src_port:u16, dst_ip:u32, dst_port:u16, proto:u8}
Value = {action:u8, outbound_tag[16]:u8, expire_at:u32, hit_count:u32}
```

### 2.2 匹配逻辑

```c
// eBPF TC ingress 中:
struct flow_key key = {
    .src_ip   = ip->saddr,
    .dst_ip   = ip->daddr,
    .src_port = tcp->source,
    .dst_port = tcp->dest,
    .protocol = ip->protocol,
};
// bpf_map_lookup_elem(&flow_map, &key) → exact match
```

**必须是完整精确匹配，不支持通配。** 这是 BPF HASH_MAP 的固有限制。

### 2.3 命中率分析

| 场景 | 同 Flow 包数 | Flow HIT 可能性 |
|------|-------------|----------------|
| TCP 短连接 (curl) | 3-5 包 | ✅ 第 2 包起可 HIT |
| TCP 长连接 (HTTP/2, gRPC) | 数百-数万包 | ✅ 第 2 包起 HIT，命中率极高 |
| UDP DNS (单查询) | 2 包 (req+resp) | ✅ 响应包 HIT |
| UDP 流 (QUIC, 游戏) | 数千包 | ✅ 极高 |
| **不同 TCP 连接同目标** | N/A | ❌ **永不 HIT** |

### 2.4 核心结论

**5-tuple 的问题是：它不能跨不同 TCP 连接共享决策。**

但这个问题是否真的需要解决？对于短连接场景（每个 curl 一个新连接），即使降维也只能在**连接建立后**起效——第一个包必须 MISS 才能建立 entry。降维的优势仅仅是后续的同目标新连接可以跳过第一次 MISS。

---

## 3. 去 src_port 降维 Key 工作机制分析

### 3.1 定义

```
Key   = {src_ip:u32, dst_ip:u32, dst_port:u16, proto:u8}
删除：src_port
```

### 3.2 预期效果

同一个 `(client_ip, target_ip, target_port, protocol)` 的所有连接共享同一决策：

```
连接1: src_ip=192.168.1.2, src_port=A, dst_ip=1.2.3.4, dst_port=443 → MISS → decision=proxy
连接2: src_ip=192.168.1.2, src_port=B, dst_ip=1.2.3.4, dst_port=443 → HIT  ← 降维后命中
```

### 3.3 匹配逻辑改变

```c
// eBPF TC ingress (降维版):
struct flow_key_lite key = {
    .src_ip   = ip->saddr,
    .dst_ip   = ip->daddr,
    .dst_port = tcp->dest,    // 仅目标端口
    .protocol = ip->protocol,
};
// 不再匹配 src_port
```

### 3.4 命中率提升预期

| 场景 | 5-tuple HIT | 降维 HIT | 提升 |
|------|------------|---------|------|
| 同连接多包 | ✅ | ✅ | 持平 |
| 同目标短连接 N 次 | ❌ | ✅(N-1 次) | 显著 |
| 不同目标 | ❌ | ❌ | 持平 |
| UDP 多次查询同 DNS | ❌(不同 src_port) | ✅ | 显著 |

---

## 3A. 混合方案：TCP 降维 + UDP 保留 5-tuple ⭐

### 3A.1 定义

**单一降维 key 的问题在于：它对 TCP 安全，但对 UDP 有风险。** 因此引出第三种方案：

```
TCP: Key = {src_ip, dst_ip, dst_port, proto}            ← 降维 (去 src_port)
UDP: Key = {src_ip, src_port, dst_ip, dst_port, proto}  ← 完整 5-tuple
```

**核心思想：按传输协议类型使用不同的 key schema。** 不追求统一，追求按需最优。

### 3A.2 理由

| 考量 | TCP | UDP |
|------|-----|-----|
| 连接状态 | 有状态 (SYN/FIN/RST 明确生命周期) | 无状态 (无连接信号) |
| src_port 随机性 | 每次连接随机分配 | 每次请求随机分配 |
| 同目标决策一致性 | ✅ 完全一致（client→target 始终相同） | ❌ 可能不同（对称 NAT 重新映射） |
| 多路复用风险 | 🟢 低（单 TCP 连接内有序） | 🔴 高（QUIC 应用层多路复用） |
| 降维安全性 | 🟢 安全 | 🔴 有风险 |
| 降维必要性 | 🟢 收益高（短连接场景 HIT rate 提升显著） | 🟡 收益低（UDP 流量占比小） |

### 3A.3 eBPF 实现方式

需要**两个独立的 BPF HASH Map**：

```c
// TCP Flow Map — 降维 key (去 src_port)
struct flow_key_tcp {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  protocol;   // 始终为 6 (IPPROTO_TCP)
    __u8  pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key_tcp);
    __type(value, struct flow_value);
} tcp_flow_map SEC(".maps");

// UDP Flow Map — 完整 5-tuple
struct flow_key_full {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);        // UDP 连接少，小容量
    __type(key, struct flow_key_full);
    __type(value, struct flow_value);
} udp_flow_map SEC(".maps");
```

**eBPF 查找逻辑**：

```c
static __always_inline int lookup_flow(struct __sk_buff *skb,
                                        struct iphdr *ip,
                                        struct tcphdr *tcp) {
    if (ip->protocol == IPPROTO_TCP) {
        struct flow_key_tcp key = {
            .src_ip   = ip->saddr,
            .dst_ip   = ip->daddr,
            .dst_port = tcp->dest,
            .protocol = IPPROTO_TCP,
        };
        struct flow_value *val = bpf_map_lookup_elem(&tcp_flow_map, &key);
        if (val) return val->action;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        struct flow_key_full key = {
            .src_ip   = ip->saddr,
            .dst_ip   = ip->daddr,
            .src_port = udp->source,
            .dst_port = udp->dest,
            .protocol = IPPROTO_UDP,
        };
        struct flow_value *val = bpf_map_lookup_elem(&udp_flow_map, &key);
        if (val) return val->action;
    }
    return -1;  // MISS
}
```

### 3A.4 预期效果对比

```
TCP 场景:
  curl http://1.2.3.4:8080 (连接1, src_port=A) → MISS → proxy → 写 tcp_flow_map
  curl http://1.2.3.4:8080 (连接2, src_port=B) → HIT  ← 降维后命中 (同目标)
  curl http://1.2.3.4:8080 (连接3, src_port=C) → HIT  ← 继续命中
  → HIT rate 从 ~30% 提升到 ~70% ✅

UDP 场景:
  dig @8.8.8.8 (src_port=X)  → MISS → 写入 udp_flow_map (完整 5-tuple)
  dig @8.8.8.8 (src_port=Y)  → MISS  ← 不同 src_port, 仍 MISS (安全, 不误合并)
  → 与 5-tuple 方案行为完全一致 ✅
```

### 3A.5 工程代价

| 代价项 | 说明 | 严重程度 |
|--------|------|---------|
| 两个 BPF Map | TCP + UDP 各一个，增加指令数 | 🟢 轻 (增加 ~15 条 BPF 指令) |
| 条件分支 | eBPF 中根据 proto 选择 map | 🟢 轻 (一个 branch) |
| 用户态写入 | SyncManager 需根据 proto 选择 map | 🟢 轻 (Go 中一个 switch) |
| Conntrack Cache 修改 | 写入时区分 TCP/UDP key 格式 | 🟡 中 (改 Insert 方法) |
| Conntrack  | 仍用统一 5-tuple, 无需修改 | 🟢 无 |

---

### 4.1 正确性：降维在 TCP 上安全吗？

**结论：在正向代理/TProxy 场景下，基本安全。**

原因：
- Marmot 是透明代理网关，决策仅基于目标地址（dst_ip + dst_port），与 src_port 无关
- 同一个 client 访问同一个目标，无论 src_port 如何变化，决策结果一致
- TCP 三次握手的 SYN + SYN-ACK + ACK 共享同一条降维 key，确保连接建立正常

### 4.2 风险：连接跟踪混淆

如果降维 key + 决策缓存写入了 `decision=proxy`，但后续某个不同进程/用户使用同一个 client_ip 访问同一个目标时，也会命中此缓存。**这通常是正确的**——因为决定是基于目标的，与来源进程无关。

### 4.3 边缘情况：状态码与 RST

```
连接1: client → server: 正常 TCP → decision=proxy
连接2: client → server: 发送 RST → 命中 flow key
```

降维 key 不会区分正常连接和异常连接。决策缓存是**单向的**，不会受 RST 影响。

---

## 5. UDP 场景对比分析

### 5.1 UDP 无连接语义

UDP 没有连接的概念。`src_port` 在 UDP 中：

- **客户端出站临时端口**：由内核随机分配，每次请求不同
- **服务端端口**：固定（如 DNS 53）

### 5.2 降维风险等级：中高

| 场景 | 风险 | 说明 |
|------|------|------|
| DNS 查询 | 🟢 低 | 同一 client 到同一 DNS 服务器的决策一致 |
| QUIC (HTTP/3) | 🟡 中 | 多路复用在同一 5-tuple 内，降维无新增风险 |
| **对称 NAT 后** | 🔴 **高** | **分析见 §6** |
| **多租户/容器** | 🟡 **中** | **分析见 §6** |

### 5.3 UDP 降维的核心风险

UDP 没有连接建立过程（无 SYN），可能存在以下问题：

1. **无连接状态**：第一个包就是数据，不能像 TCP 那样先 Miss 再决策再 Writeback
2. **无关闭通知**：UDP 没有 FIN/RST，过期只能靠 TTL
3. **应用层多路复用**：同一 `(client_ip, server_ip, server_port, UDP)` 可能承载多个独立会话（如 QUIC 的 Connection ID）

---

## 6. NAT / 多租户 / 代理系统影响分析

### 6.1 NAT 场景

```
NAT 网关后的 2 个客户端:
  客户端A (10.0.0.2:AAAA) → NAT → 公网IP:PORT_A → 目标 1.2.3.4:443
  客户端B (10.0.0.3:BBBB) → NAT → 公网IP:PORT_B → 目标 1.2.3.4:443
```

在 NAT 网关上看，两个连接共享：

| Key 字段 | 5-tuple | 降维 |
|---------|---------|------|
| src_ip | ❌ 不同 | ❌ 不同 |
| src_port | ✅ 不同 | ❌ 忽略 |
| dst_ip | ✅ 相同 | ✅ 相同 |
| dst_port | ✅ 相同 | ✅ 相同 |

**降维风险**：如果 NAT 后的两个客户端访问同一目标，降维 key 会混淆。但注意——**src_ip 仍然在 key 中**，所以 `src_ip` 仍然可以区分不同客户端。只有 NAT 将多个客户端映射到同一公网 IP 时才真正出现歧义。

**结论**：NAT 场景中，`src_ip` 才是区分多租户的关键，不是 `src_port`。降维后 `(src_ip, dst_ip, dst_port, proto)` 在 NAT 场景仍然有效。

### 6.2 代理系统场景

Marmot 是透明代理网关，**出口决策基于 dst_ip + dst_port**。所以：

- 同一个 client → 同一个 destination → 决策相同 ✅
- 多个 clients → 同一个 destination → 决策可能不同（取决于 client IP 规则）

降维 key 保留 `src_ip`，所以不同 client 可以有不同的决策。

### 6.3 容器/K8s 多租户

在同一宿主机上，不同容器可能共享同一出口 IP。此时降维 key 的 `(src_ip, dst_ip, dst_port, proto)` 无法区分不同容器。

但是——**这是正确的行为**。Marmot 的决策基于目标地址，不同容器访问同一目标的决策应该相同。如果需要容器级策略隔离，应该在决策层（Rule Engine）处理，不在 Flow Cache 层处理。

---

## 7. 性能收益分析

### 7.1 CPU 收益

```
场景: 1000 个短连接/秒, 每个连接 3 个包

5-tuple:
  Slow Path 调用次数 = 1000 次/秒 (每个连接第 1 个包)
  Fast Path 调用次数 = 2000 次/秒 (每个连接第 2-3 个包)

降维 (假设 10 个不同目标):
  首次访问各目标:
    Slow Path 调用次数 = 10 次/秒 (每个目标第 1 次)
    Fast Path 调用次数 = 2990 次/秒
```

**降维收益与"目标数/连接数"比率相关**。比率越低，收益越大。

### 7.2 BPF Map 大小

```
5-tuple:
  并发 10000 TCP 连接 → 10000 个 map entries
  每个 entry ~24 bytes → ~240KB BPF map
  Map 上限 65536 → 可支持 ~65000 并发连接

降维:
  并发 10000 TCP 连接 → 最多 10000 个 entries (但实际远少于 5-tuple)
  相同 client 同目标 → 共享同一 entry
  Map 上限 65536 → 实际可用空间更大
```

### 7.3 CPU Cache 局部性

BPF Map 是 HASH MAP。key 越小，HASH 碰撞越少，cache line 利用率越高。

```
5-tuple key size:  13 bytes + padding = 16 bytes
降维 key size:    10 bytes + padding = 12 bytes
节省:             ~25% key size
```

收益有限，非主要考量。

---

## 8. 风险分析

### 8.1 流合并风险

| 风险 | 5-tuple | 降维 | 严重程度 |
|------|---------|------|---------|
| 不同 src_port 合并 | ✅ 不合并 | ❌ 合并 | 🟡 中 |
| 不同协议合并 | ✅ 有 proto 字段 | ✅ 有 proto 字段 | 🟢 无 |
| 同一 client 多连接 | ✅ 独立 | ❌ 共享 | 🟢 低 (决策一致) |

### 8.2 错路由风险

降维 key 可能导致：

```
错误场景:
  client → server:443 decision=proxy (写入 flow cache)
  client → server:53  decision=direct (不同 dst_port, 不冲突)
  ✅ dst_port 在 key 中，不会混淆
```

不同端口不冲突，所以错路由风险**仅限于不同 src_port 间**，而这些连接的目标相同，决策应该一致。**风险极低。**

### 8.3 Session 污染风险

```
场景: client → server 正常 → decision=proxy
      之后 client → server 的首包 RST (恶意或异常)
```

降维 key 时，RST 包命中已有 entry，读取 `decision=proxy`。因为 action 是 proxy（设 fwmark=1），RST 包会被发给 TProxy。这**不影响正确性**——TProxy 收到 RST 后正常处理即可。

### 8.4 并发写入冲突

```
goroutine A: Insert(key=K, decision=proxy)
goroutine B: Insert(key=K, decision=direct)
```

写入到 BPF Map 存在竞争。Conntrack Cache 已用 `sync.RWMutex` 保护，但 BPF Map 写入无锁。**这是 5-tuple 和降维共有的问题**，不在 key 设计讨论范围内。

---

## 9. 适用场景边界划分

### 9.1 必须使用 5-tuple 的场景

1. **NAT 网关后的多客户端竞争**: 当多个 client 共享同一 `src_ip` 但决策不同时 → 5-tuple 必须
2. **出口策略与 src_port 相关**: 例如策略要求不同端口不同处理 → 5-tuple 必须
3. **状态防火墙**: 必须追踪每个独立连接状态 → 5-tuple 必须
4. **UDP 隧道/对称 NAT**: UDP 源端口映射到特定后端 → 5-tuple 必须

### 9.2 可以使用降维的场景 ✅

1. **透明代理网关**: 决策基于 dst_ip + dst_port，与 src_port 无关 → 降维安全
2. **正向代理**: 同上 → 降维安全
3. **策略路由加速**: fwmark 决策基于目标，不依赖 src_port → 降维安全
4. **CDN 缓存节点**: 流量转发决策 -> 降维安全

### 9.3 适用方案 C：TCP 降维 + UDP 5-tuple ⭐

这是 Marmot **推荐的折中方案**：

```
TCP: 降维 key {src_ip, dst_ip, dst_port, proto}
UDP: 5-tuple   {src_ip, src_port, dst_ip, dst_port, proto}
```

| 场景 | 安全性 | 理由 |
|------|--------|------|
| TCP 短连接 (HTTP) | 🟢 高 | 降维安全，同目标决策一致 |
| TCP 长连接 (gRPC/WS) | 🟢 高 | 降维安全，跨连接共享 |
| TCP 多租户 | 🟢 高 | src_ip 仍在 key 中 |
| UDP DNS | 🟢 高 | 5-tuple 精确追踪 |
| UDP QUIC/HTTP3 | 🟢 高 | 5-tuple 防止 QUIC 多路复用污染 |
| UDP 对称 NAT | 🟢 高 | 5-tuple 保持 NAT 映射准确性 |

### 9.4 分界线总结

```
src_port 是否影响决策?
│
├── 是 → 必须 5-tuple (状态防火墙 / NAT 转换 / 端口策略)
│
└── 否 → 降维安全 ✅
         └── 但需要考虑 UDP 场景的额外风险
```

Marmot 透明代理场景：**src_port 不影响决策** → 降维可行。

---

## 10. 决策建议

### 10.1 推荐方案 C：TCP 降维 + UDP 5-tuple (混合方案) ⭐

**明确推荐：Marmot Fast Path Cache 使用混合 Key 方案。**

```
TCP: Key = {src_ip, dst_ip, dst_port, proto}         → 降维
UDP: Key = {src_ip, src_port, dst_ip, dst_port, proto} → 5-tuple
```

### 10.2 理由

1. **TCP 收益最大化**：降维后短连接场景 HIT rate 从 ~30% 提升到 ~70%
2. **UDP 风险彻底避免**：对称 NAT、QUIC 多路复用、应用层混淆全部保持 5-tuple 隔离
3. **工程代价可控**：仅需两个 BPF Map + 一个 proto 条件分支
4. **Conntrack 无需修改**：session tracking 层始终使用 5-tuple
5. **与 Marmot 流量特征匹配**：TCP 占流量 >90%，是优化的主要目标

### 10.3 备选方案（不推荐）

| 方案 | 适用场景 | 不推荐理由 |
|------|---------|-----------|
| A: 统一 5-tuple | 状态防火墙 | Marmot 透明代理不需要 src_port 精度 |
| B: 统一降维 | 纯 TCP 代理 | UDP 对称 NAT 场景不安全 |

### 10.4 特殊情况处理

| 特殊情况 | 对策 |
|---------|------|
| 需要严格连接追踪 | 降维 key 仅用于 Fast Path 缓存，**conntrack 仍然用 5-tuple** |
| UDP 对称 NAT 场景 | 仅目标端口的 UDP 流量降维，其他走 5-tuple |

---

## 11. 最佳实践架构设计：分层 Key 设计

### 11.1 建议架构

```
┌──────────────────────────────────────────────┐
│  Layer 1: Conntrack (Session Tracking)        │
│  Key:  5-tuple (src_ip, src_port, dst_ip,     │
│                  dst_port, proto)              │
│  Purpose: 连接跟踪、状态超时、GC              │
│  Location: 用户态 Conntrack Cache (Go map)    │
├──────────────────────────────────────────────┤
│  Layer 2: Fast Path Cache (Decision Cache)    │
│  Key:  降维 (src_ip, dst_ip, dst_port, proto) │
│  Purpose: 跳过 Slow Path 加速决策             │
│  Location: BPF Flow Map (内核 HASH_MAP)       │
└──────────────────────────────────────────────┘
```

**注意**：当前代码的 `pkg/conntrack/` 实际同时承担了两层职责。推荐分离：

```
pkg/conntrack/    → 仅 Layer 1 (session tracking, 5-tuple)
pkg/cache/        → 新增 Layer 2 (fast path, 降维 key)
```

但 Phase 2 的 Conntrack Cache 设计规范已经定义了**不存储 Domain/Rule/DNS** 的约束，可以复用。

### 11.2 数据流

```
包到达 eBPF TC
    │
    ├── 降维 key 查 Flow BPF Map
    │   ├── HIT → 直接 action (Fast Path)
    │   └── MISS → 继续
    │
    ├── fwmark=1 → TProxy
    │
    ├── Decision Interface (Slow Path)
    │
    ├── Conntrack Cache Insert (5-tuple key)
    │   └── 用于 session 追踪、超时、统计
    │
    └── Flow BPF Map Insert (降维 key)
        └── 用于后续包的 Fast Path 决策
```

### 11.3 工程落地要点

| 要点 | 说明 |
|------|------|
| **两个 map** | Conntrack 用 5-tuple map，Flow Cache 用降维 map |
| **写入时转换** | Slow Path 得到决策后，分别写两个 map |
| **读路径仅 Flow Cache** | eBPF TC 仅查降维 map |
| **GC 由 Conntrack 驱动** | Conntrack entry 过期时，同步清理 Flow Cache entry |
| **eBPF map 的 max_entries** | 降维 key 冲突少，可将 max_entries 从 65536 降到 16384 |

### 11.4 代码级 Key 定义

```go
// Layer 1: Conntrack (session tracking) — 统一 5-tuple
type ConnKey struct {
    SrcIP    uint32
    SrcPort  uint16
    DstIP    uint32
    DstPort  uint16
    Protocol uint8
}

// Layer 2: Fast Path Cache — 按协议区分 key schema

// TCP Flow Cache Key — 降维 (去 src_port)
type TCPFlowKey struct {
    SrcIP    uint32
    DstIP    uint32
    DstPort  uint16
    Protocol uint8  // always 6
}

// UDP Flow Cache Key — 完整 5-tuple
type UDPFlowKey struct {
    SrcIP    uint32
    SrcPort  uint16
    DstIP    uint32
    DstPort  uint16
    Protocol uint8  // always 17
}

// 通用写入接口 — 根据 protocol 选择对应 map
func WriteFlowCache(proto uint8, srcIP, dstIP uint32, srcPort, dstPort uint16, action uint8) error {
    switch proto {
    case 6: // TCP
        key := TCPFlowKey{SrcIP: srcIP, DstIP: dstIP, DstPort: dstPort, Protocol: 6}
        return tcpFlowMap.Put(&key, &FlowValue{Action: action})
    case 17: // UDP
        key := UDPFlowKey{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort, Protocol: 17}
        return udpFlowMap.Put(&key, &FlowValue{Action: action})
    }
    return nil
}
```

### 11.5 迁移路径

```
Phase 2 (当前):   Conntrack Cache = 5-tuple, Flow BPF Map = 5-tuple
Phase 2.x (建议): Conntrack Cache = 5-tuple, Flow BPF Map = 降维
Phase 5:          Conntrack Cache = 5-tuple + Rule Engine
                  Flow BPF Map = 降维 + CIDR + Stats
```

---

## 附录 A：对比总表

| 对比维度 | A: 统一 5-tuple | B: 统一降维 | **C: TCP降维+UDP 5-tuple ⭐** |
|---------|------------|----------------------|--------------------------|
| **精度** | 🟢 最高 | 🟡 中 | 🟢 高 (TCP降维/UDP 5-tuple) |
| **跨连接 HIT** | ❌ 永不 | ✅ 同目标共享 | ✅ **TCP共享,UDP精确** |
| **短连接 HIT rate** | ~30% | ~70% | **~70% (TCP为主)** |
| **长连接 HIT rate** | >99% | >99% | >99% |
| **BPF Map 占用** | 🟡 每连接1 entry | 🟢 每目标1 entry | 🟢 TCP压缩, UDP精确 |
| **NAT 安全性** | 🟢 完全隔离 | 🟡 同源共享 | 🟢 TCP共享安全/UDP隔离 |
| **UDP 安全性** | 🟢 完全隔离 | 🔴 对称NAT风险 | 🟢 **保持5-tuple隔离** |
| **多租户安全性** | 🟢 完全隔离 | 🟢 src_ip在key中 | 🟢 同上 |
| **conntrack 一致性** | 🟢 一致 | 🟡 需分离 | 🟡 需分离(conntrack仍5-tuple) |
| **工程复杂度** | 🟢 低 | 🟡 中 | 🟡 **中 (两个BPF map)** |
| **推荐场景** | 状态防火墙/NAT网关 | 纯TCP代理 | **Marmot 透明代理** |

---

## 附录 B：决策流程图

```
                   ┌──────────────────────┐
                   │   应用场景是什么?      │
                   └──────────┬───────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
    ┌──────────────────┐          ┌──────────────────────┐
    │ 状态防火墙 / NAT   │          │ 透明代理 / 策略路由   │
    │ 连接追踪          │          │ TProxy / 正向代理    │
    └────────┬─────────┘          └──────────┬───────────┘
             │                               │
             ▼                               ▼
    ┌──────────────────┐          ┌──────────────────────┐
    │ 必须 5-tuple      │          │ 降维 + 5-tuple 共存  │
    │ Conntrack = Flow  │          │ Conntrack = 5-tuple  │
    │ Cache            │          │ Cache = 降维         │
    └──────────────────┘          └──────────────────────┘
                                             │
                                             ▼
                                             ┌──────────────────────────┐
                                             │ Marmot 推荐方案 C         │
                                             │                          │
                                             │ Conntrack: 统一 5-tuple   │
                                             │ TCP Flow: 降维 key        │
                                             │ UDP Flow: 5-tuple         │
                                             │                          │
                                             │ TCP HIT rate: ~70% ✅    │
                                             │ UDP 安全性: 完整保证 ✅  │
                                             └──────────────────────────┘
```

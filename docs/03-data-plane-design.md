# 3. 数据面设计（v0.3）

> ⚠️ 本文档替代原 `03-traffic-flow.md`（流量处理链路），扩展为完整数据面设计文档。

---

## 3.1 数据面全景

```
                             数据面全景
                             ────────

┌──────────────────────────────────────────────────────────────────┐
│  eBPF Kernel Space (Fast Path)                                   │
│                                                                  │
│  ┌────────────────┐     ┌────────────────┐     ┌─────────────┐  │
│  │ TC ingress     │────►│ Flow BPF Map   │────►│ Action 执行  │  │
│  │ (clsact qdisc) │     │ (HASH, 65536)  │     │             │  │
│  └───────┬────────┘     └────────┬───────┘     │ direct → 放行│  │
│          │                       │             │ proxy → TProxy│  │
│          │  Miss                 │ Hit         │ block → 丢弃 │  │
│          └───────┐               │             └──────────────┘  │
│                  ▼               │                               │
│           ┌──────────────┐      │                               │
│           │ fwmark 设置  │      │                               │
│           │ → table 100  │      │                               │
│           └──────┬───────┘      │                               │
└──────────────────┼──────────────┼───────────────────────────────┘
                   │              │
              ┌────▼──────────────▼────┐
              │  Policy Routing         │
              │  ip rule add fwmark 1   │
              │  lookup table 100       │
              │  → TProxy localhost:1080│
              └────────┬───────────────┘
                       │
┌──────────────────────▼───────────────────────────────────────────┐
│  Userspace (Slow Path)                                           │
│                                                                  │
│  ┌──────────┐     ┌──────────────┐     ┌─────────────────────┐  │
│  │ TProxy   │────►│ Rule Engine  │────►│ Conntrack Cache     │  │
│  │ TCP:1080 │     │ Match(addr)  │     │ (Go map)            │  │
│  │ UDP:1080 │     │ → MatchResult│     │                     │  │
│  └──────────┘     └──────────────┘     └──────────┬──────────┘  │
│                                                    │             │
│                                                    ▼             │
│                                          ┌──────────────────┐   │
│                                          │ BPF Map Update   │   │
│                                          │ bpf_map_update() │   │
│                                          │ → Flow BPF Map   │   │
│                                          └──────────────────┘   │
│                                                    │             │
│                                                    ▼             │
│                                          ┌──────────────────┐   │
│                                          │ 后续包 → Fast Path│   │
│                                          └──────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3.2 BPF Map Schema

### 3.2.1 Flow BPF Map（核心）

```c
// 文件: bpf/maps.h

// 5-tuple 流键
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;   // IPPROTO_TCP=6, IPPROTO_UDP=17
    __u8  pad;        // 对齐填充
};

// 流缓存值
struct flow_value {
    __u8  action;         // FLOW_ACTION_DIRECT=0
                          // FLOW_ACTION_PROXY=1
                          // FLOW_ACTION_BLOCK=2
    __u8  outbound_tag[16]; // proxy outbound tag (如 "proxy-jp\0")
    __u32 expire_at;      // 过期时间 (bpf_ktime_get_ns / 1000000000 + ttl)
    __u32 hit_count;      // 命中次数（统计用）
    __u8  reserved[4];    // 预留（对齐到 32 字节）
};

#define FLOW_MAP_MAX_ENTRIES 65536
#define FLOW_TTL_TCP  3600   // TCP: 1h
#define FLOW_TTL_UDP  120    // UDP: 2min

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_MAP_MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_map SEC(".maps");
```

### 3.2.2 CIDR 直连白名单 Map

```c
// CIDR 前缀 Trie map，用于 eBPF 级别的直连通配
// 由用户态写入：内网网段、已知国内 CIDR 等
// 匹配命中 → 直接放行，完全不进入 Flow Cache

struct cidr_key {
    __u32 prefix;     // 网络前缀（大端）
    __u8  len;        // 前缀长度
};

struct cidr_value {
    __u8  action;     // 0=放行
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct cidr_key);
    __type(value, struct cidr_value);
} cidr_whitelist SEC(".maps");
```

### 3.2.3 统计 Map

```c
struct stats_key {
    __u8 type;    // 0=fast_path_hit, 1=fast_path_miss,
                  // 2=tproxy_direct, 3=tproxy_proxy,
                  // 4=tproxy_block, 5=dns_hijack
};

struct stats_value {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct stats_value);
} stats_map SEC(".maps");
```

---

## 3.3 Flow Cache Schema（内核态运行时）

Flow Cache 是 BPF Flow Map 在 eBPF 程序运行时的逻辑视图：

```
          Flow Cache 运行视图
          ──────────────────

┌──────────────────────────────────────────┐
│  Flow BPF Map (HASH, 65536 entries)      │
│                                          │
│  Key:                                    │
│  ┌──────────────────────────────────┐   │
│  │ src_ip │ dst_ip │ src_port │    │   │
│  │ dst_port │ protocol              │   │
│  └──────────────────────────────────┘   │
│                   │                     │
│                   ▼                     │
│  Value:                                 │
│  ┌──────────────────────────────────┐   │
│  │ action │ outbound_tag │ expire │   │
│  └──────────────────────────────────┘   │
│                                          │
│ 并发访问模型:                             │
│  - eBPF TC: READ ONLY (lookup)          │
│  - Go 用户态: WRITE (update/delete)      │
│  - Go 用户态: GC (遍历 + 删除过期)       │
│                                          │
└──────────────────────────────────────────┘
```

**查找算法**：

```
TC ingress 收到数据包
        │
        ▼
提取 5-tuple: {src_ip, dst_ip, src_port, dst_port, protocol}
        │
        ▼
bpf_map_lookup_elem(&flow_map, &key)
        │
        ├── HIT ──→ 读取 action + outbound_tag
        │            │
        │            ├── DIRECT  → 不设 fwmark，内核转发
        │            ├── PROXY   → 设置 fwmark=1 → TProxy
        │            └── BLOCK   → 直接丢弃 (TC_ACT_SHOT)
        │
        └── MISS ──→ bpf_map_lookup_elem(&cidr_whitelist, &ip)
                      │
                      ├── HIT ──→ DIRECT（不发 TProxy）
                      │
                      └── MISS ──→ 设置 fwmark=1 → TProxy (Slow Path)
```

---

## 3.4 Conntrack Cache Schema（用户态）

```go
// pkg/conntrack/cache.go

// FlowKey — 5-tuple 连接标识
type FlowKey struct {
    SrcIP    net.IP `json:"src_ip"`
    DstIP    net.IP `json:"dst_ip"`
    SrcPort  uint16 `json:"src_port"`
    DstPort  uint16 `json:"dst_port"`
    Protocol uint8  `json:"protocol"` // 6=TCP, 17=UDP
}

// FlowEntry — 用户态缓存条目
type FlowEntry struct {
    Key        FlowKey   `json:"key"`
    Action     Action    `json:"action"`
    RuleID     string    `json:"rule_id"`
    RuleType   string    `json:"rule_type"`
    CreatedAt  time.Time `json:"created_at"`
    LastHitAt  time.Time `json:"last_hit_at"`
    ExpireAt   time.Time `json:"expire_at"`
    HitCount   uint64    `json:"hit_count"`
}

// Cache — Conntrack Cache 主结构
type Cache struct {
    mu       sync.RWMutex
    entries  map[FlowKey]*FlowEntry
    bpfMap   *ebpf.Map           // 对 Flow BPF Map 的引用
    stats    CacheStats
    draining bool                // 规则热加载时：排空模式
}

// NewCache 创建 Conntrack Cache
// bpfMap: 对已加载的 eBPF Flow Map 的引用（cilium/ebpf.Map）
func NewCache(bpfMap *ebpf.Map) *Cache

// Lookup 查询缓存（O(1) 哈希表）
func (c *Cache) Lookup(key FlowKey) *FlowEntry

// Insert 插入缓存 + 同步到 BPF Map
func (c *Cache) Insert(key FlowKey, entry *FlowEntry) error {
    // 1. 写入 Go map
    // 2. 序列化为 flow_value
    // 3. bpf_map_update_elem(&flow_map, &key, &value, BPF_ANY)
}

// Delete 删除缓存 + 同步删除 BPF Map
func (c *Cache) Delete(key FlowKey) error

// Evict 淘汰过期条目（定时 GC）
func (c *Cache) Evict() int {
    // 遍历 entries
    // 删除 ExpireAt < time.Now() 的条目
    // 同步删除 BPF Map
    // 返回删除数量
}

// StartGC 启动后台 GC 协程
func (c *Cache) StartGC(ctx context.Context, interval time.Duration)

// Drain 进入排空模式（规则更新时调用）
func (c *Cache) Drain() {
    c.draining = true
    // 新连接使用新规则
    // 旧连接 TTL 过期后自然淘汰
}

// Flush 强制清空所有缓存
func (c *Cache) Flush() {
    // 清空 Go map
    // 清空 BPF Map (bpf_map_delete_elem 遍历)
}
```

---

## 3.5 TCP TProxy 完整流程

```
┌──────┐     ┌────────┐     ┌──────────┐     ┌──────────┐     ┌─────────┐
│Client│     │TC BPF │     │Flow Map │     │ TProxy  │     │ sing-box│
│  :N  │     │Hook   │     │         │     │ :1080   │     │Outbound │
└──┬───┘     └────────┘     └──────────┘     └──────────┘     └─────────┘
   │            │               │               │               │
   │  SYN ────► │               │               │               │
   │            │               │               │               │
   │            │  Lookup flow_map(key)         │               │
   │            │──────────────►│               │               │
   │            │◄──── MISS ────│               │               │
   │            │               │               │               │
   │            │  Lookup cidr_whitelist(ip)    │               │
   │            │  → MISS (未知IP)              │               │
   │            │               │               │               │
   │            │  Set fwmark=1                 │               │
   │            │  → Policy Route Table 100     │               │
   │            │────────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─►│              │
   │            │               │               │               │
   │            │          TProxy 接收 SYN               │
   │            │          创建 TCP socket               │
   │            │          SO_ORIGINAL_DST 获取原始 dst   │
   │            │               │               │               │
   │            │          Rule Engine.Match(addr)         │
   │            │          → proxy, tag="auto"             │
   │            │               │               │               │
   │            │          Conntrack Cache.Insert(key)       │
   │            │          + bpf_map_update_elem(...)       │
   │            │               │               │               │
   │            │          sing-box Open TCP conn          │
   │            │────────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─►│
   │            │               │               │               │
   │ SYN-ACK ◄─│◄─ ─ ─ ─ ─ ─ ─│◄──────────────│◄──────────────│
   │            │               │               │               │
   │  ACK ────►│──────────────►│──────────────►│──────────────►│
   │            │  (后续包 Flow Cache HIT, 直接设 fwmark=1)   │
   │            │               │               │               │
   │ Data ◄───►│◄─────────────►│◄─────────────►│◄─────────────►│
   │            │               │               │               │
   │  FIN ────►│──────────────►│──────────────►│──────────────►│
   │            │               │               │               │
   │  eBPF 监测到 FIN/RST      │               │               │
   │  → 通知用户态删除 flow    │               │               │
   │  → bpf_map_delete_elem    │               │               │
   │            │               │               │               │
   │ FIN-ACK ◄─│◄─────────────│◄──────────────│◄──────────────│
```

---

## 3.6 UDP TProxy 流程

```
┌──────┐     ┌────────┐     ┌──────────┐     ┌──────────┐     ┌─────────┐
│Client│     │TC BPF │     │Flow Map │     │ TProxy  │     │ sing-box│
│  :N  │     │Hook   │     │         │     │ :1080   │     │Outbound │
└──┬───┘     └────────┘     └──────────┘     └──────────┘     └─────────┘
   │            │               │               │               │
   │ UDP Pkt ──►│               │               │               │
   │            │               │               │               │
   │            │ Lookup flow_map(key)         │               │
   │            │──────────────►│               │               │
   │            │◄──── MISS ────│               │               │
   │            │               │               │               │
   │            │ DNS 检查      │               │               │
   │            │ dst_port=53?  │               │               │
   │            │  → 是: DNS 劫持路径           │               │
   │            │  → 否: 继续                   │               │
   │            │               │               │               │
   │            │ 非 DNS UDP                   │               │
   │            │ Set fwmark=1                 │               │
   │            │ → Policy Route Table 100     │               │
   │            │────────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─►│              │
   │            │               │               │               │
   │            │          UDP TProxy 接收              │
   │            │          IP_RECVORIGDSTADDR          │
   │            │          获取原始目标地址              │
   │            │               │               │               │
   │            │          Rule Engine.Match(addr)         │
   │            │          → proxy, tag="auto"             │
   │            │               │               │               │
   │            │          Conntrack Cache.Insert(key)       │
   │            │          + bpf_map_update_elem(...)       │
   │            │               │               │               │
   │            │          sing-box UDP 隧道              │
   │            │          (UDP over TCP 可选)             │
   │            │────────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─►│
   │            │               │               │               │
   │ UDP Reply ◄│◄─ ─ ─ ─ ─ ─ ─│◄──────────────│◄──────────────│
   │            │               │               │               │
   │ 后续 UDP 包进入 Flow Cache HIT                 │
   │  → Fast Path: 直接设 fwmark=1 → TProxy        │
   │            │               │               │               │
```

**UDP 特殊处理要点**：

| 问题 | 处理方式 |
|------|---------|
| 无连接状态 | 使用 conntrack timeout（UDP 默认 120s） |
| DNS 不经过 TProxy | dst_port=53 直接从 eBPF 重定向到 DNS 子系统 |
| UDP 大包分片 | 仅首片设置 mark，后续分片自动跟随 |
| UDP over TCP | sing-box 可选模式，用于不稳定 UDP 场景 |
| QUIC/HTTP3 | 默认由 UDP 代理处理，或可配置直接放行 |

---

## 3.7 DNS 劫持流程

```
┌──────┐     ┌────────┐     ┌────────────┐     ┌────────┐
│Client│     │TC BPF │     │ DNS Server │     │ DNS    │
│  :53 │     │Hook   │     │ (Go)       │     │Upstream│
└──┬───┘     └────────┘     └────────────┘     └────────┘
   │            │               │               │
   │ DNS Req   │               │               │
   │(UDP:53)   │               │               │
   │──────────►│               │               │
   │            │               │               │
   │            │ dst_port=53?  │               │
   │            │ src_ip 检查:  │               │
   │            │  - 127.x.x.x?→ 不放行（本机） │
   │            │  - LAN IP?   → 重定向         │
   │            │               │               │
   │            │ DNS 重定向                   │
   │            │ dst=<br0_ip>:53              │
   │            │────────── ─ ─ ─ ─ ─ ─ ─ ─ ─►│
   │            │               │               │
   │            │          Rule Engine.Match    │
   │            │          ({domain, protocol:dns})│
   │            │               │               │
   │            │          dns_upstream:        │
   │            │          "domestic" / "oversea"│
   │            │               │               │
   │            │               │── DoH/DoT ──►│
   │            │               │ 或 UDP DNS    │
   │            │               │◄─────────────│
   │            │               │               │
   │            │          DNS Cache 写入       │
   │            │               │               │
   │ DNS Resp ◄─│◄─ ─ ─ ─ ─ ─ ─│               │
   │            │               │               │
```

---

## 3.8 Policy Routing 规则

```bash
# 初始化脚本：setup_policy_routing.sh

# 1. 创建独立路由表
ip route add table 100 local 0.0.0.0/0 dev lo

# 2. 添加策略路由规则
# fwmark=1 → lookup table 100 → 到 TProxy
ip rule add fwmark 1 lookup 100 priority 1000

# 3. 确保内网流量不走 TProxy
# (由 eBPF CIDR 白名单处理，不需 iptables)
# 但也可加规则做兜底：
ip rule add from <br0_network> lookup main priority 2000

# 4. 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding

# 5. TProxy 需要
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/<br0>/rp_filter

# 6. 清理脚本：cleanup_policy_routing.sh
# ip rule del fwmark 1
# ip route flush table 100
```

**规则说明**：

| 规则 | 用途 | 说明 |
|------|------|------|
| `fwmark 1 lookup 100` | 代理流量 | eBPF 标记为 proxy 的流量路由到 TProxy |
| `table 100 local 0.0.0.0/0 dev lo` | TProxy 接收 | 确保 TProxy socket 能绑定非本地 IP |
| `rp_filter = 0` | 反向路径过滤 | TProxy 需要接收非本机 IP 的包 |
| `ip_forward = 1` | IP 转发 | 网关正常转发功能 |

---

## 3.9 eBPF 与 Go 通信机制

### 3.9.1 通信全景

```
┌──────────────────────────────────────────┐
│  Go Userspace                            │
│                                          │
│  ┌────────────────┐                      │
│  │ cilium/ebpf    │                      │
│  │ Library        │                      │
│  └───────┬────────┘                      │
│          │                               │
│  ┌───────▼────────┐                      │
│  │ Conntrack      │                      │
│  │ Cache          │                      │
│  ├────────────────┤                      │
│  │ BPF Map Ops   │─── bpf syscall ────►  │
│  │ update/delete  │                      │
│  │ lookup/iterate │                      │
│  └────────────────┘                      │
└──────────────────────────────────────────┘
         │                           │
         ▼                           ▼
┌──────────────────────────────────────────┐
│  eBPF Kernel                             │
│                                          │
│  ┌────────────────┐  ┌────────────────┐  │
│  │ Flow BPF Map   │  │ TC Hook Prog  │  │
│  │ (HASH, 65536)  │◄─│ (read-only)   │  │
│  └────────────────┘  └────────────────┘  │
│                                          │
│  ┌────────────────┐  ┌────────────────┐  │
│  │ CIDR Whitelist │  │ Stats Map      │  │
│  │ (LPM_TRIE)     │  │ (ARRAY)        │  │
│  └────────────────┘  └────────────────┘  │
│                                          │
│  ┌────────────────┐                      │
│  │ Perf Event     │ (可选)               │
│  │ Ring Buffer   │──► Go 监听 FIN/RST   │
│  └────────────────┘                      │
└──────────────────────────────────────────┘
```

### 3.9.2 通信方式对比

| 方式 | 方向 | 延迟 | 使用场景 |
|------|------|------|---------|
| **BPF Map** (bpf syscall) | Go→eBPF | 低 (μs) | 写入 Flow Cache 条目、CIDR 白名单更新 |
| **BPF Map** (直接 lookup) | eBPF→Map | 极低 (ns) | TC hook 读 Flow Cache |
| **BPF Map** (遍历) | Go→eBPF | 低~中 | GC 清理过期条目、统计收集 |
| **Perf Event Ring Buffer** | eBPF→Go | 中 | （可选）通知连接关闭事件 |

### 3.9.3 关键操作时序

```text
1. Slow Path 决策完成
   ┌─────────┐    ┌─────────┐    ┌──────────┐    ┌──────────┐
   │TProxy   │───►│Rule     │───►│Conntrack │───►│Flow BPF  │
   │接收流量  │    │Engine   │    │Cache     │    │Map       │
   └─────────┘    └─────────┘    │(Go map)  │    │(kernel)  │
                                 └──────────┘    └──────────┘
                                       │            ↑
                                       └──sync──────┘

2. Fast Path 处理
   ┌──────────┐    ┌──────────┐    ┌──────────┐
   │TC Hook  │───►│Flow BPF  │───►│Action    │
   │ingress  │    │Map lookup│    │执行       │
   └──────────┘    └──────────┘    └──────────┘

3. GC 清理过期 Flow
   ┌─────────┐    ┌──────────┐    ┌──────────┐
   │Go GC    │───►│Conntrack │───►│Flow BPF  │
   │ticker   │    │Cache     │    │Map       │
   │(30s)    │    │Evict()   │    │delete()  │
   └─────────┘    └──────────┘    └──────────┘

4. 规则热更新
   ┌─────────┐    ┌──────────┐    ┌──────────┐
   │API      │───►│Rule      │───►│Cache     │
   │PUT      │    │Engine    │    │Drain()   │
   │/rules   │    │Reload()  │    │(排空)    │
   └─────────┘    └──────────┘    └──────────┘
```

### 3.9.4 Go → eBPF SDK 代码示例

```go
// pkg/bpf/loader.go — eBPF 加载与 Map 操作

import (
    "github.com/cilium/ebpf"        // eBPF 加载
    "github.com/cilium/ebpf/link"   // 程序挂载
    "github.com/cilium/ebpf/rlimit" // 资源限制
)

// 自动生成的 Go 结构体（对应 maps.h）
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ./bpf/tc_ingress.c

type FlowCacheManager struct {
    objs     bpfObjects        // eBPF 编译产物 Go binding
    flowMap  *ebpf.Map         // Flow BPF Map 句柄
    cidrMap  *ebpf.Map         // CIDR 白名单 Map 句柄
    cache    *conntrack.Cache  // 用户态 Conntrack Cache
}

func (m *FlowCacheManager) InsertFlow(key FlowKey, action Action, outboundTag string) error {
    var k bpfFlowKey
    var v bpfFlowValue

    // 填充 key
    k.SrcIp = nativeEndian.Uint32(key.SrcIP.To4())
    k.DstIp = nativeEndian.Uint32(key.DstIP.To4())
    k.SrcPort = htons(key.SrcPort)
    k.DstPort = htons(key.DstPort)
    k.Protocol = key.Protocol

    // 填充 value
    v.Action = actionCode(action.Mode)    // 0=direct, 1=proxy, 2=block
    copy(v.OutboundTag[:], outboundTag)
    v.ExpireAt = uint32(time.Now().Unix() + flowTTL)

    // 写入 BPF Map
    return m.flowMap.Put(&k, &v, ebpf.UpdateAny)
}

func (m *FlowCacheManager) DeleteFlow(key FlowKey) error {
    var k bpfFlowKey
    // ... 填充 key 同上
    return m.flowMap.Delete(&k)
}

func (m *FlowCacheManager) GC(ctx context.Context) {
    ticker := time.NewTicker(30 * time.Second)
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.cache.Evict() // 清理过期条目
        }
    }
}
```

---

## 3.10 数据面优化策略总结

### Fast Path（内核态，零用户态开销）

| 流量类型 | 处理方式 | 性能特征 |
|---------|---------|---------|
| Flow Cache HIT + DIRECT | 内核直接转发 | 🔥 接近裸机转发 |
| Flow Cache HIT + PROXY | 设 fwmark=1 → Policy Route → TProxy | 🔥 仅设置 mark，无上下文切换 |
| Flow Cache HIT + BLOCK | TC_ACT_SHOT 内核丢弃 | 🔥 零开销 |
| CIDR 白名单 HIT | 内核直接转发 | 🔥 无需建立 flow |

### Slow Path（用户态，首包开销）

| 流量类型 | 处理方式 | 性能特征 |
|---------|---------|---------|
| Flow Cache MISS | 用户态规则匹配 → 写入 cache | 🟡 首包额外 10-100μs |
| TProxy 连接代理 | socket 中转 + sing-box 加解密 | 🟡 持续加解密开销 |
| DNS 查询 | 规则匹配 → 上游查询 | 🟢 缓存命中时零开销 |
| 规则更新 | 全部用户态处理 | 🟢 非数据路径，无影响 |

### 默认关闭的优化（按需开启）

| 优化 | 说明 | 风险 |
|------|------|------|
| TCP Fast Open | 减少 SYN 握手延迟 | 需 server 支持 |
| UDP over TCP | 不稳定 UDP 场景的隧道 | 增加 TCP 连接数 |
| 连接预建 | 预建代理连接池 | 资源占用增加 |

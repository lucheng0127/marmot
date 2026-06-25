# 2. 总体架构设计（v0.3 — 审核修订版）

## 2.1 架构总览

```
┌──────────────────────────────────────────────────────────────┐
│                    Marmot Gateway System                       │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Control Plane (Go)                      │  │
│  │  ┌──────────┐  ┌──────────────────┐  ┌───────────────┐  │  │
│  │  │ Config   │  │ Rule Engine      │  │ API Server    │  │  │
│  │  │ Manager  │  │ (统一路由决策中心)│  │ (RESTful)    │  │  │
│  │  └────┬─────┘  └────────┬─────────┘  └───────┬───────┘  │  │
│  └───────┼──────────────────┼────────────────────┼───────────┘  │
│          │                  │                    │              │
│  ┌───────┼──────────────────┼────────────────────┼───────────┐  │
│  │  Data │  Plane          │                    │           │  │
│  │       │         ┌───────▼────────────┐       │           │  │
│  │       │         │ TProxy Socket      │       │           │  │
│  │       │         │ Layer              │       │           │  │
│  │       │         │ TCP :1080          │       │           │  │
│  │       │         │ UDP :1080          │       │           │  │
│  │       │         └───────┬────────────┘       │           │  │
│  │       │                 │                     │           │  │
│  │       │  ┌──────────────▼──────────────┐     │           │  │
│  │       │  │ Conntrack Fast Cache        │     │           │  │
│  │       │  │ (用户态决策缓存, 纯目标key)  │     │           │  │
│  │       │  └──────────────┬──────────────┘     │           │  │
│  │       │                 │                     │           │  │
│  │       │  ┌──────────────▼──────────────┐     │           │  │
│  │       │  │ Policy Routing               │     │           │  │
│  │       │  │ fwmark=1 → table 100 → TProxy│     │           │  │
│  │       │  └──────────────┬──────────────┘     │           │  │
│  │       │                 │                     │           │  │
│  │       │  ┌──────────────▼──────────────┐     │           │  │
│  │       │  │ eBPF TC Hook (br0 ingress)  │     │           │  │
│  │       │  │ ① CIDR 白名单查检 → 命中即直连│     │           │  │
│  │       │  │ ② 其余全部 fwmark=1 → TProxy│     │           │  │
│  │       │  │ (Flow Cache 推迟到 Phase 5) │     │           │  │
│  │       │  └──────────────────────────────┘     │           │  │
│  │       │                                        │           │  │
│  └───────┼────────────────────────────────────────┼───────────┘  │
│          │                                        │              │
│  ┌───────┼────────────────────────────────────────┼───────────┐  │
│  │  ┌────▼─────┐  ┌────────────────────────────┐ ◄────      │  │
│  │  │ DNS      │  │Proxy Engine (sing-box)     │            │  │
│  │  │Subsystem │  │                            │            │  │
│  │  │  • 127.0 │  │  • sing-box Adapter        │            │  │
│  │  │    .0.1:53│  │  • Node Manager (节点管理) │            │  │
│  │  │  • br0 :53│  │  • Health Checker         │            │  │
│  │  └──────────┘  └────────────────────────────┘            │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**核心变化一览（v0.3）**：

| 变更 | v0.2 | v0.3 |
|------|------|------|
| Conntrack Fast Cache | ❌ 无 | ✅ 新增（用户态 Decision Cache, Phase 5 升级 eBPF Flow Cache）|
| Rule Engine 优先级 | GeoIP > GeoSite | **GeoSite > GeoIP**（后述原因）|
| Node Manager | Control Plane | **Proxy Engine** |
| Health Checker | Control Plane | **Proxy Engine** |
| DNS Anti-Pollution | 未明确实现方式 | **不实现，依靠 DoH/DoT 加密** |
| 可观测性 | 仅有 `Match(addr) → Action` | 新增 `MatchResult{RuleID, RuleType, Reason}` |
| 流量路径 | 统一走 TProxy | **CIDR 直连 / fwmark=1 TProxy 分流** |
| 数据面缓存 | 无 | **用户态 Decision Cache (Phase 2) → eBPF Flow Cache (Phase 5)** |

---

## 2.2 五大子系统

### 2.2.1 Control Plane（控制面）

**职责**：配置管理、规则引擎、API 服务。

> Node Manager、Health Checker 已移至 Proxy Engine（见 2.2.4）。

| 模块 | 职责 | 关键接口 |
|------|------|---------|
| Config Manager | 读取/解析/热重载配置 | `config.Load(path)`, `config.Reload()` |
| Rule Engine | ⭐ 统一路由决策中心 | `rule.Match(addr) → MatchResult` |
| API Server | HTTP API 供外部管理 | `POST /rule`, `GET /status`, `PUT /config` |

---

### 2.2.2 Data Plane（数据面）— ⭐ 用户态 Decision Cache

**职责**：流量捕获 → CIDR 检查 + fwmark=1 → TProxy → Decision Cache

#### 数据面工作流

```
                    ┌─────────────────────┐
                    │  LAN Client → br0   │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │  TC ingress (eBPF)   │
                    │                     │
                    │ ① CIDR 白名单检查   │  ← 🔺 优先级最高
                    │  (LPM_TRIE dst IP)  │     静态规则，确定性
                    └────────┬────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
     ┌────────────────┐          ┌──────────────────────┐
     │ CIDR 白名单 HIT│          │ CIDR 白名单 MISS      │
     │ (静态规则命中) │          │                      │
     │                │          │ 设 fwmark=1           │
     │ 内核直接转发    │          │ → Policy Route       │
     │ 不设 fwmark     │          │ → TProxy :1080       │
     └────────────────┘          └──────────┬───────────┘
                                             │
                                    ┌────────▼───────────┐
                                    │ TProxy accept       │
                                    │ → SO_ORIGINAL_DST  │
                                    │ → Decision Cache   │
                                    │   Lookup(纯目标key) │
                                    └────────┬───────────┘
                                             │
                              ┌──────────────┴──────────────┐
                              ▼                             ▼
                     ┌────────────────┐          ┌─────────────────────┐
                     │ Cache HIT      │          │ Cache MISS          │
                     │ (命中已有决策)  │          │ (首次访问)           │
                     │                │          │                     │
                     │ 直接用缓存决策  │          │ Decision Interface  │
                     │ CacheHit++     │          │ → Insert Cache      │
                     │                │          │ → CacheMiss++       │
                     └────────────────┘          └─────────────────────┘
```

> **Flow Cache 说明**：eBPF Flow Cache（BPF Flow Map）在 Phase 2 中已移除。
> 当前 Phase 2 使用 StaticDecider（恒 proxy），所有流量都经过 fwmark=1 → TProxy，
> eBPF Flow Cache 无实际收益。已在 Phase 2 中移除，**将在 Phase 5（Rule Engine 引入
> multi-decision 后）重新引入**，届时 direct 流量可绕过 TProxy 实现真正 Fast Path。

#### 典型收益

**当前 Phase 2 收益**（用户态 Decision Cache）：

| 场景 | 无缓存 | 有缓存 | 收益 |
|------|--------|--------|------|
| 首次访问目标 | TProxy + Decision | TProxy + Decision | 持平 |
| 再次访问同目标 | TProxy + Decision | TProxy + Cache HIT | 减少决策开销 |
| 大量客户端同目标 | 每次独立决策 | 仅首次决策 | 显著 |

**Phase 5 预期收益**（eBPF Flow Cache 重新引入后）：

| 场景 | 无 eBPF Cache | 有 eBPF Cache | 收益 |
|------|--------------|--------------|------|
| 国内直连流量 (direct) | 每次经 TProxy | 内核直接转发 | **零 TProxy 开销** |
| 代理流量 (proxy) | 每次经 TProxy | 内核直接标记 | **持平** |

#### 为什么需要用户态 Decision Cache

| 考量 | 无 Cache | 有 Cache |
|------|---------|---------|
| 每个新建连接 | 必走 TProxy + 用户态决策 | 必走 TProxy，但跳过 Decision Interface |
| 跨连接同目标 | 每次独立决策 | 仅首次决策，后续 Cache HIT |
| CPU 使用 | 随连接数线性增长 | 仅首次决策开销 |
| 缓存重启 | 缓存丢失，需 warmup | warmup 期间退化为无缓存状态 |

> **Phase 5 预期**：eBPF Flow Cache 重新引入后，可实现 direct 流量在
> 内核态直接转发、zero TProxy 开销。当前 Phase 2 仅做到用户态缓存。

#### 数据面流程整合示意

```
                    ┌─────────────────────┐
                    │  LAN Client → br0   │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │  TC ingress (eBPF)   │
                    │  CIDR → direct bypass│
                    │  其余 → fwmark=1     │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │  TProxy :1080       │
                    │  SO_ORIGINAL_DST    │
                    │  Decision Cache     │
                    │  ┌─ HIT ─→ 用缓存   │
                    │  └─ MISS → Decision │
                    └────────────────────┘
```

---

### 2.2.3 DNS Subsystem（DNS 子系统）— ⭐ MVP 简化

**职责**：规则驱动的 DNS 分流解析、本机 DNS 隔离。

**MVP 原则**：不实现自定义 DNS 污染检测逻辑。污染防护完全依赖：

1. **GeoSite 分流** — 国外域名自动走 DoH/DoT
2. **DoH/DoT 加密** — TLS 传输层防篡改
3. **国内 DNS** — 国内域名走 UDP DNS，不涉及污染问题

> ❌ MVP 不实现：污染 IP 库维护、污染特征识别、多 DNS 结果交叉验证。

#### DNS 分流决策流

```
收到 DNS 查询 qname=example.com
│
├─ 源地址检查
│  ├─ 127.0.0.1 → 网关本机查询（直接放行，无环路）
│  └─ LAN IP    → 正常处理
│
├─ DNS 缓存检查
│  ├─ 命中 + TTL 有效 → 返回
│  └─ 未命中 → 继续
│
├─ Rule Engine.Match({Domain: "example.com", Protocol: "dns"})
│  ├─ dns_upstream: "domestic"   → UDP 114.114.114.114
│  ├─ dns_upstream: "oversea"    → DoH 1.1.1.1（TLS 加密，防污染）
│  ├─ dns_upstream: "custom"     → 自定义上游
│  └─ proxy: "proxy-us"          → 通过代理隧道转发 DNS（高级）
│
├─ 执行 DNS 查询
├─ 写入 LRU 缓存
└─ 返回客户端
```

#### 本机 DNS 隔离

```
┌─ 网关本机 ────────────────────────────┐
│  /etc/resolv.conf → 127.0.0.1:53     │
│  → DNS Subsystem 内部监听器           │
│  → 不走 eBPF TC Hook → 无环路风险     │
└──────────────────────────────────────┘

┌─ LAN 客户端 ──────────────────────────┐
│  DHCP DNS = <br0_ip> 或透明劫持       │
│  → <br0_ip>:53 外部监听器             │
└──────────────────────────────────────┘
```

---

### 2.2.4 Proxy Engine（代理引擎 — sing-box）— ⭐ Node Manager 迁移

**职责**：sing-box 适配层 + 节点管理 + 健康检查。

| 模块 | 职责 | 关键接口 |
|------|------|---------|
| sing-box Adapter | 封装 `box.New()`，对接 Marmot | `Engine.Start(options)`, `Engine.Stop()` |
| Node Manager | 管理上游代理节点（按 tag 分组） | `node.ByTag(tag) → []Node` |
| Health Checker | 周期性检测节点可用性 | `health.CheckAll()`, `health.Alive(tag) → bool` |

**集成方式**：

```
        TProxy 接收流量
              │
              ▼
       ┌──────────────┐
       │ Rule Engine  │  ← Control Plane
       └──────┬───────┘
              ▼
       Action{Mode: "proxy", Tag: "proxy-jp"}
              │
              ▼
       ┌──────────────────┐
       │  Proxy Engine    │
       │                  │
       │  ┌────────────┐  │
       │  │sing-box    │──┼──► Remote Server
       │  │Adapter     │  │
       │  └────────────┘  │
       │  ┌────────────┐  │
       │  │Node Manager│  │  ← 节点池管理
       │  └────────────┘  │
       │  ┌────────────┐  │
       │  │Health      │  │  ← 健康检查
       │  │Checker     │  │
       │  └────────────┘  │
       └──────────────────┘
```

---

### 2.2.5 Rule Engine（规则引擎）— ⭐ 优先级调整 + 可观测性

#### 规则匹配优先级（v0.3 调整）

```
优先级    规则类型         说明
──────    ────────         ────
  1       User Rule        用户自定义规则（最优先）
  2       Domain           域名精确匹配
  3       Domain Suffix    域名后缀匹配
  4       Domain Keyword   域名关键字匹配
  5       GeoSite          🔺 基于域名的 Geo 数据库（优先级提升）
  6       IP               IP/CIDR 精确匹配
  7       GeoIP            ▼ 基于 IP 的 Geo 数据库（优先级降低）
  8       Default          兜底策略
```

#### 为什么 GeoSite 优先于 GeoIP

| 对比维度 | GeoSite | GeoIP |
|---------|---------|-------|
| 匹配依据 | **域名**（应用层） | IP 地址（网络层） |
| CDN 场景 | ✅ 准确：`cdn.example.com` 含 `cn` 标签 | ❌ 不可靠：CDN IP 常回源到美国 |
| Anycast 场景 | ✅ 准确：域名归属确定 | ❌ 不可靠：Anycast IP 全球统一 |
| Cloudflare 场景 | ✅ `cloudflare-cn.com` 正确识别 | ❌ CF IP 多归属美国 |
| 国内 CDN 误判 | 域名后缀 `.cn` / `baidu.com` → CN | Akamai/CF 等 CDN 节点在国内但 IP 归 US |

**结论**：对于内容分发场景（CDN/Cloudflare/Anycast），**域名归属比 IP 归属更可靠**。GeoIP 作为 IP 层后备方案，在无法获取域名信息时（如纯 IP 流量）发挥作用。

#### 可观测性设计

```go
// v0.3 新增：带解释的匹配结果
type MatchResult struct {
    Action   Action // 决策：direct / proxy:<tag> / block / dns_upstream:<tag>
    RuleID   string // 命中的规则 ID（空字符串 = 默认规则）
    RuleType string // 规则类型：domain / domain_suffix / domain_keyword / geoip / geosite / ip / default
    Match    string // 匹配值（如 "google.com" / "CN" / "192.168.0.0/16"）
    Reason   string // 人类可读的解释（如 "域名 google.com 匹配 geosite:cn，走 direct"）
}
```

**调试能力**：

| 能力 | 实现方式 | 用途 |
|------|---------|------|
| 规则命中日志 | Debug 级别输出每个 `MatchResult` | 开发调试、规则排查 |
| 规则命中统计 | 每规则计数器 (atomic counter) | 统计热点规则、验证配置生效 |
| 规则排查 API | `GET /api/v1/rules/debug?domain=xxx.com` | 外部查询：为什么 `xxx.com` 走代理？|
| Trace 日志 | 单连接全链路 Trace ID | 端到端流量路径追踪 |

**Rule Engine 接口（v0.3）**：

```go
type RuleEngine struct {
    rules     []Rule           // 有序规则列表（按优先级排序）
    exactMap  map[string]Rule  // 域名精确匹配 → O(1) 哈希表
    suffixTrie *Trie           // 域名后缀匹配 → 反转域名 Trie O(n)
    keywordAC  *AhoCorasick   // 域名关键字匹配 → Aho-Corasick 自动机
    geoipDB   *geoip.Reader   // GeoIP 数据库
    geositeDB *geosite.Reader // GeoSite 数据库
    stats     *RuleStats      // 命中统计计数器
}

func (e *RuleEngine) Match(addr Addr) MatchResult
func (e *RuleEngine) MatchDebug(addr Addr) []MatchResult  // 返回所有匹配过程的 Trace
```

---

## 2.3 用户态 Decision Cache 设计 ⭐ 新增

### 2.3.1 设计目标

```
新连接 → TProxy (首次)
         ↓
     Decision Cache (用户态, 纯目标 key)
         ↓
后续同目标连接 → Cache HIT (跳过 Decision Interface)
```

> **Phase 5 升级路径**：当 Rule Engine 引入 non-uniform 决策后，将用户态 Decision Cache
> 写入 eBPF Flow Map，实现 direct 流量绕过 TProxy 的真正 Fast Path。

### 2.3.2 Phase 2 生命周期

```
                    Cache Lifecycle (Phase 2 — 用户态)
                    ──────────────────────────────────

  [NEW]                          fwmark=1 → TProxy
    │                                │
    ▼                                ▼
┌────────────┐  Slow Path       ┌──────────┐
│ Cache MISS │ ──────────────►  │ Decision │
│ (TProxy)   │                  │ Interface│
└────────────┘                  │ (Static) │
                                └────┬─────┘
                                     │
                            ┌────────▼────────┐
                            │ Decision Cache  │ ← 用户态写入
                            │ (Go map,        │    纯目标 key
                            │  {dst,port,pr}) │    {dst_ip, dst_port, proto}
                            └────────┬────────┘
                                     │
                            ┌────────▼────────┐
                            │ Cache HIT       │ ← 后续同目标
                            │ (跳过 Decision) │   直接使用缓存
                            └────────┬────────┘
                                     │
                            ┌────────▼────────┐
                            │ Cache TIMEOUT   │ ← TTL 过期自动删除
                            │ (TTL 淘汰)      │
                            └────────┬────────┘
                                     │
                                     ▼
                               [DELETED]
```

### 2.3.3 淘汰策略

| 策略 | 说明 | 参数 |
|------|------|------|
| TTL 基淘汰 | 每个 entry 关联 TTL，过期即删 | 3600s (默认) |
| 上限淘汰 | 缓存满时淘汰最旧条目 | 上限: 65536 entries |

### 2.3.4 Cache Key Schema

```go
// CacheKey — 纯目标 key（路由决策仅基于目标地址）
type CacheKey struct {
    DstIP    uint32
    DstPort  uint16
    Protocol uint8
}

type CacheEntry struct {
    Decision Decision  // Direct / Proxy
    LastSeen time.Time
    HitCount uint64
}
```

**不包含的字段**：SrcIP / SrcPort（决策不依赖源地址）

### 2.3.5 Fast / Slow Path 流程 (Phase 5 升级)

> eBPF Flow Cache 在 Phase 5 重新引入。此处为预留设计，当前 Phase 2 不实现。
> 届时将用户态 Decision Cache → BPF Flow Map → 内核态 Fast Path。

---

## 2.4 可靠性与性能平衡策略

### 2.4.1 两层路径

```
eBPF TC Hook (数据面)              TProxy + Decision Cache (Slow Path)
════════════════════               ════════════════════════════════════
  - CIDR 白名单检查                  - 新目标的首次决策
  - fwmark=1 策略路由                - Decision Cache 管理
  - 统计计数器                       - TTL 淘汰 + GC
```

### 2.4.2 Phase 2 缓存策略

| 场景 | 策略 | 说明 |
|------|------|------|
| 缓存满 | LRU 淘汰 | 移除最久未命中条目 |
| TTL 过期 | 自动删除 | 默认 3600s |
| 进程重启 | 缓存丢失 | 自动 warmup（warmup 期间退化为无缓存）|
| 规则变更 | 被动等待 TTL 过期 | Phase 5 实现 draining 模式 |
| 单个 proxy 节点故障 | Health Checker 自动切到同 tag 内下一节点 | 单节点不可用 |
| DNS 子系统故障 | 将 DNS 查询直接透传到上游 DNS | DNS 无分流 |
| 规则文件加载失败 | 使用最后成功加载的规则集 | 规则不更新 |
| 内存超限 | 启用连接限制，丢弃新连接 | 部分新连接失败 |

---

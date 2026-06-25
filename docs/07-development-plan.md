# 7. 第一阶段开发计划

> ⚠️ 当前阶段仅为计划输出。不允许编码实现。
> 计划中的里程碑时间估算基于单人开发，以实际投入为准。

---

## 7.1 阶段划分总览

```
Phase 0 ─ 环境与骨架                     （第 1-2 天）
Phase 1 ─ eBPF 数据面 + Flow Cache       （第 3-10 天）
Phase 2 ─ TProxy + 用户态决策缓存     （第 11-16 天）
Phase 3 ─ sing-box 引擎 + 节点管理       （第 17-22 天）
Phase 4 ─ DNS 子系统   ⭐ 简化版         （第 23-26 天）
Phase 5 ─ 规则引擎 + eBPF Fast Path      （第 27-38 天）
```

---

## 7.2 测试环境分级 ⭐ 新增

### 设计目标

解决以下问题：
- 开发环境不具备真实外网访问能力
- 过早依赖 Google / YouTube 等外网资源导致测试失败
- 外部网络环境不稳定影响开发进度

### 三级测试环境

```
Level 1 ─ 功能验证        Phase 0, Phase 1
Level 2 ─ 集成验证        Phase 2, Phase 3, Phase 4
Level 3 ─ 生产验证        Release Candidate, GA
```

---

### Level 1：功能验证环境

**目标**：验证单模块功能正确性。

**特点**：
- ✅ 不依赖真实代理服务器
- ✅ 不依赖 Google / YouTube / Facebook
- ✅ 不依赖外网连通性

**允许的技术栈**：

```
Linux Bridge
├── veth pair
├── network namespace
├── 本地 HTTP 服务  (python3 -m http.server)
├── 本地 TCP 服务   (nc -l)
├── 本地 ICMP 测试  (ping)
└── iperf3 性能测试
```

**判定原则**：
- 以模块功能正确性为准
- 不以"能否访问 Google"为验收标准

**适用阶段**：
- Phase 0（骨架）
- Phase 1（eBPF 数据面）

---

### Level 2：集成验证环境

**目标**：验证完整数据链路。

**特点**：
- ✅ 不依赖真实海外代理节点
- ✅ 使用本地模拟代理服务器
- ✅ 完整的 Client → Marmot → Proxy → Target 链路验证

**允许的技术栈**：

```
本地代理模拟（推荐 Xray）：
  dokodemo-door inbound
  + freedom outbound
  = 完整的代理环路

验证链路：
  ns-client
    ↓
  Marmot (br-test)
    ↓
  TProxy :1080
    ↓
  Xray (dokodemo-door → freedom)
    ↓
  ns-server (本地 HTTP 服务)
```

**判定原则**：
- 流量能按规则 route 到 TProxy
- TProxy 能正确劫持并将流量转发到代理引擎
- 代理引擎能正确连接目标
- DNS 能正确分流

**适用阶段**：
- Phase 2（TProxy + Conntrack）
- Phase 3（sing-box 引擎）
- Phase 4（DNS 子系统）

---

### Level 3：生产验证环境

**目标**：验证真实代理能力。

**要求**：
- 真实上游代理节点（SS/VMess/VLESS/Trojan）
- 真实海外 DNS 服务器
- 可访问的海外网站

**适用阶段**：
- Release Candidate
- GA Release

---

## 7.3 开发验证原则 ⭐ 新增

### 原则 1：分层验证

```
先功能 → 再集成 → 最后生产

Phase 1  仅在 Level 1 验证
Phase 2-4 主要在 Level 2 验证
Release  在 Level 3 验证
```

### 原则 2：禁止以外网可达性为唯一标准

Phase 1 ~ Phase 4 不允许将以下作为唯一验收标准：

```
Google
YouTube
Facebook
```

如果外网不可达，必须使用 Level 1 / Level 2 的本地模拟方案完成验证。

### 原则 3：证据原则

任何运行结论必须基于：

```
Build Log
SSH 执行结果
Test Output
bpftool / tc / ip 等工具输出
```

禁止编造执行结果。

### 原则 4：环境隔离

所有测试必须基于 netns + veth + bridge 构建，禁止依赖真实 LAN 设备。

---

## 7.4 Phase 0：环境与骨架（第 1-2 天）

### 目标
建立项目骨架、工具链、CI 基础设施

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 0.1 | Go module 初始化 (`go mod init github.com/lucheng0127/marmot`) | `go.mod`, `go.sum` | 0.5h |
| 0.2 | 创建目录结构（cmd/ internal/ pkg/ bpf/ configs/）| 目录树就位 | 0.5h |
| 0.3 | 配置结构体定义 + YAML 解析 | `internal/config/config.go` | 2h |
| 0.4 | 日志模块初始化 | `pkg/log/logger.go` | 1h |
| 0.5 | Makefile 构建系统 | `Makefile` | 2h |
| 0.6 | Docker Compose 开发环境（bpf 编译工具链）| `docker-compose.yml` | 2h |
| 0.7 | CLI 入口骨架 | `cmd/marmot/main.go` | 1h |
| 0.8 | 服务生命周期骨架（启动/关闭/信号处理）| `internal/server/server.go` | 3h |
| 0.9 | 基础 CI（Go build + lint） | `.github/workflows/ci.yml` | 2h |

**里程碑**: `make build` 可编译出 `marmot` 二进制

### 不包含的内容
- eBPF 程序
- TProxy 逻辑
- DNS 逻辑
- 任何代理逻辑

---

## 7.5 Phase 1：eBPF 数据面 + Flow Cache 基础（第 3-10 天）

### 级别：Level 1（功能验证）

### 目标
实现核心数据面：eBPF TC Hook 流量捕获 + Flow BPF Map 预分类

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 1.1 | eBPF 开发环境搭建（clang/llvm/libbpf-dev）| 可编译 .o | 2h |
| 1.2 | 编写 TC ingress BPF 程序（Flow Map lookup + miss→mark）| `bpf/tc_ingress.c` | 8h |
| 1.3 | 编写 TC egress BPF 程序 | `bpf/tc_egress.c` | 4h |
| 1.4 | 使用 cilium/ebpf 加载 BPF 程序 | `pkg/bpf/loader.go` | 4h |
| 1.5 | TC Hook attach/detach 管理 | `pkg/bpf/tc_hook.go` | 3h |
| 1.6 | Flow BPF Map Schema 定义 + 用户态操作封装 | `pkg/bpf/maps.go` | 4h |
| 1.7 | CIDR 直连白名单 BPF Map (LPM_TRIE) | `pkg/bpf/maps.go` | 3h |
| 1.8 | 统计 BPF Map (ARRAY) | `pkg/bpf/maps.go` | 2h |
| 1.9 | 策略路由脚本（ip rule/ip route）| `pkg/tproxy/routing.go` | 3h |
| 1.10 | eBPF 数据面基本通路测试（直连 vs mark）| 测试报告 | 4h |
| 1.11 | CIDR Functional Verification（LPM_TRIE 验证 + CIDR命中/不命中/MARK行为确认 + Bridge TC路径分析）| 调研报告 | 4h |

### 关键交付物
- eBPF 程序可编译并加载到网桥接口
- CIDR 直连白名单 + fwmark=1 策略路由（基本信息面）
- CIDR Functional Verification 完成（LPM_TRIE 验证 + 命中/不命中/MARK 行为确认）
- 策略路由配置自动化

> 注：Phase 1 实现了 eBPF Flow Cache 原型，但当前 Phase 2 使用 StaticDecider（恒 proxy），eBPF Flow Cache 无实际收益。
> 已在 Phase 2 中移除，将在 Phase 5（Rule Engine 引入多决策后）重新引入。

### 验证标准

```
Level 1（netns + veth + bridge）：
1. TC Program Attach 成功（tc filter show 可见 BPF 程序）
2. CIDR 白名单 LPM_TRIE 条目写入成功（Go ↔ BPF Map 通信验证）
3. CIDR 白命中后不打 MARK（通过 tc filter 验证或统计计数器）
4. 非 CIDR 流量正确设 fwmark=1（ip rule 统计）
5. Flow Map Lookup 成功（Hit/Miss 统计）
6. Flow Statistics 全部计数器正常工作
```

> 注意：Phase 1 仅验证 Go ↔ BPF Map 通信正确性 + 统计计数器正常。已完成验证。

### 不要求
- ❌ 不要求 bridge forwarding 场景的 CIDR 命中
- ❌ 不要求 TProxy 转发
- ❌ 不要求 Google 可访问

---

## 7.6 Phase 2：TProxy + 用户态决策缓存（第 11-16 天）

### 级别：Level 2（集成验证）

### 目标
实现 **TCP TProxy + SO_ORIGINAL_DST + 用户态 Decision Cache**，建立完整 Slow Path。

核心价值：
- eBPF 仅做 CIDR 白名单 + fwmark=1 策略路由（去除了当前无实际收益的 eBPF Flow Cache）
- TProxy 接收流量 → Decision → 用户态缓存（跨连接共享，纯目标 key）
- Phase 5 当 Rule Engine 引入多决策（direct/proxy）后，再重新引入 eBPF Flow Cache

```
设计依据:
  Phase 2 只有 StaticDecider (恒 proxy), eBPF Flow Cache 无任何实际收益
  所有流量都经过 fwmark=1 → TProxy, cache 应放在 TProxy 用户态
  Phase 5 有了 Rule Engine 产生 direct 决策后, eBPF Flow Cache 才有价值
```

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 2.1 | TCP TProxy 监听器（SO_ORIGINAL_DST + IP_TRANSPARENT）| `pkg/tproxy/tcp.go` | 8h |
| 2.2 | 原始目标地址提取封装 | `pkg/tproxy/conn.go` | 3h |
| 2.3 | Decision Interface 抽象（Direct/Proxy 两种决策）| `pkg/tproxy/decision.go` | 2h |
| 2.4 | 用户态 Decision Cache（纯目标 key: {dst_ip, dst_port, proto}, TTL + 淘汰）| `pkg/conntrack/cache.go` | 6h |
| 2.5 | TProxy → Decision → Cache 集成 | `pkg/tproxy/` | 4h |
| 2.6 | TCP socket relay（接收 → 转发 → 回写 — 占位, Phase 3 对接 sing-box）| `pkg/tproxy/relay.go` | 4h |
| 2.7 | 策略路由 + iptables TPROXY 自动化 | `scripts/setup-routing.sh` | 2h |
| 2.8 | 端到端测试（含 xray dokodemo-door 本地代理模拟）| 测试报告 | 4h |

### 关键交付物
- TCP TProxy 正常运行（SO_ORIGINAL_DST 可正确提取原始目标地址）
- Decision Interface 提供 Direct / Proxy 两种决策
- 用户态 Decision Cache（纯目标 key: {dst_ip, dst_port, proto}）
- 跨连接缓存命中验证（不同 src_port 共享同一目标 entry）
- 策略路由 + iptables TPROXY 自动化

---

### Decision Cache Scope ⭐

Decision Cache 职责：**缓存 TProxy 层决策结果**，跨连接共享。

```go
// CacheKey — 纯目标 key（路由决策仅基于目标地址）
type CacheKey struct {
    DstIP    uint32
    DstPort  uint16
    Protocol uint8
}

// CacheEntry — 仅缓存决策结果
type CacheEntry struct {
    Decision Decision  // Direct / Proxy
    LastSeen time.Time
    HitCount uint64
}
```

**禁止在 Decision Cache 中存储**：
- ❌ SrcIP / SrcPort（决策不依赖源地址）
- ❌ Domain / Hostname
- ❌ GeoIP / GeoSite 结果
- ❌ Rule ID / Rule Type

---

### 工作流

**第一次访问（建立缓存）**：

```
Client → br0(TC) → CIDR 检查
    ├── CIDR HIT → 直连（不设 fwmark）
    └── MISS → fwmark=1 → Policy Route → TProxy
        → SO_ORIGINAL_DST → Decision Interface
        → Decision Cache.Insert(CacheKey, Decision)
        ─── CacheMiss++
```

**第二次访问（缓存命中）**：

```
Client → br0(TC) → CIDR 检查
    ├── CIDR HIT → 直连
    └── MISS → fwmark=1 → Policy Route → TProxy
        → Decision Cache.Lookup(CacheKey)
        ├── HIT → 直接使用缓存决策
        │   └── CacheHit++
        └── MISS → Decision Interface → Insert
```

### 验证标准

```
Level 2（本地 Xray 模拟代理）：

基础验证：
1. TCP TProxy :1080 启动正常，可接收 fwmark=1 的流量
2. SO_ORIGINAL_DST 可正确提取原始目标地址
3. ns-client → br-test(TC) → TProxy → Xray(dokodemo→freedom) → 本地 HTTP 服务
4. Decision Cache Insert/Lookup 正常

缓存验证（核心验收项）：
5. 访问目标 A → CacheMiss++
6. 再次访问目标 A（不同 src_port）→ CacheHit++（纯目标 key 共享）
7. 验证: CacheMiss 仅增一次, CacheHit ≥ 1
8. GC 能清理过期 entry（TTL 超时后自动淘汰）
```

### 本地代理模拟

见 §7.12 Local Proxy Simulation。

---

## 7.7 Phase 3：sing-box 引擎 + 节点管理（第 17-22 天）

### 级别：Level 2（集成验证）

### 目标
将 sing-box 作为 outbound engine 集成到 Marmot，同时实现 Node Manager 和 Health Checker

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 3.1 | 添加 sing-box 依赖 `go get github.com/sagernet/sing-box` | go.mod 更新 | 1h |
| 3.2 | sing-box Box 实例封装（启动/停止/配置）| `pkg/proxy/engine.go` | 6h |
| 3.3 | Marmot 配置 → sing-box Options 转换器 | `pkg/proxy/options.go` | 4h |
| 3.4 | Outbound 管理 / Node Manager（节点池按 tag 分组）| `pkg/proxy/outbound.go` | 6h |
| 3.5 | Health Checker（周期性检测节点可用性，自动切换）| `pkg/proxy/health.go` | 4h |
| 3.6 | 路由规则对接（TProxy → sing-box outbound 集成）| `internal/server/server.go` | 4h |
| 3.7 | SS/VMess/VLESS/Trojan 各协议集成（sing-box library 已支持） | 测试报告 | 4h |
| 3.8 | 多节点配置 + 故障自动切换测试 | 测试报告 | 3h |
| 3.9 | 热重载配置 + 平滑切换（**stub — 待 Phase 5 细化**）| `pkg/proxy/options.go` | 4h |
| 3.10 | UDP TProxy（IP_RECVORIGDSTADDR + session relay + timeout GC）| `pkg/tproxy/udp.go` | 4h |

### 关键交付物
- sing-box 作为 library 正常运行 ✅
- TProxy → TCP relay → Xray/sing-box outbound ✅
- Node Manager + Health Checker ✅
- UDP TProxy — **已实现**（IP_RECVORIGDSTADDR + session relay + timeout GC）
- SS/VMess/VLESS/Trojan 各协议 — **依赖真实节点，待补充测试**
- 热重载 — **stub 实现，待 Phase 5 完善**

### 验证标准

```
Level 2（本地 Xray 模拟代理 + sing-box library）：

基础设施验证：
1. sing-box library 正常启动（include.Context + box.New）
2. TProxy :1080 接收 fwmark=1 流量 → SO_ORIGINAL_DST 提取
3. TCP relay → 本地 outbound（Xray dokodemo-door :10800）
4. Node Manager Add/Get/Remove/List
5. Health Checker TCP 探测 + fail 计数

集成度评估（非阻塞）：
6. SS/VMess/VLESS/Trojan — sing-box include 包已注册全部协议
7. 多节点故障切换 — 代码就绪，需真实节点验证
8. 热重载 — SIGHUP stub 实现
9. UDP TProxy — 推迟
```

---

## 7.8 Phase 4：DNS 子系统（第 23-26 天）⭐ 简化版

### 级别：Level 2（集成验证）

### 目标
实现 DNS 分流系统（MVP 不实现污染检测）

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 4.1 | DNS 服务器（监听 127.0.0.1:53 + br0_ip:53）| `pkg/dns/server.go` | 4h |
| 4.2 | DNS 引擎（查询处理 + Rule Engine 分流决策）| `pkg/dns/engine.go` | 6h |
| 4.3 | DNS 转发器（UDP/TCP upstream）| `pkg/dns/forwarder.go` | 3h |
| 4.4 | DoH Client | `pkg/dns/forwarder.go` (扩展) | 4h |
| 4.5 | DoT Client | `pkg/dns/forwarder.go` (扩展) | 3h |
| 4.6 | DNS 缓存（LRU + TTL 管理）| `pkg/dns/cache.go` | 3h |
| 4.7 | 上游 DNS 配置与热更新 | `pkg/dns/upstream.go` | 2h |
| 4.8 | DNS 透明劫持（eBPF 转发 DNS 到本地）| 与 eBPF 集成 | 3h |

> ❌ MVP 不实现：污染特征识别、污染 IP 库维护、多 DNS 交叉验证。抗污染完全依赖 GeoSite 分流 + DoH/DoT TLS 加密。

### 关键交付物
- LAN 客户端 DNS 被透明劫持到 Marmot DNS 服务器
- DNS 分流决策正常工作
- 本机 DNS 使用 127.0.0.1:53 不受透明劫持影响

### 验证标准

```
Level 2（本地验证）：
1. DNS 服务器启动，监听 127.0.0.1:53 + br0_ip:53
2. dig @127.0.0.1 example.com 返回正确结果
3. 本机 DNS 与 LAN 客户端 DNS 隔离（无环路）
4. DNS 缓存正常工作（二次查询不触发上游）
5. Rule Engine 能影响 DNS 上游选择
```

> 注：Phase 4 不要求外网 DNS 可达。可使用本地 dnsmasq 或直接配置 UDP 上游验证。

---

## 7.9 Phase 5：规则引擎 + 可观测性 + 整合（第 27-35 天）

### 级别：Level 2 → Level 3

### 目标
实现完整规则引擎（含 GeoIP/GeoSite/域名匹配）、可观测性设计、系统整合测试

### 任务状态

| # | 任务 | 状态 | 说明 |
|---|------|------|------|
| 5.1 | GeoIP 数据加载（MaxMind DB）| ✅ | `pkg/geo/data.go` — mmdb 格式 |
| 5.2 | GeoSite 数据加载 | 🟡 | `pkg/geo/data.go` stub — 需下载 db |
| 5.3 | Geo 数据热更新机制 | 🟡 | 定时 reload 已实现，需完善 |
| 5.4 | 规则引擎主接口 + 优先级 | ✅ | 8 级优先级 (Domain→Suffix→Kw→GeoSite→CIDR→GeoIP→Default) |
| 5.5 | 域名精确匹配 | ✅ | `pkg/rule/engine.go` exactMap |
| 5.6 | 域名后缀匹配（Trie）| ✅ | `pkg/rule/trie.go` |
| 5.7 | 域名关键字匹配（Aho-Corasick）| ✅ | `pkg/rule/ahocorasick.go` |
| 5.8 | GeoIP Matcher | ✅ | Level 3 验证: CN→direct,US→proxy |
| 5.9 | IP CIDR Matcher | ✅ | `pkg/rule/cidr.go` |
| 5.10 | 规则热加载 | 🟡 | `pkg/rule/loader.go` — SIGHUP stub |
| 5.11 | MatchResult Trace | ✅ | `pkg/observe/match_trace.go` |
| 5.12 | 规则命中统计 | ✅ | `pkg/observe/match_trace.go` Stats |
| 5.13 | Debug API | 🟡 | 骨架，未绑定 HTTP |
| 5.14 | Decision→RuleEngine 集成 | ✅ | `pkg/tproxy/decision.go` RuleEngineDecider |
| 5.15 | eBPF Flow Cache 重新引入 | ✅ | TCP 4-tuple / UDP 5-tuple dual map |
| 5.16 | 端到端集成测试 | ✅ | Pi Level 2+3 验证完成 |
| 5.17 | 树莓派验证 | ✅ | 完整链路：CIDR→DNS→FlowCache→RuleEngine→TProxy→Relay→Xray→JP01 |
| 5.18 | 性能基准测试 | 🟡 | 待完成 |
| 5.19 | 文档完善 | ⬅ 本次提交 | README + 配置说明 |

### 规则优先级
```
1. User Rule        (用户自定义规则)
2. Domain           (精确域名)
3. Domain Suffix    (域名后缀)
4. Domain Keyword   (域名关键字)
5. GeoSite          (域名 Geo 数据库) 🔺 高于 GeoIP
6. IP               (IP/CIDR 精确匹配)
7. GeoIP            (IP Geo 数据库) ▼ 低于 GeoSite
8. Default          (兜底)
```

---

### 关键交付物
- 完整规则引擎（GeoIP + GeoSite + Domain + IP CIDR）
- Decision Interface → Rule Engine 集成
- ⭐ **eBPF Flow Cache 重新引入**（direct 流量绕过 TProxy，实现真正 Fast Path）
- 可观测性（MatchResult Trace + 命中统计 + Debug API）
- 端到端集成测试通过

---

## 7.10 里程碑总表

| 里程碑 | 时间 | 级别 | 检查点 |
|--------|------|------|--------|
| M0: 构建通过 | Day 2 | — | `make build` 编译成功 |
| M1: eBPF 数据面 | Day 10 | L1 | TC Hook attach + Flow Map + CIDR 白名单 + 统计 |
| M2: TProxy + 用户态缓存 | Day 16 | L2 | TCP TProxy + Decision + 用户态 Cache + 跨连接 HIT |
| M3: 多协议代理 | Day 22 | L2 | sing-box 本地集成 + 节点故障切换 |
| M4: DNS 分流 | Day 26 | L2 | 透明劫持 + 分流决策 + 本机隔离 |
| M5: 生产就绪 | Day 38 | ✅ L3 GeoIP | 规则引擎 + eBPF Flow Cache + GeoIP 分流 + 全链路测试 |

---

## 7.11 不包含的内容

- ❌ HTTP API 控制面（Phase 5 仅骨架）
- ❌ 负载均衡（Phase 2 仅基础 fallback）
- ❌ 丰富的 Dashboard UI
- ❌ QUIC / HTTP3 代理
- ❌ 多网关集群
- ❌ 实际外网代理验证（属于 Release 阶段）

---

## 7.12 本地代理模拟方案 ⭐ 新增

### 为什么需要本地代理模拟

在 Phase 2 ~ Phase 4 的开发测试中，需要验证完整的代理链路：

```
Client → Marmot → TProxy → Proxy Engine → Target
```

但开发环境可能不具备真实海外代理节点。因此需要本地模拟。

### 推荐方案：Xray

**Xray**（v2fly 分支）支持 `dokodemo-door` 协议，可以搭建完全本地化的代理测试环境。

### 配置模板

```json
{
  "log": { "loglevel": "debug" },
  "inbounds": [
    {
      "port": 10800,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 0,
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
```

### 验证链路

```
ns-client ←→ br-test ←→ Marmot (TC+TProxy)
                              │
                          TProxy :1080
                              │
                          Xray dokodemo-door :10800
                              │
                          Xray freedom outbound
                              │
                     ┌────────┴────────┐
                     ▼                 ▼
              本地 HTTP :8080        ns-server
              (python3 -m http.server)
```

### 验证步骤

```
1. 启动本地 HTTP 服务（ns-server 或 宿主机）
2. 启动 Xray（dokodemo-door → freedom）
3. 启动 Marmot（TProxy :1080 → 转发到 Xray :10800）
4. ns-client curl http://<target_ip>:8080
5. 验证链路：curl 成功 → 代理链路正常
```

### 优点
- 完全本地化，不依赖任何外部网络
- `dokodemo-door` 可以验证 TProxy 原始目标地址提取是否正确
- `freedom` outbound 可以验证流量是否正确路由到目标
- 可以手动制造故障场景验证 Health Checker

---

## 7.13 Phase 6：系统完善与自动化（第 39-45 天）

### 级别：Level 3（生产就绪）

### 目标
完成 Phase 5 遗留的 🟡 优化项，实现基础设施自动化（无需人工执行 iptables/net 配置）。

### 任务清单

| # | 任务 | 状态 | 说明 |
|---|------|------|------|
| 6.1 | 策略路由 + iptables TPROXY + DNS REDIRECT 自动化 | 🔴 **本次实现** | `pkg/netif/` 子系统, 启动自动配置, 退出自动清理 |
| 6.2 | DNS → Flow Cache 写回（解决域名规则不生效问题）| 🟡 | TProxy 在 DNS 解析时写入 Flow Cache, 后续 TCP 直命中 |
| 6.3 | GeoSite v2fly .dat 格式解析 | 🟡 | `pkg/geo/` 增加 .dat 读取器 |
| 6.4 | 域名规则 (domain/domain_suffix) 实际工作 | 🟡 | 依赖 6.2 (DNS→FlowCache) |
| 6.5 | SIGHUP 热重载（Engine/DNS/Rules）| 🟡 | 配置变更自动重载, 不中断现有连接 |
| 6.6 | HTTP API（MatchResult Trace + Debug）| 🟡 | `pkg/observe/debug.go` 绑定 HTTP |
| 6.7 | 性能基准测试（wrk/iperf3）| 🟡 | 对比 eBPF Flow Cache ON/OFF |
| 6.8 | Geo 数据库热更新 | 🟡 | 定时下载 + 热重载 |
| 6.9 | UDP Flow Cache 写回优化 | 🟡 | 首包即写回, 减少 UDP MISS |

### 关键交付物
- 网络规则自动化（零人工 iptables 操作）
- 域名规则正常工作（DNS → Flow Cache 联动）
- 热重载可用
- HTTP API 可用

### 验证标准

```
Level 3（生产环境）：
1. `marmot start` 后不需要任何手工 iptables 命令
2. `dig @8.8.8.8` 自动劫持到本地 DNS（无需人工配置 nat 规则）
3. 域名规则（domain_suffix: .cn → direct）正常工作
4. SIGHUP 后规则/TProxy/DNS 全部刷新
5. 进程退出后 iptables 规则全部清理干净
6. 性能基准: eBPF Flow Cache ON 比 OFF 提升 ≥30%
```

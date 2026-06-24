# 2. 总体架构设计（v0.2 — 审核修订版）

## 2.1 架构总览

```
┌──────────────────────────────────────────────────────────────┐
│                    Marmot Gateway System                       │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Control Plane (Go)                      │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │  │
│  │  │ Config   │  │ Rule     │  │ Node     │  │ Health  │ │  │
│  │  │ Manager  │  │ Engine   │  │ Manager  │  │ Checker │ │  │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │  │
│  │       └──────────────┼──────────────┼─────────────┘        │
│  └──────────────────────┼──────────────┼──────────────────────┘
│                         │              │                       │
│  ┌──────────────────────┼──────────────┼──────────────────────┐│
│  │  Data Plane          │              │    【统一规则引擎】  ││
│  │  ┌───────────────────▼──────────────▼──────────────────┐  ││
│  │  │               TProxy Socket Layer                     │  ││
│  │  │  TCP TProxy :1080  │  UDP TProxy :1080               │  ││
│  │  │  ↓ 规则引擎决策：direct / proxy (by tag)             │  ││
│  │  └───────────────────────┬──────────────────────────────┘  ││
│  │                          │                                  ││
│  │  ┌───────────────────────▼──────────────────────────────┐  ││
│  │  │     Policy Routing (ip rule / ip route)               │  ││
│  │  │  fwmark=1 → lookup table 100 → TProxy localhost:1080 │  ││
│  │  │  DNS 上游查询直通 (跳过 eBPF 劫持)                   │  ││
│  │  └───────────────────────┬──────────────────────────────┘  ││
│  │                          │                                  ││
│  │  ┌───────────────────────▼──────────────────────────────┐  ││
│  │  │    eBPF TC Hook — 粗粒度预分类                       │  ││
│  │  │  br0 ingress                                          │  ││
│  │  │  - IP CIDR map 直连白名单 → fwmark=0 (内核转发)     │  ││
│  │  │  - 本机自身流量 → fwmark=0 (loopback 防护)           │  ││
│  │  │  - 其余所有 → fwmark=1 (TProxy 全量接收)             │  ││
│  │  └───────────────────────────────────────────────────────┘  ││
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Proxy Engine (sing-box)                       │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │  │
│  │  │ SS       │  │ VMess    │  │ VLESS    │  │ Trojan  │ │  │
│  │  │ Outbound │  │ Outbound │  │ Outbound │  │ Outbound│ │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  sing-box Route Router (对接 Marmot 规则引擎)      │  │  │
│  │  │  根据 tag 选择对应 outbound group                   │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  DNS Subsystem                             │  │
│  │  ┌────────────────────────────────────────────────────┐   │  │
│  │  │  Rule-Driven DNS Forwarder                         │   │  │
│  │  │  - 规则引擎决定每个域名使用哪个 DNS 上游           │   │  │
│  │  │  - 上游池: UDP DNS / TCP DNS / DoH / DoT           │   │  │
│  │  │  - 每个上游可配置 tag (直连/代理)                  │   │  │
│  │  └────────────────────────────────────────────────────┘   │  │
│  │  ┌────────────────────────────────────────────────────┐   │  │
│  │  │  DNS 监听器分离设计                                 │   │  │
│  │  │  - 127.0.0.1:53      ← 网关本机 DNS 解析           │   │  │
│  │  │  - <br0_ip>:53       ← LAN 客户端 DNS (透明劫持)   │   │  │
│  │  │  - 本机 DNS 查询不走 eBPF → 无环路风险             │   │  │
│  │  └────────────────────────────────────────────────────┘   │  │
│  │  ┌──────────┐  ┌────────────┐  ┌──────────────────┐     │  │
│  │  │ DNS      │  │ DNS Cache  │  │ Anti-Pollution   │     │  │
│  │  │ Server   │  │ (LRU+TTL)  │  │ Filter           │     │  │
│  │  └──────────┘  └────────────┘  └──────────────────┘     │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 2.2 五大子系统

### 2.2.1 Control Plane（控制面）

**职责**：系统配置管理、规则引擎、节点管理、健康检查、API 服务

**核心变化**：Rule Engine 成为 Control Plane 的中心枢纽，DNS 和 Proxy 都向其查询路由决策。

| 模块 | 职责 | 关键接口 |
|------|------|---------|
| Config Manager | 读取/解析/热重载配置 | `config.Load(path)`, `config.Reload()` |
| Rule Engine | ⭐ 统一路由决策中心 | `rule.Match(addr) → Action{Tag, Outbound}` |
| Node Manager | 管理上游代理节点（按 tag 分组）| `node.ByTag(tag) → []Node` |
| Health Checker | 周期性检测节点可用性 | `health.Ping(tag) → bool` |
| API Server | HTTP API 供外部管理 | `POST /rule`, `GET /status`, `PUT /config` |

**Rule Engine 核心接口**：

```go
type Action struct {
    Mode     string // "direct" | "proxy" | "block" | "dns_upstream"
    Tag      string // outbound tag（如 "proxy-jp"、"proxy-us"），Mode="proxy" 时有效
    Upstream string // DNS upstream tag，Mode="dns_upstream" 时有效
}

type Addr struct {
    IP       net.IP
    Domain   string
    Port     uint16
    Protocol string // "tcp" | "udp"
}

// 统一匹配接口：同时被 Proxy Engine 和 DNS Subsystem 调用
func (e *Engine) Match(addr Addr) Action
```

---

### 2.2.2 Data Plane（数据面）— ⭐ 审核修订核心

**职责**：流量捕获、粗粒度预分类、透明代理重定向

**核心设计决策：两阶段分类架构**

```
eBPF 粗粒度预分类 → TProxy 全量接收 → 用户态规则引擎细粒度决策
```

#### 为什么是两阶段？

| 阶段 | 位置 | 粒度 | 能力 | 更新方式 |
|------|------|------|------|---------|
| ① 粗粒度预分类 | eBPF TC Hook (内核) | IP CIDR 白名单 | 仅 IP 匹配 | BPF Map 热更新 |
| ② 细粒度决策 | TProxy → Rule Engine (用户态) | 域+IP+协议组合 | 自定义域/GeoIP/GeoSite | Go 配置热加载 |

#### 流量处理流

```
                    Data Plane Flow
                    ┌──────────┐
    LAN Client ──►  │ br0      │
                    │ (Bridge) │
                    └────┬─────┘
                         │
                    ┌────▼──────────┐
                    │ TC ingress     │  ← eBPF 粗粒度预分类
                    │  (eBPF)       │     仅做 IP CIDR map 匹配
                    └───────┬───────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
     ┌──────────────────┐     ┌──────────────────┐
     │ 匹配直连CIDR白名单│     │ 未匹配任何规则    │
     │ 或本机自身流量    │     │ (包括所有WAN流量) │
     │ fwmark=0          │     │ fwmark=1          │
     └───────┬──────────┘     └────────┬─────────┘
             │                         │
             ▼                         ▼
     ┌──────────────────┐     ┌──────────────────────┐
     │ 内核转发 (直连)   │     │ Policy Route Table 100│
     │ 零 TProxy 开销    │     │ → TProxy :1080      │
     └──────────────────┘     └──────────┬───────────┘
                                         │
                                    ┌────▼──────────┐
                                    │ TProxy 接收    │
                                    │ 获取原始目标    │
                                    │ (SO_ORIGINAL_DST│
                                    │ /IP_RECVORIGDADDR)│
                                    └────┬──────────┘
                                         │
                                    ┌────▼──────────┐
                                    │ Rule Engine    │  ← 用户态细粒度决策
                                    │ Match(addr)    │
                                    └────┬──────────┘
                                         │
                          ┌──────────────┼──────────────┐
                          ▼              ▼              ▼
                   ┌──────────┐  ┌──────────────┐  ┌────────┐
                   │ direct   │  │ proxy(tag)   │  │ block  │
                   │ 直接TCP  │  │ sing-box     │  │ 丢弃   │
                   │ 连接目标  │  │ outbound     │  │        │
                   └──────────┘  └──────────────┘  └────────┘
```

**直连路径（TProxy "direct" 模式）**：
- TProxy 识别到规则引擎返回 `Action{Mode: "direct"}` 时
- 从 TProxy socket 直接建立到原始目标的 TCP/UDP 连接
- 数据在用户态走一圈后回到内核 → 有一定开销，但这是灵活性的代价
- 注：被 BPF IP CIDR 白名单匹配的流量完全不经过 TProxy，是真正零开销直连

#### 为什么选择这种设计？

| 考量维度 | TC 完全分类 | TProxy 完全决策 | ✅ 两阶段（本文案）|
|----------|-----------|---------------|------------------|
| 实现复杂度 | 🔴 高（BPF 编程复杂） | 🟢 低（全部 Go） | 🟡 中 |
| 直连流量性能 | 🟢 最高（内核转发） | 🟡 有 TProxy 开销 | 🟢 白名单零开销 |
| 分类灵活性 | 🔴 低（仅 IP） | 🟢 高（域+IP 组合） | 🟢 高 |
| 规则热更新 | 🟡 BPF Map 操作 | 🟢 Go 原生 | 🟢 双通道 |
| 可调试性 | 🔴 困难（内核态） | 🟢 容易（用户态） | 🟢 容易 |
| BPF 代码安全 | 🔴 复杂=高风险 | 🟢 极小=低风险 | 🟢 极小 |
| 规则引擎复杂度 | 🔴 不适用 | 🟢 不受限 | 🟢 不受限 |

**结论**：两阶段是当前最优解。BPF 只维护一个简单的 IP CIDR map（极少修改），所有灵活的规则决策在用户态完成。

---

### 2.2.3 DNS Subsystem（DNS 子系统）— ⭐ 审核修订

**职责**：规则驱动的 DNS 分流解析、本机 DNS 无影响、抗污染

#### 核心设计原则

1. **规则驱动**：DNS 上游选择由同一套 Rule Engine 决定
2. **监听器分离**：本机 DNS vs LAN DNS 物理隔离，杜绝环路
3. **上游池化**：可配置多个 DNS 上游，每个带 tag 和协议类型

#### DNS 监听器分离架构

```
┌─ 网关本机 ─────────────────────────────────────┐
│  /etc/resolv.conf → 127.0.0.1:53              │
│  (marmot 自己需要解析 DoH 服务器域名、          │
│   代理节点域名等)                               │
│  → DNS Subsystem 内部监听器                     │
│   127.0.0.1:53                                 │
│  → 直接通信，路径：                             │
│   进程 → localhost:53 → DNS Engine             │
│   ↑ 完全不走 eBPF TC Hook，无环路风险           │
└───────────────────────────────────────────────┘

┌─ LAN 客户端 ────────────────────────────────────┐
│  DHCP 分配的 DNS = <br0_ip>                     │
│  或透明劫持：UDP dst=:53 → <br0_ip>:53          │
│  → DNS Subsystem 外部监听器                     │
│   <br0_ip>:53                                   │
│  → eBPF 根据 src IP 排除本机流量                 │
└───────────────────────────────────────────────┘
```

#### DNS 分流决策流

```
收到 DNS 查询 qname=example.com
│
├─ 源地址检查
│  ├─ 127.0.0.1 → 网关本机查询（直接放行到 DNS Engine）
│  └─ LAN IP → 来自客户端（正常处理）
│
├─ DNS 缓存检查
│  ├─ 命中 + TTL 有效 → 返回
│  └─ 未命中 → 继续
│
├─ Rule Engine.Match({Domain: "example.com", Protocol: "dns"})
│  ├─ Action{Mode: "dns_upstream", Tag: "domestic"}
│  │   → 使用 "domestic" 上游池（UDP 114.114）
│  ├─ Action{Mode: "dns_upstream", Tag: "oversea"}
│  │   → 使用 "oversea" 上游池（DoH 1.1.1.1）
│  ├─ Action{Mode: "dns_upstream", Tag: "custom"}
│  │   → 使用自定义 DNS 上游
│  └─ Action{Mode: "proxy", Tag: "proxy-us"}
│      → 通过代理隧道转发 DNS（高级场景）
│
├─ 执行 DNS 查询（根据选定的上游）
│
├─ 后处理
│  ├─ 污染检测 → 过滤可疑结果
│  ├─ 写入 LRU 缓存
│  └─ 返回客户端
```

#### DNS 上游池配置结构

```yaml
dns:
  upstreams:
    - tag: "domestic"
      protocol: "udp"
      addr: "114.114.114.114:53"
      # 规则引擎返回 dns_upstream:domestic 时使用

    - tag: "domestic-backup"
      protocol: "tcp"
      addr: "223.5.5.5:53"

    - tag: "oversea"
      protocol: "doh"
      addr: "https://1.1.1.1/dns-query"
      # 规则引擎返回 dns_upstream:oversea 时使用

    - tag: "oversea-backup"
      protocol: "dot"
      addr: "tls://8.8.8.8:853"
```

#### 本机 DNS 隔离保障

| 机制 | 说明 | 原理 |
|------|------|------|
| 双监听器 | `127.0.0.1:53` + `<br0_ip>:53` | 物理端口隔离 |
| src IP 过滤 | eBPF 对本机源 IP 不做重定向 | 内核级防护 |
| /etc/resolv.conf | 指向 localhost | 进程级配置 |
| 上游 DoH/DoT 查询 | 从网关本机发起的 DNS 连接 | 不经过透明劫持 |

---

### 2.2.4 Proxy Engine（代理引擎 — sing-box）

**职责**：作为上游代理 outbound engine，根据规则引擎的 tag 选择对应 outbound 出站

| 组件 | 说明 |
|------|------|
| Outbound Group | 按 tag 分组的节点池（如 "proxy-jp"、"proxy-us"、"proxy-hk"）|
| Route Router | 对接 Marmot 规则引擎，根据 tag 选择 outbound |
| Protocol Adapter | SS / VMess / VLESS / Trojan |

**集成方式**：

```
        TProxy 接收流量
              │
              │ 提取原始目标地址
              ▼
       ┌──────────────┐
       │ Rule Engine  │  ← 用户态统一规则引擎
       │ Match(addr)  │
       └──────┬───────┘
              │
              ▼
       Action{Mode: "proxy", Tag: "proxy-jp"}
              │
              ▼
       ┌──────────────────┐
       │  sing-box Box    │
       │                  │
       │  Route Router ──►│ 根据 "proxy-jp" tag
       │                  │ 选择对应的 Outbound Group
       │  Outbound Group  │
       │  - proxy-jp      │
       │    ├─ SS JP1     │──► Remote Server
       │    ├─ VMess JP2  │──► Remote Server
       │    └─ Trojan JP3 │──► Remote Server
       │  - proxy-us      │
       │  - proxy-hk      │
       │  - direct        │
       └──────────────────┘
```

---

### 2.2.5 Rule Engine（规则引擎）— ⭐ 审核修订为统一中心

**定位变更**：从"分流匹配器"升级为"统一路由决策中心"

**调用方**：
- Proxy Engine：决策流量走 direct / proxy(tag) / block
- DNS Subsystem：决策域名走哪个 DNS upstream
- (未来) HTTP API：外部查询路由结果

#### 规则匹配优先级

```
1. 自定义域名规则       ── 精确匹配域名（规则引擎最优先）
2. 自定义 IP 规则       ── 精确匹配 IP/CIDR
3. GeoSite 规则         ── 基于域名归属
4. GeoIP 规则           ── 基于 IP 归属
5. 默认规则             ── 兜底策略

每个规则可指定 Action：
  - 对流量：direct / proxy:<tag> / block
  - 对 DNS：dns_upstream:<tag> / proxy:<tag> / block
```

#### 规则数据结构

```go
type Rule struct {
    ID         string   // 规则唯一 ID
    Type       string   // "ip" | "domain" | "geoip" | "geosite" | "default"
    Match      string   // 匹配值：IP/CIDR/域名/geo 标签
    Action     Action   // 命中后执行的动作
    Priority   int      // 优先级（数值越小优先级越高）
    Metadata   map[string]string
}

type Action struct {
    Mode     string // "direct" | "proxy" | "block" | "dns_upstream"
    Tag      string // outbound tag 或 DNS upstream tag
}
```

#### 配置示例

```yaml
rules:
  # ---- 自定义域名 ----
  - type: domain
    match: "netflix.com"
    action:
      mode: proxy
      tag: "proxy-us"        # Netflix 走美国节点

  - type: domain
    match: "bilibili.com"
    action:
      mode: direct           # B站直连

  - type: domain
    match: "google.com"
    action:
      mode: direct           # 可能只在 DNS 层面用
      dns_upstream: domestic # DNS 走国内（被墙域名可独立配置）

  # ---- 自定义 IP ----
  - type: ip
    match: "10.0.0.0/8"
    action:
      mode: direct           # 内网直连

  # ---- Geo ----
  - type: geoip
    match: "CN"
    action:
      mode: direct

  - type: geosite
    match: "cn"
    action:
      mode: direct

  - type: geosite
    match: "geolocation-!cn"
    action:
      mode: proxy
      tag: "auto"            # auto = 健康检测得分最高的节点

  # ---- 默认 ----
  - type: default
    action:
      mode: proxy
      tag: "auto"
```

---

## 2.3 可靠性与性能平衡策略 ⭐ 新增

### 2.3.1 分层压力隔离

```
热路径 (Hot Path)             温路径 (Warm Path)           冷路径 (Cold Path)
━━━━━━━━━━━━━━━━━━━━         ━━━━━━━━━━━━━━━━━━━━         ━━━━━━━━━━━━━━━━━━━━
eBPF TC (内核)                TProxy (用户态)              API Server
  - 每包处理                    - 每个连接处理                 - 管理操作
  - O(1) BPF map 查找          - 规则引擎匹配                 - 规则配置
  - 固定低延迟                  - 中等延迟 (μs 级)            - 高延迟可接受
  - 无锁设计                    - 每连接 goroutine             - 同步处理

可靠性保障：                    可靠性保障：                   可靠性保障：
- BPF 程序验证器               - 连接超时                     - 请求限流
- 最小化 BPF 指令              - 优雅降级                     - 认证授权
- 回退到 iptables              - sing-box 异常恢复
```

### 2.3.2 降级策略矩阵

| 故障场景 | 降级行为 | 影响 |
|----------|---------|------|
| eBPF 加载失败 | 回退到 iptables TPROXY | 性能降级，功能完整 |
| sing-box 核心故障 | 全部流量切为 direct | DNS 正常，无代理 |
| 单个 proxy 节点故障 | 自动切换到同 tag 内下一节点 | 单节点不可用，整体正常 |
| DNS 子系统故障 | 将 DNS 查询直接透传到上游 DNS | DNS 无分流，可解析 |
| Geo 数据更新失败 | 继续使用旧数据 | 规则精度降低，不影响路由 |
| 规则文件加载失败 | 使用最后成功加载的规则集 | 规则不更新，已有连接正常 |
| 内存超限 | 启用连接限制，丢弃新连接 | 部分新连接失败 |

### 2.3.3 高可用设计

```
┌─ 优雅启动顺序 ─────────────────────────────────┐
│  1. Config Load          (配置决定一切)         │
│  2. Rule Engine Init     (规则先行，供后续查询) │
│  3. DNS Server Start     (DNS 先就绪)           │
│  4. Proxy Engine Init    (sing-box 准备)         │
│  5. TProxy Listen        (准备接收流量)         │
│  6. eBPF Load + Attach   (最后挂载，开始处理)   │
│  7. Health Check Start   (监控就位)             │
└────────────────────────────────────────────────┘

┌─ 优雅关闭顺序 ─────────────────────────────────┐
│  1. 停止健康检查                                │
│  2. Detach eBPF (停止接收新流量)                │
│  3. 关闭 TProxy (停止处理进行中连接)            │
│  4. 关闭 Proxy Engine (等待代理完成)            │
│  5. 关闭 DNS Server (等待 DNS 查询完成)         │
│  6. 等待所有正在连接完成 (graceful period)       │
│  7. 退出                                         │
└────────────────────────────────────────────────┘
```

### 2.3.4 关键安全边界

| 边界 | 保护措施 |
|------|---------|
| eBPF 程序 | BPF verifier 验证 + 最小指令集 + 不允许循环 |
| TProxy | 连接数上限 + 单 IP 连接限速 |
| DNS | 递归查询深度限制 + 超时控制 |
| sing-box | 资源隔离（goroutine 池 + 内存限制） |
| API | 认证鉴权 + 速率限制 + 输入校验 |

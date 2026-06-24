# 5. Architecture Decision Record (ADR)

## ADR-001: 为什么选择 Golang

| 元数据 | 内容 |
|--------|------|
| 决策 ID | ADR-001 |
| 日期 | 2026-06-24 |
| 状态 | ✅ 已决策 |
| 决策者 | marmot 团队 |

**背景**：需要为 Marmot 透明代理网关选择控制面（Control Plane）语言。

**备选方案**：

| 方案 | 优势 | 劣势 |
|------|------|------|
| Go | 编译为单二进制、天生并发、eBPF 库（cilium/ebpf）成熟、sing-box 同为 Go | GC 延迟对极端性能场景有影响 |
| Rust | 零成本抽象、无 GC、极致性能 | 学习曲线陡峭、eBPF 生态不成熟、与 sing-box 集成困难 |
| Python | 开发速度快 | 性能差、运行时依赖、不适合系统级编程 |
| C | 极致性能 | 内存安全风险、开发效率低、并发复杂 |

**决策**：✅ **选用 Golang**

**理由**：

1. **sing-box 兼容性**：sing-box 是 Go 实现的，只有 Go 能将其作为 library 直接嵌入，无需 IPC/RPC/子进程
2. **eBPF 生态**：`cilium/ebpf` 提供了纯 Go 的 eBPF 加载与操作能力，无需 CGo 包装
3. **编译产物**：单二进制部署，非常适合嵌入式 Linux 网关设备
4. **并发模型**：Goroutine 天然适合流量处理场景（每个连接一个 goroutine）
5. **团队背景**：项目创建者使用 Go（用户：ShawnLu）

**结果**：Marmot 控制面全部使用 Go 实现。

---

## ADR-002: 为什么选择 eBPF TC Hook

| 元数据 | 内容 |
|--------|------|
| 决策 ID | ADR-002 |
| 日期 | 2026-06-24 |
| 状态 | ✅ 已决策 |
| 决策者 | marmot 团队 |

**背景**：需要决定流量捕获的核心机制。

**备选方案**：

| 方案 | 优势 | 劣势 |
|------|------|------|
| eBPF TC Hook | 内核原生、性能极高、可编程、支持 skb 操作 | 内核版本要求 5.10+ |
| iptables TPROXY | 成熟稳定、无需编译 | 规则集性能随规模下降、不支持自定义逻辑 |
| nftables | 比 iptables 好、系统集成 | 仍无 eBPF 灵活、不支持用户态逻辑 |
| raw socket / AF_PACKET | 灵活 | 需要用户态轮询、性能差、高 CPU 占用 |

**决策**：✅ **选用 eBPF TC Hook**

**理由**：

1. **性能最优**：TC Hook 在内核网络栈的最早入口点（ingress）和最后出口点（egress），用户态无需参与
2. **可编程**：可编写任意分类逻辑，不局限于规则表匹配
3. **避免 iptables 瓶颈**：大量 iptables 规则时性能断崖式下降，eBPF 使用 BPF map 做 O(1) 查找
4. **少量依赖**：仅依赖内核 BPF 功能，无需额外内核模块
5. **CO-RE 支持**：通过 BTF + cilium/ebpf 实现一次编译到处运行，免去 kernel-devel 依赖

**结果**：流量分类标记全部在 eBPF TC Hook 中完成。

---

## ADR-003: 为什么复用 sing-box

| 元数据 | 内容 |
|--------|------|
| 决策 ID | ADR-003 |
| 日期 | 2026-06-24 |
| 状态 | ✅ 已决策 |
| 决策者 | marmot 团队 |

**背景**：需要支持多协议上游代理（SS/VMess/VLESS/Trojan）。

**备选方案**：

| 方案 | 优势 | 劣势 |
|------|------|------|
| 复用 sing-box library | 协议完整、路由灵活、维护成本低 | 版本依赖、API 不稳定风险 |
| 自行实现协议栈 | 完全可控 | 工作量巨大、协议更新风险、安全漏洞 |
| 子进程调用 sing-box | 解耦 | IPC 复杂、配置同步困难、无法热 reload |
| 使用其他代理库（如 v2ray）| v2ray 成熟 | v2ray Go 生态已转向 sing-box |

**决策**：✅ **复用 sing-box 作为 library**

**理由**：

1. **禁止重新造轮子**：SS/VMess/VLESS/Trojan 各协议实现复杂度极高，且协议需要跟随服务端更新
2. **Go module 原生**：sing-box 作为 Go library 导入，直接调用 `box.New()` 即可
3. **路由复用**：sing-box 内置 Route Router 可直接对接 Marmot 的分流需求
4. **多节点管理**：sing-box 的 Outbound Provider 天然支持多节点池
5. **热重载**：sing-box 支持 options 热更新，契合 Marmot 的 API 控制需求

**解耦策略**：

```
Marmot 通过 option.Options 结构体配置 sing-box
         │
         │ 仅传递 Outbound 配置
         │ 不控制 Inbound 部分（由 Marmot TProxy 处理）
         ▼
┌──────────────────┐
│  sing-box Box    │
│  作为纯 Outbound │
│  engine 运行     │
└──────────────────┘
         │
         │ 返回代理结果流量
         ▼
Marmot 控制逆流回客户端
```

**结果**：sing-box 作为 outbound engine 以 library 形式集成，Marmot 控制面通过 `option.Options` 驱动。

---

## ADR-004: 为什么 DNS 分流设计这样做

| 元数据 | 内容 |
|--------|------|
| 决策 ID | ADR-004 |
| 日期 | 2026-06-24 |
| 状态 | ✅ 已决策 |
| 决策者 | marmot 团队 |

**背景**：需要设计 DNS 抗污染系统。

**备选方案**：

| 方案 | 优势 | 劣势 |
|------|------|------|
| 独立 DNS + 基于 GeoSite 分流 | 精准可控、抗污染 | 实现复杂度中等 |
| 全部上游走 DoH | 加密传输 | 国内 DoH 被墙、延迟高 |
| 全部本地 UDP DNS | 简单 | 不抗污染 |
| 全局使用 dnscrypt-proxy | 成熟方案 | 额外进程、集成复杂 |

**决策**：✅ **基于 GeoSite 分流的双 DNS 策略**

**理由**：

1. **国内 DNS 低延迟**：国内域名使用国内 DNS（UDP: 114.114.114.114），延迟低且不触发墙检测
2. **国外 DNS 抗污染**：国外域名使用 DoH/DoT 查询，防止正常域名的 DNS 污染
3. **GeoSite 数据库**：sing-box 提供的 geosite.dat 覆盖数万国内外域名，规则精准
4. **纯 Go 实现**：`github.com/miekg/dns` 完整实现 DNS 协议，无需额外进程
5. **DNS 缓存**：LRU 缓存大幅减少上游查询压力，提高响应速度

**风险与对策**：

| 风险 | 对策 |
|------|------|
| GeoSite 数据过期 | 支持热更新 + 周期性下载最新数据 |
| DNS 劫持 | DoH/DoT 使用 TLS 加密传输 |
| 性能瓶颈 | Go DNS server 并发处理 + LRU 缓存 |

**结果**：Marmot 内置 DNS 服务器，基于 GeoSite 分流，国内外 DNS 独立查询。

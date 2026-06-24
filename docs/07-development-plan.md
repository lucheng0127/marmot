# 7. 第一阶段开发计划

> ⚠️ 当前阶段仅为计划输出。不允许编码实现。
> 计划中的里程碑时间估算基于单人开发，以实际投入为准。

---

## 7.1 阶段划分总览

```
Phase 0 ─ 环境与骨架                     （第 1-2 天）
Phase 1 ─ eBPF 数据面 + TProxy 基础     （第 3-8 天）
Phase 2 ─ sing-box 引擎集成              （第 9-14 天）
Phase 3 ─ DNS 子系统                     （第 15-19 天）
Phase 4 ─ 规则引擎 + Geo 数据            （第 20-24 天）
Phase 5 ─ 整合测试 + 优化                （第 25-30 天）
```

---

## 7.2 Phase 0：环境与骨架（第 1-2 天）

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

## 7.3 Phase 1：eBPF 数据面 + TProxy 基础（第 3-8 天）

### 目标
实现核心数据面：eBPF TC Hook 流量捕获 + TProxy socket 透明代理

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 1.1 | eBPF 开发环境搭建（clang/llvm/libbpf-dev）| 可编译 .o | 2h |
| 1.2 | 编写 TC ingress BPF 程序（分类+mark 逻辑）| `bpf/tc_ingress.c` | 6h |
| 1.3 | 编写 TC egress BPF 程序（出口处理）| `bpf/tc_egress.c` | 4h |
| 1.4 | 使用 cilium/ebpf 加载 BPF 程序 | `pkg/bpf/loader.go` | 4h |
| 1.5 | TC Hook attach/detach 管理 | `pkg/bpf/tc_hook.go` | 3h |
| 1.6 | eBPF Map 管理（用户态 ↔ 内核态 IPC）| `pkg/bpf/maps.go` | 3h |
| 1.7 | TCP TProxy 监听器 | `pkg/tproxy/tcp.go` | 6h |
| 1.8 | UDP TProxy 监听器（骨架）| `pkg/tproxy/udp.go` | 4h |
| 1.9 | 原始目标地址提取（SO_ORIGINAL_DST）| `pkg/tproxy/conn.go` | 3h |
| 1.10 | 策略路由脚本（ip rule/ip route）| `pkg/tproxy/routing.go` | 3h |
| 1.11 | 端到端 TCP 代理通路测试 | 测试报告 | 4h |

### 关键交付物
- eBPF 程序可编译并加载到网桥接口
- TCP 流量可被捕获并转发到 TProxy :1080
- 策略路由配置自动化

### 验证标准
```
# 物理验证步骤（在网关设备上）
1. 启动 marmot
2. LAN 客户端 curl https://www.google.com
3. 确认能正常返回（通过代理）
4. LAN 客户端 curl https://www.baidu.com
5. 确认能正常返回（直连）
6. tcpdump 验证流量路径
```

---

## 7.4 Phase 2：sing-box 引擎集成（第 9-14 天）

### 目标
将 sing-box 作为 outbound engine 集成到 Marmot

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 2.1 | 添加 sing-box 依赖 `go get github.com/sagernet/sing-box` | go.mod 更新 | 1h |
| 2.2 | sing-box Box 实例封装（启动/停止/配置）| `pkg/proxy/engine.go` | 6h |
| 2.3 | Marmot 配置 → sing-box Options 转换器 | `pkg/proxy/options.go` | 4h |
| 2.4 | Outbound 管理（节点池、Mux、Fallback）| `pkg/proxy/outbound.go` | 6h |
| 2.5 | 路由规则对接（TC mark → sing-box rule）| `pkg/proxy/router.go` | 4h |
| 2.6 | SS/VMess/VLESS/Trojan 各协议集成测试 | 测试报告 | 4h |
| 2.7 | 多节点配置与切换测试 | 测试报告 | 2h |
| 2.8 | 热重载配置 + 平滑切换 | `pkg/proxy/options.go` | 4h |

### 关键交付物
- sing-box 作为 library 正常启动
- TProxy 转发流量 → sing-box outbound → 远程服务器
- 多节点支持（节点故障自动切换）

---

## 7.5 Phase 3：DNS 子系统（第 15-19 天）

### 目标
实现 DNS 抗污染 + 分流系统

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 3.1 | DNS 服务器（监听 UDP/TCP :53）| `pkg/dns/server.go` | 4h |
| 3.2 | DNS 引擎（查询处理+分流决策）| `pkg/dns/engine.go` | 6h |
| 3.3 | DNS 转发器（UDP/TCP upstream）| `pkg/dns/forwarder.go` | 3h |
| 3.4 | DoH Client | `pkg/dns/forwarder.go` (扩展) | 4h |
| 3.5 | DoT Client | `pkg/dns/forwarder.go` (扩展) | 3h |
| 3.6 | DNS 缓存（LRU + TTL 管理）| `pkg/dns/cache.go` | 3h |
| 3.7 | DNS 污染检测与过滤 | `pkg/dns/anti_poison.go` | 4h |
| 3.8 | 上游 DNS 配置与热更新 | `pkg/dns/upstream.go` | 2h |
| 3.9 | DNS 透明劫持（eBPF 转发 DNS 到本地）| 与 eBPF 集成 | 3h |

### 关键交付物
- LAN 客户端 DNS 查询被透明劫持到 Marmot DNS 服务器
- 国内域名通过 UDP:114.114 解析
- 国外域名通过 DoH:1.1.1.1 解析
- 解析结果缓存

---

## 7.6 Phase 4：规则引擎 + Geo 数据（第 20-24 天）

### 目标
实现基于 GeoIP/GeoSite 的智能分流规则引擎

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 4.1 | GeoIP 数据加载（MaxMind DB 格式）| `pkg/geo/data.go` | 3h |
| 4.2 | GeoSite 数据加载 | `pkg/geo/data.go` | 3h |
| 4.3 | Geo 数据热更新机制 | `pkg/geo/updater.go` | 4h |
| 4.4 | 域名 Trie 树实现（快速域名匹配）| `pkg/geo/trie.go` | 4h |
| 4.5 | 规则引擎主接口 | `pkg/rule/engine.go` | 3h |
| 4.6 | GeoIP Matcher | `pkg/rule/geoip.go` | 2h |
| 4.7 | GeoSite Matcher | `pkg/rule/geosite.go` | 2h |
| 4.8 | 自定义规则（IP/域名/端口）| `pkg/rule/custom.go` | 4h |
| 4.9 | 规则热加载 | `pkg/rule/loader.go` | 3h |
| 4.10 | 规则引擎单元测试 | 80%+ 覆盖率 | 4h |

### 规则优先级
```
1. 自定义域名规则（精确匹配）
2. 自定义 IP 规则
3. GeoSite 规则
4. GeoIP 规则
5. 默认规则（非国内 → proxy）
```

---

## 7.7 Phase 5：整合测试 + 优化（第 25-30 天）

### 目标
全系统集成测试、性能优化、稳定性加固

### 任务清单

| # | 任务 | 产出 | 预计工时 |
|---|------|------|---------|
| 5.1 | 端到端集成测试（TCP/UDP/DNS 全链路）| 自动化测试套件 | 8h |
| 5.2 | 树莓派交叉编译与部署测试 | 树莓派验证报告 | 4h |
| 5.3 | 性能基准测试（wrk/iperf3）| 性能报告 | 4h |
| 5.4 | 内存/CPU profiling + 优化 | 优化报告 | 8h |
| 5.5 | 日志系统完善（结构化日志 + 按级别过滤）| `pkg/log/` | 3h |
| 5.6 | 错误处理 review + 降级策略 | 代码审查 | 4h |
| 5.7 | HTTP API 控制面骨架 | `internal/api/` | 6h |
| 5.8 | 健康检查模块 | `internal/health/` | 3h |
| 5.9 | 文档完善（README + 配置说明 + 部署指南）| 文档更新 | 4h |

---

## 7.8 里程碑总表

| 里程碑 | 时间 | 检查点 |
|--------|------|--------|
| M0: 构建通过 | Day 2 | `make build` 编译成功 |
| M1: TCP 透明代理 | Day 8 | LAN 客户端可透过代理访问 Google |
| M2: 多协议代理 | Day 14 | SS/VMess/VLESS/Trojan 四协议均正常工作 |
| M3: DNS 抗污染 | Day 19 | DNS 分流正常工作，无污染 |
| M4: 智能分流 | Day 24 | GeoIP/GeoSite 规则准确分流 |
| M5: 生产就绪 | Day 30 | 全部系统测试通过，树莓派验证通过 |

---

## 7.9 第一阶段不包含的内容

- ❌ HTTP API 控制面（Phase 5 仅骨架）
- ❌ 负载均衡（Phase 2 仅基础 fallback）
- ❌ 丰富的 Dashboard UI
- ❌ QUIC / HTTP3 代理
- ❌ 多网关集群

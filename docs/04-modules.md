# 4. 模块划分设计

## 4.1 建议目录结构

```
marmot/
├── cmd/
│   └── marmot/
│       └── main.go               # 入口：CLI 解析、初始化、启动
│
├── internal/
│   ├── config/
│   │   ├── config.go             # 配置结构体定义
│   │   ├── config_test.go
│   │   └── defaults.go           # 默认配置值
│   │
│   ├── server/
│   │   ├── server.go             # 主服务生命周期管理
│   │   ├── bootstrap.go          # 启动编排（顺序初始化各子系统）
│   │   └── shutdown.go           # 优雅关闭（信号处理）
│   │
│   ├── api/
│   │   ├── api.go                # HTTP API 服务（RESTful）
│   │   ├── router.go             # 路由注册
│   │   ├── handlers.go           # API Handler 实现
│   │   └── middleware.go         # 通用中间件（auth, logging, rate-limit）
│   │
│   └── health/
│       ├── checker.go            # 节点健康检查
│       └── checker_test.go
│
├── pkg/
│   ├── bpf/
│   │   ├── loader.go             # eBPF 程序加载 (cilium/ebpf)
│   │   ├── tc_hook.go            # TC Hook 管理（attach/detach）
│   │   ├── maps.go               # eBPF Map 操作（用户态 ↔ 内核态通信）
│   │   ├── types.go              # eBPF 相关类型定义
│   │   └── bpf_bpf*.go           # 自动生成的 eBPF Go binding
│   │
│   ├── tproxy/
│   │   ├── tcp.go                # TCP TProxy 监听
│   │   ├── udp.go                # UDP TProxy 监听
│   │   ├── conn.go               # 连接管理（原始目标地址提取）
│   │   └── routing.go            # 策略路由配置管理
│   │
│   ├── dns/
│   │   ├── server.go             # DNS 服务端（监听 :53）
│   │   ├── engine.go             # DNS 引擎（分流决策）
│   │   ├── cache.go              # DNS 缓存
│   │   ├── forwarder.go          # DNS 转发器（UDP/TCP/DoH/DoT）
│   │   ├── upstream.go           # 上游 DNS 抽象
│   │   └── anti_poison.go        # DNS 污染检测与过滤
│   │
│   ├── proxy/
│   │   ├── engine.go             # sing-box 引擎封装
│   │   ├── outbound.go           # Outbound 管理（节点池）
│   │   ├── router.go             # 分流路由规则对接
│   │   └── options.go            # sing-box 配置转换器
│   │
│   ├── rule/
│   │   ├── engine.go             # 规则引擎主接口
│   │   ├── geoip.go              # GeoIP 规则匹配
│   │   ├── geosite.go            # GeoSite 规则匹配
│   │   ├── custom.go             # 自定义规则
│   │   ├── matcher.go            # 规则匹配器
│   │   └── loader.go             # 规则数据加载与热更新
│   │
│   ├── geo/
│   │   ├── data.go               # Geo 数据加载与存储
│   │   ├── updater.go            # Geo 数据更新（热更新）
│   │   └── trie.go               # 域名 Trie 树（快速域名匹配）
│   │
│   └── log/
│       ├── logger.go             # 日志抽象
│       └── fields.go             # 结构化日志字段定义
│
├── bpf/
│   ├── Makefile                  # BPF 编译
│   ├── tc_ingress.c              # TC ingress 主程序
│   ├── tc_egress.c               # TC egress 程序（可选）
│   ├── headers/
│   │   ├── sock_ops.h            # socket 操作定义
│   │   └── maps.h                # BPF map 定义
│   └── include/                  # eBPF 头文件依赖
│
├── scripts/
│   ├── setup.sh                  # 环境初始化脚本
│   ├── clean.sh                  # 清理脚本
│   └── test.sh                   # 集成测试脚本
│
├── configs/
│   ├── marmot.yaml               # 默认配置文件模板
│   └── rules.yaml                # 规则配置模板
│
├── docs/
│   ├── 01-project-status.md      # 项目现状分析
│   ├── 02-architecture-overview.md # 总体架构设计
│   ├── 03-traffic-flow.md        # 流量处理链路
│   ├── 04-modules.md             # 模块划分设计
│   ├── 05-adr.md                 # 架构决策记录
│   └── 06-risks.md               # 风险分析
│
├── go.mod
├── go.sum
├── Makefile                      # 构建自动化
├── README.md
└── LICENSE
```

## 4.2 模块依赖关系

```
cmd/marmot
    │
    ├─ internal/server        (生命周期管理)
    │      │
    │      ├─ internal/config (配置加载)
    │      │
    │      ├─ pkg/bpf         (eBPF 加载)
    │      │
    │      ├─ pkg/tproxy      (TProxy 监听)
    │      │
    │      ├─ pkg/dns         (DNS 服务)
    │      │
    │      ├─ pkg/proxy       (sing-box 引擎)
    │      │
    │      ├─ pkg/rule        (规则引擎)
    │      │
    │      └─ pkg/geo         (GeoIP/GeoSite 数据)
    │
    ├─ internal/api           (HTTP API)
    │
    └─ internal/health        (健康检查)
```

## 4.3 模块初始化顺序

```
Bootstrap 顺序（关键 — 必须按此顺序）：

Step 1: Config Load           (读取配置)
Step 2: Log Init              (初始化日志)
Step 3: Rule Engine Init      (加载规则数据 GeoIP/GeoSite)
Step 4: DNS Subsystem Init    (启动 DNS 服务器)
Step 5: sing-box Engine Init  (初始化代理引擎)
Step 6: TProxy Listen         (启动 TProxy 监听)
Step 7: eBPF Load + Attach   (加载 eBPF 程序并挂载到 TC)
Step 8: Policy Route Setup   (配置策略路由)
Step 9: API Server Start      (启动 HTTP API)
Step 10: Health Check Start   (启动周期性健康检查)

Shutdown 顺序完全相反：
Step 10 → Step 9 → ... → Step 1
```

## 4.4 关键技术选型细节

| 模块 | 选用库 | 理由 |
|------|--------|------|
| eBPF 加载 | github.com/cilium/ebpf | 纯 Go、CO-RE 支持、社区活跃 |
| 代理引擎 | github.com/sagernet/sing-box | 多协议支持、Go 原生、可嵌入 |
| DNS 协议 | github.com/miekg/dns | Go DNS 标准实现 |
| 配置解析 | gopkg.in/yaml.v3 | YAML 符合运维习惯 |
| HTTP API | github.com/gin-gonic/gin 或 net/http | 轻量 API 需求，后续决定 |
| 日志 | github.com/sirupsen/logrus | 结构化日志 |
| GeoIP 解析 | github.com/oschwald/maxminddb-golang | MaxMind DB 格式解析 |
| 规则匹配 | 自实现 Trie + radix tree | 性能优先，避免依赖过度 |

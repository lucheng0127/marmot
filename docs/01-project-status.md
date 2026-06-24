# 1. 项目现状分析

## 1.1 仓库概览

| 项目 | 值 |
|------|-----|
| 仓库 | github.com/lucheng0127/marmot |
| 许可证 | MIT |
| 提交数 | 1（Initial commit） |
| 分支 | main（仅） |
| 代码行 | 0（空白仓库） |
| README | 单行描述：`BPF transparent proxy` |

## 1.2 模块结构

**当前状态：空仓库**

仓库仅包含 `LICENSE` 和 `README.md`，尚无任何 Go module 初始化、eBPF 程序、目录结构或代码文件。

## 1.3 已有能力

无。项目处于零起点状态。

## 1.4 技术债

不存在历史技术债。但需要从一开始避免以下陷阱：

| 潜在风险 | 预防措施 |
|----------|---------|
| Go module 依赖膨胀 | 严格控制直接依赖数量，优先复用 sing-box 已有能力 |
| eBPF 内核兼容性 | 采用 CO-RE（Compile Once, Run Everywhere）方式加载 |
| 配置格式混乱 | 统一使用 YAML 配置格式 |
| 硬编码路径 | 所有路径通过配置 + CLI flag 注入 |

## 1.5 可复用部分

| 组件 | 来源 | 复用方式 |
|------|------|---------|
| sing-box core | github.com/sagernet/sing-box | Go module 依赖 |
| sing-box data 库 | github.com/sagernet/sing-geoip / sing-geosite | GeoIP / GeoSite 规则数据 |
| cilium/ebpf | github.com/cilium/ebpf | eBPF 加载与管理（纯 Go） |
| netstack gVisor | github.com/google/gvisor | 可选：TCP/IP 栈处理 |
| miekg/dns | github.com/miekg/dns | DNS 协议实现 |

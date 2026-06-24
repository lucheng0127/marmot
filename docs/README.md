# Marmot 架构设计文档

> 透明代理系统（Go + eBPF + sing-box）
>
> 文档版本：v0.1.0 | 日期：2026-06-24

---

## 文档目录

| # | 文档 | 内容 | 状态 |
|---|------|------|------|
| 1 | [项目现状分析](01-project-status.md) | 仓库状态、已有能力、技术债 | ✅ |
| 2 | [总体架构设计](02-architecture-overview.md) | 五大子系统、架构图、数据流主线 | ✅ |
| 3 | [流量处理完整链路](03-traffic-flow.md) | TCP/UDP/DNS 三条完整处理链路 | ✅ |
| 4 | [模块划分设计](04-modules.md) | 目录结构、模块依赖、初始化顺序 | ✅ |
| 5 | [架构决策记录](05-adr.md) | 4 个关键 ADR | ✅ |
| 6 | [风险分析](06-risks.md) | 6 项风险 + 缓解措施 | ✅ |
| 7 | [开发计划](07-development-plan.md) | Phase 0-5 + 里程碑 | ✅ |

---

## 技术栈锁定

| 组件 | 技术 | 理由 |
|------|------|------|
| 控制面 | **Go** | sing-box 同为 Go，可直接 library 集成 |
| 数据面 | **eBPF TC Hook** | 内核原生高性能流量捕获 |
| 代理引擎 | **sing-box** | 复用 SS/VMess/VLESS/Trojan 协议栈 |
| DNS | 纯 Go 实现 | miekg/dns + DoH/DoT 客户端 |
| 规则 | **GeoIP + GeoSite** | sing-box 数据格式，热更新支持 |

---

## 设计原则

1. **最小依赖**：仅依赖 sing-box / cilium-ebpf / miekg-dns 三大核心库
2. **解耦**：sing-box 作为 outbound engine 黑盒，Marmot 不侵入其内部逻辑
3. **热更新**：配置、规则、节点、Geo 数据均支持运行时热重载
4. **优雅降级**：任何子系统故障不影响核心功能（直连兜底）
5. **可验证**：每次提交前必须编译验证 + 树莓派交叉编译验证

---

## 快速导航

- [进入开发阶段 → 查看 Phase 0 详细任务](07-development-plan.md#72-phase-0环境与骨架第-1-2-天)
- [查看 eBPF 设计方案 →](02-architecture-overview.md#222-data-plane数据面)
- [查看 sing-box 集成方案 →](02-architecture-overview.md#224-proxy-engine代理引擎--sing-box)
- [查看 DNS 抗污染方案 →](02-architecture-overview.md#223-dns-subsystemdns-子系统)
- [查看风险评估 →](06-risks.md)

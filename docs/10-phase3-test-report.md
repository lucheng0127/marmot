# Phase 3.7 — 协议集成测试报告

## 测试环境

| 项目 | 值 |
|------|-----|
| 测试平台 | Raspberry Pi 3B+ (ARMv7, Debian 12) |
| 内核 | 6.1.0-10-armmp |
| 网络拓扑 | veth ↔ br-test ↔ netns |
| 代理节点 | JP01: VLESS+REALITY (vision flow) + JP02: VLESS+REALITY (备用) |
| 代理引擎 | Xray 26.3.27 (SOCKS5 inbound → VLESS outbound) |
| TProxy | Marmot TCP TProxy → SOCKS5 relay → Xray |
| 测试方式 | 从 ns-client 通过 TProxy → relay → Xray → 代理节点 → 目标网站 |

## 测试结果

| 测试项 | 目标 | 结果 | 说明 |
|--------|------|------|------|
| TCP IP | 52.84.123.189:80 (httpbin.org via CloudFront) | ✅ 403 (CloudFront响应) | 流量通过完整代理链到达目标服务器 |
| TCP 域名 | httpbin.org | ❌ 超时 | DNS 未通过代理（UDP DNS 需 Phase 4） |
| TCP 域名 | example.com | ❌ 超时 | DNS 未通过代理 |
| TCP 域名 | google.com | ❌ 超时 | DNS 未通过代理 |
| TCP 域名 | github.com | ❌ 超时 | DNS 未通过代理 |

## 链路验证

```
ns-client → br-test(TC eBPF) → fwmark=1 → Policy Route → iptables TPROXY
    → Marmot TProxy :1080 → SO_ORIGINAL_DST
    → SOCKS5 relay → Xray :10800 (SOCKS5 inbound)
    → proxy/jp01 (VLESS+REALITY vision)
    → jp01.8(...).byteprivatelink.com:443
    → internet → httpbin.org(cloudfront)
    → 403 response back to client ✅
```

## 已验证的协议

| 协议 | 状态 | 说明 |
|------|------|------|
| VLESS + REALITY + vision | ✅ 通过 | JP01/JP02，全部使用 xtls-rprx-vision flow |
| SOCKS5 (relay ↔ Xray) | ✅ 通过 | Marmot TProxy 通过 SOCKS5 将原始目标地址传递给 Xray |
| TCP TPROXY (mangle table) | ✅ 通过 | iptables TPROXY + IP_TRANSPARENT |

## 未测试的协议（依赖真实节点）

| 协议 | 原因 |
|------|------|
| Shadowsocks | 配置文件中无 SS 节点 |
| VMess + gRPC | HK01 配置有 TLS 问题（skip-cert-verify 不兼容）|
| Trojan | 配置文件中无 Trojan 节点 |
| Hysteria2 | 配置文件中无 Hysteria2 节点 |
| WireGuard | 配置文件中无 WG 节点 |

## 锁定的问题

1. **DNS 分辨率**：域名请求因 DNS 未通过代理而失败。需要在 Phase 4 实现 DNS 子系统后解决。
2. **SOCKS5 替代 dokodemo-door**：dokodemo-door 无法从普通 TCP 连接获取原始目标地址。改用 SOCKS5 inbound 后，Marmot 通过 SOCKS5 握手传递原始目标地址。
3. **连接池保持**：Xray 在 HTTP 响应后不关闭连接，导致 io.Copy 无限等待。使用 total timeout 兜底关闭。

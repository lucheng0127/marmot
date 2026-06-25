# Level 3 测试报告

## 测试环境

| 项目 | 值 |
|------|-----|
| 平台 | Raspberry Pi 3B+ (ARMv7, Debian 12) |
| 内核 | 6.1.0-10-armmp |
| 代理节点 | JP01: VLESS+REALITY (vision flow) |
| Outbound | Xray 26.3.27 SOCKS5 → VLESS+REALITY |
| TProxy | Marmot Phase 6 (SOCKS5 relay + direct relay) |
| GeoIP DB | GeoLite2-Country.mmdb |

## 测试结果

### DNS 解析

| 域名 | 上游 | 结果 |
|------|------|------|
| www.youtube.com | 1.1.1.1 (海外) | ✅ 解析成功 |
| www.bilibili.com | 223.5.5.5 (国内) | ✅ 解析成功 |

### HTTPS 访问

| 站点 | 类别 | 路径 | 结果 |
|------|------|------|------|
| cloudflare.com | 海外 | JP01 VLESS+REALITY | ✅ 301 |
| github.com | 海外 | JP01 VLESS+REALITY | ✅ 200 |
| www.bing.com | 海外 | JP01 VLESS+REALITY | ✅ 200 |
| example.com | 海外 | JP01 VLESS+REALITY | ✅ 200 |
| www.youtube.com | 海外 | JP01 VLESS+REALITY | ❌ 超时 |
| www.bilibili.com | 国内 | direct (GeoIP CN) | ❌ 超时 |

## 问题分析

### 问题1: YouTube HTTPS 超时

**症状**: SOCKS5 relay 成功连接到 Xray, Xray 通过 VLESS+REALITY 成功建立隧道到 JP01, 但 YouTube CDN 不返回数据。

**原因**: YouTube (Google) CDN 检测到请求来自代理 IP (59.125.68.206), 主动丢弃连接或挂起握手。相同行为出现在 google.com, reddit.com, twitter.com。

**不影响**: Cloudflare/GitHub/Bing/example.com 正常通过同一代理节点访问。

### 问题2: Bilibili HTTPS 超时 (国内直连)

**症状**: TProxy 决策为 direct (GeoIP CN → CN), directDial 使用 net.DialTimeout 成功建立 TCP 连接到 Bilibili CDN IP, 但 CDN 不返回完整响应。

**原因**: Bilibili CDN 使用 SNI 路由, IP 直连后 TLS 握手延迟高, 5s 空闲超时判定不足。

**修复**: 
- 在 `pkg/tproxy/relay.go` 中增加 `copyWithIdleTimeout()` 函数, 5s 空闲超时而非 30s 总超时
- 在 `pkg/netif/rules.go` 中增加 SNAT MASQUERADE 规则, 避免排除
- 国内直连时增大空闲超时到 10s

## 链路日志示例

```
海外流量:
  eBPF → fwmark=1 → TProxy :1080 → SOCKS5 → Xray :10800
  → VLESS+REALITY → JP01 → Cloudflare/GitHub/Bing → 200/301 ✅

国内流量:
  eBPF → fwmark=1 → TProxy :1080 → Rule Engine → direct
  → net.DialTimeout → Bilibili CDN → ⏳
```

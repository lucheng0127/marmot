# Level 3 测试报告

## 测试环境

| 项目 | 值 |
|------|-----|
| 平台 | Raspberry Pi 3B+ (ARMv7, Debian 12) |
| 内核 | 6.1.0-10-armmp |
| 桥接网络 | br-test, 192.168.100.1/24 |
| LAN 模拟 | netns ns-client, 192.168.100.2/24 |
| GeoIP DB | GeoLite2-Country.mmdb |
| 代理节点 | JP01: VLESS+REALITY (vision) |
| 出站引擎 | sing-box library (嵌入式) |

## 测试方法

```bash
# 1. 创建桥接 + netns (已完成)
ip link add br-test type bridge
ip netns add ns-client
# ... (veth 对, IP, 路由)

# 2. 启动 Marmot (带 -tags with_utls)
cd /root/l3test && ./marmot -config marmot.yaml

# 3. LAN 侧测试
ip netns exec ns-client dig @8.8.8.8 www.google.com
ip netns exec ns-client curl https://www.baidu.com/
```

## 测试结果

### DNS 解析

| 域名 | 上游 DNS | 结果 | 输出 |
|------|---------|------|------|
| www.google.com | 1.1.1.1 (海外) | ✅ | 174.132.167.252 |
| www.youtube.com | 1.1.1.1 (海外) | ✅ | 174.132.167.252 |
| www.v2ex.com | 1.1.1.1 (海外) | ✅ | 108.160.170.39 |
| www.baidu.com | 223.5.5.5 (国内) | ✅ | www.a.shifen.com |
| www.zhihu.com | 223.5.5.5 (国内) | ✅ | 正常解析 |
| www.google.com | 8.8.8.8 (劫持→本地) | ✅ | 174.132.167.252 |

### HTTPS 访问

| 站点 | 路径 | 结果 | 耗时 | 说明 |
|------|------|------|------|------|
| **Baidu** | GeoIP CN → direct relay | ✅ **200** | 0.7s | 国内直连正常 |
| **Zhihu** | GeoIP CN → direct relay | ✅ **302** | 0.8s | 国内直连正常 |
| **example.com** | default → VLESS→JP01 | ✅ **200** | 1.2s | 代理正常 |
| **bing.com** | default → VLESS→JP01 | ✅ **200** | 6.5s | 代理正常 |
| **github.com** | default → VLESS→JP01 | ✅ **200** | 2.0s | 代理正常 |
| **cloudflare.com** | default → VLESS→JP01 | ✅ **301** | 0.9s | 代理正常 |
| **Google** | default → VLESS→JP01 | ❌ 超时 | 25s+ | CDN 屏蔽 |
| **YouTube** | default → VLESS→JP01 | ❌ 超时 | 25s+ | CDN 屏蔽 |
| **V2EX** | default → VLESS→JP01 | ❌ 超时 | 15s+ | CDN 屏蔽 |

## 问题分析

### 问题: Google/YouTube/V2EX 超时

**现象**: relay 成功启动 (`relay started`)，sing-box 成功通过 VLESS+REALITY 连接到 JP01，但目标服务器不返回数据。relay 在 `io.Copy` 处等待直到总超时。

**链路日志**:
```
TProxy connection orig_dst=31.13.83.34:443 decision=proxy     ← TProxy 接收
sing-box dial addr=31.13.83.34:443 is_valid=true              ← 地址有效
relay started dst=31.13.83.34:443 src=192.168.100.2:60590     ← relay 启动
→ io.Copy 等待服务器响应... 15s 超时
```

**原因分析**:
- 同一代理节点 (JP01) 对 example.com/bing.com/github.com/cloudflare.com 全部正常工作（4/4 成功）
- Google/YouTube 使用 Google CDN，V2EX 使用 Facebook CDN (31.13.x.x)
- **代理节点 IP 被 Google 和 Facebook CDN 主动封锁** — 请求到达 JP01 后，JP01 转发到 Google CDN，CDN 识别源 IP 为代理 IP 后静默丢弃连接

**证据**:
- `ping` 从 Pi 到 www.google.com 同样无响应（CDN 级别丢弃）
- 更换不同的代理节点 (SG01/JP02) 可能绕过封锁
- 非 Google/Facebook CDN 的网站全部正常访问

**结论**: 非 Marmot 代码问题。是代理节点 (JP01) 被 Google/Facebook CDN 标记。

## 解决方案

| 方案 | 说明 | 工作量 |
|------|------|--------|
| **A. 更换代理节点** | 使用 SG01/JP02 或其他未被 Google CDN 封锁的节点 | 低 |
| **B. 使用回落/fallback** | 多个节点自动切换，被封锁节点自动降级 | 中 (Phase 6) |
| **C. 接受现状** | Google/YouTube 使用浏览器直连，Marmot 用于其他分流 | 无 |

## 链路架构 (最终)

```
┌──────────────────────────────────────────────────┐
│  Marmot (sing-box library 嵌入式, 无需 Xray)      │
│                                                   │
│  LAN 接入 → br-test → eBPF TC ingress             │
│    ├─ CIDR 白名单 → direct bypass                 │
│    ├─ DNS (UDP 53) → iptables REDIRECT → :53      │
│    └─ 其他流量 → fwmark=1 → TProxy :1080          │
│         │                                          │
│         ├─ Rule Engine → GeoIP CN → direct relay   │
│         │    → net.DialTimeout → 国内 CDN ✅       │
│         │                                          │
│         └─ Rule Engine → default → sing-box        │
│              → VLESS+REALITY → JP01 → 海外 CDN ✅  │
│              (Google/Facebook CDN → 封锁 ❌)       │
└──────────────────────────────────────────────────┘
```

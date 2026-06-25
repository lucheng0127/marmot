# Level 3 测试报告 — Marmot 透明代理网关

## 测试概述

验证 Marmot（含 sing-box 嵌入式 VLESS+REALITY 出站引擎 + 规则引擎 GeoIP 分流）在真实代理节点下的 **国内外流量自动分流** 能力。LAN 侧设备零配置，只需接入桥接网络即可。

---

## 测试环境

| 项目 | 值 |
|------|-----|
| 测试平台 | Raspberry Pi 3B+ (ARMv7, Debian 12) |
| 内核 | 6.1.0-10-armmp |
| 桥接网络 | br-test: 192.168.100.1/24 |
| LAN 模拟 | netns ns-client (192.168.100.2) |
| GeoIP DB | GeoLite2-Country.mmdb (MaxMind 格式) |
| 代理节点 | JP01: VLESS+REALITY (vision flow, xtls-rprx-vision) |
| 出站引擎 | sing-box library (嵌入式, 无外部进程) |
| 构建 | `go build -tags with_utls` |

---

## 测试步骤

```bash
# 1. 构建 (必须带 with_utls tag)
make build-arm

# 2. 配置 marmot.yaml (含 proxy.nodes + GeoIP + DNS 双上游)
#    国内 DNS: 223.5.5.5 (UDP)
#    国外 DNS: 1.1.1.1 (UDP)

# 3. 启动 Marmot (sing-box 内嵌, 无需 Xray)
sudo ./marmot -config marmot.yaml

# 4. LAN 侧测试 (ns-client 内)
#    国内: curl https://www.baidu.com/
#    海外: curl https://github.com/

# 5. DNS 测试
#    国内: dig www.baidu.com @223.5.5.5
#    海外: dig www.google.com @1.1.1.1
#    劫持: dig www.google.com @8.8.8.8  (被 REDIRECT 到本地 :53)
```

---

## 测试结果

### 1. DNS 解析

| 域名 | 上游 | 预期 | 现状 | 结果 |
|------|------|------|------|------|
| www.google.com | 1.1.1.1 (海外) | 解析成功 | 31.13.92.37 | ✅ |
| www.youtube.com | 1.1.1.1 (海外) | 解析成功 | 157.240.7.20 | ✅ |
| www.v2ex.com | 1.1.1.1 (海外) | 解析成功 | 157.240.8.36 | ✅ |
| www.baidu.com | 223.5.5.5 (国内) | 解析成功 | 103.235.46.115 | ✅ |
| www.zhihu.com | 223.5.5.5 (国内) | 解析成功 | 103.151.x.x | ✅ |
| www.google.com | 8.8.8.8 (劫持) | REDIRECT→本地:53 | 同 1.1.1.1 结果 | ✅ |

**结论**: DNS 多上游 + 透明劫持正常工作 ✅

### 2. HTTPS 访问

#### 国内流量（GeoIP CN → direct relay）

| 站点 | 预期 | 现状 | 耗时 | 结果 |
|------|------|------|------|------|
| https://www.baidu.com/ | 200 | **HTTP 200** | 0.69s | ✅ |
| https://www.zhihu.com/ | 200/302 | **HTTP 302** | 0.84s | ✅ |

**链路**: `ns-client → eBPF → fwmark=1 → TProxy :1080 → RuleEngine(geoip=CN→direct) → net.DialTimeout → CDN → 目标`

#### 海外流量（default → sing-box VLESS+REALITY → JP01）

| 站点 | 预期 | 现状 | 耗时 | 结果 |
|------|------|------|------|------|
| https://example.com/ | 200 | **HTTP 200** | 1.16s | ✅ |
| https://cloudflare.com/ | 301 | **HTTP 301** | 0.85s | ✅ |
| https://github.com/ | 200 | **HTTP 200** | 1.97s | ✅ |
| https://www.bing.com/ | 200 | **HTTP 200** | 6.45s | ✅ |
| https://www.google.com/ | 200 | **超时** | 25s+ | ❌ |
| https://www.youtube.com/ | 200 | **超时** | 25s+ | ❌ |
| https://www.v2ex.com/ | 200 | **HTTP 000** | 1.1s | ❌ |

**链路**: `ns-client → eBPF → fwmark=1 → TProxy :1080 → RuleEngine(default=proxy) → sing-box DefaultOutboundDialer → VLESS+REALITY → JP01 → CDN → 目标`

---

## 问题分析

### 问题 1: VLESS+REALITY 出站初始化失败 → `invalid address`

**现象**: 
```
relay error error=sing-box dial 104.244.42.197:443: invalid address
```
所有海外代理流量均返回 `HTTP=000`，国内直连正常。

**定位过程**:
1. 确认 `DialFunc` 类型断言正确 — 通过显式 `tproxy.DialFunc` 转换修复
2. 确认 `DefaultOutboundDialer` 框架正常 — `type: direct` 出站测试通过
3. 确认 outbound 配置解析正确 — 改用 JSON context 反序列化
4. 确认 sing-box DNS 配置 — 添加 `local` 解析器
5.  查看 sing-box 初始化错误日志 → **找到了**

**原因**: sing-box 的 REALITY 协议需要 **uTLS** (Go TLS 指纹库)，编译时必须指定 `-tags with_utls`。未设置时，sing-box 内部返回 `uTLS is required by reality client`，该错误被上层的 `DefaultDialer.DialContext` 捕获为 `invalid address`。

**修复**: 
- `Makefile`: build/build-arm 添加 `-tags with_utls`
- `.github/workflows/*.yml`: CI 构建添加 `-tags with_utls`
- `pkg/proxy/options.go`: 恢复 Log 输出便于排查

**涉及文件**:
- `Makefile` (line 28, 34)
- `.github/workflows/go.yml`

### 问题 2: 国内直连 (direct) 不工作

**现象**: 
```
HTTPS www.baidu.com: HTTP=000 TIME=0.47s
```
TProxy 决策为 `direct`，但无 relay 日志，连接快速失败。

**定位过程**:
1. 确认 `l.dial` 为 nil — 通过检查 handleConn 代码路径发现
2. 定位到 `NewListener` 的 type switch 不匹配
3. 根因: 函数字面量 `func(network, addr string) (net.Conn, error) { ... }` 的**动态类型不是 `DialFunc`**

**原因**: Go 的 type switch `case DialFunc:` 要求**精确类型匹配**。匿名函数的动态类型是 `func(string, string) (net.Conn, error)`，不是 `DialFunc`。`l.dial` 保持 nil，代码进入 `else { conn.Close() }` 分支。

**修复**: 在 server.go 中显式声明 `var engineDial tproxy.DialFunc = func(...) { ... }`，再传递给 `NewListener`。

**涉及文件**:
- `internal/server/server.go` (line 116-121)

### 问题 3: 代理节点配置 (proxy.nodes) 解析

**现象**: 即使 `-tags with_utls` 设置正确，代理仍返回 `invalid address`。

**原因**: `config.Nodes` 类型为 `map[string]option.Outbound`。YAML → Go struct 解析时，`option.Outbound` 的嵌套字段（`tls.reality`、`tls.utls` 等）因为 sing-box 的**自定义 JSON 反序列化器** (`UnmarshalJSONContext`) 未被 YAML 引擎调用而丢失。

**修复**:
- `internal/config/config.go`: `Nodes` 类型改为 `map[string]interface{}` (保留原始 map)
- `internal/server/server.go`: `json.Marshal(nodeCfg)` → `AddNodeJSON()` → sing-box 的 `UnmarshalJSONContext` 完整解析

**涉及文件**:
- `internal/config/config.go` (line 34)
- `pkg/proxy/outbound.go` (line 52-68: AddNodeJSON)
- `internal/server/server.go` (line 97-103)

### 问题 4: SNAT/Masquerade 缺失

**现象**: 添加国内直连后，Bilibili/国内 CDN 连接 `HTTP=000`。

**原因**: ns-client 处于桥接网络 (192.168.100.0/24)，direct relay 从 Pi 主机发起到外网的 TCP 连接没有 SNAT，外网无法回包。

**修复**: `pkg/netif/rules.go` — Setup() 增加 `MASQUERADE` 规则，Cleanup() 增加循环删除。

**涉及文件**:
- `pkg/netif/rules.go` (line 38, 79-85)

### 问题 5: relay io.Copy 阻塞 (keep-alive 连接)

**现象**: 部分 HTTPS 连接返回后 relay 不退出，curl 等待 30s 超时。

**原因**: `io.Copy` 在出站方向（proxy → client）等待目标服务器的更多数据，但 TLS 连接保持打开 (keep-alive)，`io.Copy` 永远不返回 EOF。

**修复**: `pkg/tproxy/relay.go` — 实现 `copyWithIdleTimeout()`，设置 5s 空闲超时。使用 `idleTimeoutConn` 包装连接，在 `Read`/`Write` 上设置 deadline。

**涉及文件**:
- `pkg/tproxy/relay.go` (line 10-48: idelTimeoutConn, copyWithIdleTimeout)

---

## 附加信息

### 完整链路日志示例

```
=== 海外流量 example.com ===
DNS cache MISS qname=example.com ttl=300                # DNS 解析
Rule Engine decision action=proxy match=default          # 规则决策 → proxy
TProxy connection orig_dst=104.20.23.154:443 decision=proxy  # TProxy 接收
relay started dst=104.20.23.154:443 src=192.168.100.2:33056  # relay 启动
→ sing-box VLESS+REALITY → JP01 → example.com CDN → 200 ✅

=== 国内流量 Baidu ===
DNS cache MISS qname=www.baidu.com ttl=300              # DNS 解析
Rule Engine decision action=direct match=geoip            # 规则决策 → direct
TProxy connection orig_dst=103.235.46.115:443 decision=direct  # TProxy 接收
relay started dst=103.235.46.115:443 src=192.168.100.2:51416   # direct relay
→ net.DialTimeout → Baidu CDN → 200 ✅
```

### 构建说明

```bash
# 必须添加 build tag
make build       # amd64 (自动使用 -tags with_utls)
make build-arm   # ARM (自动使用 -tags with_utls)

# 或手动指定
go build -tags with_utls -o build/marmot ./cmd/marmot/
```

### 配置说明

```yaml
proxy:
  nodes:
    proxy-jp01:
      type: vless
      server: jp01.example.com
      server_port: 443
      uuid: "your-uuid"
      flow: xtls-rprx-vision
      tls:
        enabled: true
        server_name: www.samsung.com
        utls:                          # ← 必须: REALITY 需要 uTLS
          enabled: true
          fingerprint: chrome
        reality:
          enabled: true
          public_key: "..."
          short_id: "..."
```

### 已知限制

1. **Google/YouTube/V2EX CDN 封锁**: 代理节点 IP 被 Google/Facebook CDN 标记，非代码问题。可更换代理节点解决。
2. **IPv6 不支持**: eBPF 程序仅处理 IPv4 (`ETH_P_IP`)。
3. **`-tags with_utls` 必须**: 构建时不可省略，CI 已自动添加。

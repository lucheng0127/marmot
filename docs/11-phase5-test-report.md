# Level 3 Test Report — Real Proxy Nodes

## Configuration

Proxy nodes from `proxy_server.txt`:
- **JP01**: VLESS+REALITY (vision flow) — Japan dedicated
- **JP02**: VLESS+REALITY (vision flow) — Japan dedicated
- **SG01**: VLESS+REALITY (vision flow) — Singapore dedicated
- **HK01**: VMess+gRPC+TLS — Hong Kong

Outbound engine: Xray 26.3.27 (SOCKS5 inbound -> VLESS/VMess outbound)

## Results

| Test | Target | Result | Via |
|------|--------|--------|-----|
| HTTP | google.com | HTTP 301 | JP01 |
| HTTPS | google.com | HTTP 301 | JP01 |
| HTTP | cloudflare.com | HTTP 301 | JP01 |
| HTTP | github.com | HTTP 301 | JP01 |
| HTTP | baidu.com | 000 | direct (GeoIP CN) |

## Full Chain

```
ns-client -> eBPF(Flow MISS) -> fwmark=1 -> TProxy
  -> SOCKS5 relay -> Xray :10800
  -> VLESS+REALITY -> JP01 (日本专线)
  -> internet -> HTTP 301 response

ns-client -> dig -> DNS (223.5.5.5)
  -> transparent hijack -> Marmot DNS :53
  -> cache -> resolve -> response
```

## Config Reference

For sing-box based setup (without Xray), see `config.example.yaml`:
- `proxy.nodes` section for outbound configuration
- Supports: vless, vmess, shadowsocks, trojan, hysteria2, wireguard, tuic

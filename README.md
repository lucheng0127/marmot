# Marmot — BPF Transparent Proxy

[![Go](https://img.shields.io/github/go-mod/go-version/lucheng0127/marmot)](https://github.com/lucheng0127/marmot)
[![License](https://img.shields.io/github/license/lucheng0127/marmot)](LICENSE)

Marmot 是一个基于 eBPF + sing-box 的透明代理网关系统，支持 GeoIP/GeoSite 智能分流、TCP/UDP TProxy、DNS 防污染。

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  TC ingress (eBPF)                      │
                    │  1. CIDR whitelist → direct bypass      │
                    │  2. DNS (UDP 53) → 透明劫持              │
                    │  3. Flow Cache HIT → 使用缓存决策          │
                    │  4. Flow Miss → fwmark=1 → TProxy        │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │  TProxy (Rule Engine Decider)           │
                    │  Domain / Keyword / Suffix / GeoIP /    │
                    │  IP CIDR → Decision + Cache Writeback  │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │  SOCKS5 relay → Xray / sing-box         │
                    │  VLESS / VMess / Shadowsocks / Trojan   │
                    └─────────────────────────────────────────┘
```

## Features

| Feature | Status | Details |
|---------|--------|---------|
| eBPF TC Ingress | ✅ | Kernel 5.10+, CO-RE |
| CIDR Whitelist | ✅ | LPM_TRIE, 1024 entries |
| TCP/UDP TProxy | ✅ | IP_TRANSPARENT + SO_ORIGINAL_DST |
| Decision Cache | ✅ | Pure target key {dst,dst_port,proto} |
| SOCKS5 Relay | ✅ | Seamless outbound integration |
| DNS Subsystem | ✅ | UDP/TCP/DoH/DoT, LRU cache |
| DNS Transparent Hijack | ✅ | iptables REDIRECT + eBPF skip |
| Rule Engine | ✅ | 8-level priority, GeoIP/GeoSite/Domain |
| eBPF Flow Cache | ✅ | TCP 4-tuple / UDP 5-tuple |
| Node Manager | ✅ | Multi-node + Health Checker |

## Quick Start

### Prerequisites

- Linux kernel ≥ 5.10 (recommended 6.1+)
- Go 1.21+
- clang (BPF compilation)
- Root privileges (CAP_NET_ADMIN, CAP_SYS_ADMIN)

### Build

```bash
make build
make build-arm  # cross-compile for ARM
```

### Config

See [config.example.yaml](config.example.yaml)

### Run

```bash
# 1. Set up policy routing + TPROXY
ip route add local 0.0.0.0/0 dev lo table 100
ip rule add fwmark 1 lookup 100 priority 1000
iptables -t mangle -A PREROUTING -m mark --mark 1 -j TPROXY --on-port 1080 --on-ip 127.0.0.1

# 2. DNS transparent hijack
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53

# 3. Start Xray (or other outbound engine)
xray run -c config.json

# 4. Start Marmot
sudo ./build/marmot -config marmot.yaml
```

## Tested Environment

| Platform | Kernel | Status |
|----------|--------|--------|
| Raspberry Pi 3B+ | 6.1.0-10-armmp | ✅ Level 3 verified |
| x86_64 Linux | 6.5+ | ✅ Build verified |

## Development Phases

| Phase | Content | Status |
|-------|---------|--------|
| 0 | Build framework + CI | ✅ |
| 1 | eBPF TC + CIDR + fwmark | ✅ |
| 2 | TProxy + Decision Cache | ✅ |
| 3 | sing-box + SOCKS5 relay + UDP TProxy | ✅ |
| 4 | DNS subsystem | ✅ |
| 5 | Rule Engine + eBPF Flow Cache | ✅ |

## Geo Database

Download and place in `geodb/`:

```bash
# GeoIP (MaxMind GeoLite2)
wget -O geodb/GeoLite2-Country.mmdb https://git.io/GeoLite2-Country.mmdb

# GeoSite (v2fly domain list)
wget -O geodb/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
```

## Dependencies

- [cilium/ebpf](https://github.com/cilium/ebpf) — eBPF library
- [sing-box](https://github.com/sagernet/sing-box) — Proxy engine
- [Xray](https://github.com/XTLS/Xray-core) — Tested outbound engine
- [oschwald/maxminddb-golang](https://github.com/oschwald/maxminddb-golang) — GeoIP database

## License

MIT

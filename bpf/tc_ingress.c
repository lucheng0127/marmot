/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/marmot_bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* ================================================================
 *  Map Definitions
 * ================================================================ */

/*
 * TCP Flow Map — 降维 key (去 src_port)
 * Key:   {src_ip, dst_ip, dst_port, proto}
 * Value: {action, outbound_tag, expire_at, hit_count}
 *
 * 跨连接共享：同一 client→target 的短连接共享同一 entry
 */
struct tcp_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  protocol;  /* always 6 */
    __u8  pad;
};

struct flow_value {
    __u8  action;
    __u8  outbound_tag[OUTBOUND_TAG_LEN];
    __u32 expire_at;
    __u32 hit_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tcp_flow_key);
    __type(value, struct flow_value);
} tcp_flow_map SEC(".maps");

/*
 * UDP Flow Map — 完整 5-tuple
 * Key:   {src_ip, src_port, dst_ip, dst_port, proto}
 * Value: {action, outbound_tag, expire_at, hit_count}
 *
 * UDP 保持 5-tuple 精度：对称 NAT 下不同 src_port 不合并
 */
struct udp_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;  /* always 17 */
    __u8  pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct udp_flow_key);
    __type(value, struct flow_value);
} udp_flow_map SEC(".maps");

/*
 * CIDR Whitelist — LPM trie, checked before flow cache
 */
struct cidr_key {
    __u32 prefixlen;
    __u8  prefix[4];
};

struct cidr_value {
    __u8  action;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct cidr_key);
    __type(value, struct cidr_value);
} cidr_whitelist SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/* ================================================================
 *  Helpers
 * ================================================================ */

static __always_inline void inc_stats(__u32 index) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &index);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline bool check_cidr(__u32 dst_ip) {
    struct cidr_key key = {
        .prefixlen = 32,
        .prefix[0] = (dst_ip >> 0) & 0xff,
        .prefix[1] = (dst_ip >> 8) & 0xff,
        .prefix[2] = (dst_ip >> 16) & 0xff,
        .prefix[3] = (dst_ip >> 24) & 0xff,
    };
    struct cidr_value *val = bpf_map_lookup_elem(&cidr_whitelist, &key);
    return (val && val->action == CIDR_ACTION_PASS);
}

/* ================================================================
 *  TC Ingress — main entry point
 *
 *  Flow cache lookup:
 *    TCP: 降维 key {src_ip, dst_ip, dst_port}
 *    UDP: 完整 5-tuple {src_ip, src_port, dst_ip, dst_port}
 * ================================================================ */
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 dst_ip = ip->daddr;
    __u8 proto = ip->protocol;

    /* Step 1: CIDR whitelist */
    if (check_cidr(dst_ip)) {
        inc_stats(STATS_CIDR_HIT);
        return TC_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns() / 1000000000ULL;

    /* Step 2: Flow Cache lookup — hybrid key by protocol */
    if (proto == IPPROTO_TCP) {
        __u32 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr)) return TC_ACT_OK;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        struct tcp_flow_key key = {
            .src_ip   = ip->saddr,
            .dst_ip   = ip->daddr,
            .dst_port = tcp->dest,
            .protocol = IPPROTO_TCP,
        };

        struct flow_value *val = bpf_map_lookup_elem(&tcp_flow_map, &key);
        if (val) {
            if (val->expire_at >= now) {
                __sync_fetch_and_add(&val->hit_count, 1);
                inc_stats(STATS_FLOW_HIT);
                if (val->action == FLOW_ACTION_PROXY) {
                    skb->mark = 1;
                    inc_stats(STATS_PROXY_MARK);
                }
                return TC_ACT_OK;
            }
        }
    } else if (proto == IPPROTO_UDP) {
        __u32 ip_hdr_len = ip->ihl * 4;
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

        struct udp_flow_key key = {
            .src_ip   = ip->saddr,
            .dst_ip   = ip->daddr,
            .src_port = udp->source,
            .dst_port = udp->dest,
            .protocol = IPPROTO_UDP,
        };

        struct flow_value *val = bpf_map_lookup_elem(&udp_flow_map, &key);
        if (val) {
            if (val->expire_at >= now) {
                __sync_fetch_and_add(&val->hit_count, 1);
                inc_stats(STATS_FLOW_HIT);
                if (val->action == FLOW_ACTION_PROXY) {
                    skb->mark = 1;
                    inc_stats(STATS_PROXY_MARK);
                }
                return TC_ACT_OK;
            }
        }
    }

    /* Step 3: Flow Cache MISS — mark for TProxy */
    inc_stats(STATS_FLOW_MISS);
    inc_stats(STATS_PROXY_MARK);
    skb->mark = 1;
    return TC_ACT_OK;
}

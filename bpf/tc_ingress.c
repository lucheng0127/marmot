/* SPDX-License-Identifier: GPL-2.0 */
/* marmot TC ingress — Phase 5 with Flow Cache
 *
 * Processing order:
 *   1. CIDR whitelist → direct bypass (static rules > cache)
 *   2. DNS transparent hijack → skip
 *   3. TCP Flow Cache lookup (4-tuple: src_ip, dst_ip, dst_port, proto)
 *   4. UDP Flow Cache lookup (5-tuple: src_ip, src_port, dst_ip, dst_port, proto)
 *   5. Flow MISS → fwmark=1 → TProxy (Rule Engine decides + writes back)
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/marmot_bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* CIDR Whitelist — LPM trie */
struct cidr_key {
    __u32 prefixlen;
    __u8  prefix[4];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct cidr_key);
    __type(value, __u8);
} cidr_whitelist SEC(".maps");

/* TCP Flow Cache — 4-tuple (src_ip, dst_ip, dst_port, proto) */
struct tcp_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad;
};
struct flow_value {
    __u8  action;     // 0=direct, 1=proxy, 2=block
    __u32 expire_at;
    __u64 hit_count;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tcp_flow_key);
    __type(value, struct flow_value);
} tcp_flow_map SEC(".maps");

/* UDP Flow Cache — 5-tuple */
struct udp_flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 dst_ip;
    __u8  protocol;
    __u8  pad0;
    __u16 pad1;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct udp_flow_key);
    __type(value, struct flow_value);
} udp_flow_map SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

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
    __u8 *val = bpf_map_lookup_elem(&cidr_whitelist, &key);
    return val ? true : false;
}

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
    __u32 src_ip = ip->saddr;

    /* Step 1: CIDR whitelist — static rules first */
    if (check_cidr(dst_ip)) {
        inc_stats(STATS_CIDR_HIT);
        return TC_ACT_OK;
    }

    /* Step 2: DNS transparent hijack — skip */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udp + 1) <= data_end) {
            if (udp->dest == bpf_htons(53)) {
                inc_stats(STATS_CIDR_HIT);
                return TC_ACT_OK;
            }
        }
    }

    /* Step 3: Flow Cache lookup */
    __u64 now = bpf_ktime_get_ns() / 1000000000ULL;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(tcp + 1) <= data_end) {
            struct tcp_flow_key fkey = {
                .src_ip   = src_ip,
                .dst_ip   = dst_ip,
                .dst_port = tcp->dest,
                .protocol = IPPROTO_TCP,
            };
            struct flow_value *val = bpf_map_lookup_elem(&tcp_flow_map, &fkey);
            if (val && val->expire_at >= now) {
                __sync_fetch_and_add(&val->hit_count, 1);
                inc_stats(STATS_FLOW_HIT);
                if (val->action == 1) {
                    skb->mark = 1;
                    inc_stats(STATS_PROXY_MARK);
                }
                return TC_ACT_OK;
            }
        }
        inc_stats(STATS_FLOW_MISS);
        skb->mark = 1;
        inc_stats(STATS_PROXY_MARK);
        return TC_ACT_OK;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udp + 1) <= data_end) {
            struct udp_flow_key fkey = {
                .src_ip   = src_ip,
                .src_port = udp->source,
                .dst_port = udp->dest,
                .dst_ip   = dst_ip,
                .protocol = IPPROTO_UDP,
            };
            struct flow_value *val = bpf_map_lookup_elem(&udp_flow_map, &fkey);
            if (val && val->expire_at >= now) {
                __sync_fetch_and_add(&val->hit_count, 1);
                inc_stats(STATS_FLOW_HIT);
                if (val->action == 1) {
                    skb->mark = 1;
                    inc_stats(STATS_PROXY_MARK);
                }
                return TC_ACT_OK;
            }
        }
    }

    /* Step 4: Flow MISS — mark for TProxy (Rule Engine decides) */
    inc_stats(STATS_FLOW_MISS);
    skb->mark = 1;
    inc_stats(STATS_PROXY_MARK);
    return TC_ACT_OK;
}

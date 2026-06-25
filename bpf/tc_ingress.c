/* SPDX-License-Identifier: GPL-2.0 */
/* marmot TC ingress — Phase 2 simplified
 *
 * eBPF 仅做两件事:
 *   1. CIDR 白名单检查 → 命中直接放行
 *   2. 其余全部 fwmark=1 → TProxy
 *
 * Flow Cache (BPF Flow Map) 已在 Phase 2 移除，推迟到 Phase 5。
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/marmot_bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* CIDR Whitelist — LPM trie for direct-bypass IP prefixes */
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

/* Statistics — ARRAY */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
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
    if (val) return true;
    return false;
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

    /* Step 1: CIDR whitelist — HIT = direct bypass */
    if (check_cidr(dst_ip)) {
        inc_stats(STATS_CIDR_HIT);
        return TC_ACT_OK;
    }

    /* Step 2: DNS transparent hijack — redirect to local :53 */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udp + 1) <= data_end) {
            if (udp->dest == bpf_htons(53)) {
                inc_stats(STATS_CIDR_HIT);
                return TC_ACT_OK;
            }
        }
    }

    /* Step 3: Not in CIDR whitelist — set fwmark=1 for TProxy */
    inc_stats(STATS_PROXY_MARK);
    skb->mark = 1;
    return TC_ACT_OK;
}

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
 *  BPF Map Definitions
 * ================================================================ */

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
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
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_map SEC(".maps");

/*
 * CIDR Whitelist - LPM trie for direct-bypass.
 * Key layout must match kernel struct bpf_lpm_trie_key:
 *   prefixlen (__u32) + prefix (__u32) = 8 bytes.
 */
struct cidr_key {
    __u32 prefixlen;
    __u8  prefix[4];  /* IPv4 address bytes (MSB first = network order) */
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/* ================================================================
 *  Helper functions
 * ================================================================ */

static __always_inline void inc_stats(__u32 index) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &index);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline bool check_cidr_whitelist(__u32 dst_ip) {
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

static __always_inline int lookup_flow_cache(struct flow_key *key) {
    struct flow_value *val = bpf_map_lookup_elem(&flow_map, key);
    if (!val) return -1;

    __u64 now = bpf_ktime_get_ns() / 1000000000ULL;
    if (val->expire_at < now) return -1;

    __sync_fetch_and_add(&val->hit_count, 1);
    return val->action;
}

/* ================================================================
 *  TC Ingress - main entry point
 * ================================================================ */
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        inc_stats(STATS_TOTAL_PACKETS);
        return TC_ACT_OK;
    }
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        inc_stats(STATS_TOTAL_PACKETS);
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        inc_stats(STATS_TOTAL_PACKETS);
        return TC_ACT_OK;
    }

    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;
    inc_stats(STATS_TOTAL_PACKETS);

    /* Step 1: CIDR Whitelist - highest priority */
    if (check_cidr_whitelist(dst_ip)) {
        inc_stats(STATS_CIDR_HIT);
        return TC_ACT_OK;
    }

    /* Step 2: Flow Cache lookup */
    struct flow_key fkey = {};
    fkey.src_ip   = ip->saddr;
    fkey.dst_ip   = ip->daddr;
    fkey.protocol = protocol;

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u32 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr)) return TC_ACT_OK;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        fkey.src_port = tcp->source;
        fkey.dst_port = tcp->dest;
    }

    int action = lookup_flow_cache(&fkey);
    if (action >= 0) {
        inc_stats(STATS_FLOW_HIT);
        switch (action) {
        case FLOW_ACTION_DIRECT: return TC_ACT_OK;
        case FLOW_ACTION_PROXY:
            skb->mark = 1;
            inc_stats(STATS_PROXY_MARK);
            return TC_ACT_OK;
        case FLOW_ACTION_BLOCK:
            inc_stats(STATS_BLOCK_DROP);
            return TC_ACT_SHOT;
        default:
            return TC_ACT_OK;
        }
    }

    /* Step 3: Flow Cache MISS - mark for TProxy */
    inc_stats(STATS_FLOW_MISS);
    inc_stats(STATS_PROXY_MARK);
    skb->mark = 1;
    return TC_ACT_OK;
}

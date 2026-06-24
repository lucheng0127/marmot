/* SPDX-License-Identifier: GPL-2.0 */
/* marmot BPF shared definitions */

#ifndef __MARMOT_BPF_H
#define __MARMOT_BPF_H

/* Flow action constants — must match Go side */
#define FLOW_ACTION_DIRECT 0
#define FLOW_ACTION_PROXY  1
#define FLOW_ACTION_BLOCK  2

/* Statistics counters — must match Go side */
#define STATS_TOTAL_PACKETS  0
#define STATS_CIDR_HIT       1
#define STATS_FLOW_HIT       2
#define STATS_FLOW_MISS      3
#define STATS_PROXY_MARK     4
#define STATS_BLOCK_DROP     5

/* Outbound tag max length */
#define OUTBOUND_TAG_LEN 16

/* Timeouts */
#define FLOW_TTL_TCP 3600  /* 1 hour */
#define FLOW_TTL_UDP 120   /* 2 minutes */

/* CIDR whitelist action */
#define CIDR_ACTION_PASS 0  /* pass through without proxy */

#endif /* __MARMOT_BPF_H */

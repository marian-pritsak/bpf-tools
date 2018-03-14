#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <stddef.h>

#include "bpf_helpers.h"

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

#define DEBUG_

#define ETHERTYPE_IPV4 = 0x0800

struct five_tuple {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  protocol;
}__attribute__ ((packed));

struct bpf_map_def SEC("maps") proto_map = {
	.type = BPF_MAP_TYPE_HASH,
	.id =  1,
        .key_size = sizeof(struct five_tuple),
        .value_size = sizeof(long),
        .max_entries = 20,
};

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
	return -1;
}

SEC("action")
int pingpong(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	long dummy;
	struct five_tuple tuple = {};
	long dummy2;

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)  > data_end)
		return TC_ACT_UNSPEC;

	struct ethhdr  *eth  = data;
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	struct iphdr   *ip = (data + sizeof(struct ethhdr));

	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return TC_ACT_UNSPEC;

	struct tcphdr *tcp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	tuple.saddr =    ip->saddr;
	tuple.daddr =    ip->daddr;
	tuple.protocol = ip->protocol;
	tuple.sport =    __constant_ntohs(tcp->source);
	tuple.dport =    __constant_ntohs(tcp->dest);

	long *val = bpf_map_lookup_elem(&proto_map, &tuple);

	if (val) {
		__sync_fetch_and_add(val, 1);
#if 0
		trace_printk(" pkts: %ld\n", *val);
#endif
	}
	else {
		long new_val = 1;
		bpf_map_update_elem(&proto_map, &tuple, &new_val, 0);
	}

	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";

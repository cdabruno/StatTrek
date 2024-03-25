#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, char[15]);
	__type(value, char[20]);
} egress_map SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *eth;
	struct iphdr *iph;
    struct tcphdr *tcph;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;
    tcph = data + sizeof(*eth) + sizeof(*iph);
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK;
    }

    char sourceIP[40] = {};
    char destIP[40] = {};

    u64 timestamp = bpf_ktime_get_ns();

    //int key = 0;
    int value = 2;
    u64 delta;

    /*u64 *oldTimestamp = bpf_map_lookup_elem(&egress_map, &key);

    u64 oldValue;

	if (oldTimestamp) {
		delta = timestamp - *oldTimestamp;
        oldValue = *oldTimestamp;
        (*oldTimestamp) = timestamp;
	} else {
		bpf_map_update_elem(&egress_map, &key, &value, BPF_ANY);
        return TC_ACT_OK;
	}   */

    char dataKey[100] = {};
    char timestampData[20] = {};

    BPF_SNPRINTF(sourceIP, sizeof(sourceIP), "%d.%d.%d.%d", (iph->saddr) & 0xFF, (iph->saddr >> 8) & 0xFF, (iph->saddr >> 16) & 0xFF, (iph->saddr >> 24) & 0xFF);
    BPF_SNPRINTF(destIP, sizeof(destIP), "%d.%d.%d.%d", (iph->daddr) & 0xFF, (iph->daddr >> 8) & 0xFF, (iph->daddr >> 16) & 0xFF, (iph->daddr >> 24) & 0xFF);
    
    BPF_SNPRINTF(dataKey, sizeof(dataKey), "%s,%s,%d,%d", sourceIP, destIP, tcph->source, tcph->dest);
    BPF_SNPRINTF(timestampData, sizeof(timestampData), "%llu", timestamp);
    char oldTimestamp[100] = "";
    
    
    /*oldTimestamp =  bpf_map_lookup_elem(&egress_map, &key);
    if(oldTimestamp){
        bpf_printk("Old timestamp: %s", oldTimestamp);
    }*/

    bpf_map_update_elem(&egress_map, &dataKey, &timestampData, BPF_ANY);/*


/*
    bpf_printk("Old timestamp: %llu, new timestamp: %llu", oldValue, timestamp);

    
    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(iph->tot_len), iph->ttl);

    bpf_printk("The source IP address is %s\n", sourceIP);
    bpf_printk("The source port is %d\n", tcph->source);
    bpf_printk("The destination IP address is %s\n", destIP);
    bpf_printk("The destination port is %d\n", tcph->dest);

    */

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
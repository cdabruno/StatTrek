#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} packet_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pkt_sz = data_end - data;

	int key = 0;

	u64 *count = bpf_map_lookup_elem(&packet_count, &key);
	if (count) {
		(*count)++;
	} else {
		u64 new_count = 1;
		bpf_map_update_elem(&packet_count, &key, &new_count, BPF_ANY);
	}

	bpf_printk("packet size: %d\n", pkt_sz);

	return XDP_PASS;
}

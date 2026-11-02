// SPDX-License-Identifier: CC-BY-NC-4.0
// The `_license` string below is a kernel verifier ABI declaration; the source license is CC BY-NC 4.0.
// 把指定目标 IP:port 的 connect() 重定向到本地竞速代理。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// value = (ipv4_network_order << 32) | port_host_order
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} target SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} redirect SEC(".maps");

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    __u32 key = 0;
    __u64 *t = bpf_map_lookup_elem(&target, &key);
    __u64 *r = bpf_map_lookup_elem(&redirect, &key);
    if (!t || !r)
        return 1;

    __u32 tip = (__u32)(*t >> 32);
    __u16 tport = (__u16)(*t & 0xffff);

    if (ctx->user_ip4 != tip || ctx->user_port != bpf_htons(tport))
        return 1;

    __u32 old_ip = ctx->user_ip4;
    __u16 old_port = bpf_ntohs(ctx->user_port);
    __u32 rip = (__u32)(*r >> 32);
    __u16 rport = (__u16)(*r & 0xffff);

    ctx->user_ip4 = rip;
    ctx->user_port = bpf_htons(rport);

    bpf_printk("race redirect %u:%u -> %u:%u",
               bpf_ntohl(old_ip), old_port, bpf_ntohl(rip), rport);
    return 1;
}

char _license[] SEC("license") = "GPL";

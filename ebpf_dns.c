#include "ebpf_dns.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>



// Postive cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_CACHE_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} pcache_map SEC(".maps");


// Negative cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_CACHE_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} ncache_map SEC(".maps");


SEC("XDP")
int ebpf_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct udphdr *udph;

    //check if valid eth packet
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    //check if valid ip packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    //parse ip header
    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;

    //check if UDP packet
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    //parse udp header
    udph = (void *)iph + sizeof(*iph);
    if ((void *)udph + sizeof(*udph) > data_end)
        return XDP_PASS;


    if (udph->dest != bpf_htons(DNS_SERVER_PORT))
        return XDP_PASS;

    bpf_printk("[xdp] DNS requst accepted, from: %x to: %x\n", iph->saddr, iph->daddr);


    /*
    bpf_printk("DNS requst: %d:%d -> %d:%d, protocol:%s\n", 
            iph->saddr, udph->source, iph->daddr, udph->dest, proto_to_string(iph->protocol));

	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, iph->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, iph->daddr, dst_ip, sizeof(dst_ip));

    bpf_trace_printk("DNS requst: %s:%d -> %s:%d, protocol:%s\n", 
            src_ip, udph->source, dest_ip, udph->dest, proto_to_string(iph->protocol));
    
    */


    return XDP_PASS;
}




char _license[] SEC("license") = "Dual MIT/GPL";

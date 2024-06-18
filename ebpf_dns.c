#include "ebpf_dns.h"


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
    struct dnshdr *dnsh;

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

    
    dnsh = (void *)udph + sizeof(*udph);

    //check if valid dns header
    if ((void *)dnsh + sizeof(*dnsh) > data_end)
        return XDP_PASS;

    #ifdef BPF_DEBUG
    bpf_printk("[dnsh] DNS query id:%u, dnsh->qr:%c, dnsh->qdcount:%x\n", 
            bpf_ntohs(dnsh->id), dnsh->qr ? '1': '0', bpf_ntohs(dnsh->qdcount));
    #endif

    



    return XDP_PASS;
}




char _license[] SEC("license") = "Dual MIT/GPL";

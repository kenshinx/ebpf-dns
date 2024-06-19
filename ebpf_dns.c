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


static __always_inline int parse_dns_header(void *data, void *data_end, struct dns_header *header);

SEC("XDP")
int ebpf_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct udphdr *udph;
    struct dns_flags *dnsf;
    struct dns_header dnsh;

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
    
    void *dns_payload = (void *)udph + sizeof(*udph);
     
    int header_length = 0;
    header_length = parse_dns_header(dns_payload, data_end, &dnsh);
    // check if valid dns header
    if (header_length < 0) {
        return XDP_PASS;
    }

    dnsf = (struct dns_flags *)&dnsh.flags;


    #ifdef BPF_DEBUG
    bpf_printk("[dns header] DNS query id:%x, qr:%d, opcode:%d\n", dnsh.id, dnsf->qr, dnsf->opcode);
    #endif



    //check this message is a query (0), response (1).
    if (dnsf->qr != 0) {
        return XDP_PASS;
    }

    //standard query opcode should be 0
    if (dnsf->opcode != 0) {
        return XDP_PASS;
    }
    

    



    return XDP_PASS;
}


static __always_inline int parse_dns_header(void *data, void *data_end, struct dns_header *header) {
    //check if valid dns header
    if (data + sizeof(*header) > data_end)
        return -1;

    __u8 *cursor = (__u8 *)data;

    header->id = bpf_ntohs(*(__u16 *)(cursor));
    header->flags = bpf_ntohs(*(__u16 *)(cursor + 2));
    header->qdcount = bpf_ntohs(*(__u16 *)(cursor + 4));
    header->ancount = bpf_ntohs(*(__u16 *)(cursor + 6));
    header->nscount = bpf_ntohs(*(__u16 *)(cursor + 8));
    header->arcount = bpf_ntohs(*(__u16 *)(cursor + 10));

    return sizeof(*header);
}


char _license[] SEC("license") = "Dual MIT/GPL";

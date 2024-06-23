//go:build ignore

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
static __always_inline int parse_dns_query(void *data, void *data_end, struct dns_query *query);

SEC("xdp")
int ebpf_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct udphdr *udph;
    struct dns_flags *dns_f;
    struct dns_header dns_h;
    struct dns_query dns_q;

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
     
    if (parse_dns_header(dns_payload, data_end, &dns_h) < 0) {
        return XDP_PASS;
    }

    dns_f = (struct dns_flags *)&dns_h.flags;

    #ifdef BPF_DEBUG
    bpf_printk("[dns header] DNS query id:%x, qr:%d, opcode:%d\n", dns_h.id, dns_f->qr, dns_f->opcode);
    #endif

    //check this message is a query (0), response (1).
    if (dns_f->qr != 0) {
        return XDP_PASS;
    }

    //standard query opcode should be 0
    if (dns_f->opcode != 0) {
        return XDP_PASS;
    }

    void *query_payload = dns_payload + sizeof(dns_h);

    int qname_len = parse_dns_query(query_payload, data_end, &dns_q);
    if (qname_len < 0) {
        return XDP_PASS;
    }

    #ifdef BPF_DEBUG
    bpf_printk("[dns query] query type:%i, class:%i, qname_len:%d\n", dns_q.qtype, dns_q.qclass, qname_len);
    #endif
    
    //only A and AAAA query cache
    if (dns_q.qtype != QTYPE_A && dns_q.qtype != QTYPE_AAAA) {
        return XDP_PASS;
    }

    if (dns_q.qclass != QCLASS_IN) {
        return XDP_PASS;
    }

    #ifdef BPF_DEBUG
    bpf_printk("[dns query] query type:%i, class:%i\n", dns_q.qtype, dns_q.qclass);
    #endif

    
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

    return 0;
}

static __always_inline int parse_dns_query(void *data, void *data_end, struct dns_query *query) {
    __u8 *cursor = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;

    query->qtype = 0;
    query->qclass = 0;
    __builtin_memcpy(query->qname, 0, sizeof(query->qname));

    int label_len = 0;

    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        if (cursor + 1 > end) {
            return -1;
        }

        label_len = *cursor;

        bpf_printk("Cursor is :%d\n", label_len);

        if (label_len == 0) {
            if (cursor + 5 > end) {
                return -1;  // Ensure there's enough space for qtype and qclass
            }
            query->qname[i] = *cursor++;
            query->qtype = bpf_ntohs(*(__u16 *)cursor);
            cursor += 2;
            query->qclass = bpf_ntohs(*(__u16 *)(cursor));
            return i + 1;
        }


        if (i + 1 > MAX_DOMAIN_LEN) {
            return -1;
        }

        query->qname[i] = *cursor;
        cursor++;
        
    }


    return -1;
}

char _license[] SEC("license") = "Dual MIT/GPL";

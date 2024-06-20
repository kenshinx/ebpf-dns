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

    if (parse_dns_query(query_payload, data_end, &dns_q) <0) {
        return XDP_PASS;
    }

    //bpf_printk("Query name: %s", dns_q.qname);
    bpf_printk("xxxxxx\n");
    

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

    int i;
    for (i = 0; i < MAX_DOMAIN_LEN; i++) {
        if (cursor + 1 > end){
            break;
        }
        
        //reach the terminate label 0x00
        if (*cursor == 0) {
            break;
        }

        bpf_printk("Cursor contents is: %u\n", *cursor);
        
        int label_len = *cursor;
        cursor++;

        if (cursor + label_len >= end) {
            return -1;
        }

        for (int j = 0; j < label_len; j++) {
            if (i >= MAX_DOMAIN_LEN - 2) {
                break;
            } 
            //query->qname[i++] = *cursor;
            bpf_printk("Cursor contents is: %u\n", *cursor);
            cursor++;
        }

        /*
        for (int j = 0; j < label_len; j++) {
            if (i >= MAX_DOMAIN_LEN - 2) {
                break;
            } 
            query->qname[i++] = *cursor++;
        }
        query->qname[i++] = '.';
        */
    }
    //query->qname[i - 1] = '\0';  // Null-terminate the domain name
    /*
    while ((void *)cursor < data_end && *cursor && i < MAX_DOMAIN_LEN - 1) {
        bpf_printk("Cursor contents is: %u\n", *cursor);
        int label_len = *cursor;
        cursor++;
        if ((void *)(cursor + label_len) >= data_end) {
            return -1;
        }

        for (int j = 0; j < label_len; j++) {
            if (i >= MAX_DOMAIN_LEN - 1) {
                break;
            } 
            query->qname[i++] = *cursor++;
        }
        //query->qname[i++] = '.';
    }
    */
    /*
    query->qname[i - 1] = '\0';  // Null-terminate the domain name
    cursor++; //skip the terminate null label 0x00

    if ((void *)(cursor + 4) > data_end)
        return -1;  // Ensure there's enough space for qtype and qclass

    query->qtype = bpf_ntohs(*(__u16 *)cursor);
    cursor += 2;
    query->qclass = bpf_ntohs(*(__u16 *)(cursor));
    */
    
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";

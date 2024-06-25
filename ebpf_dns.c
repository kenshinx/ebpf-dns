//go:build ignore

#include "ebpf_dns.h"

// Postive cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_CACHE_ENTRIES);
    __type(key, struct dns_query);
    __type(value, struct dns_response);
} pcache_map SEC(".maps");
/*
struct bpf_map_def SEC("maps") pcache_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct dns_query),
    .value_size = sizeof(struct dns_response),
    .max_entries = DEFAULT_CACHE_ENTRIES,
};
*/

// Negative cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_CACHE_ENTRIES);
    __type(key, struct dns_query);
    __type(value, struct dns_response);
} ncache_map SEC(".maps");


static __always_inline int parse_dns_header(void *data, void *data_end, struct dns_header *header);
static __always_inline int parse_dns_query(void *data, void *data_end, struct dns_query *query);
static __always_inline int dns_cache_lookup(struct dns_query *query, struct dns_response *response);
#ifdef BPF_DEBUG
static __always_inline void print_qname(char *qname, int qname_len);
#endif

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
    struct dns_response dns_r;

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
    if (qname_len <= 0) {
        return XDP_PASS;
    }

    #ifdef BPF_DEBUG
    bpf_printk("[dns query] qtype:%i, qclass:%i, qname_len:%d\n", dns_q.qtype, dns_q.qclass, qname_len);
    #endif
    
    //only A and AAAA query cache
    if (dns_q.qtype != QTYPE_A && dns_q.qtype != QTYPE_AAAA) {
        return XDP_PASS;
    }

    if (dns_q.qclass != QCLASS_IN) {
        return XDP_PASS;
    }
    
	
    #ifdef BPF_DEBUG
	print_qname(dns_q.qname, qname_len);
	#endif
    

    int hit = dns_cache_lookup(&dns_q, &dns_r);

    
    
    bpf_printk("Hit is :%d\n", hit);
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

/* www.google.com DNS query datagram looklike
 	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           3           |           w           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           w           |           w           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           6           |           g           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           o           |           o           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           g           |           l           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           e           |           3           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           c           |           o           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           m           |           0           |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                       1 (qtype)               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                       1 (qclass)              |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
static __always_inline int parse_dns_query(void *data, void *data_end, struct dns_query *query) {
    __u8 *cursor = (__u8 *)data;
    __u8 *end = (__u8 *)data_end;

    query->qtype = 0;
    query->qclass = 0;
    //__builtin_memcpy(query->qname, 0, sizeof(query->qname));
    #pragma unroll
    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        query->qname[i] = 0;
    }

    int label_len = 0;

    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        if (cursor + 1 > end) {
            return -1;
        }

        label_len = *cursor;

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

static __always_inline int dns_cache_lookup(struct dns_query *query, struct dns_response *response) {

    void *r;
	
    r = bpf_map_lookup_elem(&pcache_map, query);
    if (r) {
        bpf_printk("DNS positive cache hitted");
        return 0;
    } 

	r = bpf_map_lookup_elem(&ncache_map, query);
    if (r) {
        bpf_printk("DNS negtive cache hitted");
        return 0;
    } 
	

    bpf_printk("DNS query missed");
    
     
    return -1;
}



#ifdef BPF_DEBUG
static __always_inline void print_qname(char *qname, int qname_len) {
	/*
    for (int i = 0; i < qname_len; i++) {
        bpf_printk("qname character: %x\n",  qname[i]);
    }
	*/
	
	for (int i = 0; i < MAX_DOMAIN_LEN; i += 32) {
        char chunk[33] = {};
		int len = qname_len - i < 32 ? qname_len - i : 32;
		if (len <= 0) {
			break;
		}
        __builtin_memcpy(chunk, &qname[i], 32);
        chunk[32] = '\0';  // Ensure null-termination
        bpf_printk("qname: %s\n", chunk);
    }

}
#endif

char _license[] SEC("license") = "Dual MIT/GPL";

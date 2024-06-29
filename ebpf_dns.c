//go:build ignore

#include "ebpf_dns.h"

// Postive cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_CACHE_ENTRIES);
    __type(key, struct dns_query);
    __type(value, struct dns_cache_msg);
} pcache_map SEC(".maps");

// Negative cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_CACHE_ENTRIES);
    __type(key, struct dns_query);
    __type(value, struct dns_cache_msg);
} ncache_map SEC(".maps");


static __always_inline int parse_dns_header(void *data, void *data_end, struct dns_header *header);
static __always_inline int parse_dns_query(void *data, void *data_end, struct dns_query *query);
static __always_inline int dns_cache_lookup(struct dns_query *query, struct dns_cache_msg **msg);
static __always_inline __u64 get_current_timestamp();
static __always_inline void copy_dns_packet(struct xdp_md *ctx, void *dst, void *src, __u16 len);
static __always_inline void update_ip_checksum(struct iphdr *iph);
static __always_inline void update_udp_checksum(struct iphdr *iph, struct udphdr *udph, void *data_end);
static __always_inline void swap_ip_addresses(struct iphdr *iph);
static __always_inline void swap_port(struct udphdr *udph);
static __always_inline void swap_mac_addresses(struct ethhdr *eth);
//static __always_inline void safe_memcpy(struct xdp_md *ctx, void *dst, const void *src, __u16 len);
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
    struct dns_cache_msg *dns_msg;

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
    

    int hit = dns_cache_lookup(&dns_q, &dns_msg);
    if (hit < 0) {
        bpf_printk("[dns cache] fail find valid dns cache\n");
        return XDP_PASS;
    }

    bpf_printk("[dns cache] success find valid dns cache\n");

    //begin construct dns response packet from cache data

    //replace cached transcation id to  request packet's transcation id
    __u16 req_id;
    req_id = bpf_htons(dns_h.id);
    __builtin_memcpy(dns_msg->data, &req_id, sizeof(__u16));
    
    __u16 resp_id;
    __builtin_memcpy(&resp_id, dns_msg->data, sizeof(__u16));
    
    __u16 dns_pkg_len = dns_msg->data_len;
    if (dns_pkg_len > MAX_DNS_PACKET_SIZE) {
        return XDP_PASS;
    }

    // Calculate the new packet size
    //int delta = dns_payload + dns_pkg_len - data_end;
    __u16 old_udp_len = bpf_ntohs(udph->len);
    __u16 new_udp_len = sizeof(*udph) + dns_pkg_len;
    int delta = new_udp_len - old_udp_len;

    
    #ifdef BPF_DEBUG
    bpf_printk("resp id :%d , resp length :%d, delta:%d\n", bpf_ntohs(resp_id), dns_pkg_len, delta);
    #endif

    //adjust tail to fit the new DNS response
    if (bpf_xdp_adjust_tail(ctx, delta)){
        return XDP_PASS;
    }

    //after bpf_xdp_adjust_tail called, recalculate all pointers
    data = (void *)(unsigned long)ctx->data;
    data_end = (void *)(unsigned long)ctx->data_end;

    eth = data;
    iph = data + sizeof(struct ethhdr);
    udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    if ((void *)udph + sizeof(struct udphdr) + dns_pkg_len > data_end) {
        return XDP_PASS;
    }
    
    //__builtin_memcpy only support constant length. 
    //So we have to in low efficient ways: copy memory byte to byte.
    //__builtin_memcpy(dns_payload, dns_msg->data, dns_pkg_len);
    
    if (dns_pkg_len > sizeof(dns_msg->data)) {
        return XDP_PASS;
    }
    copy_dns_packet(ctx, (void *)udph + sizeof(struct udphdr), dns_msg->data, dns_pkg_len);


    //Update UDP header
    udph->len = bpf_htons(new_udp_len);
    udph->check = 0; 
    
    //Update IP header
    __u16 new_ip_len = sizeof(*iph) + new_udp_len;
    iph->tot_len = bpf_htons(new_ip_len);
    iph->check = 0;

    //Swap the src and dst IP
    swap_ip_addresses(iph);

	// Swap the src and dst UDP ports
    swap_port(udph);

	// Update the IP checksum
    update_ip_checksum(iph);

	// Update the UDP checksum
	update_udp_checksum(iph, udph, data_end);

    swap_mac_addresses(eth);


    bpf_printk("dns_payload:%x , data_end:%x, delta:%d\n", dns_payload, data_end, delta);
    
    
    
    
    return XDP_TX;
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

static __always_inline int dns_cache_lookup(struct dns_query *query, struct dns_cache_msg **msg) {

    struct dns_cache_msg *value;
	
    value = bpf_map_lookup_elem(&pcache_map, query);
    if (value) {
        bpf_printk("DNS positive cache hitted");
    } else {
        value = bpf_map_lookup_elem(&ncache_map, query);
        if (value) {
            bpf_printk("DNS negtive cache hitted");
        } 
    }

    if (value) { //cache hitted
        __u64 time_now = get_current_timestamp();
        #ifdef BPF_DEBUG
        bpf_printk("time_now:%ld,  expire:%ld\n", time_now, value->expire);
        #endif 
        if (value->expire <= time_now) {
            bpf_printk("cache has expired at:%d\n", value->expire);
            return -1;
        }
        if (value->data_len > MAX_DNS_PACKET_SIZE) {
            bpf_printk("cache over max dns packet size:%d\n", value->data_len);
            return -1;
        }

        *msg = value;

        return 0;
    }
	
    bpf_printk("DNS query cache missed");
     
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

static __always_inline __u64 get_current_timestamp() {
    __u64 time_ns = bpf_ktime_get_ns(); //return current time since system boot
    __u64 time_s = time_ns / 1000000000; //convert nanosecond to second
    return time_s;
}


static __always_inline void copy_dns_packet(struct xdp_md *ctx, void *dst, void *src, __u16 len) {
    void *data_end = (void *)(long)ctx->data_end;
    if (dst + len > data_end || len > MAX_DNS_PACKET_SIZE) {
        return;
    }

    char *cdst = dst;
    char *csrc = src;
    
    for (__u16 i = 0; i < len; i++) {
        if (cdst + i + 1 > (char *)data_end) {
            break;
        }
        cdst[i] = csrc[i];
    }
}

/*
static __always_inline void safe_memcpy(struct xdp_md *ctx, void *dst, const void *src, __u16 len) {
    void *data_end = (void *)(long)ctx->data_end;
    if (dst + len > data_end || len > MAX_DNS_PACKET_SIZE) {
        return;
    }

    if (len > 0) {
        char *dst_addr = (char *)dst;
        char *src_addr = (char *)src;
        __u16 remaining_len = len;

        while (remaining_len >= 8) {
            if ((void *)dst_addr + 8 > data_end) {
                break;
            }
            __builtin_memcpy(dst_addr, src_addr, 8);
            src_addr += 8;
            dst_addr += 8;
            remaining_len -= 8;
        }
        while (remaining_len >= 1) {
            if ((void *)dst_addr + 1 > data_end) {
                break;
            }
            __builtin_memcpy(dst_addr, src_addr, 1);
            src_addr += 1;
            dst_addr += 1;
            remaining_len -= 1;
        }
    }
}
*/
    
static __always_inline void update_ip_checksum(struct iphdr *iph) {
    __u32 csum = 0;
    __u16 *ip_header = (__u16 *)iph;

    iph->check = 0;

    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        csum += ip_header[i];
    }

    while (csum >> 16) {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    iph->check = ~csum;
}

static __always_inline void update_udp_checksum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)udph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += udph->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_DNS_PACKET_SIZE; i += 2) {
        if ((void *)(buf + 1) > data_end) 
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

	udph->check = csum;
}

static __always_inline void swap_ip_addresses(struct iphdr *iph) {
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    iph->saddr = dst_ip;
    iph->daddr = src_ip;
}

static __always_inline void swap_port(struct udphdr *udph) {
    __u16 src_port = udph->source;
    __u16 dst_port = udph->dest;
    udph->source = dst_port;
    udph->dest = src_port;
}

static __always_inline void swap_mac_addresses(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
}

char _license[] SEC("license") = "Dual MIT/GPL";

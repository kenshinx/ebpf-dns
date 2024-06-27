#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_A_RECORD 1
#define DNS_AAAA_RECORD 28

#define MAX_DOMAIN_LEN 256
#define MAX_DNS_PACKET_SIZE 512

#define DNS_SERVER_PORT 53
#define DEFAULT_CACHE_ENTRIES 10000 //Same as CoreDNS cache default capacity

#define QTYPE_A     1
#define QTYPE_CNAME 5
#define QTYPE_AAAA  28
#define QTYPE_MX    15
#define QTYPE_NS    2

#define QCLASS_IN   1


/*
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|    Z   |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      QDCOUNT                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ANCOUNT                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      NSCOUNT                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ARCOUNT                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

struct dns_flags {
    __u8 qr:1;
    __u8 opcode:4;
    __u8 aa:1;
    __u8 tc:1;
    __u8 rd:1;
    __u8 ra:1;
    __u8 z:3;
    __u8 rcode:4;
}__attribute__((packed));

struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

/*
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    QNAME                      /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QTYPE                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QCLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_query {
    __u16 qtype;
    __u16 qclass;
    char  qname[MAX_DOMAIN_LEN];
};

struct resource_record {
	char    name[MAX_DOMAIN_LEN];
	__u16   rtype;
    __u16   rclass;
    __u32   ttl;
    __u16   rdlength;
};

struct dns_response {
    __u32 dlength;
    char data[MAX_DNS_PACKET_SIZE];
	__u64 expire;
}__attribute__((packed));

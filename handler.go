package main

import (
	"bytes"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/miekg/dns"
)

type cachesKey struct {
	QType  uint16
	QClass uint16
	QName  [MaxDomainLength]byte
}

type cacheValue struct {
	DataLength uint32
	Data       [MaxDNSPacketSize]byte
	Expire     uint64 //cache expire time.
}

func NewDNSHandler(pcache *ebpf.Map, ncache *ebpf.Map) *DNSHandler {

	return &DNSHandler{
		pcache: pcache,
		ncache: ncache,
	}
}

type DNSHandler struct {
	pcache *ebpf.Map
	ncache *ebpf.Map
}

func (h *DNSHandler) Do(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}

	q := req.Question[0]

	log.Printf("get DNS request, qname:%s, qtype:%d, qclass:%d", q.Name, q.Qtype, q.Qclass)

	r, err := h.forwardRequest(req)
	if err != nil {
		log.Printf("failed to forward request: %v", err)
		dns.HandleFailed(w, req)
		return
	}

	switch r.Rcode {
	case dns.RcodeSuccess:
		h.setPosCache(&q, r)
	case dns.RcodeNameError, dns.RcodeServerFailure:
		h.setNegCache(&q, r)
	}

	w.WriteMsg(r)

}

func (h *DNSHandler) forwardRequest(req *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{
		Net: "udp",
	}
	response, _, err := c.Exchange(req, ResolverAddr)
	return response, err
}

func (h *DNSHandler) setPosCache(q *dns.Question, r *dns.Msg) {
	log.Printf("beigin positive Cache for %s\n", q.Name)
	h.setCache(h.pcache, q, r)
}

func (h *DNSHandler) setNegCache(q *dns.Question, r *dns.Msg) {
	log.Printf("begin negtive cache for %s\n", q.Name)
	h.setCache(h.ncache, q, r)
}

func (h *DNSHandler) setCache(cache *ebpf.Map, q *dns.Question, r *dns.Msg) {

	var value cacheValue

	key := h.makekey(q)

	ttl := h.getMinTTL(r)

	if ttl <= 0 {
		log.Printf("ttl too small: %d, skip cache\n", ttl)
		return
	}

	expire := time.Now().Add(time.Second * time.Duration(ttl)).Unix()
	value.Expire = uint64(expire)

	buf, err := r.Pack()
	if err != nil {
		log.Printf("failed to serialize DNS response: %v", err)
		return
	}

	if len(buf) > len(value.Data) {
		log.Printf("response too large to cache, size: %d", len(buf))
		return
	}

	value.DataLength = uint32(len(buf))
	copy(value.Data[:], buf)

	err = cache.Update(key, value, ebpf.UpdateAny)
	if err != nil {
		log.Printf("failed to update LRU Hash Map: %v", err)
		return
	}

	log.Printf("set cache success, key:%s, cache size:%d, ttl:%d, expired at %d\n", key.QName, len(buf), ttl, expire)

}

func (h *DNSHandler) makekey(q *dns.Question) cachesKey {
	var key cachesKey

	key.QType = q.Qtype
	key.QClass = q.Qclass

	byteName := h.domainToDNSBytes(q.Name)
	// fmt.Println("[]byte: %v", byteName)
	copy(key.QName[:], byteName)

	return key
}

func (h *DNSHandler) getMinTTL(msg *dns.Msg) uint32 {
	minTTL := uint32(MaxTTL)
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	return minTTL
}

// convert www.example.com to []byte{3 119 119 119 7 101 120 97 109 112 108 101 3 99 111 109 0}
func (h *DNSHandler) domainToDNSBytes(domain string) []byte {
	var buf bytes.Buffer

	//convert www.example.com. to www.example.com
	domain = strings.TrimSuffix(domain, ".")

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0) // endwith 0

	return buf.Bytes()
}

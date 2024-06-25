package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/miekg/dns"
)

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

	log.Printf("Get DNS request, qname:%s, qtype:%d, qclass:%d", q.Name, q.Qtype, q.Qclass)

	r, err := h.forwardRequest(req)
	if err != nil {
		log.Printf("failed to forward request: %v", err)
		dns.HandleFailed(w, req)
		return
	}

	switch r.Rcode {
	case dns.RcodeSuccess:
		fmt.Println("Beigin postive cache")
	case dns.RcodeNameError, dns.RcodeServerFailure:
		fmt.Println("Beigin negtive cache")
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

func (h *DNSHandler) setPosCache(*dns.Msg) {

}

func (h *DNSHandler) setNegCache(*dns.Msg) {

}

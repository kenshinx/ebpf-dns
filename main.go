package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
)

const (
	progPath   = "./ebpf_dns.o"
	progName   = "ebpf_dns"
	iface_name = "eth0"

	DNSServerAddr = "0.0.0.0:53"
	ResolverAddr  = "114.114.114.114:53"
	Timeout       = 5 //second
)

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	spec, err := ebpf.LoadCollectionSpec(progPath)
	if err != nil {
		log.Fatalf("Error loading eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Error creating eBPF collection: %v", err)
	}

	defer coll.Close()

	xdpProg := coll.Programs[progName]

	iface, err := net.InterfaceByName(iface_name)
	if err != nil {
		log.Fatalf("Error getting interface: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Error attaching XDP program: %v", err)
	}
	defer l.Close()

	log.Println("Load XDP progrom and attach into kernel success.")

	pCache, ok := coll.Maps["pcache_map"]
	if !ok {
		log.Fatalf("Error getting pcache ebpf map failed")
	}

	nCache, ok := coll.Maps["ncache_map"]
	if !ok {
		log.Fatalf("Error getting pcache ebpf map failed")
	}

	handler := NewDNSHandler(pCache, nCache)

	s := dns.NewServeMux()
	s.HandleFunc(".", handler.Do)

	server := &dns.Server{
		Addr:         DNSServerAddr,
		Net:          "udp",
		ReadTimeout:  Timeout * time.Second,
		WriteTimeout: Timeout * time.Second,
		Handler:      s,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("failed to start DNS server: %v", err)
		}
	}()
	log.Printf("DNS server is running on %s\n", DNSServerAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down DNS server...")
	server.Shutdown()

}

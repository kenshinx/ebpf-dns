package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	progPath   = "./ebpf_dns.o"
	progName   = "ebpf_dns"
	iface_name = "eth0"
)

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	spec, err := ebpf.LoadCollectionSpec(progPath)
	if err != nil {
		log.Fatalf("Error loading eBPF program: %v", err)
	}

	fmt.Println("sepc.Programs: %s", spec.Programs["ebpf_dns"])
	fmt.Println("sepc.Maps: %s", spec.Maps["ncache_map"])

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Error creating eBPF collection: %v", err)
	}

	defer coll.Close()

	fmt.Println("collection: %s", coll)
	for name := range coll.Programs {
		fmt.Printf("Program in collection: %s", name)
	}
	xdpProg := coll.Programs[progName]
	fmt.Println(xdpProg)
	/*
		var objs ebpf_dnsObjects
		if err := loadEbpf_dnsObjects(&objs, nil); err != nil {
			log.Fatal("Loading eBPF objects:", err)
		}
		defer objs.Close()

	*/
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

	/*
		cacheMap := collection.Maps[mapName]
		if cacheMap == nil {
			log.Fatalf("Map not found in collection")
		}
	*/

	log.Println("eBPF DNS server is running...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("Checking cache...")
			// Here, you can add code to manage the cache, e.g., evicting old entries

		case s := <-sig:
			log.Printf("Received signal %v, exiting...", s)
			return
		}
	}
}

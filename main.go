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
	/*
		for name, prog := range spec.Programs {
			log.Printf("Program name: %s, Type: %v", name, prog.Type)
		}
	*/

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Error creating eBPF collection: %v", err)
	}

	defer coll.Close()

	/*
		for name := range coll.Programs {
			fmt.Printf("Program in collection: %s", name)
		}
	*/
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

	log.Println("eBPF DNS server is running...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(60 * time.Second)
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

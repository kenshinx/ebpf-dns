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

	if err := loadXDPProgram(); err != nil {
		log.Fatalf("Error load and attach eBPF program: %v", err)
		return
	}

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

func loadXDPProgram() (err error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(progPath)
	if err != nil {
		log.Fatalf("Error loading eBPF program: %v", err)
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Error creating eBPF collection: %v", err)
		return err
	}

	defer coll.Close()

	xdpProg := coll.Programs[progName]

	iface, err := net.InterfaceByName(iface_name)
	if err != nil {
		log.Fatalf("Error getting interface: %v", err)
		return err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Error attaching XDP program: %v", err)
		return err
	}
	defer l.Close()

	return nil

}

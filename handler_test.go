package main

import (
	"bytes"
	"testing"
)

func TestDomainToDNSBytes(t *testing.T) {
	h := &DNSHandler{}
	want := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	t.Run("with trailing dot", func(t *testing.T) {
		got := h.domainToDNSBytes("www.example.com.")
		if !bytes.Equal(got, want) {
			t.Fatalf("domainToDNSBytes with trailing dot got %v, want %v", got, want)
		}
	})

	t.Run("without trailing dot", func(t *testing.T) {
		got := h.domainToDNSBytes("www.example.com")
		if !bytes.Equal(got, want) {
			t.Fatalf("domainToDNSBytes without trailing dot got %v, want %v", got, want)
		}
	})
}

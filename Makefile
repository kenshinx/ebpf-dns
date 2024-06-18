CC = clang
BPFCC = $(CC) -target bpf
LLC = llc

OPT = -O2
WARN = -Wall -Werror
DEBUG = -g

BPF_PROG = ebpf_dns
BPF_OBJ = $(BPF_PROG).o

LIBBPF_INCLUDE ?= /usr/include/bpf


BPF_CFLAGS ?= $(WARN) $(OPT) $(DEBUG) $(CFLAGS)
BPF_CFLAGS += -I$(LIBBPF_INCLUDE)


all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_PROG).c
	$(BPFCC) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -rf $(BPF_OBJ)

test:
	@echo $(BPFCC) $(BPF_CFLAGS) -c $< -o $@


.PHONY: all clean


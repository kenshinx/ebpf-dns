CC = clang
BPFCC = $(CC) -target bpf
LLC = llc

OPT = -O2
WARN = -Wall -Werror
DEBUG = -g

BPF_PROG = ebpf_dns
BPF_OBJ = $(BPF_PROG).o

LIBBPF_INCLUDE ?= /usr/include/bpf

BPF_DEBUG ?= $(BPF_DEBUG_OPEN)

BPF_CFLAGS ?= $(WARN) $(OPT) $(DEBUG) $(BPF_DEBUG) $(CFLAGS) 
BPF_CFLAGS += -I$(LIBBPF_INCLUDE)


all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_PROG).c
	$(BPFCC) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(BPF_PROG)

test:
	@echo $(BPFCC) $(BPF_CFLAGS) -c $< -o $@

debug:
	$(MAKE) BPF_DEBUG_OPEN="-DBPF_DEBUG"

go:
	$(MAKE) debug && go build -o $(BPF_PROG) main.go

.PHONY: all clean


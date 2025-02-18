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


bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_PROG).c
	$(BPFCC) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(BPF_PROG)

test:
	@echo $(BPFCC) $(BPF_CFLAGS) -c $< -o $@

debug:
	$(MAKE) BPF_DEBUG_OPEN="-DBPF_DEBUG"

go:
	go build -o $(BPF_PROG)

all:
	$(MAKE) clean && $(MAKE) && go build -o $(BPF_PROG)

.PHONY: all clean debug


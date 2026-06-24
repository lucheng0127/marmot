# BPF program Makefile
# Compiles .c files to .o BPF bytecode using clang

CLANG   ?= clang
CFLAGS  ?= -target bpf -g -O2 -Wall -Werror
INCLUDES = -I.

BPF_SRCS := $(wildcard *.c)
BPF_OBJS := $(BPF_SRCS:.c=.o)

.PHONY: all clean

all: $(BPF_OBJS)

%.o: %.c
	@echo "  BPF $@"
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.o

verify: $(BPF_OBJS)
	@for obj in $(BPF_OBJS); do \
		echo "Checking $$obj..."; \
		llvm-objdump -h $$obj 2>/dev/null | grep -E "^(  [0-9]|.*tc|.*maps|.*license)" || true; \
	done

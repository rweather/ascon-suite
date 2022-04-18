
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_riscv32e \
	bin/ascon_riscv32i \
	bin/ascon_riscv64

all: $(TARGETS)

bin/ascon_riscv32e: ascon_riscv32.c ../common/copyright.h
	@mkdir -p bin
	$(CC) -DRV32E $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/ascon_riscv32i: ascon_riscv32.c ../common/copyright.h
	@mkdir -p bin
	$(CC) -DRV32I $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/ascon_riscv64: ascon_riscv64.c ../common/copyright.h
	@mkdir -p bin
	$(CC) -DRV64I $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/ascon_riscv32e >../../src/core/ascon-asm-riscv32e.S
	bin/ascon_riscv32i >../../src/core/ascon-asm-riscv32i.S
	bin/ascon_riscv64 >../../src/core/ascon-asm-riscv64i.S

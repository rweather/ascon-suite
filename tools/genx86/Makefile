
include ../../rules/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I..
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_x86_64

all: $(TARGETS)

bin/ascon_x86_64: ascon_x86_64.c ../copyright.h
	@mkdir -p bin
	$(CC) -DFORCE_ARM_MODE $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/ascon_x86_64  >../../src/core/ascon-asm-x86-64.S

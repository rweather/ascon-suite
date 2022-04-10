
include ../../rules/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I..
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_xtensa

all: $(TARGETS)

bin/ascon_xtensa: ascon_xtensa.c ../copyright.h
	@mkdir -p bin
	$(CC) -DFORCE_ARM_MODE $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/ascon_xtensa >../../src/core/ascon-asm-xtensa.S

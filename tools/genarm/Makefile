
include ../../rules/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I..
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_armv7m

all: $(TARGETS)

bin/ascon_armv7m: ascon_armv7m.c ../copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/ascon_armv7m >../../src/ascon-permutation-armv7-asm.S


include ../../rules/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I..
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_armv6m \
	bin/ascon_armv7m

all: $(TARGETS)

bin/ascon_armv6m: ascon_armv6m.c ../copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/ascon_armv7m: ascon_armv7m.c ../copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/ascon_armv6m >../../src/ascon-permutation-armv6m-asm.S
	bin/ascon_armv7m >../../src/ascon-permutation-armv7m-asm.S

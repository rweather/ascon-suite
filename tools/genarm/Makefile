
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_armv6 \
	bin/ascon_armv6m \
	bin/ascon_armv7m \
	bin/ascon_armv8a_64

all: $(TARGETS)

bin/ascon_armv6: ascon_armv7m.c ../common/copyright.h
	@mkdir -p bin
	$(CC) -DFORCE_ARM_MODE $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/ascon_armv6m: ascon_armv6m.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/ascon_armv7m: ascon_armv7m.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/ascon_armv8a_64: ascon_armv8a_64.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/ascon_armv6  >../../src/core/ascon-asm-armv6.S
	bin/ascon_armv6m >../../src/core/ascon-asm-armv6m.S
	bin/ascon_armv7m >../../src/core/ascon-asm-armv7m.S
	bin/ascon_armv8a_64 >../../src/core/ascon-asm-armv8a-64.S

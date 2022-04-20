
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_xtensa_32 \
	bin/ascon_xtensa_64

all: $(TARGETS)

bin/ascon_xtensa_32: ascon_xtensa_32.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/ascon_xtensa_64: ascon_xtensa_64.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

# The 64-bit host word order version is slightly faster than the
# 32-bit bit-sliced implementation on Xtensa.  The funnel shift
# instruction "src" makes it possible to do efficient 64-bit rotates.
generate: all
	bin/ascon_xtensa_64 >../../src/core/ascon-asm-xtensa.S

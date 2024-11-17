
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common -I../../src/core
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/geninit

all: $(TARGETS)

bin/geninit: geninit.c ../common/copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all

.PHONY: iv-ascon-hash iv-ascon-xof

iv-ascon-hash: all
	@bin/geninit 02 00 cc 00 01 08 00 00

iv-ascon-xof: all
	@bin/geninit 03 00 cc 00 00 08 00 00

iv-ascon-cxof: all
	@bin/geninit 04 00 cc 00 00 08 00 00

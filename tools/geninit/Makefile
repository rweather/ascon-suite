
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

.PHONY: iv-ascon-hash iv-ascon-hasha iv-ascon-xof iv-ascon-xofa

iv-ascon-hash: all
	@bin/geninit 00 40 0c 00 00 00 01 00

iv-ascon-hasha: all
	@bin/geninit 00 40 0c 04 00 00 01 00

iv-ascon-xof: all
	@bin/geninit 00 40 0c 00 00 00 00 00

iv-ascon-xofa: all
	@bin/geninit 00 40 0c 04 00 00 00 00

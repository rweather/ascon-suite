
include ../common/options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../common
LDFLAGS += $(COMMON_LDFLAGS)

COMMON_DEPS = \
	../common/copyright.h \
	../common/reg_alloc.h \
	../common/reg_alloc.c \
	x86_common.h \
	x86_common.c

COMMON_SRCS = \
	../common/reg_alloc.c \
	x86_common.c

TARGETS = \
	bin/ascon_i386 \
	bin/ascon_x86_64 \
	bin/ascon_x86_64_masked \
	bin/ascon_x86_64_masked_word

all: $(TARGETS)

bin/ascon_i386: ascon_i386.c $(COMMON_DEPS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_SRCS) $(LDFLAGS)

bin/ascon_x86_64: ascon_x86_64.c $(COMMON_DEPS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_SRCS) $(LDFLAGS)

bin/ascon_x86_64_masked: ascon_x86_64_masked.c $(COMMON_DEPS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_SRCS) $(LDFLAGS)

bin/ascon_x86_64_masked_word: ascon_x86_64_masked_word.c $(COMMON_DEPS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_SRCS) $(LDFLAGS)

clean:
	rm -rf $(TARGETS) bin

check:

generate: all
	bin/ascon_i386  >../../src/core/ascon-asm-i386.S
	bin/ascon_x86_64  >../../src/core/ascon-asm-x86-64.S
	bin/ascon_x86_64_masked 2  >../../src/masking/ascon-x2-asm-x86-64.S
	bin/ascon_x86_64_masked 3  >../../src/masking/ascon-x3-asm-x86-64.S
	bin/ascon_x86_64_masked 4  >../../src/masking/ascon-x4-asm-x86-64.S
	bin/ascon_x86_64_masked_word  >../../src/masking/ascon-word-asm-x86-64.S

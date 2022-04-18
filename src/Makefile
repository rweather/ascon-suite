
include ../rules/options.mak

.PHONY: all clean check

INCLUDE_DIR = ../include

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)
CFLAGS += -I$(INCLUDE_DIR) -I. -Icore

LIBRARY = obj/libascon.a

C_SOURCES = \
	aead/ascon-aead-128.c \
	aead/ascon-aead-128a.c \
	aead/ascon-aead-80pq.c \
	aead/ascon-aead-common.c \
	core/ascon-c32.c \
	core/ascon-c64.c \
	core/ascon-clean.c \
	core/ascon-direct-xor.c \
	core/ascon-sliced32.c \
	core/ascon-sliced64.c \
	hash/ascon-hasha.c \
	hash/ascon-hash.c \
	hash/ascon-xofa.c \
	hash/ascon-xof.c \
	isap/ascon-isap-128.c \
	isap/ascon-isap-128a.c \
	mac/ascon-hmac.c \
	mac/ascon-hmaca.c \
	mac/ascon-kmac.c \
	mac/ascon-kmaca.c \
	siv/ascon-siv-128.c \
	siv/ascon-siv-128a.c \
	siv/ascon-siv-80pq.c
ASM_SOURCES = \
	core/ascon-asm-armv6m.S \
	core/ascon-asm-armv7m.S \
	core/ascon-asm-armv6.S \
	core/ascon-asm-armv8a-64.S \
	core/ascon-asm-avr5.S \
	core/ascon-asm-i386.S \
	core/ascon-asm-m68k.S \
	core/ascon-asm-riscv32e.S \
	core/ascon-asm-riscv32i.S \
	core/ascon-asm-riscv64i.S \
	core/ascon-asm-x86-64.S \
	core/ascon-asm-xtensa.S

OBJECTS  = $(patsubst %.c,obj/%.o,$(C_SOURCES))
OBJECTS += $(patsubst %.S,obj/%.o,$(ASM_SOURCES))
DEPS     = $(patsubst %.c,obj/%.o.d,$(C_SOURCES))
DEPS    += $(patsubst %.S,obj/%.o.d,$(ASM_SOURCES))

all: $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	rm -f $(LIBRARY)
	@mkdir -p `dirname $@`
	$(AR) rc $(LIBRARY) $(OBJECTS)

clean:
	rm -f $(OBJECTS) $(DEPS) $(LIBRARY)

obj/%.o: %.c
	@mkdir -p `dirname $@`
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<
	@$(CC) -MM $(CPPFLAGS) $(CFLAGS) $< >$@.d
	@mv -f $@.d $@.d.tmp
	@sed -e 's|.*:|$@:|' < $@.d.tmp > $@.d
	@sed -e 's/.*://' -e 's/\\$$//' < $@.d.tmp | fmt -1 | \
            sed -e 's/^ *//' -e 's/$$/:/' >> $@.d
	@rm -f $@.d.tmp

obj/%.o: %.S
	@mkdir -p `dirname $@`
	$(CC) -x assembler-with-cpp $(CPPFLAGS) $(CFLAGS) -o $@ -c $<
	@$(CC) -MM -x assembler-with-cpp $(CPPFLAGS) $(CFLAGS) $< >$@.d
	@mv -f $@.d $@.d.tmp
	@sed -e 's|.*:|$@:|' < $@.d.tmp > $@.d
	@sed -e 's/.*://' -e 's/\\$$//' < $@.d.tmp | fmt -1 | \
            sed -e 's/^ *//' -e 's/$$/:/' >> $@.d
	@rm -f $@.d.tmp

check:

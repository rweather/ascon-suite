
include ../rules/options.mak

.PHONY: all clean check arduino

INCLUDE_DIR = ../include

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)
CFLAGS += -I$(INCLUDE_DIR) -I. -Icore

LIBRARY = obj/libascon.a

MAIN_C_SOURCES = \
	aead/ascon-aead-128.c \
	aead/ascon-aead-128a.c \
	aead/ascon-aead-80pq.c \
	hash/ascon-hasha.c \
	hash/ascon-hash.c \
	hash/ascon-xofa.c \
	hash/ascon-xof.c \
	siv/ascon-siv-128.c \
	siv/ascon-siv-128a.c \
	siv/ascon-siv-80pq.c
UTIL_C_SOURCES = \
	core/ascon-c32.c \
	core/ascon-c64.c \
	core/ascon-direct-xor.c \
	core/ascon-sliced32.c \
	core/ascon-sliced64.c \
	core/ascon-util.c \
	aead/ascon-aead-common.c
UTIL_ASM_EMBEDDED_SOURCES = \
	core/ascon-asm-armv6m.S \
	core/ascon-asm-armv7m.S \
	core/ascon-asm-avr5.S \
	core/ascon-asm-xtensa.S
UTIL_ASM_DESKTOP_SOURCES = \
	core/ascon-asm-armv6.S \
	core/ascon-asm-armv8a-64.S
UTIL_INCLUDES = \
	core/ascon-sliced32.h \
	core/ascon-util.h \
	core/ascon-util-snp.h \
	aead/ascon-aead-common.h
ALL_INCLUDES = \
	core/ascon-select-backend.h \
	$(UTIL_INCLUDES)

C_SOURCES = $(MAIN_C_SOURCES) $(UTIL_C_SOURCES)
ASM_SOURCES = $(UTIL_ASM_EMBEDDED_SOURCES) $(UTIL_ASM_DESKTOP_SOURCES)

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

# The 'arduino' rule create the Arduino version of the source code
# under the directory "../ASCON" from the top-level.  The code is
# modified to comply with Arduino IDE conventions for libraries.

ARDUINO_SRCDIR = ../../ASCON/src
ARDUINO_COPY_SOURCES = ../tools/arduino/copy-sources.sh
ARDUINO_COPY_INCLUDES = ../tools/arduino/copy-includes.sh
ARDUINO_COPY_UTILS = ../tools/arduino/copy-utils.sh

UTIL_SOURCES = $(UTIL_C_SOURCES) $(UTIL_ASM_EMBEDDED_SOURCES)
MAIN_SOURCES = $(MAIN_C_SOURCES)

arduino:
	$(SHELL) $(ARDUINO_COPY_SOURCES) $(ARDUINO_SRCDIR) $(MAIN_SOURCES)
	$(SHELL) $(ARDUINO_COPY_INCLUDES) $(ARDUINO_SRCDIR) ../include/ascon/*.h
	$(SHELL) $(ARDUINO_COPY_UTILS) $(ARDUINO_SRCDIR)/utility $(UTIL_SOURCES) $(UTIL_INCLUDES)

-include $(DEPS)

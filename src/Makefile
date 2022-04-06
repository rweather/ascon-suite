
include ../rules/options.mak

.PHONY: all clean check

INCLUDE_DIR = ../include

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)
CFLAGS += -I$(INCLUDE_DIR) -I.

LIBRARY = obj/libascon.a

C_SOURCES = \
	ascon-permutation-avr-api.c \
	ascon-permutation-c32.c \
	ascon-permutation-c64.c \
	ascon-permutation-sliced32.c
ASM_SOURCES = \
	ascon-permutation-armv6m-asm.S \
	ascon-permutation-armv7m-asm.S \
	ascon-permutation-avr-asm.S

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

-include $(DEPS)

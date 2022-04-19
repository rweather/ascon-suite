
TOPDIR = ../../..

include $(TOPDIR)/rules/options.mak

.PHONY: all clean

ASCONLIB = $(TOPDIR)/src/obj/libascon.a

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)
CFLAGS += -I$(TOPDIR)/include

LDFLAGS += $(COMMON_LDFLAGS)
LDFLAGS += -L$(TOPDIR)/src/obj -lascon

TARGET = obj/encrypt

SOURCES = main.c

OBJECTS  = $(patsubst %.c,obj/%.o,$(SOURCES))
DEPS     = $(patsubst %.o,%.o.d,$(OBJECTS))

all: $(TARGET)

$(TARGET): $(OBJECTS) $(ASCONLIB)
	@mkdir -p `dirname $@`
	$(CC) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(OBJECTS) $(DEPS) $(TARGET)

obj/%.o: %.c
	@mkdir -p `dirname $@`
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<
	@$(CC) -MM $(CPPFLAGS) $(CFLAGS) $< >$@.d
	@mv -f $@.d $@.d.tmp
	@sed -e 's|.*:|$@:|' < $@.d.tmp > $@.d
	@sed -e 's/.*://' -e 's/\\$$//' < $@.d.tmp | fmt -1 | \
            sed -e 's/^ *//' -e 's/$$/:/' >> $@.d
	@rm -f $@.d.tmp

-include $(DEPS)

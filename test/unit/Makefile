
include ../../rules/options.mak

.PHONY: all clean check

ASCONLIB = ../../src/obj/libascon.a

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)
CFLAGS += -I../../include

LDFLAGS += $(COMMON_LDFLAGS)
LDFLAGS += -L../../src/obj -lascon

TARGET = obj/unit-tests

SOURCES = \
	test-permutation.c \
	test-cipher.c \
	test-main.c

OBJECTS  = $(patsubst %.c,obj/%.o,$(SOURCES))
DEPS     = $(patsubst %.o,%.o.d,$(OBJECTS))

all: $(TARGET)

$(TARGET): $(OBJECTS) $(ASCONLIB)
	@mkdir -p `dirname $@`
	$(CXX) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(OBJECTS) $(DEPS) $(TARGET)

check: $(TARGET)
	./$(TARGET)

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

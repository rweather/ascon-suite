
include ../common/options.mak

.PHONY: all clean check generate

CXXFLAGS += -g $(COMMON_CFLAGS) $(STDC_CXXFLAGS) -I../common

TARGET = genavr

OBJS = \
	algorithm_ascon.o \
	code.o \
	code_out.o \
	interpret.o \
        main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

check: all
	./$(TARGET) --test

code.o: code.h
code_out.o: code.h
algorithm_ascon.o: code.h gen.h
interpret.o: code.h

generate: $(TARGET)
	./$(TARGET) ASCON >../../src/core/ascon-asm-avr5.S

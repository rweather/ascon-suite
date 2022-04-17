
include ../../rules/options.mak

LIBSRC_DIR = ../../src

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)/aead -I$(LIBSRC_DIR)/core -I../../include
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR)/obj -lascon

TARGET1 = kat
TARGET2 = kat-gen

OBJS1 = \
    kat.o \
    algorithms.o \
    timing.o \
    internal-chachapoly.o \
    internal-blake2s.o

OBJS2 = \
    kat-gen.o \
    algorithms.o

DEPS = $(LIBSRC_DIR)/obj/libascon.a

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

$(TARGET2): $(OBJS2) $(DEPS)
	$(CC) -o $(TARGET2) $(OBJS2) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

RUN_KAT = $(SHELL) ./kat-run.sh ./$(TARGET1) ./$(TARGET2)

check: $(TARGET1) $(TARGET2)
	@$(RUN_KAT) ASCON-128 ASCON-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128a ASCON-128a.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-80pq ASCON-80pq.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-HASH ASCON-HASH.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-HASHA ASCON-HASHA.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-XOF ASCON-XOF.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-XOFA ASCON-XOFA.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-XOF-fixed-length ASCON-HASH.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-XOFA-fixed-length ASCON-HASHA.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128-SIV ASCON-128-SIV.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128a-SIV ASCON-128a-SIV.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-80pq-SIV ASCON-80pq-SIV.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-A-128 ISAP-A-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-A-128A ISAP-A-128A.txt $(KAT_OPTIONS)

perf:
	@$(MAKE) check KAT_OPTIONS=--performance

kat.o: algorithms.h timing.h $(wildcard $(LIBSRC_DIR)/*.h)
kat-gen.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
algorithms.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
timing.o: timing.h $(wildcard $(LIBSRC_DIR)/*.h)

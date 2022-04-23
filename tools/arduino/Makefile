
.PHONY: all clean check arduino generate

TOP_DIR = ../..
INCLUDE_DIR = $(TOP_DIR)/include
SOURCE_DIR = $(TOP_DIR)/src
ARDUINO_SRCDIR = ../../../ascon-arduino/src

# Source files to copy to the main Arduino src directory.
MAIN_SOURCES = \
	$(SOURCE_DIR)/aead/ascon-aead-128.c \
	$(SOURCE_DIR)/aead/ascon-aead-128a.c \
	$(SOURCE_DIR)/aead/ascon-aead-80pq.c \
	$(SOURCE_DIR)/aead/ascon-aead-inc-128.c \
	$(SOURCE_DIR)/aead/ascon-aead-inc-128a.c \
	$(SOURCE_DIR)/aead/ascon-aead-inc-80pq.c \
	$(SOURCE_DIR)/hash/ascon-hasha.c \
	$(SOURCE_DIR)/hash/ascon-hash.c \
	$(SOURCE_DIR)/hash/ascon-xofa.c \
	$(SOURCE_DIR)/hash/ascon-xof.c \
	$(SOURCE_DIR)/isap/ascon-isap-128.c \
	$(SOURCE_DIR)/isap/ascon-isap-128a.c \
	$(SOURCE_DIR)/kdf/ascon-hkdf.c \
	$(SOURCE_DIR)/kdf/ascon-hkdfa.c \
	$(SOURCE_DIR)/kdf/ascon-pbkdf2.c \
	$(SOURCE_DIR)/mac/ascon-hmac.c \
	$(SOURCE_DIR)/mac/ascon-hmaca.c \
	$(SOURCE_DIR)/mac/ascon-kmac.c \
	$(SOURCE_DIR)/mac/ascon-kmaca.c \
	$(SOURCE_DIR)/random/ascon-prng.c \
	$(SOURCE_DIR)/random/ascon-random.c \
	$(SOURCE_DIR)/siv/ascon-siv-128.c \
	$(SOURCE_DIR)/siv/ascon-siv-128a.c \
	$(SOURCE_DIR)/siv/ascon-siv-80pq.c

# Source files to copy to the Arduino src/utility directory.
# We copy a subset of the backends, as it is unlikely that an
# Arduino will be running on an x86-64 system any time soon!
UTIL_SOURCES = \
	$(SOURCE_DIR)/aead/ascon-aead-common.c \
	$(SOURCE_DIR)/core/ascon-asm-armv6m.S \
	$(SOURCE_DIR)/core/ascon-asm-armv7m.S \
	$(SOURCE_DIR)/core/ascon-asm-avr5.S \
	$(SOURCE_DIR)/core/ascon-asm-xtensa.S \
	$(SOURCE_DIR)/core/ascon-c32.c \
	$(SOURCE_DIR)/core/ascon-c64.c \
	$(SOURCE_DIR)/core/ascon-clean.c \
	$(SOURCE_DIR)/core/ascon-direct-xor.c \
	$(SOURCE_DIR)/core/ascon-sliced32.c \
	$(SOURCE_DIR)/core/ascon-sliced64.c \
	$(SOURCE_DIR)/core/ascon-version.c \
	$(SOURCE_DIR)/random/ascon-trng-due.c \
	$(SOURCE_DIR)/random/ascon-trng-esp.c \
	$(SOURCE_DIR)/random/ascon-trng-none.c

UTIL_INCLUDES = \
	$(SOURCE_DIR)/core/ascon-sliced32.h \
	$(SOURCE_DIR)/core/ascon-util.h \
	$(SOURCE_DIR)/core/ascon-util-snp.h \
	$(SOURCE_DIR)/aead/ascon-aead-common.h \
	$(SOURCE_DIR)/isap/ascon-isap-common.h \
	$(SOURCE_DIR)/kdf/ascon-hkdf-common.h \
	$(SOURCE_DIR)/mac/ascon-hmac-common.h \
	$(SOURCE_DIR)/mac/ascon-kmac-common.h \
	$(SOURCE_DIR)/random/ascon-trng.h

all:

# The 'arduino' rule creates the Arduino version of the source code
# under the directory "../ascon-arduino" from the top-level.  The code is
# modified to comply with Arduino IDE conventions for libraries.

ARDUINO_COPY_SOURCES = ./copy-sources.sh
ARDUINO_COPY_INCLUDES = ./copy-includes.sh
ARDUINO_COPY_UTILS = ./copy-utils.sh
ARDUINO_COPY_VERSION_H = ./copy-version-h.sh

arduino:
	$(SHELL) $(ARDUINO_COPY_SOURCES) $(ARDUINO_SRCDIR) $(MAIN_SOURCES)
	$(SHELL) $(ARDUINO_COPY_INCLUDES) $(ARDUINO_SRCDIR) $(INCLUDE_DIR)/ascon/*.h
	$(SHELL) $(ARDUINO_COPY_UTILS) $(ARDUINO_SRCDIR)/utility $(UTIL_SOURCES) $(UTIL_INCLUDES)
	$(SHELL) $(ARDUINO_COPY_VERSION_H) $(ARDUINO_SRCDIR)/ascon-version.h $(INCLUDE_DIR)/ascon/version.h.in $(TOP_DIR)/CMakeLists.txt

generate: arduino

clean:

check:

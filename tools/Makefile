
.PHONY: all clean generate check arduino

SUBDIRS = \
	genarm \
	genavr \
	genm68k \
	genx86 \
	genxtensa

all:
	for dir in $(SUBDIRS) ; do (cd $$dir ; $(MAKE) all) ; done

clean:
	for dir in $(SUBDIRS) ; do (cd $$dir ; $(MAKE) clean) ; done

generate:
	for dir in $(SUBDIRS) ; do (cd $$dir ; $(MAKE) generate) ; done

check:

arduino:
	(cd arduino; $(MAKE) arduino)

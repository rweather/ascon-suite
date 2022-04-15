
.PHONY: all clean check arduino

all:
	(cd src; $(MAKE) all)
	(cd test; $(MAKE) all)

clean:
	(cd src; $(MAKE) clean)
	(cd test; $(MAKE) clean)
	(cd tools; $(MAKE) clean)

check: all
	(cd src; $(MAKE) check)
	(cd test; $(MAKE) check)

arduino:
	(cd tools; $(MAKE) arduino)

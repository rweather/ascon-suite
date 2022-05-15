
.PHONY: all

all: test-nopic.s test-pic.s test-predefined.h

test-nopic.s: test.c
	$(CC) $(CFLAGS) -S -c test.c -o test-nopic.s

test-pic.s: test.c
	$(CC) $(CFLAGS) -fPIC -S -c test.c -o test-pic.s

test-predefined.h:
	$(CC) $(CFLAGS) -dM -E - </dev/null >test-predefined.h

clean:
	rm -f test-nopic.s test-pic.s test-predefined.h

CFLAGS=-march=native -Ofast -Wall -W -Wshadow -Wmissing-prototypes

all: dsvpn

dsvpn: src/dsvpn.c src/charm.c include/charm.h include/dsvpn.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/dsvpn.c src/charm.c
	strip $@

clean:
	rm -f dsvpn *~

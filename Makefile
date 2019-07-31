CFLAGS?=-march=native -Ofast -Wall -W -Wshadow -Wmissing-prototypes $(OPTFLAGS)
PREFIX?=/usr/local

all: dsvpn

dsvpn: Makefile src/vpn.c src/charm.c src/os.c include/charm.h include/vpn.h include/os.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/vpn.c src/charm.c src/os.c

install: dsvpn
	install -s -m 0755 dsvpn $(PREFIX)/sbin

uninstall:
	rm $(PREFIX)/sbin/dsvpn

clean:
	rm -f dsvpn *~

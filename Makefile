CFLAGS?=-march=native -Ofast -fno-stack-check -Wall -W -Wshadow -Wmissing-prototypes $(OPTFLAGS)
PREFIX?=/usr/local

all: dsvpn

dsvpn: Makefile src/vpn.c src/charm.c src/os.c include/charm.h include/vpn.h include/os.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/vpn.c src/charm.c src/os.c
	strip $@

install: dsvpn
	install -m 0755 dsvpn $(PREFIX)/sbin

uninstall:
	rm $(PREFIX)/sbin/dsvpn

clean:
	rm -f dsvpn *~

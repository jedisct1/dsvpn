CFLAGS?=-march=native -Ofast -Wall -W -Wshadow -Wmissing-prototypes $(OPTFLAGS)

all: dsvpn

dsvpn: Makefile src/vpn.c src/charm.c src/os.c include/charm.h include/vpn.h include/os.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/vpn.c src/charm.c src/os.c
	strip $@

clean:
	rm -f dsvpn *~

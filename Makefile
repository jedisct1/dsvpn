CFLAGS=-march=native -Ofast -Wall -W -Wshadow -Wmissing-prototypes

all: dsvpn

dsvpn: src/dsvpn.c src/charm.c src/os.c include/charm.h include/dsvpn.h include/os.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/dsvpn.c src/charm.c src/os.c
	strip $@

clean:
	rm -f dsvpn *~

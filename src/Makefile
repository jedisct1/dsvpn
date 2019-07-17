CFLAGS=-march=native -Ofast -Wall -W -Wshadow -Wmissing-prototypes

all: dsvpn

dsvpn: dsvpn.c charm.c
	$(CC) $(CFLAGS) -o $@ $^
	strip $@

clean:
	rm -f dsvpn *~

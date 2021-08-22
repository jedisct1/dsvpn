CFLAGS_FILE?=.cflags
COMPILE_TEST_FILE?=.test.c
PREFIX?=/usr/local

all: dsvpn

dsvpn: $(CFLAGS_FILE) Makefile src/vpn.c src/charm.c src/os.c include/charm.h include/vpn.h include/os.h
	$(CC) $$(cat "$(CFLAGS_FILE)") $(OPTFLAGS) -Iinclude -o $@ src/vpn.c src/charm.c src/os.c
	strip $@

install: dsvpn
	install -d $(PREFIX)/sbin
	install -m 0755 dsvpn $(PREFIX)/sbin

uninstall:
	rm -f $(PREFIX)/sbin/dsvpn

clean:
	rm -f dsvpn *~ $(CFLAGS_FILE) $(COMPILE_TEST_FILE)

$(CFLAGS_FILE):
	@CFLAGS="$(CFLAGS)"
	@if [ -z "$$CFLAGS" ]; then \
		if [ ! -r "$(CFLAGS_FILE)" ]; then \
			echo "int main(void) { return 0; }" > "$(COMPILE_TEST_FILE)"; \
			for flag in -march=native -mtune=native -Ofast -Wno-unused-command-line-argument; do \
				$(CC) $${CFLAGS} $${flag} "$(COMPILE_TEST_FILE)" >/dev/null 2>&1 && CFLAGS="$$CFLAGS $$flag"; \
			done; \
			rm -f a.out \
			CFLAGS="$${CFLAGS} -Wall -W -Wshadow -Wmissing-prototypes"; \
		fi \
	fi; \
	echo "$$CFLAGS" > "$(CFLAGS_FILE)"

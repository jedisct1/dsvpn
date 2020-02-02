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
			for flag in -march=native -mcpu=native -Ofast -Wno-unused-command-line-argument; do \
				$(CC) $${CFLAGS} $${flag} "$(COMPILE_TEST_FILE)" >/dev/null 2>&1 && CFLAGS="$$CFLAGS $$flag"; \
			done; \
			CFLAGS="$${CFLAGS} -Wall -W -Wshadow -Wmissing-prototypes"; \
			echo "#include <unistd.h>\n#include <sys/syscall.h>\nint main(void) { char buf[32] = {0}; syscall(SYS_getrandom, buf, 32, 0); }" > "$(COMPILE_TEST_FILE)"; \
			if ! $(CC) "$(COMPILE_TEST_FILE)" >/dev/null 2>&1; then \
				arch=$$(uname -m); \
				case $$arch in \
	              aarch64) CFLAGS="$$CFLAGS -DSYS_getrandom=278";; \
				  x86_64) CFLAGS="$$CFLAGS -DSYS_getrandom=318";; \
				esac; \
			fi \
		fi \
	fi; \
	echo "$$CFLAGS" > "$(CFLAGS_FILE)"

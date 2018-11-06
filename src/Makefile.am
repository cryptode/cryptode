
AM_CFLAGS = $(JSONC_INCLUDES) $(OPENSSL_INCLUDES) $(NEREON_INCLUDES) -Wall -Wextra

if DARWIN
bin_PROGRAMS = cryptoded cryptode
else
bin_PROGRAMS = cryptode
sbin_PROGRAMS = cryptoded
endif

cryptoded_SOURCES = cryptoded.nos.c conf.nos.c cryptoded.c log.c cmd.c util.c vpn.c conf.c json.c
cryptoded_CFLAGS = -D_CRYPTODED_SOURCE
cryptoded_LDADD = $(CRYPTODED_LDADD)
cryptoded_LDFLAGS = $(JSONC_LDFLAGS) $(NEREON_LDFLAGS)

cryptode_SOURCES = conf.nos.c cryptode.nos.c cryptode.c coc_shared.c util.c conf.c json.c
cryptode_LDADD = $(CRYPTODE_LDADD)
cryptode_LDFLAGS = $(JSONC_LDFLAGS) $(OPENSSL_LDFLAGS) $(NEREON_LDFLAGS)

include_HEADERS = common.h cryptoded.h cmd.h log.h util.h vpn.h coc_shared.h conf.h json.h

cryptode.nos.c: cryptode.nos
	$(NEREON_TO_CC) cryptode.nos ./ cryptode

cryptoded.nos.c: cryptoded.nos
	$(NEREON_TO_CC) cryptoded.nos ./ cryptoded

conf.nos.c: conf.nos
	$(NEREON_TO_CC) conf.nos ./ vpnconf

clean-local:
	rm -rf cryptoded.nos.c cryptoded.nos.h
	rm -rf conf.nos.c conf.nos.h

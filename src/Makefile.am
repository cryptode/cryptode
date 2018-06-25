
AM_CFLAGS = $(JSONC_INCLUDES) $(OPENSSL_INCLUDES) $(NEREON_INCLUDES) -Wall -Wextra

if DARWIN
bin_PROGRAMS = rvd rvc
else
bin_PROGRAMS = rvc
sbin_PROGRAMS = rvd
endif

rvd_SOURCES = rvd.nos.c rvd.c log.c cmd.c util.c vpn.c conf.c json.c
rvd_CFLAGS = -D_RVD_SOURCE
rvd_LDADD = $(RVD_LDADD)
rvd_LDFLAGS = $(JSONC_LDFLAGS) $(NEREON_LDFLAGS)

rvc_SOURCES = rvc.c rvc_shared.c util.c conf.c json.c
rvc_LDADD = $(RVC_LDADD)
rvc_LDFLAGS = $(JSONC_LDFLAGS) $(OPENSSL_LDFLAGS)

include_HEADERS = common.h rvd.h cmd.h log.h util.h vpn.h rvc_shared.h conf.h json.h

rvd.nos.c: rvd.nos
	$(NEREON_TO_CC) rvd.nos ./

clean-local:
	rm -rf rvd.nos.c rvd.nos.h

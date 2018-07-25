
AM_CFLAGS = $(JSONC_INCLUDES) $(OPENSSL_INCLUDES) $(NEREON_INCLUDES) -Wall -Wextra

if DARWIN
bin_PROGRAMS = rvd rvc
else
bin_PROGRAMS = rvc
sbin_PROGRAMS = rvd
endif

rvd_SOURCES = rvd.nos.c conf.nos.c rvd.c log.c cmd.c util.c vpn.c conf.c json.c
rvd_CFLAGS = -D_RVD_SOURCE
rvd_LDADD = $(RVD_LDADD)
rvd_LDFLAGS = $(JSONC_LDFLAGS) $(NEREON_LDFLAGS)

rvc_SOURCES = conf.nos.c rvc.nos.c rvc.c rvc_shared.c util.c conf.c json.c
rvc_LDADD = $(RVC_LDADD)
rvc_LDFLAGS = $(JSONC_LDFLAGS) $(OPENSSL_LDFLAGS) $(NEREON_LDFLAGS)

include_HEADERS = common.h rvd.h cmd.h log.h util.h vpn.h rvc_shared.h conf.h json.h

rvc.nos.c: rvc.nos
	$(NEREON_TO_CC) rvc.nos ./ rvc

rvd.nos.c: rvd.nos
	$(NEREON_TO_CC) rvd.nos ./ rvd

conf.nos.c: conf.nos
	$(NEREON_TO_CC) conf.nos ./ vpnconf

clean-local:
	rm -rf rvd.nos.c rvd.nos.h
	rm -rf conf.nos.c conf.nos.h

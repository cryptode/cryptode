
AM_CFLAGS = $(JSONC_INCLUDES) $(OPENSSL_INCLUDES) -Wall -Wextra

if DARWIN
bin_PROGRAMS = rvd rvc
else
bin_PROGRAMS = rvc
sbin_PROGRAMS = rvd
endif

rvd_SOURCES = rvd.c log.c cmd.c util.c vpn.c conf.c
rvd_CFLAGS = -D_RVD_SOURCE
rvd_LDADD = $(RVD_LDADD)
rvd_LDFLAGS = $(JSONC_LDFLAGS)

rvc_SOURCES = rvc.c rvc_shared.c util.c conf.c
rvc_LDADD = $(RVC_LDADD)
rvc_LDFLAGS = $(JSONC_LDFLAGS) $(OPENSSL_LDFLAGS)

include_HEADERS = common.h rvd.h cmd.h log.h util.h vpn.h rvc_shared.h

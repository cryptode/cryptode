
AM_CFLAGS = $(JSONC_INCLUDES) $(OPENSSL_INCLUDES) -Wall -Wextra

sbin_PROGRAMS = rvd
bin_PROGRAMS = rvc

rvd_SOURCES = rvd.c log.c cmd.c util.c vpn.c
rvd_LDADD = $(RVD_LDADD)
rvd_LDFLAGS = $(JSONC_LDFLAGS)

rvc_SOURCES = rvc.c rvc_shared.c util.c
rvc_LDADD = $(RVC_LDADD)
rvc_LDFLAGS = $(JSONC_LDFLAGS) $(OPENSSL_LDFLAGS)

include_HEADERS = common.h rvd.h cmd.h log.h util.h vpn.h rvc_shared.h

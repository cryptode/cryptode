
AM_CFLAGS = $(JSONC_INCLUDES) $(OPENSSL_INCLUDES) -Wall -Wextra

bin_PROGRAMS = rvd rvc

rvd_SOURCES = rvd.c log.c cmd.c util.c vpn.c
rvd_LDADD = $(JSONC_LIBS)
rvd_LDFLAGS = $(JSONC_LDFLAGS)

rvc_SOURCES = rvc.c rvc_shared.c util.c
rvc_LDADD = $(JSONC_LIBS) $(OPENSSL_LIBS)
rvc_LDFLAGS = $(JSONC_LDFLAGS) $(OPENSSL_LDFLAGS)

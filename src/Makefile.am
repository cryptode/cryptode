
AM_CFLAGS = $(JSONC_INCLUDES) -Wall -Wextra

bin_PROGRAMS = rvcd rvc

rvcd_SOURCES = rvcd.c log.c cmd.c util.c vpn.c
rvcd_LDADD = $(JSONC_LIBS)
rvcd_LDFLAGS = $(JSONC_LDFLAGS)

rvc_SOURCES = rvcd_console.c
rvc_LDADD = $(JSONC_LIBS)
rvc_LDFLAGS = $(JSONC_LDFLAGS)

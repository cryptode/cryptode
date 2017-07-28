
AM_CFLAGS = $(JSONC_INCLUDES)

bin_PROGRAMS = rvcd rvcd_console

rvcd_SOURCES = rvcd.c log.c cmd.c util.c config.c vpn.c
rvcd_LDADD = $(JSONC_LIBS)
rvcd_LDFLAGS = $(JSONC_LDFLAGS)

rvcd_console_SOURCES = rvcd_console.c

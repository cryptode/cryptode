
AM_CFLAGS = $(JSONC_INCLUDES) -Wall -Wextra

dist_check_SCRIPTS = runtests.sh
noinst_PROGRAMS =
TESTS =

if ENABLE_TESTS
noinst_PROGRAMS += cryptoded_tests
cryptoded_tests_LDADD = $(CRYPTODED_LDADD)
cryptoded_tests_LDFLAGS = $(JSONC_LDFLAGS)
TESTS += $(dist_check_SCRIPTS)
endif

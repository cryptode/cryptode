
AM_CFLAGS = $(JSONC_INCLUDES) -Wall -Wextra

dist_check_SCRIPTS = runtests.sh
noinst_PROGRAMS =
TESTS =

if ENABLE_TESTS
noinst_PROGRAMS += rvd_tests
rvd_tests_LDADD = $(RVD_LDADD)
rvd_tests_LDFLAGS = $(JSONC_LDFLAGS)
TESTS += $(dist_check_SCRIPTS)
endif

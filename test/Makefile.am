
test_scripts = \
  basic.test \
  commandline.test \
  executables.test \
  import-export.test \
  invite-join.test \
  ns-ping.test \
  ping.test \
  sptps-basic.test \
  variables.test

TESTS = \
	basic.test \
	commandline.test \
	executables.test \
	import-export.test \
	invite-join.test \
	invite-offline.test \
	invite-tinc-up.test \
	ns-ping.test \
	ping.test \
	scripts.test \
	sptps-basic.test \
	variables.test

dist_check_SCRIPTS = $(TESTS)

EXTRA_DIST = testlib.sh

check_PROGRAMS = pong simple

pong_SOURCES = pong.c

simple_SOURCES = \
	simple.c

pong_LDFLAGS = -L$(top_srcdir)/src -ltinc

simple_CFLAGS =  -I$(top_srcdir)/src -I/usr/include -iquote$(top_srcdir)/src
simple_LDFLAGS = -L$(top_srcdir)/src -lcmocka -ltincd -lchacha_poly1305 -led25519


clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-killall pong
	-rm -rf *.test.?


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
	simple.c \
	../src/gcrypt/cipher.c1 \
	../src/gcrypt/crypto.c \
	../src/gcrypt/digest.c gcrypt/digest.h \
	../src/gcrypt/prf.c \
	../src/gcrypt/rsa.c

pong_LDFLAGS = -L$(top_srcdir)/src -ltinc

simple_CFLAGS =  -I$(top_srcdir)/src -I/usr/include -iquote$(top_srcdir)/src
simple_LDFLAGS = -L$(top_srcdir)/src -lcmocka -lreadline -pthread -lgcrypt -lm \
	../src/buffer.o ../src/conf.o ../src/connection.o ../src/control.o \
	../src/dropin.o ../src/dummy_device.o ../src/edge.o ../src/event.o \
	../src/fd_device.o ../src/graph.o ../src/hash.o ../src/ifconfig.o \
	../src/list.o ../src/logger.o ../src/meta.o ../src/multicast_device.o \
	../src/names.o ../src/net.o ../src/net_packet.o ../src/net_setup.o \
	../src/net_socket.o ../src/netutl.o ../src/node.o ../src/process.o \
	../src/protocol_auth.o ../src/protocol_edge.o ../src/protocol_key.o \
	../src/protocol_misc.o ../src/protocol.o ../src/protocol_subnet.o \
	../src/raw_socket_device.o ../src/route.o ../src/script.o \
	../src/slpd.o ../src/splay_tree.o ../src/sptps.o \
	../src/subnet.o ../src/subnet_parse.o \
	../src/utils.o ../src/version.o \
	../src/linux/device.o \
	../src/ed25519/add_scalar.o\
	../src/ed25519/ecdh.o\
	../src/ed25519/ecdsagen.o\
	../src/ed25519/ecdsa.o\
	../src/ed25519/fe.o\
	../src/ed25519/ge.o\
	../src/ed25519/key_exchange.o\
	../src/ed25519/keypair.o\
	../src/ed25519/sc.o\
	../src/ed25519/sha512.o\
	../src/ed25519/sign.o\
	../src/ed25519/verify.o\
	../src/chacha-poly1305/chacha.o ../src/chacha-poly1305/chacha-poly1305.o ../src/chacha-poly1305/poly1305.o

clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-killall pong
	-rm -rf *.test.?

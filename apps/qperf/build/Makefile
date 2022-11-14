ROOT_PATH=../../llvm14-ldb
CC=$(ROOT_PATH)/build/bin/clang
AR=$(ROOT_PATH)/build/bin/llvm-ar
RANLIB=/usr/bin/ranlib

LDBINIT = $(ROOT_PATH)/libldb/ldb_init.o

LDB_LDFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer
LDB_CCFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer -I$(ROOT_PATH)/libldb

quicly_src = frame.c cc-reno.c cc-cubic.c cc-pico.c defaults.c local_cid.c loss.c quicly.c \
						 ranges.c rate.c recvstate.c remote_cid.c retire_cid.c sendstate.c sentmap.c \
						 streambuf.c
quicly_obj = $(addprefix extern/quicly/CMakeFiles/quicly.dir/lib/, $(quicly_src:.c=.c.o))

picotls_src = openssl.c pembase64.c picotls.c
picotls_obj = $(addprefix extern/CMakeFiles/picotls.dir/quicly/deps/picotls/lib/, $(picotls_src:.c=.c.o))

qperf_src = main.c client.c client_stream.c server.c server_stream.c common.c
qperf_obj = $(addprefix CMakeFiles/qperf.dir/, $(qperf_src:.c=.c.o))

QUICLY_CCFLAGS = -I../extern/quicly/deps/klib -I../extern/quicly/deps/picotls/include \
								 -I../extern/quicly/deps/picotest -I../extern/quicly/include -Iextern/quicly \
								 -D_GNU_SOURCE -pthread -std=c99 -Wall -g -DQUICLY_USE_TRACER=1 -O2 -MD \

PICOTLS_CCFLAGS = -I../extern/quicly/deps/picotls/include -O2 -MD

QPERF_CCFLAGS = -DQPERF_VERSION=\"1.0.0.0\" -I../extern/quicly/include \
								-I../extern/quicly/deps/picotls/include -Werror=implicit-function-declaration \
								-Werror=incompatible-pointer-types -Werror=shift-count-overflow -O2 -MD

all: extern/quicly/quicly-tracer.h qperf

extern/quicly/quicly-tracer.h:
	../extern/quicly/misc/probe2trace.pl -a tracer < ../extern/quicly/quicly-probes.d > $@

qperf: $(qperf_obj) extern/quicly/libquicly.a extern/libpicotls.a $(LDBINIT)
	$(CC) $(qperf_obj) $(LDB_LDFLAGS) -o $@ $(LDBINIT) extern/quicly/libquicly.a \
		extern/libpicotls.a -lev -O2 -pthread -lm /usr/lib/x86_64-linux-gnu/libssl.so \
	 	/usr/lib/x86_64-linux-gnu/libcrypto.so

extern/quicly/libquicly.a: $(quicly_obj)
	$(AR) qc $@ $(quicly_obj)
	$(RANLIB) $@

extern/libpicotls.a: $(picotls_obj)
	$(AR) qc $@ $(picotls_obj)
	$(RANLIB) $@

extern/quicly/CMakeFiles/quicly.dir/lib/%.c.o: ../extern/quicly/lib/%.c
	$(CC) $(LDB_CCFLAGS) $(QUICLY_CCFLAGS) -MT $@ -MF $@.d -o $@ -c $<

extern/CMakeFiles/picotls.dir/quicly/deps/picotls/lib/%.c.o: ../extern/quicly/deps/picotls/lib/%.c
	$(CC) $(LDB_CCFLAGS) $(PICOTLS_CCFLAGS) -MT $@ -MF $@.d -o $@ -c $<

CMakeFiles/qperf.dir/%.c.o: ../%.c
	$(CC) $(LDB_CCFLAGS) $(QPERF_CCFLAGS) -MT $@ -MF $@.d -o $@ -c $<

clean:
	rm -f extern/quicly/libquicly.a extern/libpicotls.a $(quicly_obj) $(picotls_obj) $(qperf_obj) qperf

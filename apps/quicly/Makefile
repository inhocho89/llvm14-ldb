ROOT_PATH=../llvm14-ldb
CC=$(ROOT_PATH)/build/bin/clang
AR=$(ROOT_PATH)/build/bin/llvm-ar
RANLIB=/usr/bin/ranlib
#CC=/usr/bin/cc
#AR=/usr/bin/ar

LDBINIT = $(ROOT_PATH)/libldb/ldb_init.o

LDB_LDFLAGS = -g -fdebug-default-version=3 -fno-optimize-sibling-calls -fno-omit-frame-pointer
LDB_CCFLAGS = -g -fdebug-default-version=3 -fno-optimize-sibling-calls -fno-omit-frame-pointer -I$(ROOT_PATH)/libldb

QUICLY_FLAGS = -I./deps/klib -I./deps/picotls/include -I./quicly/deps/picotest -I./include \
							 -I./ -D_GNU_SOURCE -pthread -std=c99 -Wall -g -DQUICLY_USE_TRACER=1 -O2 -MD

quicly_src = frame.c cc-reno.c cc-cubic.c cc-pico.c defaults.c local_cid.c loss.c quicly.c ranges.c rate.c recvstate.c \
						 remote_cid.c retire_cid.c sendstate.c sentmap.c streambuf.c
quicly_obj = $(addprefix CMakeFiles/quicly.dir/lib/, $(quicly_src:.c=.c.o))

picotls_src = openssl.c pembase64.c picotls.c fusion.c
picotls_obj = $(addprefix CMakeFiles/cli.dir/deps/picotls/lib/, $(picotls_src:.c=.c.o))

libcli_src = frame.c cc-reno.c cc-cubic.c cc-pico.c defaults.c local_cid.c loss.c quicly.c \
						 ranges.c rate.c recvstate.c remote_cid.c retire_cid.c sendstate.c sentmap.c streambuf.c
libcli_obj = $(addprefix CMakeFiles/cli.dir/lib/, $(libcli_src:.c=.c.o))

cli_src = cli.c
cli_obj = $(addprefix CMakeFiles/cli.dir/src/, $(cli_src:.c=.c.o))

all: quicly-tracer.h libquicly.a cli

quicly-tracer.h:
	misc/probe2trace.pl -a tracer < quicly-probes.d > quicly-tracer.h

cli: $(picotls_obj) $(libcli_obj) $(cli_obj) $(LDBINIT)
	$(CC) $(LDB_LDFLAGS) -D_GNU_SOURCE -pthread -std=c99 -Wall -g -DQUICLY_USE_TRACER=1 -O2 -rdynamic $(picotls_obj) $(libcli_obj) $(cli_obj) $(LDBINIT) \
		-o cli -lssl -lcrypto -ldl -lm

libquicly.a: $(quicly_obj)
	$(AR) qc libquicly.a $(quicly_obj)
	$(RANLIB) libquicly.a

CMakeFiles/quicly.dir/lib/%.c.o: lib/%.c
	$(CC) $(LDB_CCFLAGS) -I./deps/klib -I./deps/picotls/include -I./deps/picotest -I./include -I./ -D_GNU_SOURCE -pthread -std=c99 -Wall -g \
	 	-DQUICLY_USE_TRACER=1 -O2 -MD -MT $@ -MF $@.d -o $@ -c $<

CMakeFiles/cli.dir/deps/picotls/lib/%.c.o: deps/picotls/lib/%.c
	$(CC) $(LDB_CCFLAGS) -I./deps/klib -I./deps/picotls/include -I./deps/picotest -I./include -I./ -D_GNU_SOURCE -pthread -std=c99 -Wall -g \
		-DQUICLY_USE_TRACER=1 -O2 -mavx2 -maes -mpclmul -mvaes -mvpclmulqdq -DQUICLY_HAVE_FUSION=1 -MD -MT $@ -MF $@.d -o $@ -c $<

CMakeFiles/cli.dir/lib/%.c.o: lib/%.c
	$(CC) $(LDB_CCFLAGS) -I./deps/klib -I./deps/picotls/include -I./deps/picotest -I./include -I./ -D_GNU_SOURCE -pthread -std=c99 -Wall -g \
		-DQUICLY_TRACER=1 -O2 -mavx2 -maes -mpclmul -mvaes -mvpclmulqdq -DQUICLY_HAVE_FUSION=1 -MD -MT $@ -MF $@.d -o $@ -c $<

CMakeFiles/cli.dir/src/%.c.o: src/%.c
	$(CC) $(LDB_CCFLAGS) -I./deps/klib -I./deps/picotls/include -I./deps/picotest -I./include -I./ -D_GNU_SOURCE -pthread -std=c99 -Wall -g \
		-DQUICLY_TRACER=1 -O2 -mavx2 -maes -mpclmul -mvaes -mvpclmulqdq -DQUICLY_HAVE_FUSION=1 -MD -MT $@ -MF $@.d -o $@ -c $<

clean:
	rm -f quicly-tracer.h $(quicly_obj) libquicly.a $(picotls_obj) $(libcli_obj) $(cli_obj) cli

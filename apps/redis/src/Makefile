ROOT_PATH=../../llvm14-ldb
CC = $(ROOT_PATH)/build/bin/clang
LIBLDB = $(ROOT_PATH)/libldb/libldb.a

LDB_LDFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer
LDB_CCFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer -I$(ROOT_PATH)/libldb -I$(ROOT_PATH)/include

server_src = adlist.c quicklist.c ae.c anet.c dict.c server.c sds.c zmalloc.c lzf_c.c lzf_d.c pqsort.c zipmap.c sha1.c \
						 ziplist.c release.c networking.c util.c object.c db.c replication.c rdb.c t_string.c t_list.c t_set.c \
						 t_zset.c t_hash.c config.c aof.c pubsub.c multi.c debug.c sort.c intset.c syncio.c cluster.c crc16.c \
						 endianconv.c slowlog.c eval.c bio.c rio.c rand.c memtest.c syscheck.c crcspeed.c crc64.c bitops.c \
						 sentinel.c notify.c setproctitle.c blocked.c hyperloglog.c latency.c sparkline.c redis-check-rdb.c \
						 redis-check-aof.c geo.c lazyfree.c module.c evict.c expire.c geohash.c geohash_helper.c childinfo.c \
						 defrag.c siphash.c rax.c t_stream.c listpack.c localtime.c lolwut.c lolwut5.c lolwut6.c acl.c tracking.c \
						 socket.c tls.c sha256.c timeout.c setcpuaffinity.c monotonic.c mt19937-64.c resp_parser.c call_reply.c \
						 script_lua.c script.c functions.c function_lua.c commands.c strl.c connection.c unix.c
server_obj = $(server_src:.c=.o)

all: redis-server

redis-server: $(server_obj) $(LIBLDB)
	$(CC) $(LDB_LDFLAGS) -flto -g -ggdb -rdynamic -o redis-server $(server_obj) $(LIBLDB) ../deps/hiredis/libhiredis.a \
		../deps/lua/src/liblua.a ../deps/hdr_histogram/libhdrhistogram.a ../deps/fpconv/libfpconv.a ../deps/jemalloc/lib/libjemalloc.a \
	 	-lm -ldl -pthread -lrt

%.o: %.c
	$(CC) $(LDB_CCFLAGS) -pedantic -DREDIS_STATIC= -std=c11 -Wall -W -Wno-missing-field-initializers -Werror=deprecated-declarations \
		-O3 -g -ggdb -flto -I../deps/hiredis -I../deps/linenoise -I../deps/lua/src -I../deps/hdr_histogram -I../deps/fpconv \
	 	-DUSE_JEMALLOC -I../deps/jemalloc/include -MMD -o $@ -c $<

clean:
	rm -f $(server_obj) redis-server

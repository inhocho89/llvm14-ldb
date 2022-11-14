ROOT_PATH=../..
CC = $(ROOT_PATH)/build/bin/clang
LDBINIT = $(ROOT_PATH)/libldb/ldb_init.o

LDB_LDFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer
LDB_CCFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer -I$(ROOT_PATH)/libldb

memcached_src = memcached.c hash.c jenkins_hash.c murmur3_hash.c slabs.c items.c assoc.c \
								thread.c daemon.c stats_prefix.c util.c cache.c bipbuffer.c base64.c logger.c \
								crawler.c itoa_ljust.c slab_automove.c authfile.c restart.c proto_text.c \
								proto_bin.c extstore.c crc32c.c storage.c slab_automove_extstore.c

memcached_obj = $(addprefix memcached-,$(memcached_src:.c=.o))

all: memcached

memcached: $(memcached_obj) $(LDBINIT)
	$(CC) $(LDB_LDFLAGS) -O2 -pthread -Wall -Werror -pedantic -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -o $@ $(memcached_obj) $(LDBINIT) -levent

memcached-%.o: %.c
	$(CC) $(LDB_CCFLAGS) -DHAVE_CONFIG_H -I. -DNDEBUG -g -O2 -pthread -Wall -Werror -pedantic -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -MT $@ -MD -MP -c -o $@ $<

clean:
	rm -f $(memcached_obj) memcached

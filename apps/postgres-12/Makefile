ROOT_PATH=../llvm14-ldb
CC = $(ROOT_PATH)/build/bin/clang
AR = /usr/bin/ar
LIBLDB = $(ROOT_PATH)/libldb/libldb.a

LDB_LDFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer
LDB_CCFLAGS = -g -fdebug-default-version=3 -fno-omit-frame-pointer -I$(ROOT_PATH)/libldb/include

common_srv_src_ = base64.c config_info.c controldata_utils.c d2s.c exec.c f2s.c file_perm.c ip.c \
									keywords.c kwlookup.c link-canary.c md5.c pg_lzcompress.c pgfnames.c psprintf.c \
									relpath.c rmtree.c saslprep.c scram-common.c string.c unicode_norm.c username.c \
									wait_error.c sha2.c
common_src_ = $(common_srv_src) fe_memutils.c file_utils.c logging.c restricted_token.c
common_src = $(addprefix src/common/,$(common_src_))
common_obj = $(addprefix src/common/,$(common_src_:.c=.o))
common_shlib_obj = $(addprefix src/common/,$(common_src_:.c=_shlib.o))
common_srv_obj = $(addprefix src/common/,$(common_srv_src_:.c=_srv.o))

COMMON_CCFLAGS = -Wall -fno-strict-aliasing -fwrapv -g -ggdb -Og -g3 -fno-omit-frame-pointer \
								 -I. -I./src/common -I./src/include -D_GNU_SOURCE 

port_src_ = fls.c strlcat.c strlcpy.c getpeereid.c pg_crc32c_sse42.c pg_crc32c_sb8.c \
						pg_crc32c_sse42_choose.c chklocale.c erand48.c inet_net_ntop.c noblock.c \
						path.c pg_bitutils.c pgcheckdir.c pgmkdirp.c pgsleep.c pg_strong_random.c \
						pgstrcasecmp.c pgstrsignal.c pqsignal.c qsort.c qsort_arg.c quotes.c \
						snprintf.c sprompt.c strerror.c tar.c thread.c
PORT_CCFLAGS = -Wall -Wmissing-prototypes -Wpointer-arith -Wdeclaration-after-statement \
							 -Werror=vla -Wendif-labels -Wformat-security -fno-strict-aliasing -fwrapv \
							 -g -ggdb -Og -g3 -fno-omit-frame-pointer -I./src/port -I./src/include \
							 -D_GNU_SOURCE 

port_src = $(addprefix src/port/,$(port_src_))
port_obj = $(addprefix src/port/,$(port_src_:.c=.o))
port_shlib_obj = $(addprefix src/port/,$(port_src_:.c=_shlib.o))
port_srv_obj = $(addprefix src/port/,$(port_src_:.c=_srv.o))

timezone_src_ = localtime.c strftime.c pgtz.c
timezone_src = $(addprefix src/timezone/,$(timezone_src_))

backend_bootstrap_src_ = bootparse.c bootstrap.c
backend_bootstrap_src = $(addprefix src/backend/bootstrap/,$(backend_bootstrap_src_))

backend_libpq_src_ = be-fsstubs.c be-secure.c be-secure-common.c auth.c crypt.c hba.c ifaddr.c \
										 pqcomm.c pqformat.c pqmq.c pqsignal.c auth-scram.c
backend_libpq_src = $(addprefix src/backend/libpq/,$(backend_libpq_src_))

backend_port_src_ = atomics.c pg_sema.c pg_shmem.c
backend_port_src = $(addprefix src/backend/port/,$(backend_port_src_))

backend_regex_src_ = regcomp.c regerror.c regexec.c regfree.c regprefix.c regexport.c
backend_regex_src = $(addprefix src/backend/regex/,$(backend_regex_src_))

backend_replication_src_ = walsender.c walreceiverfuncs.c walreceiver.c basebackup.c repl_gram.c \
													 slot.c slotfuncs.c syncrep.c syncrep_gram.c
backend_replication_src = $(addprefix src/backend/replication/,$(backend_replication_src_))

backend_utils_adt_src_ = $(wildcard src/backend/utils/adt/*.c)
backend_utils_adt_excl_ = jsonpath_scan.c levenshtein.c like_match.c
backend_utils_adt_excl = $(addprefix src/backend/utils/adt/,$(backend_utils_adt_excl_))
backend_utils_adt_src = $(filter-out $(backend_utils_adt_excl),$(backend_utils_adt_src_))

backend_utils_mb_src_ = encnames.c conv.c mbutils.c wchar.c wstrcmp.c wstrncmp.c
backend_utils_mb_src = $(addprefix src/backend/utils/mb/,$(backend_utils_mb_src_))

backend_utils_misc_src_ = guc.c help_config.c pg_config.c pg_controldata.c pg_rusage.c ps_status.c \
													queryenvironment.c rls.c sampling.c superuser.c timeout.c tzparser.c
backend_utils_misc_src = $(addprefix src/backend/utils/misc/,$(backend_utils_misc_src_))

backend_utils_sort_src_ = logtape.c sharedtuplestore.c sortsupport.c tuplesort.c tuplestore.c
backend_utils_sort_src = $(addprefix src/backend/utils/sort/,$(backend_utils_sort_src_))

backend_utils_fmgr_src = $(wildcard src/backend/utils/fmgr/*.c)
backend_utils_fmgr_obj = $(backend_utils_fmgr_src:.c=.o)

backend_jit_src = $(wildcard src/backend/jit/*.c)
backend_jit_obj = $(backend_jit_src:.c=.o)

postgres_src = $(timezone_src) $(wildcard src/backend/access/brin/*.c) \
							 $(wildcard src/backend/access/common/*.c) \
							 $(wildcard src/backend/access/gin/*.c) $(wildcard src/backend/access/gist/*.c) \
							 $(wildcard src/backend/access/hash/*.c) $(wildcard src/backend/access/heap/*.c) \
							 $(wildcard src/backend/access/index/*.c) $(wildcard src/backend/access/nbtree/*.c) \
							 $(wildcard src/backend/access/rmgrdesc/*.c) $(wildcard src/backend/access/spgist/*.c) \
							 $(wildcard src/backend/access/table/*.c) $(wildcard src/backend/access/tablesample/*.c)\
							 $(wildcard src/backend/access/ple/*.c) \
							 $(wildcard src/backend/access/transam/*.c) $(backend_bootstrap_src) \
							 $(wildcard src/backend/catalog/*.c) $(wildcard src/backend/parser/*.c) \
							 $(wildcard src/backend/commands/*.c) $(wildcard src/backend/executor/*.c) \
							 $(wildcard src/backend/foreign/*.c) $(wildcard src/backend/lib/*.c) \
							 $(backend_libpq_src) $(wildcard src/backend/main/*.c) $(wildcard src/backend/nodes/*.c) \
							 $(wildcard src/backend/optimizer/geqo/*.c) $(wildcard src/backend/optimizer/path/*.c) \
							 $(wildcard src/backend/optimizer/plan/*.c) $(wildcard src/backend/optimizer/prep/*.c) \
							 $(wildcard src/backend/optimizer/util/*.c) $(wildcard src/backend/partitioning/*.c) \
							 $(backend_port_src) $(wildcard src/backend/postmaster/*.c) $(backend_regex_src)\
							 $(wildcard src/backend/replication/logical/*.c) $(backend_replication_src) \
							 $(wildcard src/backend/rewrite/*.c) $(wildcard src/backend/statistics/*.c) \
							 $(wildcard src/backend/storage/buffer/*.c) $(wildcard src/backend/storage/file/*.c) \
							 $(wildcard src/backend/storage/freespace/*.c) $(wildcard src/backend/storage/ipc/*.c) \
							 $(wildcard src/backend/storage/large_object/*.c) $(wildcard src/backend/storage/lmgr/*.c) \
							 $(wildcard src/backend/storage/page/*.c) $(wildcard src/backend/storage/smgr/*.c) \
							 $(wildcard src/backend/storage/sync/*.c) $(wildcard src/backend/tcop/*.c) \
							 $(wildcard src/backend/tsearch/*.c) $(backend_utils_adt_src) \
							 $(wildcard src/backend/utils/cache/*.c) $(wildcard src/backend/utils/error/*.c) \
							 $(wildcard src/backend/utils/hash/*.c) \
							 $(wildcard src/backend/utils/init/*.c) $(backend_utils_mb_src) $(backend_utils_misc_src) \
							 $(wildcard src/backend/utils/mmgr/*.c) $(wildcard src/backend/utils/resowner/*.c) \
							 $(backend_utils_sort_src) $(wildcard src/backend/utils/time/*.c) \
							 $(wildcard src/backend/utils/*.c)
postgres_obj = $(postgres_src:.c=.o)
POSTGRES_CCFLAGS =  -Wall -Wmissing-prototypes -Wpointer-arith -Wdeclaration-after-statement -Werror=vla \
									 -Wendif-labels -Wmissing-format-attribute -Wformat-security -fno-strict-aliasing \
									 -fwrapv -g -ggdb -Og -g3 -fno-omit-frame-pointer -I./src/include -D_GNU_SOURCE 

all: src/common/libpgcommon.a src/common/libpgcommon_shlib.a src/common/libpgcommon_srv.a \
	src/port/libpgport.a src/port/libpgport_shlib.a src/port/libpgport_srv.a src/timezone/zic \
	src/backend/postgres

src/backend/postgres: $(postgres_obj) $(backend_utils_fmgr_obj) $(backend_jit_obj)
	$(CC) $(LDB_LDFLAGS) -Wall -Wmissing-prototypes -Wpointer-arith -Wdeclaration-after-statement -Werror=vla \
		-Wendif-labels -Wmissing-format-attribute -Wformat-security -fno-strict-aliasing -fwrapv \
		-fexcess-precision=standard -Wno-format-truncation -Wno-stringop-truncation -g -ggdb -Og -g3 \
		-fno-omit-frame-pointer $^ src/port/libpgport_srv.a src/common/libpgcommon_srv.a $(LIBLDB) \
		-Wl,--as-needed -Wl,-rpath,'/home/ubuntu/build/lib',--enable-new-dtags \
		-Wl,-E -lcrypt -lm -o $@

src/timezone/zic: src/timezone/zic.o src/port/libpgport.a src/common/libpgcommon.a
	$(CC) $(LDB_LDFLAGS) -Wall -Wmissing-prototypes -Wpointer-arith -Wdeclaration-after-statement \
		-Werror=vla -Wendif-labels -Wmissing-format-attribute -Wformat-security -fno-strict-aliasing -fwrapv \
		-fexcess-precision=standard -Wno-format-truncation -Wno-stringop-truncation -g -ggdb -Og -g3 \
		-fno-omit-frame-pointer -Wl,--as-needed \
		-Wl,-rpath,'/home/ubuntu/build/lib',--enable-new-dtags -lz -lreadline -lcrypt \
		-lm $^ $(LIBLDB) -o $@

src/common/libpgcommon.a: $(common_obj)
	rm -f $@
	$(AR) crs $@ $^

src/common/libpgcommon_shlib.a: $(common_shlib_obj)
	rm -f $@
	$(AR) crs $@ $^

src/common/libpgcommon_srv.a: $(common_srv_obj)
	rm -f $@
	$(AR) crs $@ $^

src/port/libpgport.a: $(port_obj)
	rm -f $@
	$(AR) crs $@ $^

src/port/libpgport_shlib.a: $(port_shlib_obj)
	rm -f $@
	$(AR) crs $@ $^

src/port/libpgport_srv.a: $(port_srv_obj)
	rm -f $@
	$(AR) crs $@ $^

$(postgres_obj): %.o: %.c
	$(CC) $(LDB_CCFLAGS) $(POSTGRES_CCFLAGS) -c -o $@ $<

$(backend_utils_fmgr_obj) $(backend_jit_obj): %.o: %.c
	$(CC) $(LDB_CCFLAGS) $(POSTGRES_CCFLAGS) -DDLSUFFIX=\".so\" -c -o $@ $<

src/common/%.o: src/common/%.c
	$(CC) $(LDB_CCFLAGS) $(COMMON_CCFLAGS) -DFRONTEND -c -o $@ $<

src/common/%_shlib.o: src/common/%.c
	$(CC) $(LDB_CCFLAGS) $(COMMON_CCFLAGS) -DFRONTEND -fPIC -c $< -o $@

src/common/%_srv.o: src/common/%.c
	$(CC) $(LDB_CCFLAGS) $(COMMON_CCFLAGS) -c $< -o $@

src/port/%.o: src/port/%.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -DFRONTEND -c -o $@ $<

src/port/%_shlib.o: src/port/%.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -DFRONTEND -fPIC -c $< -o $@

src/port/%_srv.o: src/port/%.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -fPIC -c $< -o $@
	
src/port/pg_crc32c_sse42.o: src/port/pg_crc32c_sse42.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -DFRONTEND -msse4.2 -c -o $@ $<

src/port/pg_crc32c_sse42_shlib.o: src/port/pg_crc32c_sse42.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -DFRONTEND -fPIC -msse4.2 -c -o $@ $<

src/port/pg_crc32c_sse42_srv.o: src/port/pg_crc32c_sse42.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -msse4.2 -c -o $@ $<

src/port/thread.o: src/port/thread.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -DFRONTEND -pthread -D_REENTRANT -D_THREAD_SAFE -D_POSIX_PTHREAD_SEMANTICS -c -o $@ $<

src/port/thread_shlib.o: src/port/thread.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -DFRONTEND -fPIC -pthread -D_REENTRANT -D_THREAD_SAFE -D_POSIX_PTHREAD_SEMANTICS -c -o $@ $<

src/port/thread_srv.o: src/port/thread.c
	$(CC) $(LDB_CCFLAGS) $(PORT_CCFLAGS) -pthread -D_REENTRANT -D_THREAD_SAFE -D_POSIX_PTHREAD_SEMANTICS -c -o $@ $<


clean:
	rm -f $(common_obj) $(common_shlib_obj) $(common_srv_obj) $(port_obj) $(port_shlib_obj) $(port_srv_obj) $(postgres_obj) \
		src/common/libpgcommon.a src/common/libpgcommon_shlib.a src/common/libpgcommon_srv.a \
		src/port/libport.a src/port/libport_shlib.a src/port/libport_srv.a src/timezone/zic src/backend/postgres

ROOT_PATH=../../llvm14-ldb
CC = $(ROOT_PATH)/build/bin/clang
CXX = $(ROOT_PATH)/build/bin/clang++
AR = /usr/bin/ar
RANLIB = /usr/bin/ranlib

event_src_ = buffer.c bufferevent.c bufferevent_filter.c bufferevent_pair.c \
						 bufferevent_ratelim.c bufferevent_sock.c event.c evmap.c evthread.c \
						 evutil.c evutil_rand.c evutil_time.c watch.c listener.c log.c signal.c \
						 strlcpy.c select.c poll.c epoll.c signalfd.c event_tagging.c http.c evdns.c ws.c \
						 sha1.c evrpc.c

event_src = $(addprefix ../,$(event_src_))
event_obj = $(addprefix CMakeFiles/event_static.dir/,$(addsuffix .o,$(event_src_)))

CC_FLAGS = -DHAVE_CONFIG_H -DTINYTEST_LOCAL -I./include -I../include -I../compat -I../ -Wall \
					 -Wextra -Wno-unused-parameter -Wstrict-aliasing -Wstrict-prototypes -Wundef \
					 -fno-strict-aliasing -Wmissing-prototypes -Winit-self -Wmissing-field-initializers \
					 -Wdeclaration-after-statement -Waddress -Woverride-init \
					 -Wwrite-strings -Wno-unused-function -Wno-pragmas -O3 -DNDEBUG -MD

LDB_CCFLAGS = -g -O3 -fdebug-default-version=3 -fno-omit-frame-pointer

all: lib/libevent.a

lib/libevent.a: $(event_obj)
	$(AR) qc $@ $^
	$(RANLIB) $@

CMakeFiles/event_static.dir/sha1.c.o: ../sha1.c
	$(CC) $(CC_FLAGS) $(LDB_CCFLAGS) -DLITTLE_ENDIAN=1 -MT $@ -MF $@.d -o $@ -c $<

CMakeFiles/event_static.dir/%.c.o: ../%.c
	$(CC) $(CC_FLAGS) $(LDB_CCFLAGS) -MT $@ -MF $@.d -o $@ -c $<

clean:
	rm -f lib/libevent.a $(event_obj)

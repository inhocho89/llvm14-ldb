all: lcclient
	
lcclient: lcclient.o waitgroup.o
	g++ lcclient.o waitgroup.o -lpthread -o lcclient

lcclient.o: lcclient.cc
	g++ lcclient.cc -c -o lcclient.o

waitgroup.o: waitgroup.cc
	g++ waitgroup.cc -c -o waitgroup.o

clean:
	rm -rf lcclient lcclient.o waitgroup.o

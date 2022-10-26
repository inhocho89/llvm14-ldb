all: mcclient
	
mcclient: mcclient.o waitgroup.o
	g++ mcclient.o waitgroup.o -o mcclient

mcclient.o: mcclient.cc
	g++ mcclient.cc -c -o mcclient.o

waitgroup.o: waitgroup.cc
	g++ waitgroup.cc -c -o waitgroup.o

clean:
	rm -rf mcclient mcclient.o waitgroup.o

all: tcp_block

tcp_block: tcp_block.o main.o
	g++ -g -o tcp_block main.o tcp_block.o -lpcap

tcp_block.o: tcp_block.cpp tcp_block.h
	g++ -g -c -o tcp_block.o tcp_block.cpp

main.o: main.cpp tcp_block.h tcp_block.cpp
	g++ -g -c -o main.o main.cpp

clean:
	rm -rf tcp_block *.o
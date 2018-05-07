dedup : packages dependencies
	gcc -g -o dedup dedup.o log.o `pkg-config fuse openssl sqlite3 --libs`

packages:
	sudo apt-get install -y libssl-dev pkg-config libfuse2 libfuse-dev sqlite3 libsqlite3-dev

dependencies : 
	gcc -g -Wall `pkg-config fuse --cflags` -c dedup.c -c log.c

clean:
	rm -f dedup *.o

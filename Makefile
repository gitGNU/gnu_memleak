CC=gcc
CCFLAGS=-g3 -O3 -Wall -Wextra -rdynamic -DUSE_DL_PREFIX -DREALLOC_ZERO_BYTES_FREE -DUSE_LOCKS

clean:
	rm libmemleak.so test
	rm ./debian/memleak-lib/usr/lib/libmemleak.so
	rm ./debian/memleak-lib/usr/sbin/run-with-memleak.sh       	
build:	
	$(CC) $(CCFLAGS) src/malloc.c src/memleak.c -shared -fPIC -o libmemleak.so -ldl -lpthread
	$(CC) -g  -O2 -Wall -Wextra  src/test.c -o test
	
deb:
	cp libmemleak.so ./debian/memleak-lib/usr/lib
	cp run-with-memleak.sh ./debian/memleak-lib/usr/sbin
install:
	cp libmemleak.so /usr/lib/
	cp run-with-memleak.sh /usr/sbin


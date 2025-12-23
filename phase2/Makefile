CC=gcc
CFLAGS=-Wall -Wextra -Werror -O2
LDLIBS=-lcap-ng -lseccomp

all: simple_container

simple_container: simple_container.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f simple_container

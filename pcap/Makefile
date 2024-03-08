GCC=cc
CFLAGS+=-Wall -g
CFLAGS+=-DUSE_SLEEP
LIBS=-lpcap
SRC=$(wildcard *.c)
PROGS=$(patsubst %.c,%,$(SRC))
#OBJS = $(SRC:.c=.o)

%: %.c
	$(GCC) $(CFLAGS+) $< $(LIBS) -o $@ 

all: $(PROGS)

clean:	
	rm -f *.core $(PROGS) *~




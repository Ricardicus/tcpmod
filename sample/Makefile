CC = gcc

SRCS := sample.c

OBJS := $(subst .c,.o,$(SRCS))

%.o : %.c
	$(CC) -o $@ $< -c

.PHONY : sample

all: sample

sample: $(OBJS)
	$(CC) -o $@ $^

clean:
	rm -f *.o sample
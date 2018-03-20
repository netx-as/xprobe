PROG_NAME := xprobe
SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
OBJS := ${SOURCES:.c=.o}
CC := gcc
CFLAGS += -Wall -std=c99 -w -Wextra -pedantic -D_BSD_SOURCE
NOERR := 2>/dev/null

.PHONY: all clean

all: $(PROG_NAME)

$(PROG_NAME): $(OBJS) $(HEADERS)
	$(LINK.c) $(OBJS) -o $(PROG_NAME) -lpthread

clean:
	$(RM) $(PROG_NAME)
	$(RM) $(OBJS)

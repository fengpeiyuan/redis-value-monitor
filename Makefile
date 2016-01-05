APP_NAME = redis-value-monitor
CC=gcc 
CFLAGS= -g -O0 -Wall 
LINK = $(CC)
INC =
DEPS = -lpcap

.PHONY: default all clean
default: $(APP_NAME)
all:default

$(APP_NAME): monitor.o
		$(LINK) -o $(APP_NAME) monitor.o $(DEPS)
monitor.o: monitor.c
		$(CC) -c $(CFLAGS) monitor.h monitor.c 
		

install:

clean:
	rm -f $(APP_NAME) monitor.o

APP_NAME = redis-value-monitor
CC=gcc 
CFLAGS= -g -O0 -Wall 
LINK = $(CC)
INC =
DEPS = -lpcap

.PHONY: default all clean
default: $(APP_NAME)
all:default

$(APP_NAME): main.o
		$(LINK) -o $(APP_NAME) main.o $(DEPS)
main.o: main.c
		$(CC) -c $(CFLAGS) monitor.h main.c 
		

install:

clean:
	rm -f $(APP_NAME) $(APP_NAME).o

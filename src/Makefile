CC=gcc
CFLAGS=-g -O2 -std=gnu99
OBJECTS=main.o
SOURCES=main.c daemon.c rules.c
HEADERS=daemon.h rules.h const.h
TARGET=../bin/memleakd

memleakd: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $(TARGET) $(ENDFLAGS)

main.o: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -c main.c $(ENDFLAGS)

clean:
	rm *.o

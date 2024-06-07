LIB=/home/pi/identity-cbindings/target/release

CC = gcc
CFLAGS = -Wall -g
CPPFLAGS = -I ./
LDFLAGS = -Wl,-rpath=$(LIB) -L $(LIB)

LDLIBS = -lidentity_openssl

SOURCES = main.c
TARGET = main

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)
	
clean:
	rm main

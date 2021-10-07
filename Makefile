CC = g++
CFLAGS = -Wall -Werror -pedantic
LFLAGS= -lpcap
TARGET = my_client
LIBS = base64.o
OBJ = $(TARGET).o $(LIBS)


.PHONY: all clean pack

all: $(TARGET) clean

$(TARGET): $(OBJ)
		$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $<

clean:
		rm -f $(OBJ)
		rm -f xfiala61.tar

pack: all
	tar -cvf xfiala61.tar Makefile my_client.cpp manual.pdf
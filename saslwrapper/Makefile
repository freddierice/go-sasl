CC=gcc
CFLAGS=-Wall
AR=ar
TARGET=libsaslwrapper.a
SRC_FILES=$(wildcard ./*.c)
OBJ_FILES=$(patsubst %.c, %.o,$(SRC_FILES))

all: $(TARGET)

%.o: %.c 
	$(CC) $(CFLAGS) -c $^ -o $@

$(TARGET): $(OBJ_FILES)
	$(AR) -cq $@ $^

clean:
	@rm -f $(TARGET) *.o

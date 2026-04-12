CC      = clang
CFLAGS  = -O2 -Wall -D_CRT_SECURE_NO_WARNINGS
TARGET  = NoRWX.exe

SRCS    = main.c veh.c emulator.c decoder.c flags.c \
          handlers/move.c handlers/arith.c handlers/logic.c \
          handlers/control.c handlers/stack.c handlers/misc.c \
          handlers/two_byte.c handlers/sse.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f $(TARGET) *.o handlers/*.o

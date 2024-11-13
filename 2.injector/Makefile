CC          = gcc
CFLAGS		= -c -Wall
LDFLAGS		= -lpcap
SOURCES		= injector.c
INCLUDES	= -I.
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= injector

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) 
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@  

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf $(OBJECTS) $(TARGET)

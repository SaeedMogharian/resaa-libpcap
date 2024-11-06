# Compiler and flags for C++
CC          = g++
CFLAGS      = -c -Wall
LDFLAGS     = -lpcap
SOURCES     = injector.cpp
INCLUDES    = -I.
OBJECTS     = $(SOURCES:.cpp=.o)
TARGET      = injector

# Default target to build the executable
all: $(SOURCES) $(TARGET)

# Link the object files to create the executable
$(TARGET): $(OBJECTS) 
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@  

# Compile the source file into an object file
.cpp.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

# Clean target to remove object files and executable
clean:
	rm -rf $(OBJECTS) $(TARGET)

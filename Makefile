# Define variables
PACKAGE_DIR = /root/projects/resaa-transparent-node/pcapplusplus-24.09-ubuntu-22.04-gcc-11.4.0-x86_64
PKG_CONFIG_PATH = $(PACKAGE_DIR)/lib/pkgconfig
CXX = g++
CXXFLAGS = `PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags PcapPlusPlus`
LDFLAGS = `PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs PcapPlusPlus`

# Targets
TARGET = ipPass
SRC = ipPass.cpp
OBJ = $(SRC:.cpp=.o)

# Rules
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)

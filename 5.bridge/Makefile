CC = g++
CFLAGS = -Wall -std=c++17 -I./src
LDFLAGS = -lpcap

SRC_DIR = src
OBJ_DIR = obj
BIN = bridge

SRC = $(wildcard $(SRC_DIR)/*.cpp)
OBJ = $(SRC:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN)

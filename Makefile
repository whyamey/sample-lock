CC = gcc
WARN_FLAGS = -Wall -Wextra
STD_FLAGS = -std=c11 -D_POSIX_C_SOURCE=200809L
OPTIM_FLAGS = -O3 -march=native -flto -funroll-loops -ftree-vectorize
CFLAGS = $(WARN_FLAGS) $(STD_FLAGS) $(OPTIM_FLAGS)
LDFLAGS = $(OPTIM_FLAGS) -lssl -lcrypto

SRC_DIR = src
BIN_DIR = bin
SRC = $(SRC_DIR)/sample-lock.c
EXEC = $(BIN_DIR)/sample-lock

all: $(EXEC)

$(EXEC): $(SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)
	@echo "Compilation successful (Optimized with march=native). Executable: $@"

$(BIN_DIR):
	@mkdir -p $@

clean:
	rm -f $(EXEC) *.o
	@echo "Cleaned up executable and object files."

.PHONY: all clean


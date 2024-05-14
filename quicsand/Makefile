# Compiler
CC = gcc

# Flags for local compilation
CFLAGS = -Wall -Wextra -pedantic -std=c11 -Iinclude -I/home/tiagoduarte25/Desktop/thesis/app/implementations/msquic/src/inc -D_GNU_SOURCE
LDFLAGS = -L/home/tiagoduarte25/Desktop/thesis/app/implementations/msquic/build/bin/Release/
LDLIBS = -lyaml -lmsquic

# Flags for docker deployment
#CFLAGS = -Wall -Wextra - pendatic -std=c11 -Iinclude -I/app/implementations/msquic/src/inc
#LDFLAGS = -L/app/implementations/msquic/build/bin/Release/
#LDLIBS = -lyaml -lmsquic

# Directories
SRCDIR = src
LIBDIR = lib
BINDIR = bin
CLIENT_BINDIR = $(BINDIR)/client
SERVER_BINDIR = $(BINDIR)/server

# Source files
CLIENT_SRC = $(wildcard $(SRCDIR)/client/*.c)
SERVER_SRC = $(wildcard $(SRCDIR)/server/*.c)
LIB_SRC = $(wildcard $(SRCDIR)/*.c)

# Object files
CLIENT_OBJ = $(patsubst $(SRCDIR)/client/%.c,$(CLIENT_BINDIR)/%.o,$(CLIENT_SRC))
SERVER_OBJ = $(patsubst $(SRCDIR)/server/%.c,$(SERVER_BINDIR)/%.o,$(SERVER_SRC))
LIB_OBJ = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%.o,$(LIB_SRC))

# Target executables
CLIENT_TARGET = client
SERVER_TARGET = server


# Rule to create bin/client and bin/server directories if dont't exist
$(CLIENT_BINDIR) $(SERVER_BINDIR):
	mkdir -p $@

# Rule to compile object files from client source files
$(CLIENT_BINDIR)/%.o: $(SRCDIR)/client/%.c | $(CLIENT_BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to compile object files from server source files
$(SERVER_BINDIR)/%.o: $(SRCDIR)/server/%.c | $(SERVER_BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to compile object files from library source files
$(BINDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to link the object files and create the client executable
$(CLIENT_BINDIR)/$(CLIENT_TARGET): $(CLIENT_OBJ) $(LIB_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Rule to link the object files and create the server executable
$(SERVER_BINDIR)/$(SERVER_TARGET): $(SERVER_OBJ) $(LIB_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Phony target to compile the program
.PHONY: all
all: $(CLIENT_BINDIR)/$(CLIENT_TARGET) $(SERVER_BINDIR)/$(SERVER_TARGET)

# Phony target to clean object files and executables
.PHONY: clean
clean:
	rm -rf $(BINDIR)/*.o $(CLIENT_BINDIR) $(SERVER_BINDIR)


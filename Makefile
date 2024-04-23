# Compiler
CC = gcc

# Flags for local compilation
LOCAL_CFLAGS = -Iinclude -I/home/tiagoduarte25/Desktop/thesis/app/implementations/msquic/src/inc
LOCAL_LDFLAGS = -L/home/tiagoduarte25/Desktop/thesis/app/implementations/msquic/build/bin/Release/
LOCAL_LDLIBS = -lyaml -lmsquic

# Flags for msquic deployment
MSQUIC_CFLAGS = -Iquicsand/include -Imsquic/src/inc
MSQUIC_LDFLAGS = -Lmsquic/build/bin/Release/
MSQUIC_LDLIBS = -lyaml -lmsquic

# Flags for lsquic compilation
LSQUIC_CFLAGS = -Iquicsand/include -Ilsquic/include
LSQUIC_LDFLAGS = -Llsquic/
LSQUIC_LDLIBS = -lyaml

# Directories
SRCDIR = quicsand/src
LIBDIR = quicsand/lib
BINDIR = quicsand/bin
CLIENT_BINDIR = $(BINDIR)/client
SERVER_BINDIR = $(BINDIR)/server

# Source files
CLIENT_SRC = $(wildcard $(SRCDIR)/client/*.c) $(wildcard $(SRCDIR)/client_$(IMPLEMENTATION)/*.c)
SERVER_SRC = $(wildcard $(SRCDIR)/server/*.c) $(wildcard $(SRCDIR)/server_$(IMPLEMENTATION)/*.c)
LIB_SRC = $(wildcard $(SRCDIR)/*.c)

# Object files
CLIENT_OBJ = $(patsubst $(SRCDIR)/client/%.c,$(CLIENT_BINDIR)/%.o,$(CLIENT_SRC))
SERVER_OBJ = $(patsubst $(SRCDIR)/server/%.c,$(SERVER_BINDIR)/%.o,$(SERVER_SRC))
LIB_OBJ = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%.o,$(LIB_SRC))

# Target executables
CLIENT_TARGET = client
SERVER_TARGET = server

# Rule to create bin/client and bin/server directories if don't exist
$(CLIENT_BINDIR) $(SERVER_BINDIR):
	mkdir -p $@

# Rule to compile object files from client source files
$(CLIENT_BINDIR)/%.o: $(SRCDIR)/client/%.c | $(CLIENT_BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLIENT_BINDIR)/%.o: $(SRCDIR)/client_$(IMPLEMENTATION)/%.c | $(CLIENT_BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to compile object files from server source files
$(SERVER_BINDIR)/%.o: $(SRCDIR)/server/%.c | $(SERVER_BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_BINDIR)/%.o: $(SRCDIR)/server_$(IMPLEMENTATION)/%.c | $(SERVER_BINDIR)
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

# Target for local compilation
local: CFLAGS = $(LOCAL_CFLAGS)
local: LDFLAGS = $(LOCAL_LDFLAGS)
local: LDLIBS = $(LOCAL_LDLIBS)
local: all

# Target for msquic deployment
msquic: CFLAGS = $(MSQUIC_CFLAGS)
msquic: LDFLAGS = $(MSQUIC_LDFLAGS)
msquic: LDLIBS = $(MSQUIC_LDLIBS)
msquic: all

# Target for lsquic compilation
lsquic: CFLAGS = $(LSQUIC_CFLAGS)
lsquic: LDFLAGS = $(LSQUIC_LDFLAGS)
lsquic: LDLIBS = $(LSQUIC_LDLIBS)
lsquic: all

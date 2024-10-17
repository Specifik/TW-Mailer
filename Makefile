CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -O2

# Executables
CLIENT_EXEC = client
SERVER_EXEC = server

# Source files
CLIENT_SRC = client.cpp
SERVER_SRC = server.cpp

# Target
all: $(CLIENT_EXEC) $(SERVER_EXEC)

# Build client executable
$(CLIENT_EXEC): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Build server executable
$(SERVER_EXEC): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Clean up
clean:
	rm -f $(CLIENT_EXEC) $(SERVER_EXEC) *.o
	rm -rf mail

.PHONY: all clean

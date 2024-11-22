CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -O2
LDFLAGS = -lldap -llber -lpthread

TARGETS = client server

all: $(TARGETS)

client: client.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp

server: server.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp $(LDFLAGS)

clean:
	rm -f $(TARGETS)

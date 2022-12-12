CC = /bin/g++
EXE = socks_server hw4.cgi
LINUX_FLAGS=-std=c++14 -Wall -pedantic -pthread -lboost_system
LINUX_INCLUDE_DIRS=/usr/local/include
LINUX_INCLUDE_PARAMS=$(addprefix -I , $(LINUX_INCLUDE_DIRS))
LINUX_LIB_DIRS=/usr/local/lib
LINUX_LIB_PARAMS=$(addprefix -L , $(LINUX_LIB_DIRS))

all:
	$(CC) socks_server.cpp -o socks_server $(LINUX_INCLUDE_PARAMS) $(LINUX_LIB_PARAMS) $(LINUX_FLAGS)
	$(CC) console.cpp -o hw4.cgi $(LINUX_INCLUDE_PARAMS) $(LINUX_LIB_PARAMS) $(LINUX_FLAGS)

clean:
	rm $(EXE)
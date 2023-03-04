all: main server

main: hw1.cpp
	g++ hw1.cpp -o main -lpcap

server: server.cpp
	g++ -std=c++17 server.cpp -o server

clean:
	rm -f main server
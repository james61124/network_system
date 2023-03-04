all: main client

main: hw1.cpp
	g++ hw1.cpp -o main -lpcap

client: client.cpp
	g++ -std=c++17 client.cpp -o client

clean:
	rm -f main client
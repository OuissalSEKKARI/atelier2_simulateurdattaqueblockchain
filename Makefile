CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall

all: atelier2

atelier2: main.cpp blockchain2.h attacks.h detector.h sha256.h merkle.h
	$(CXX) $(CXXFLAGS) -o atelier2 main.cpp

run: atelier2
	./atelier2

clean:
	rm -f atelier2 results.csv

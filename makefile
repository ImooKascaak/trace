AD=trace

CXXFLAGS=-Wall -Wextra -pedantic -std=c++11 -g
CXX=g++

all: $(AD)

default: $(AD)

$(CL): $(AD).cpp

clean:
	rm trace

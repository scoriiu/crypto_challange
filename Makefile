UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
	CXX?=llvm-g++
else
	CXX?=g++
endif

debug: CXXFLAGS += -g
debug: all

CXXFLAGS=-std=c++14 -Wall -O
TARGET=crypto

.PHONY: clean clean-all

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) utils.cpp aes.cpp main.cpp -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
ifeq ($(UNAME_S),Darwin)
	rm -rf crypto.dSYM
endif

clean-all:  clean
	$(MAKE) clean-all -C .

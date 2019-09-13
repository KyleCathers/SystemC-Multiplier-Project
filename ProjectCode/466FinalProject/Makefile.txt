SYSTEMC     := /opt/Accellera/systemc-2.3.1
TARGET_ARCH := linux64

CC     := /usr/bin/g++
CFLAGS := -O3 -Wall -Wextra -pedantic

IDIR := -I ./ -isystem $(SYSTEMC)/include
LDIR := -L ./ -L $(SYSTEMC)/lib-$(TARGET_ARCH)
LIBS := -lsystemc -lm


EXE     := main.x
SOURCES := $(wildcard *.cpp)
HEADERS := $(wildcard *.h)
OBJECTS := $(SOURCES:%.cpp=%.o)

$(EXE): $(OBJECTS) Makefile 
	$(CC) $(CFLAGS) $(LDIR) -o $@ $(OBJECTS) $(LIBS) 2>&1 | c++filt

$(OBJECTS): $(SOURCES) $(HEADERS) Makefile
	$(CC) $(CFLAGS) $(IDIR) -c $(SOURCES)


.PHONY: all, clean

all: $(EXE)

clean:
	rm -f -v *~ *.vcd $(OBJECTS) $(EXE) core


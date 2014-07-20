SOURCES := $(wildcard *.c *.cpp)
OBJECTS := $(patsubst %.c,%.o,$(SOURCES))
OBJECTS := $(patsubst %.cpp,%.o,$(OBJECTS))
HEADERS := $(wildcard *.h include/*.h)

COMMON  := -O2 -Wall -march=native
CFLAGS  := $(CFLAGS) $(COMMON)
CXXFLAGS := $(CXXFLAGS) $(COMMON)
CC      := gcc
CXX     := g++
LDFLAGS := $(LDFLAGS)
LDADD   :=  -lfcgi -lcrypto -lssl
INCLUDE :=  # -I../path/to/headers/
# NOTE: you should run make from this directory, else the following
# may not work.
DEFS    := -DHTMLPATH=\"$(shell pwd)/../html/\"

TARGET  := main.fcgi

.PHONY : all
all : $(TARGET)

# {{{ for debugging
DBGFLAGS := -g
debug : CFLAGS += $(DBGFLAGS)
debug : CXXFLAGS += $(DBGFLAGS)
debug : all
.PHONY : debug
# }}}

# build and restart service:
.PHONY : restart
restart : $(TARGET)
	pkill -x $(TARGET) || echo "service was not running."
	spawn-fcgi -a127.0.0.1 -p9000 -n ./$(TARGET) &

$(TARGET) : test.o b64dec.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDADD)

$(HELLO) : hello.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

%.o : %.cpp $(HEADERS)
	$(CXX) $(DEFS) $(INCLUDE) $(CXXFLAGS) -c $< -o $@

%.o : %.c $(HEADERS)
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c $< -o $@

.PHONY : clean
clean :
	rm -f $(TARGET) $(OBJECTS)



SOURCES := $(wildcard *.c *.cpp)
OBJECTS := $(patsubst %.c,%.o,$(SOURCES))
OBJECTS := $(patsubst %.cpp,%.o,$(OBJECTS))
HEADERS := $(wildcard *.h include/*.h)

COMMON  := -O2 -Wall -march=native -Wformat=2
CFLAGS  := $(CFLAGS) $(COMMON)
CXXFLAGS := $(CXXFLAGS) $(COMMON)
CC      := gcc
CXX     := g++
LD      := $(CC)
LDFLAGS := $(LDFLAGS) -L/home/wes/repos/others/libwebsockets/build/lib/ \
	-Wl,-O1,-rpath /home/wes/repos/others/libwebsockets/build/lib/
LDADD   := -lssl -lcrypto -lwebsockets -lrt
INCLUDE := -I/home/wes/repos/others/libwebsockets/lib/
DEFS    :=  # -DLINUX

TOKENGEN := token-gen
TOKEND   := tokend
AUTHD    := authd
TARGETS  := $(TOKENGEN) $(AUTHD) $(TOKEND)

.PHONY : all
all : $(TARGETS)

# {{{ for debugging
DBGFLAGS := -g
debug : CFLAGS += $(DBGFLAGS)
debug : CXXFLAGS += $(DBGFLAGS)
debug : all
.PHONY : debug
# }}}

$(TARGETS) : % : %.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

%.o : %.cpp $(HEADERS)
	$(CXX) $(DEFS) $(INCLUDE) $(CXXFLAGS) -c $< -o $@

%.o : %.c $(HEADERS)
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c $< -o $@

.PHONY : clean
clean :
	rm -f $(TARGET) $(OBJECTS)



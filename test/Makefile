VERBOSE ?=
DEBUG   ?=

Q = @
V =
ifeq ($(VERBOSE),1)
	Q =
	V = -v
endif

CXXSRC  = $(wildcard *.cpp)

EXECUTABLES = $(CXXSRC:.cpp=)
TESTS = $(CXXSRC:.cpp=.test)

CC      = g
GCC     = $(Q)$(CC)cc
GXX     = $(Q)$(CC)++
ECHO    = @echo -e
RM      = $(Q)rm $(V)

ifeq ($(DEBUG),1)
	DBGFLAGS = -g
else
	DBGFLAGS =
endif

OPTFLAGS= -O3
IFLAGS  = -I../include
WFLAGS  = -Wall -Wextra -Wpedantic -Wnull-dereference -Wshadow
WFLAGS += -Wdouble-promotion -Winit-self -Wswitch-default -Wswitch-enum
WFLAGS += -Wundef -Wconversion -Winline -Waddress
COMFLAGS= $(WFLAGS)

GCCFLAGS= $(OPTFLAGS) $(IFLAGS) $(COMFLAGS) $(DFLAGS)
CXXFLAGS= $(GCCFLAGS) -std=c++17

all: $(EXECUTABLES)

%: %.cpp
	$(ECHO) "G++\t$@"
	$(GXX) $(CXXFLAGS) $< -o $@

%.test: %
	$(ECHO) "Testing\t$<"
	@./$< >/dev/null

.PHONY: test
tests: $(TESTS)

.PHONY: clean
clean:
	$(RM) -f $(EXECUTABLES)

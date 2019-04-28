CXX=g++
CXXFLAGS=-I. -Lcryptopp810 -lcryptopp -static
PREFIX=bin/blsig_


all: $(PREFIX)get_client_secret
all: $(PREFIX)get_blinded_hash
all: $(PREFIX)get_blind_signature
all: $(PREFIX)get_unblinded_signature
all: $(PREFIX)verify_unblinded_signature
all: test

$(PREFIX)%: %.cxx 
	$(CXX) $< $(CXXFLAGS) -o $@

test: test.cxx
	$(CXX) $< $(CXXFLAGS) -g -o $(PREFIX)$@

%.cxx: includes.h

includes.h: common_functions.h
includes.h: inner_functions.h

clean:
	rm -f $(PREFIX)*

.PHONY: clean all


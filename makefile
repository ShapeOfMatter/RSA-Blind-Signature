CXX=g++
CXXFLAGS=-I. -Lcryptopp810 -lcryptopp -static
OUTDIR=bin/
PREFIX=$(OUTDIR)blsig_
INCLUDES=includes.h common_functions.h inner_functions.h pem-rd.h

all: $(PREFIX)get_client_secret
all: $(PREFIX)get_blinded_hash
all: $(PREFIX)get_blind_signature
all: $(PREFIX)get_unblinded_signature
all: $(PREFIX)verify_unblinded_signature
all: $(OUTDIR)test

$(PREFIX)%: %.cxx $(INCLUDES)
	$(CXX) $< $(CXXFLAGS) -o $@

$(OUTDIR)test: test.cxx $(INCLUDES)
	$(CXX) $< $(CXXFLAGS) -g -o $@

clean:
	rm -f $(PREFIX)*
	rm $(OUTDIR)test

.PHONY: clean all


CXX=g++
CXXFLAGS=-I. -Lcryptopp810 -lcryptopp -g

blind: blind.cxx
	$(CXX) $< $(CXXFLAGS) -o bin/$@

clean:
	@rm -f $(DESTDIR)/*

.PHONY: clean


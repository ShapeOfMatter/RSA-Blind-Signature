CXX=g++
CXXFLAGS=-I. -Lcryptopp810 -lcryptopp -g

blind: blind.cxx
	$(CXX) $< $(CXXFLAGS) -o $@

clean:
	@rm -f *.exe

CXX = g++
COMPILERFLAGS = -Wall -Wextra -Wno-sign-compare
CPPFLAGS = -I/opt/homebrew/include
LINKFLAGS = -L/opt/homebrew/lib
LINKLIBS = -lsodium

NODEOBJECTS = obj/proof_net.o

.PHONY: all clean

all: node gen_key

node: $(NODEOBJECTS) | obj
	$(CXX) $(COMPILERFLAGS) $^ -o $@ $(LINKFLAGS) $(LINKLIBS)

gen_key: src/gen_key.cpp
	$(CXX) $(COMPILERFLAGS) $(CPPFLAGS) $< -o $@ $(LINKFLAGS) $(LINKLIBS)

clean:
	$(RM) obj/*.o node gen_key

obj/%.o: src/%.cpp | obj
	$(CXX) $(COMPILERFLAGS) $(CPPFLAGS)  -c -o $@ $<

obj:
	mkdir -p obj

COMPILERFLAGS = -Wall -Wextra -Wno-sign-compare
CPPFLAGS = -I/opt/homebrew/include
LINKFLAGS = -L/opt/homebrew/lib
LINKLIBS = -lsodium

NODEOBJECTS = obj/node.o obj/utils.o
ACCOUNTINGOBJECTS = obj/accounting.o obj/utils.o

.PHONY: all clean

all: node accounting gen_key

node: $(NODEOBJECTS) | obj
	$(CXX) $(COMPILERFLAGS) $^ -o $@ $(LINKFLAGS) $(LINKLIBS)

accounting: $(ACCOUNTINGOBJECTS) | obj
	$(CXX) $(COMPILERFLAGS) $^ -o $@ $(LINKFLAGS) $(LINKLIBS)

gen_key: src/gen_key.cpp
	$(CXX) $(COMPILERFLAGS) $(CPPFLAGS) $< -o $@ $(LINKFLAGS) $(LINKLIBS)

clean:
	$(RM) obj/*.o node accounting gen_key

obj/%.o: src/%.cpp | obj
	$(CXX) $(COMPILERFLAGS) $(CPPFLAGS)  -c -o $@ $<

obj:
	mkdir -p obj

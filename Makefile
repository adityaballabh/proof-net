CPP = g++
COMPILERFLAGS = -g -Wall -Wextra -Wno-sign-compare

NODEOBJECTS = obj/proof_net.o

.PHONY: all clean

node: $(NODEOBJECTS) | obj
	$(CPP) $(COMPILERFLAGS) $^ -o $@

clean :
	$(RM) obj/*.o node

obj/%.o: src/%.cpp | obj
	$(CPP) $(COMPILERFLAGS) -c -o $@ $<

obj:
	mkdir -p obj

all: debugger

linenoise.o: linenoise.c
	gcc -I./include/ -c linenoise.c -o linenoise.o

debugger: linenoise.o
	g++ -std=c++11 -I./include $(pkg-config --cflags --libs libelf++) $(pkg-config --cflags --libs libdwarf++) first_debugger.cpp linenoise.o -o first_debugger

clean:
	rm *.o first_debugger


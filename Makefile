all: debugger

linenoise.o: linenoise.c
	gcc -I./include/ -c linenoise.c -o linenoise.o

debugger: linenoise.o
	g++ -std=c++11 -I./include first_debugger.cpp -lelf++ -ldwarf++ linenoise.o -o first_debugger
	g++ -std=c++11 -I./include second_debugger.cpp -lelf++ -ldwarf++ linenoise.o -o second_debugger

clean:
	rm *.o first_debugger


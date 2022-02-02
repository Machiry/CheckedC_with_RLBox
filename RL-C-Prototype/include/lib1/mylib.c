#include "mylib.h"
#include "../../mylibheader.hpp"
#include "../../main.cpp"
#include <signal.h>
#include <stdio.h>

void hello() {
  printf("Called from Lib1 implementation\n");
}

unsigned add(unsigned a, unsigned b) _Checked {
  return a + b;
}

void echo(const char* str : itype(_Nt_array_ptr<const char>)) {
	//Bring down the program if user enters cheat code
	if(0 == strncmp("HESOYAM!",str,sizeof("HESOYAM!")))
	{
	  raise(SIGSEGV);
	  printf(">CRASH Inside Lib1");
	}
	printf(">Lib1 prints: %s\n", str);
}

int main()
{
	char* f1= "_unsafe_add";
	int a =10;
	int b = 20;
	int result = 100;
	printf(" result is %d\n", result);
	invoked_unchecked_function(_unsafe_add, a,b, result);
	printf(" result is %d", result);
	return 0;
}

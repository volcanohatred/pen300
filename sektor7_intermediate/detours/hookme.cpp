#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "user32.lib")
//#pragma comment is a compiler directive which indicates Visual C++ to 
//leave a comment in the generated object file.
//The comment can then be read by the linker when it processes object files.

int main(){
    printf("Welcome to hookme. I love captian hook!");
    MessageBox(NULL, "First message", "HOOKS", MB_OK);
    MessageBox(NULL, "Second message", "HOOKS", MB_OK);
    MessageBox(NULL, "Third message", "HOOKS", MB_OK);

    printf("hookme :  Roger and out!\n");

    return 0;
} 
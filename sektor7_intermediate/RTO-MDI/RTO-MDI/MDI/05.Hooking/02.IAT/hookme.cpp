/*

 Red Team Operator code template
 Target app for hooking

 author: reenz0h (twitter: @SEKTOR7net)

*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "user32.lib")

int main(void){

	printf("hookme.exe: Starting.\n");

	MessageBox(NULL, "First message", "HOOKS", MB_OK);
	MessageBox(NULL, "Second message", "HOOKS", MB_OK);
	MessageBox(NULL, "Third message", "HOOKS", MB_OK);

	printf("hookme.exe: Roger and out!\n");

    return 0;
}

#include <stdio.h>
#include <curses.h>
#include <stdlib.h>

int main()
{
	FILE *fp;
	char s;
	//clrscr();
	fp=fopen("/var/spool/printer.log","r");
	//fp=fopen("/etc/passwd", "r");
    if(fp==NULL)
	{
		printf("\nCANNOT OPEN FILE");
	}
	do
    {
		s=getc(fp);
        fprintf(stderr, "%c", s);
	
	}
	while(s!=EOF);
	fclose(fp);
	return 0;
}
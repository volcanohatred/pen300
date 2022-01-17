#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main ()
{
    char command[500];
    int error = 0;
    fprintf( stderr, "HELP?" );
    strcpy(command, "echo 'hello jack' > a.txt & mkdir d & mv a.txt /app/lib/public/incoming/a.txt");
    //strcpy(command, "sed -i '1iresources :people' sample_sed_test.text");
    error = system(command);
    printf("%s\n", command);
    printf("%d\n", error);
    return(0);
} 
/* clean-sat.c
 */

#include <stdio.h>

int
main(int argc, char **argv)
{
    int c;

    if( argc > 1 ) {
	fprintf(stderr, "no arguments, please\n");
	return 1;
    }

    while( (c=getchar()) == '\n' )
	;
    while( c != EOF ) {
	putchar(c);
	c = getchar();
    }

    return 0;
}


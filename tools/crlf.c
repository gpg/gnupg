/* crlf.c
 */

#include <stdio.h>

int
main(int argc, char **argv)
{
    int c, lc;
    int off=0;

    if( argc > 1 ) {
	fprintf(stderr, "no arguments, please\n");
	return 1;
    }

    lc = -1;
    while( (c=getchar()) != EOF ) {
      #if 0
	if( c == '\r' && lc == ' ' )
	    fprintf(stderr,"SP,CR at %d\n", off );
	if( c == '\n' && lc == ' ' )
	    fprintf(stderr,"SP,LF at %d\n", off );
      #endif
	if( c == '\n' && lc == '\r' )
	    putchar(c);
	else if( c == '\n' ) {
	    putchar('\r');
	    putchar(c);
	}
	else if( c != '\n' && lc == '\r' ) {
	    putchar('\n');
	    putchar(c);
	}
	else
	    putchar(c);

	lc = c;
	off++;
    }

    return 0;
}


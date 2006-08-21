/* crlf.c
 * Copyright (C) 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
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

/* clean-sat.c
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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


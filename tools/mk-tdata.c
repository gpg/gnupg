/* mk-tdata.c
 *
 *  Create some simple random testdata
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#ifndef RAND_MAX   /* for SunOS */
  #define RAND_MAX 32767
#endif

int
main(int argc, char **argv)
{
    int i, c;
    int limit =0;

    limit = argc > 1 ? atoi(argv[1]) : 0;

    srand(getpid());

    for(i=0; !limit || i < limit; i++ ) {
      #ifdef HAVE_RAND
	c = ((unsigned)(1 + (int) (256.0*rand()/(RAND_MAX+1.0)))-1);
      #else
	c = ((unsigned)(1 + (int) (256.0*random()/(RAND_MAX+1.0)))-1);
      #endif
	putchar(c);
    }
    return 0;
}


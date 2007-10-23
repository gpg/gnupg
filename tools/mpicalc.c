/* mpitest.c - test the mpi functions
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This is an RPN calculator; values must be given in hex.
 * Operation is like dc(1) except that the input/output radix is
 * always 16 and you can use a '-' to prefix a negative number.
 * Addition operators: ++ and --. All operators must be delimited by a blank
 *
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "util.h"
#include "mpi.h"
#include "i18n.h"

#define STACKSIZE  100
static MPI stack[STACKSIZE];
static int stackidx;


const char *
strusage( int level )
{
    const char *p;
    switch( level ) {
      case 10:
      case 0:	p = "mpicalc - v" VERSION "; "
		    "Copyright 1997 Werner Koch (dd9jn)" ; break;
      case 13:	p = "mpicalc"; break;
      case 14:	p = VERSION; break;
      case 1:
      case 11:	p = "Usage: mpicalc (-h for help)";
		break;
      case 2:
      case 12:	p =
    "\nSyntax: mpicalc [options] [files]\n"
    "MPI RPN calculator\n";
	break;
      default:	p = default_strusage(level);
    }
    return p;
}


static void
i18n_init(void)
{
#ifdef ENABLE_NLS
  setlocale( LC_ALL, "" );
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain( PACKAGE );
#endif
}


static void
do_add(void)
{
    if( stackidx < 2 ) {
	fputs("stack underflow\n",stderr);
	return;
    }
    mpi_add( stack[stackidx-2], stack[stackidx-2], stack[stackidx-1] );
    stackidx--;
}

static void
do_sub(void)
{
    if( stackidx < 2 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_sub( stack[stackidx-2], stack[stackidx-2], stack[stackidx-1] );
    stackidx--;
}

static void
do_inc(void)
{
    if( stackidx < 1 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_add_ui( stack[stackidx-1], stack[stackidx-1], 1 );
}

static void
do_dec(void)
{
    if( stackidx < 1 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
 /* mpi_sub_ui( stack[stackidx-1], stack[stackidx-1], 1 ); */
}

static void
do_mul(void)
{
    if( stackidx < 2 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_mul( stack[stackidx-2], stack[stackidx-2], stack[stackidx-1] );
    stackidx--;
}

static void
do_mulm(void)
{
    if( stackidx < 3 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_mulm( stack[stackidx-3], stack[stackidx-3],
				 stack[stackidx-2], stack[stackidx-1] );
    stackidx -= 2;
}

static void
do_div(void)
{
    if( stackidx < 2 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_fdiv_q( stack[stackidx-2], stack[stackidx-2], stack[stackidx-1] );
    stackidx--;
}

static void
do_rem(void)
{
    if( stackidx < 2 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_fdiv_r( stack[stackidx-2], stack[stackidx-2], stack[stackidx-1] );
    stackidx--;
}

static void
do_powm(void)
{
    MPI a;
    if( stackidx < 3 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    a= mpi_alloc(10);
    mpi_powm( a, stack[stackidx-3], stack[stackidx-2], stack[stackidx-1] );
    mpi_free(stack[stackidx-3]);
    stack[stackidx-3] = a;
    stackidx -= 2;
}

static void
do_inv(void)
{
    MPI a = mpi_alloc(40);
    if( stackidx < 2 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_invm( a, stack[stackidx-2], stack[stackidx-1] );
    mpi_set(stack[stackidx-2],a);
    mpi_free(a);
    stackidx--;
}

static void
do_gcd(void)
{
    MPI a = mpi_alloc(40);
    if( stackidx < 2 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_gcd( a, stack[stackidx-2], stack[stackidx-1] );
    mpi_set(stack[stackidx-2],a);
    mpi_free(a);
    stackidx--;
}

static void
do_rshift(void)
{
    if( stackidx < 1 ) {
	fputs("stack underflow\n", stderr);
	return;
    }
    mpi_rshift( stack[stackidx-1],stack[stackidx-1], 1 );
}


int
main(int argc, char **argv)
{
    static ARGPARSE_OPTS opts[] = {
    {0} };
    ARGPARSE_ARGS pargs;
    int i, c;
    int state = 0;
    char strbuf[1000];
    int stridx=0;

    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags = 0;

    i18n_init();
    while( arg_parse( &pargs, opts) ) {
	switch( pargs.r_opt ) {
	  default : pargs.err = 2; break;
	}
    }
    if( argc )
	usage(1);


    for(i=0; i < STACKSIZE; i++ )
	stack[i] = NULL;
    stackidx =0;

    while( (c=getc(stdin)) != EOF ) {
	if( !state ) {	/* waiting */
	    if( isdigit(c) ) {
		state = 1;
		ungetc(c, stdin);
		strbuf[0] = '0';
		strbuf[1] = 'x';
		stridx=2;
	    }
	    else if( isspace(c) )
		;
	    else {
		switch(c) {
		  case '+':
		    if( (c=getc(stdin)) == '+' )
			do_inc();
		    else {
			ungetc(c, stdin);
			do_add();
		    }
		    break;
		  case '-':
		    if( (c=getc(stdin)) == '-' )
			do_dec();
		    else if( isdigit(c) || (c >='A' && c <= 'F') ) {
			state = 1;
			ungetc(c, stdin);
			strbuf[0] = '-';
			strbuf[1] = '0';
			strbuf[2] = 'x';
			stridx=3;
		    }
		    else {
			ungetc(c, stdin);
			do_sub();
		    }
		    break;
		  case '*':
		    do_mul();
		    break;
		  case 'm':
		    do_mulm();
		    break;
		  case '/':
		    do_div();
		    break;
		  case '%':
		    do_rem();
		    break;
		  case '^':
		    do_powm();
		    break;
		  case 'I':
		    do_inv();
		    break;
		  case 'G':
		    do_gcd();
		    break;
		  case '>':
		    do_rshift();
		    break;
		  case 'i': /* dummy */
		    if( !stackidx )
			fputs("stack underflow\n", stderr);
		    else {
			mpi_free(stack[stackidx-1]);
			stackidx--;
		    }
		    break;
		  case 'd': /* duplicate the tos */
		    if( !stackidx )
			fputs("stack underflow\n", stderr);
		    else if( stackidx < STACKSIZE ) {
			mpi_free(stack[stackidx]);
			stack[stackidx] = mpi_copy( stack[stackidx-1] );
			stackidx++;
		    }
		    else
			fputs("stack overflow\n", stderr);
		    break;
		  case 'c':
		    for(i=0; i < stackidx; i++ )
			mpi_free(stack[i]), stack[i] = NULL;
		    stackidx = 0;
		    break;
		  case 'p': /* print the tos */
		    if( !stackidx )
			puts("stack is empty");
		    else {
			mpi_print(stdout, stack[stackidx-1], 1 );
			putchar('\n');
		    }
		    break;
		  case 'f': /* print the stack */
		    for( i = stackidx-1 ; i >= 0; i-- ) {
			printf("[%2d]: ", i );
			mpi_print(stdout, stack[i], 1 );
			putchar('\n');
		    }
		    break;
		  default:
		    fputs("invalid operator\n", stderr);
		}
	    }
	}
	else if( state == 1 ) { /* in a number */
	    if( !isxdigit(c) ) { /* store the number */
		state = 0;
		ungetc(c, stdin);
		if( stridx < 1000 )
		    strbuf[stridx] = 0;

		if( stackidx < STACKSIZE ) {
		    if( !stack[stackidx] )
			stack[stackidx] = mpi_alloc(10);
		    if( mpi_fromstr(stack[stackidx], strbuf) )
			fputs("invalid number\n", stderr);
		    else
			stackidx++;
		}
		else
		    fputs("stack overflow\n", stderr);
	    }
	    else { /* store digit */
		if( stridx < 999 )
		    strbuf[stridx++] = c;
		else if( stridx == 999 ) {
		    strbuf[stridx] = 0;
		    fputs("string too large - truncated\n", stderr);
		    stridx++;
		}
	    }
	}

    }
    for(i=0; i < stackidx; i++ )
	mpi_free(stack[i]);
    return 0;
}

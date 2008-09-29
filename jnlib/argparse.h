/* argparse.h
 *	Copyright (C) 1998,1999,2000,2001,2006 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBJNLIB_ARGPARSE_H
#define LIBJNLIB_ARGPARSE_H

#include <stdio.h>
#include "types.h"

typedef struct {
     int  *argc;	    /* pointer to argc (value subject to change) */
     char ***argv;	    /* pointer to argv (value subject to change) */
     unsigned flags;	    /* Global flags (DO NOT CHANGE) */
     int err;		    /* print error about last option */
			    /* 1 = warning, 2 = abort */
     int r_opt; 	    /* return option */
     int r_type;	    /* type of return value (0 = no argument found)*/
     union {
	 int   ret_int;
	 long  ret_long;
	 unsigned long ret_ulong;
	 char *ret_str;
     } r;		    /* Return values */
     struct {
	 int idx;
	 int inarg;
	 int stopped;
	 const char *last;
	 void *aliases;
	 const void *cur_alias;
     } internal;	    /* DO NOT CHANGE */
} ARGPARSE_ARGS;

typedef struct {
    int 	short_opt;
    const char *long_opt;
    unsigned flags;
    const char *description; /* optional option description */
} ARGPARSE_OPTS;


/* Error values.  */
#define ARGPARSE_IS_ARG            (-1)
#define ARGPARSE_INVALID_OPTION    (-2)
#define ARGPARSE_MISSING_ARG       (-3)
#define ARGPARSE_KEYWORD_TOO_LONG  (-4)
#define ARGPARSE_READ_ERROR        (-5)
#define ARGPARSE_UNEXPECTED_ARG    (-6)
#define ARGPARSE_INVALID_COMMAND   (-7)
#define ARGPARSE_AMBIGUOUS_OPTION  (-8)
#define ARGPARSE_AMBIGUOUS_COMMAND (-9)
#define ARGPARSE_INVALID_ALIAS     (-10)
#define ARGPARSE_OUT_OF_CORE       (-11)


int arg_parse( ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts);
int optfile_parse( FILE *fp, const char *filename, unsigned *lineno,
		   ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts);
void usage( int level );
const char *strusage( int level );
void set_strusage( const char *(*f)( int ) );

#endif /*LIBJNLIB_ARGPARSE_H*/

/* util.h
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_UTIL_H
#define G10_UTIL_H

#include "errors.h"
#include "types.h"
#include "mpi.h"


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
	 ulong ret_ulong;
	 char *ret_str;
     } r;		    /* Return values */
     struct {
	 int index;
	 int inarg;
	 int stopped;
	 const char *last;
     } internal;	    /* DO NOT CHANGE */
} ARGPARSE_ARGS;

typedef struct {
    int 	short_opt;
    const char *long_opt;
    unsigned flags;
    const char *description; /* optional option description */
} ARGPARSE_OPTS;

/*-- logger.c --*/
void printstr( int level, const char *fmt, ... );
void log_bug( const char *fmt, ... );
void log_fatal( const char *fmt, ... );
void log_error( const char *fmt, ... );
void log_info( const char *fmt, ... );
void log_debug( const char *fmt, ... );
void log_hexdump( const char *text, char *buf, size_t len );
void log_mpidump( const char *text, MPI a );

/*-- errors.c --*/
const char * g10_errstr( int no );

/*-- argparse.c --*/
int arg_parse( ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts);
void usage( int level );
const char *default_strusage( int level );


/*-- (main program) --*/
const char *strusage( int level );


/*-- fileutil.c --*/

/*-- miscutil.c --*/
u32 make_timestamp(void);

/*-- strgutil.c --*/
void free_strlist( STRLIST sl );
#define FREE_STRLIST(a) do { free_strlist((a)); (a) = NULL ; } while(0)
char *memistr( char *buf, size_t buflen, const char *sub );
#define stricmp(a,b) strcasecmp((a),(b))


/******** some macros ************/
#ifndef STR
  #define STR(v) #v
#endif
#define STR2(v) STR(v)
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

#endif /*G10_UTIL_H*/

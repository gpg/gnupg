/* logger.c  -	log functions
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "util.h"

/****************
 * General interface for printing a line
 * level 0 := print to /dev/null
 *	 1 := print to stdout
 *	 2 := print as info to stderr
 *	 3 := ditto but as error
 */
void
printstr( int level, const char *fmt, ... )
{
    va_list arg_ptr ;

    if( !level )
	return;

    if( !fmt ) {
	putc('\n', level? stderr: stdout);
	return;
    }

    va_start( arg_ptr, fmt ) ;
    if( level < 2 ) {
	vfprintf(stdout,fmt,arg_ptr) ;
    }
    else {
	fprintf(stderr, level==2? "%s: ": "%s: error: ", strusage(13) ) ;
	vfprintf(stderr,fmt,arg_ptr) ;
    }
    va_end(arg_ptr);
}


void
log_info( const char *fmt, ... )
{
    va_list arg_ptr ;

    fprintf(stderr, "info: " ) ;
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
}

void
log_error( const char *fmt, ... )
{
    va_list arg_ptr ;

    fprintf(stderr, "error: " ) ;
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
}

void
log_fatal( const char *fmt, ... )
{
    va_list arg_ptr ;

    fprintf(stderr, "Fatal: " ) ;
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
    exit(2);
}

void
log_bug( const char *fmt, ... )
{
    va_list arg_ptr ;

    fprintf(stderr, "\nInternal Error: " ) ;
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
    fflush(stderr);
    abort();
}

void
log_debug( const char *fmt, ... )
{
    va_list arg_ptr ;

    fprintf(stderr, "DBG: " ) ;
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
}



void
log_hexdump( const char *text, char *buf, size_t len )
{
    int i;

    fprintf(stderr, "DBG: %s", text );
    for(i=0; i < len; i++ )
	fprintf(stderr, " %02X", ((byte*)buf)[i] );
    fputc('\n', stderr);
}


void
log_mpidump( const char *text, MPI a )
{
    fprintf(stderr, "DBG: %s", text );
    mpi_print(stderr, a, 1 );
    fputc('\n', stderr);
}


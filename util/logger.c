/* logger.c  -	log functions
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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

static char pidstring[15];
static char *pgm_name;
static int errorcount;

void
log_set_name( const char *name )
{
    m_free(pgm_name);
    if( name )
	pgm_name = m_strdup(name);
    else
	pgm_name = NULL;
}

const char *
log_get_name(void)
{
    return pgm_name? pgm_name : "";
}


void
log_set_pid( int pid )
{
    if( pid )
	sprintf(pidstring,"[%u]", (unsigned)pid );
    else
	*pidstring = 0;
}

int
log_get_errorcount( int clear)
{
    int n = errorcount;
    if( clear )
	errorcount = 0;
    return n;
}

static void
print_prefix(const char *text)
{
    if( pgm_name )
	fprintf(stderr, "%s%s: %s", pgm_name, pidstring, text );
    else
	fprintf(stderr, "?%s: %s", pidstring, text );
}

void
g10_log_info( const char *fmt, ... )
{
    va_list arg_ptr ;

    print_prefix("");
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
}

void
g10_log_error( const char *fmt, ... )
{
    va_list arg_ptr ;

    print_prefix("");
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
    errorcount++;
}

void
g10_log_fatal( const char *fmt, ... )
{
    va_list arg_ptr ;

    print_prefix("fatal: ");
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
    secmem_dump_stats();
    exit(2);
}

void
g10_log_bug( const char *fmt, ... )
{
    va_list arg_ptr ;

    putc('\n', stderr );
    print_prefix("Ooops: ");
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
    fflush(stderr);
    secmem_dump_stats();
    abort();
}

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
void
g10_log_bug0( const char *file, int line, const char *func )
{
    log_bug("Ohhhh jeeee ... (%s:%d:%s)\n", file, line, func );
}
#else
void
g10_log_bug0( const char *file, int line )
{
    log_bug("Ohhhh jeeee ... (%s:%d)\n", file, line);
}
#endif

void
g10_log_debug( const char *fmt, ... )
{
    va_list arg_ptr ;

    print_prefix("DBG: ");
    va_start( arg_ptr, fmt ) ;
    vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
}



void
g10_log_hexdump( const char *text, char *buf, size_t len )
{
    int i;

    print_prefix(text);
    for(i=0; i < len; i++ )
	fprintf(stderr, " %02X", ((byte*)buf)[i] );
    fputc('\n', stderr);
}


void
g10_log_mpidump( const char *text, MPI a )
{
    print_prefix(text);
    mpi_print(stderr, a, 1 );
    fputc('\n', stderr);
}


/* logging.c -	useful logging functions
 *	Copyright (C) 1998, 1999 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/* This file should replace logger.c in the future - for now it is not
 * used GnuPG.
 * It is a quite simple implemenation but sufficient for most purposes.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include "libjnlib-config.h"
#include "logging.h"

enum my_log_levels {
    MY_LOG_BEGIN,  /* only print the timestamp if configured */
    MY_LOG_CONT,
    MY_LOG_INFO,
    MY_LOG_WARN,
    MY_LOG_ERROR,
    MY_LOG_FATAL,
    MY_LOG_BUG,
    MY_LOG_DEBUG
};

static FILE *logstream;
static int use_time;
static int missing_lf;

#if 0
static void
write2stderr( const char *s )
{
    write( 2, s, strlen(s) );
}


static void
do_die(int rc, const char *text )
{
    write2stderr("\nFatal error: ");
    write2stderr(text);
    write2stderr("\n");
    abort();
}
#endif

void
log_set_file( const char *name )
{
    FILE *fp = (name && strcmp(name,"-"))? fopen(name, "a") : stderr;
    if( !fp ) {
	fprintf(stderr, "failed to open log file `%s': %s\n",
						name, strerror(errno));
	return;
    }
    setvbuf( fp, NULL, _IOLBF, 0 );

    if( logstream && logstream != stderr )
	fclose( logstream );
    logstream = fp;
    use_time = fp != stderr;
    missing_lf = 0;
}


int
log_get_fd()
{
    return fileno(logstream?logstream:stderr);
}

static void
do_logv( int level, const char *fmt, va_list arg_ptr )
{
    if( !logstream )
	logstream = stderr;

    if( missing_lf && level != MY_LOG_CONT )
	putc('\n', logstream );
    missing_lf = 0;

    if( use_time && level != MY_LOG_CONT ) {
	/* Note this does not work for multiple line logging as we would
	 * need to print to a buffer first */
	struct tm *tp;
	time_t atime = time(NULL);

	tp = localtime( &atime );
	fprintf( logstream, "%04d-%02d-%02d %02d:%02d:%02d ",
		    1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
			 tp->tm_hour, tp->tm_min, tp->tm_sec );
    }

    switch ( level ) {
      case MY_LOG_BEGIN: break;
      case MY_LOG_CONT: break;
      case MY_LOG_INFO: break;
      case MY_LOG_WARN: break;
      case MY_LOG_ERROR: break;
      case MY_LOG_FATAL: fputs("Fatal: ",logstream ); break;
      case MY_LOG_BUG: fputs("Ohhhh jeeee: ", logstream); break;
      case MY_LOG_DEBUG: fputs("DBG: ", logstream ); break;
      default: fprintf(logstream,"[Unknown log level %d]: ", level ); break;
    }

    if( fmt ) {
	vfprintf(logstream,fmt,arg_ptr) ;
	if( *fmt && fmt[strlen(fmt)-1] != '\n' )
	    missing_lf = 1;
    }

    if( level == MY_LOG_FATAL )
	exit(2);
    if( level == MY_LOG_BUG )
	abort();
}

static void
do_log( int level, const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( level, fmt, arg_ptr );
    va_end(arg_ptr);
}



void
log_info( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( MY_LOG_INFO, fmt, arg_ptr );
    va_end(arg_ptr);
}

void
log_error( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( MY_LOG_ERROR, fmt, arg_ptr );
    va_end(arg_ptr);
}


void
log_fatal( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( MY_LOG_FATAL, fmt, arg_ptr );
    va_end(arg_ptr);
    abort(); /* never called, bugs it makes the compiler happy */
}

void
log_bug( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( MY_LOG_BUG, fmt, arg_ptr );
    va_end(arg_ptr);
    abort(); /* never called, but it makes the compiler happy */
}

void
log_debug( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( MY_LOG_DEBUG, fmt, arg_ptr );
    va_end(arg_ptr);
}


void
log_printf( const char *fmt, ... )
{
    va_list arg_ptr ;

    if( !fmt ) {
	do_logv( MY_LOG_BEGIN, NULL, NULL );
    }
    else {
	va_start( arg_ptr, fmt ) ;
	do_logv( MY_LOG_CONT, fmt, arg_ptr );
	va_end(arg_ptr);
    }
}


#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
void
bug_at( const char *file, int line, const char *func )
{
    do_log( MY_LOG_BUG,
	     ("... this is a bug (%s:%d:%s)\n"), file, line, func );
    abort(); /* never called, but it makes the compiler happy */
}
#else
void
bug_at( const char *file, int line )
{
    do_log( MY_LOG_BUG,
	     _("you found a bug ... (%s:%d)\n"), file, line);
    abort(); /* never called, but it makes the compiler happy */
}
#endif


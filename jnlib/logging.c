/* logging.c -	useful logging functions
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
 * used by GnuPG but by GPA.
 * It is a quite simple implemenation but sufficient for most purposes.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __MINGW32__
  #include <io.h>
#endif

#define JNLIB_NEED_LOG_LOGV 1
#include "libjnlib-config.h"
#include "logging.h"


static FILE *logstream;
static char prefix_buffer[80];
static int with_time;
static int with_prefix;
static int with_pid;

static int missing_lf;
static int errorcount;

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

int
log_get_errorcount (int clear)
{
    int n = errorcount;
    if( clear )
	errorcount = 0;
    return n;
}

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

    if (logstream && logstream != stderr && logstream != stdout)
      fclose( logstream );
    logstream = fp;
    missing_lf = 0;
}

void
log_set_fd (int fd)
{
  FILE *fp;
  
  if (fd == 1)
    fp = stdout;
  else if (fd == 2)
    fp = stderr;
  else
    fp = fdopen (fd, "a");
  if (!fp)
    {
      fprintf (stderr, "failed to fdopen log fd %d: %s\n",
               fd, strerror(errno));
      return;
    }
  setvbuf (fp, NULL, _IOLBF, 0);
  
  if (logstream && logstream != stderr && logstream != stdout)
    fclose( logstream);
  logstream = fp;
  missing_lf = 0;
}


void
log_set_prefix (const char *text, unsigned int flags)
{
  if (text)
    {
      strncpy (prefix_buffer, text, sizeof (prefix_buffer)-1);
      prefix_buffer[sizeof (prefix_buffer)-1] = 0;
    }
  
  with_prefix = (flags & 1);
  with_time = (flags & 2);
  with_pid  = (flags & 4);
}


const char *
log_get_prefix (unsigned int *flags)
{
  if (flags)
    {
      *flags = 0;
      if (with_prefix)
        *flags |= 1;
      if (with_time)
        *flags |= 2;
      if (with_pid)
        *flags |=4;
    }
  return prefix_buffer;
}

int
log_get_fd()
{
    return fileno(logstream?logstream:stderr);
}

FILE *
log_get_stream ()
{
    return logstream?logstream:stderr;
}


static void
do_logv( int level, const char *fmt, va_list arg_ptr )
{
  if (!logstream)
    logstream = stderr;

  if (missing_lf && level != JNLIB_LOG_CONT)
    putc('\n', logstream );
  missing_lf = 0;

  if (level != JNLIB_LOG_CONT)
    { /* Note this does not work for multiple line logging as we would
       * need to print to a buffer first */
      if (with_time)
        {
          struct tm *tp;
          time_t atime = time (NULL);
          
          tp = localtime (&atime);
          fprintf (logstream, "%04d-%02d-%02d %02d:%02d:%02d ",
                   1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
                   tp->tm_hour, tp->tm_min, tp->tm_sec );
        }
      if (with_prefix)
        fputs (prefix_buffer, logstream);
      if (with_pid)
        fprintf (logstream, "[%u]", (unsigned int)getpid ());
      if (!with_time)
        putc (':', logstream);
      putc (' ', logstream);
    }

  switch (level)
    {
    case JNLIB_LOG_BEGIN: break;
    case JNLIB_LOG_CONT: break;
    case JNLIB_LOG_INFO: break;
    case JNLIB_LOG_WARN: break;
    case JNLIB_LOG_ERROR: break;
    case JNLIB_LOG_FATAL: fputs("Fatal: ",logstream ); break;
    case JNLIB_LOG_BUG: fputs("Ohhhh jeeee: ", logstream); break;
    case JNLIB_LOG_DEBUG: fputs("DBG: ", logstream ); break;
    default: fprintf(logstream,"[Unknown log level %d]: ", level ); break;
    }

  if (fmt)
    {
      vfprintf(logstream,fmt,arg_ptr) ;
      if (*fmt && fmt[strlen(fmt)-1] != '\n')
        missing_lf = 1;
    }

  if (level == JNLIB_LOG_FATAL)
    exit(2);
  if (level == JNLIB_LOG_BUG)
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
log_logv (int level, const char *fmt, va_list arg_ptr)
{
  do_logv (level, fmt, arg_ptr);
}

void
log_info( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( JNLIB_LOG_INFO, fmt, arg_ptr );
    va_end(arg_ptr);
}

void
log_error( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( JNLIB_LOG_ERROR, fmt, arg_ptr );
    va_end(arg_ptr);
    /* protect against counter overflow */
    if( errorcount < 30000 )
	errorcount++;
}


void
log_fatal( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( JNLIB_LOG_FATAL, fmt, arg_ptr );
    va_end(arg_ptr);
    abort(); /* never called, bugs it makes the compiler happy */
}

void
log_bug( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( JNLIB_LOG_BUG, fmt, arg_ptr );
    va_end(arg_ptr);
    abort(); /* never called, but it makes the compiler happy */
}

void
log_debug( const char *fmt, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    do_logv( JNLIB_LOG_DEBUG, fmt, arg_ptr );
    va_end(arg_ptr);
}


void
log_printf (const char *fmt, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, fmt);
  do_logv (fmt ? JNLIB_LOG_CONT : JNLIB_LOG_BEGIN, fmt, arg_ptr);
  va_end (arg_ptr);
}

/* Print a hexdump of BUFFER.  With TEXT of NULL print just the raw
   dump, with TEXT just an empty string, print a trailing linefeed,
   otherwise print an entire debug line. */
void
log_printhex (const char *text, const void *buffer, size_t length)
{
  if (text && *text)
    log_debug ("%s ", text);
  if (length)
    {
      const unsigned char *p = buffer;
      log_printf ("%02X", *p);
      for (length--, p++; length--; p++)
        log_printf (" %02X", *p);
    }
  if (text)
    log_printf ("\n");
}


#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
void
bug_at( const char *file, int line, const char *func )
{
    do_log( JNLIB_LOG_BUG,
	     ("... this is a bug (%s:%d:%s)\n"), file, line, func );
    abort(); /* never called, but it makes the compiler happy */
}
#else
void
bug_at( const char *file, int line )
{
    do_log( JNLIB_LOG_BUG,
	     _("you found a bug ... (%s:%d)\n"), file, line);
    abort(); /* never called, but it makes the compiler happy */
}
#endif


/* logging.c - Useful logging functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006, 
 *               2009, 2010 Free Software Foundation, Inc.
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


#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef HAVE_W32_SYSTEM
# include <sys/socket.h>
# include <sys/un.h>
#endif /*HAVE_W32_SYSTEM*/
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>



#define JNLIB_NEED_LOG_LOGV 1
#define JNLIB_NEED_AFLOCAL 1
#include "libjnlib-config.h"
#include "logging.h"

#ifdef HAVE_W32_SYSTEM
# define S_IRGRP S_IRUSR
# define S_IROTH S_IRUSR
# define S_IWGRP S_IWUSR
# define S_IWOTH S_IWUSR
#endif


#ifdef HAVE_W32CE_SYSTEM
# define isatty(a)  (0)
#endif


static estream_t logstream;
static int log_socket = -1;
static char prefix_buffer[80];
static int with_time;
static int with_prefix;
static int with_pid;
static unsigned long (*get_tid_callback)(void);
static int running_detached;
static int force_prefixes;

static int missing_lf;
static int errorcount;


int
log_get_errorcount (int clear)
{
    int n = errorcount;
    if( clear )
	errorcount = 0;
    return n;
}

void
log_inc_errorcount (void)
{
   errorcount++;
}


/* The following 3 functions are used by es_fopencookie to write logs
   to a socket.  */
struct fun_cookie_s
{
  int fd;
  int quiet;
  int want_socket;
  int is_socket;
  char name[1];
};


/* Write NBYTES of BUFFER to file descriptor FD. */
static int
writen (int fd, const void *buffer, size_t nbytes)
{
  const char *buf = buffer;
  size_t nleft = nbytes;
  int nwritten;
  
  while (nleft > 0)
    {
      nwritten = write (fd, buf, nleft);
      if (nwritten < 0 && errno == EINTR)
        continue;
      if (nwritten < 0)
        return -1;
      nleft -= nwritten;
      buf = buf + nwritten;
    }
  
  return 0;
}


static ssize_t 
fun_writer (void *cookie_arg, const void *buffer, size_t size)
{
  struct fun_cookie_s *cookie = cookie_arg;

  /* Note that we always try to reconnect to the socket but print
     error messages only the first time an error occured.  If
     RUNNING_DETACHED is set we don't fall back to stderr and even do
     not print any error messages.  This is needed because detached
     processes often close stderr and by writing to file descriptor 2
     we might send the log message to a file not intended for logging
     (e.g. a pipe or network connection). */
#ifndef HAVE_W32_SYSTEM
  if (cookie->want_socket && cookie->fd == -1)
    {
      /* Not yet open or meanwhile closed due to an error. */
      cookie->is_socket = 0;
      cookie->fd = socket (PF_LOCAL, SOCK_STREAM, 0);
      if (cookie->fd == -1)
        {
          if (!cookie->quiet && !running_detached
              && isatty (es_fileno (es_stderr)))
            es_fprintf (es_stderr, "failed to create socket for logging: %s\n",
                        strerror(errno));
        }
      else
        {
          struct sockaddr_un addr;
          size_t addrlen;
          
          memset (&addr, 0, sizeof addr);
          addr.sun_family = PF_LOCAL;
          strncpy (addr.sun_path, cookie->name, sizeof (addr.sun_path)-1);
          addr.sun_path[sizeof (addr.sun_path)-1] = 0;
          addrlen = SUN_LEN (&addr);
      
          if (connect (cookie->fd, (struct sockaddr *) &addr, addrlen) == -1)
            {
              if (!cookie->quiet && !running_detached
                  && isatty (es_fileno (es_stderr)))
                es_fprintf (es_stderr, "can't connect to `%s': %s\n",
                            cookie->name, strerror(errno));
              close (cookie->fd);
              cookie->fd = -1;
            }
        }
      
      if (cookie->fd == -1)
        {
          if (!running_detached)
            {
              /* Due to all the problems with apps not running
                 detached but being called with stderr closed or
                 used for a different purposes, it does not make
                 sense to switch to stderr.  We therefore disable it. */
              if (!cookie->quiet)
                {
                  /* fputs ("switching logging to stderr\n", stderr);*/
                  cookie->quiet = 1;
                }
              cookie->fd = -1; /*fileno (stderr);*/
            }
        }
      else /* Connection has been established. */
        {
          cookie->quiet = 0;
          cookie->is_socket = 1;
        }
    }
#endif /*HAVE_W32_SYSTEM*/

  log_socket = cookie->fd;
  if (cookie->fd != -1 && !writen (cookie->fd, buffer, size))
    return (ssize_t)size; /* Okay. */ 

  if (!running_detached && cookie->fd != -1
      && isatty (es_fileno (es_stderr)))
    {
      if (*cookie->name)
        es_fprintf (es_stderr, "error writing to `%s': %s\n",
                    cookie->name, strerror(errno));
      else
        es_fprintf (es_stderr, "error writing to file descriptor %d: %s\n",
                    cookie->fd, strerror(errno));
    }
  if (cookie->is_socket && cookie->fd != -1)
    {
      close (cookie->fd);
      cookie->fd = -1;
      log_socket = -1;
    }

  return (ssize_t)size;
}


static int
fun_closer (void *cookie_arg)
{
  struct fun_cookie_s *cookie = cookie_arg;

  if (cookie->fd != -1 && cookie->fd != 2)
    close (cookie->fd);
  jnlib_free (cookie);
  log_socket = -1;
  return 0;
}


/* Common function to either set the logging to a file or a file
   descriptor. */
static void
set_file_fd (const char *name, int fd) 
{
  estream_t fp;
  int want_socket;
  struct fun_cookie_s *cookie;

  /* Close an open log stream.  */
  if (logstream)
    {
      es_fclose (logstream);
      logstream = NULL;
    }

  /* Figure out what kind of logging we want.  */
  if (name && !strcmp (name, "-"))
    {
      name = NULL;
      fd = es_fileno (es_stderr);
    }

#ifndef HAVE_W32_SYSTEM
  if (name)
    {
      want_socket = (!strncmp (name, "socket://", 9) && name[9]);
      if (want_socket)
        name += 9;
    }
  else
#endif /*HAVE_W32_SYSTEM*/
    {
      want_socket = 0;
    }

  /* Setup a new stream.  */

  /* The xmalloc below is justified because we can expect that this
     function is called only during initialization and there is no
     easy way out of this error condition.  */
  cookie = jnlib_xmalloc (sizeof *cookie + (name? strlen (name):0));
  strcpy (cookie->name, name? name:"");
  cookie->quiet = 0;
  cookie->is_socket = 0;
  cookie->want_socket = want_socket;
  if (!name)
    cookie->fd = fd;
  else if (want_socket)
    cookie->fd = -1;
  else
    {
      do
        cookie->fd = open (name, O_WRONLY|O_APPEND|O_CREAT,
                           (S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR|S_IWGRP|S_IWOTH));
      while (cookie->fd == -1 && errno == EINTR);
    }
  log_socket = cookie->fd;

  {
    es_cookie_io_functions_t io = { NULL };
    io.func_write = fun_writer;
    io.func_close = fun_closer;
    
    fp = es_fopencookie (cookie, "w", io);
  }

  /* On error default to a stderr based estream.  */
  if (!fp)
    fp = es_stderr;

  es_setvbuf (fp, NULL, _IOLBF, 0);
  
  logstream = fp;

  /* We always need to print the prefix and the pid for socket mode,
     so that the server reading the socket can do something
     meaningful. */
  force_prefixes = want_socket;

  missing_lf = 0;
}


/* Set the file to write log to.  The special names NULL and "-" may
   be used to select stderr and names formatted like
   "socket:///home/foo/mylogs" may be used to write the logging to the
   socket "/home/foo/mylogs".  If the connection to the socket fails
   or a write error is detected, the function writes to stderr and
   tries the next time again to connect the socket.
  */
void
log_set_file (const char *name) 
{
  set_file_fd (name? name: "-", -1);
}

void
log_set_fd (int fd)
{
  set_file_fd (NULL, fd);
}


void
log_set_get_tid_callback (unsigned long (*cb)(void))
{
  get_tid_callback = cb;
}


void
log_set_prefix (const char *text, unsigned int flags)
{
  if (text)
    {
      strncpy (prefix_buffer, text, sizeof (prefix_buffer)-1);
      prefix_buffer[sizeof (prefix_buffer)-1] = 0;
    }
  
  with_prefix = (flags & JNLIB_LOG_WITH_PREFIX);
  with_time = (flags & JNLIB_LOG_WITH_TIME);
  with_pid  = (flags & JNLIB_LOG_WITH_PID);
  running_detached = (flags & JNLIB_LOG_RUN_DETACHED);
}


const char *
log_get_prefix (unsigned int *flags)
{
  if (flags)
    {
      *flags = 0;
      if (with_prefix)
        *flags |= JNLIB_LOG_WITH_PREFIX;
      if (with_time)
        *flags |= JNLIB_LOG_WITH_TIME;
      if (with_pid)
        *flags |= JNLIB_LOG_WITH_PID;
      if (running_detached)
        *flags |= JNLIB_LOG_RUN_DETACHED;
    }
  return prefix_buffer;
}

/* This function returns true if the file descriptor FD is in use for
   logging.  This is preferable over a test using log_get_fd in that
   it allows the logging code to use more then one file descriptor.  */
int
log_test_fd (int fd)
{
  if (logstream)
    {
      int tmp = es_fileno (logstream);
      if ( tmp != -1 && tmp == fd)
        return 1;
    }
  if (log_socket != -1 && log_socket == fd)
    return 1;
  return 0;
}

int
log_get_fd ()
{
  return logstream? es_fileno(logstream) : -1;
}

estream_t
log_get_stream ()
{
  if (!logstream)
    {
      log_set_file (NULL); /* Make sure a log stream has been set.  */
      assert (logstream);
    }
  return logstream;
}

static void
do_logv (int level, int ignore_arg_ptr, const char *fmt, va_list arg_ptr)
{
  if (!logstream)
    {
      log_set_file (NULL); /* Make sure a log stream has been set.  */
      assert (logstream);
    }

  es_flockfile (logstream);
  if (missing_lf && level != JNLIB_LOG_CONT)
    es_putc_unlocked ('\n', logstream );
  missing_lf = 0;

  if (level != JNLIB_LOG_CONT)
    { /* Note this does not work for multiple line logging as we would
       * need to print to a buffer first */
      if (with_time && !force_prefixes)
        {
          struct tm *tp;
          time_t atime = time (NULL);
          
          tp = localtime (&atime);
          es_fprintf_unlocked (logstream, "%04d-%02d-%02d %02d:%02d:%02d ",
                               1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
                               tp->tm_hour, tp->tm_min, tp->tm_sec );
        }
      if (with_prefix || force_prefixes)
        es_fputs_unlocked (prefix_buffer, logstream);
      if (with_pid || force_prefixes)
        {
          if (get_tid_callback)
            es_fprintf_unlocked (logstream, "[%u.%lx]", 
                        (unsigned int)getpid (), get_tid_callback ());
          else
            es_fprintf_unlocked (logstream, "[%u]", (unsigned int)getpid ());
        }
      if (!with_time || force_prefixes)
        es_putc_unlocked (':', logstream);
      /* A leading backspace suppresses the extra space so that we can
         correctly output, programname, filename and linenumber. */
      if (fmt && *fmt == '\b')
        fmt++;
      else
        es_putc_unlocked (' ', logstream);
    }

  switch (level)
    {
    case JNLIB_LOG_BEGIN: break;
    case JNLIB_LOG_CONT: break;
    case JNLIB_LOG_INFO: break;
    case JNLIB_LOG_WARN: break;
    case JNLIB_LOG_ERROR: break;
    case JNLIB_LOG_FATAL: es_fputs_unlocked ("Fatal: ",logstream ); break;
    case JNLIB_LOG_BUG:   es_fputs_unlocked ("Ohhhh jeeee: ", logstream); break;
    case JNLIB_LOG_DEBUG: es_fputs_unlocked ("DBG: ", logstream ); break;
    default: 
      es_fprintf_unlocked (logstream,"[Unknown log level %d]: ", level);
      break;
    }

  if (fmt)
    {
      if (ignore_arg_ptr)
        es_fputs_unlocked (fmt, logstream);
      else
        es_vfprintf_unlocked (logstream, fmt, arg_ptr);
      if (*fmt && fmt[strlen(fmt)-1] != '\n')
        missing_lf = 1;
    }

  if (level == JNLIB_LOG_FATAL)
    {
      if (missing_lf)
        es_putc_unlocked ('\n', logstream);
      es_funlockfile (logstream);
      exit (2);
    }
  else if (level == JNLIB_LOG_BUG)
    {
      if (missing_lf)
        es_putc_unlocked ('\n', logstream );
      es_funlockfile (logstream);
      abort ();
    }
  else
    es_funlockfile (logstream);
}


static void
do_log (int level, const char *fmt, ...)
{
  va_list arg_ptr ;
  
  va_start (arg_ptr, fmt) ;
  do_logv (level, 0, fmt, arg_ptr);
  va_end (arg_ptr);
}


void
log_logv (int level, const char *fmt, va_list arg_ptr)
{
  do_logv (level, 0, fmt, arg_ptr);
}


static void
do_log_ignore_arg (int level, const char *str, ...)
{
  va_list arg_ptr;
  va_start (arg_ptr, str);
  do_logv (level, 1, str, arg_ptr);
  va_end (arg_ptr);
}


void
log_string (int level, const char *string)
{
  /* We need a dummy arg_ptr, but there is no portable way to create
     one.  So we call the do_logv function through a variadic wrapper.
     MB: Why not just use "%s"?  */
  do_log_ignore_arg (level, string);
}


void
log_info (const char *fmt, ...)
{
  va_list arg_ptr ;
  
  va_start (arg_ptr, fmt);
  do_logv (JNLIB_LOG_INFO, 0, fmt, arg_ptr);
  va_end (arg_ptr);
}


void
log_error (const char *fmt, ...)
{
  va_list arg_ptr ;
  
  va_start (arg_ptr, fmt);
  do_logv (JNLIB_LOG_ERROR, 0, fmt, arg_ptr);
  va_end (arg_ptr);
  /* Protect against counter overflow.  */
  if (errorcount < 30000)
    errorcount++;
}


void
log_fatal (const char *fmt, ...)
{
  va_list arg_ptr ;
  
  va_start (arg_ptr, fmt);
  do_logv (JNLIB_LOG_FATAL, 0, fmt, arg_ptr);
  va_end (arg_ptr);
  abort (); /* Never called; just to make the compiler happy.  */
}


void
log_bug (const char *fmt, ...)
{
  va_list arg_ptr ;

  va_start (arg_ptr, fmt);
  do_logv (JNLIB_LOG_BUG, 0, fmt, arg_ptr);
  va_end (arg_ptr);
  abort (); /* Never called; just to make the compiler happy.  */
}


void
log_debug (const char *fmt, ...)
{
  va_list arg_ptr ;
  
  va_start (arg_ptr, fmt);
  do_logv (JNLIB_LOG_DEBUG, 0, fmt, arg_ptr);
  va_end (arg_ptr);
}


void
log_printf (const char *fmt, ...)
{
  va_list arg_ptr;
  
  va_start (arg_ptr, fmt);
  do_logv (fmt ? JNLIB_LOG_CONT : JNLIB_LOG_BEGIN, 0, fmt, arg_ptr);
  va_end (arg_ptr);
}


/* Flush the log - this is useful to make sure that the trailing
   linefeed has been printed.  */
void
log_flush (void)
{
  do_log_ignore_arg (JNLIB_LOG_CONT, NULL);
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
  do_log (JNLIB_LOG_BUG, ("... this is a bug (%s:%d:%s)\n"), file, line, func);
  abort (); /* Never called; just to make the compiler happy.  */
}
#else
void
bug_at( const char *file, int line )
{
  do_log (JNLIB_LOG_BUG, _("you found a bug ... (%s:%d)\n"), file, line);
  abort (); /* Never called; just to make the compiler happy.  */
}
#endif


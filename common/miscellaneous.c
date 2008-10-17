/* miscellaneous.c - Stuff not fitting elsewhere
 *	Copyright (C) 2003, 2006 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <errno.h>

#define JNLIB_NEED_LOG_LOGV
#include "util.h"
#include "iobuf.h"
#include "i18n.h"


/* Used by libgcrypt for logging.  */
static void
my_gcry_logger (void *dummy, int level, const char *fmt, va_list arg_ptr)
{
  (void)dummy;
  
  /* Map the log levels.  */
  switch (level)
    {
    case GCRY_LOG_CONT: level = JNLIB_LOG_CONT; break;
    case GCRY_LOG_INFO: level = JNLIB_LOG_INFO; break;
    case GCRY_LOG_WARN: level = JNLIB_LOG_WARN; break;
    case GCRY_LOG_ERROR:level = JNLIB_LOG_ERROR; break;
    case GCRY_LOG_FATAL:level = JNLIB_LOG_FATAL; break;
    case GCRY_LOG_BUG:  level = JNLIB_LOG_BUG; break;
    case GCRY_LOG_DEBUG:level = JNLIB_LOG_DEBUG; break;
    default:            level = JNLIB_LOG_ERROR; break;  
    }
  log_logv (level, fmt, arg_ptr);
}


/* This function is called by libgcrypt on a fatal error.  */
static void
my_gcry_fatalerror_handler (void *opaque, int rc, const char *text)
{
  (void)opaque;

  log_fatal ("libgcrypt problem: %s\n", text ? text : gpg_strerror (rc));
  abort ();
}


/* This function is called by libgcrypt if it ran out of core and
   there is no way to return that error to the caller.  We do our own
   function here to make use of our logging functions. */
static int
my_gcry_outofcore_handler (void *opaque, size_t req_n, unsigned int flags)
{
  static int been_here;  /* Used to protect against recursive calls. */

  (void)opaque;

  if (!been_here)
    {
      been_here = 1;
      if ( (flags & 1) )
        log_fatal (_("out of core in secure memory "
                     "while allocating %lu bytes"), (unsigned long)req_n);
      else
        log_fatal (_("out of core while allocating %lu bytes"),
                   (unsigned long)req_n);
    }
  return 0; /* Let libgcrypt call its own fatal error handler.
               Actually this will turn out to be
               my_gcry_fatalerror_handler. */
}


/* Setup libgcrypt to use our own logging functions.  Should be used
   early at startup. */
void
setup_libgcrypt_logging (void)
{
  gcry_set_log_handler (my_gcry_logger, NULL);
  gcry_set_fatalerror_handler (my_gcry_fatalerror_handler, NULL);
  gcry_set_outofcore_handler (my_gcry_outofcore_handler, NULL);
}



/* Decide whether the filename is stdout or a real filename and return
 * an appropriate string.  */
const char *
print_fname_stdout (const char *s)
{
    if( !s || (*s == '-' && !s[1]) )
	return "[stdout]";
    return s;
}


/* Decide whether the filename is stdin or a real filename and return
 * an appropriate string.  */
const char *
print_fname_stdin (const char *s)
{
    if( !s || (*s == '-' && !s[1]) )
	return "[stdin]";
    return s;
}

/* fixme: Globally replace it by print_sanitized_buffer. */
void
print_string( FILE *fp, const byte *p, size_t n, int delim )
{
  print_sanitized_buffer (fp, p, n, delim);
}

void
print_utf8_string2 ( FILE *fp, const byte *p, size_t n, int delim )
{
  print_sanitized_utf8_buffer (fp, p, n, delim);
}

void
print_utf8_string( FILE *fp, const byte *p, size_t n )
{
    print_utf8_string2 (fp, p, n, 0);
}

/* Write LENGTH bytes of BUFFER to FP as a hex encoded string.
   RESERVED must be 0. */
void
print_hexstring (FILE *fp, const void *buffer, size_t length, int reserved)
{
#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))
  const unsigned char *s;

  (void)reserved;

  for (s = buffer; length; s++, length--)
    {
      putc ( tohex ((*s>>4)&15), fp);
      putc ( tohex (*s&15), fp);
    }
#undef tohex
}

char *
make_printable_string (const void *p, size_t n, int delim )
{
  return sanitize_buffer (p, n, delim);
}



/*
 * Check if the file is compressed.
 */
int
is_file_compressed (const char *s, int *ret_rc)
{
    iobuf_t a;
    byte buf[4];
    int i, rc = 0;
    int overflow;

    struct magic_compress_s {
        size_t len;
        byte magic[4];
    } magic[] = {
        { 3, { 0x42, 0x5a, 0x68, 0x00 } }, /* bzip2 */
        { 3, { 0x1f, 0x8b, 0x08, 0x00 } }, /* gzip */
        { 4, { 0x50, 0x4b, 0x03, 0x04 } }, /* (pk)zip */
    };
    
    if ( iobuf_is_pipe_filename (s) || !ret_rc )
        return 0; /* We can't check stdin or no file was given */

    a = iobuf_open( s );
    if ( a == NULL ) {
        *ret_rc = gpg_error_from_syserror ();
        return 0;
    }

    if ( iobuf_get_filelength( a, &overflow ) < 4 && !overflow) {
        *ret_rc = 0;
        goto leave;
    }

    if ( iobuf_read( a, buf, 4 ) == -1 ) {
        *ret_rc = a->error;
        goto leave;
    }

    for ( i = 0; i < DIM( magic ); i++ ) {
        if ( !memcmp( buf, magic[i].magic, magic[i].len ) ) {
            *ret_rc = 0;
            rc = 1;
            break;
        }
    }

leave:    
    iobuf_close( a );
    return rc;
}


/* Try match against each substring of multistr, delimited by | */
int
match_multistr (const char *multistr,const char *match)
{
  do
    {
      size_t seglen = strcspn (multistr,"|");
      if (!seglen)
	break;
      /* Using the localized strncasecmp! */
      if (strncasecmp(multistr,match,seglen)==0)
	return 1;
      multistr += seglen;
      if (*multistr == '|')
	multistr++;
    }
  while (*multistr);

  return 0;
}



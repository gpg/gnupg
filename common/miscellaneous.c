/* miscellaneous.c - Stuff not fitting elsewhere
 *	Copyright (C) 2003, 2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

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
    case GCRY_LOG_CONT: level = GPGRT_LOG_CONT; break;
    case GCRY_LOG_INFO: level = GPGRT_LOG_INFO; break;
    case GCRY_LOG_WARN: level = GPGRT_LOG_WARN; break;
    case GCRY_LOG_ERROR:level = GPGRT_LOG_ERROR; break;
    case GCRY_LOG_FATAL:level = GPGRT_LOG_FATAL; break;
    case GCRY_LOG_BUG:  level = GPGRT_LOG_BUG; break;
    case GCRY_LOG_DEBUG:level = GPGRT_LOG_DEBUG; break;
    default:            level = GPGRT_LOG_ERROR; break;
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


/* Print an out of core message and let the process die.  The printed
 * error is taken from ERRNO.  */
void
xoutofcore (void)
{
  gpg_error_t err = gpg_error_from_syserror ();
  log_fatal (_("error allocating enough memory: %s\n"), gpg_strerror (err));
  abort (); /* Never called; just to make the compiler happy.  */
}


/* This is safe version of realloc useful for reallocing a calloced
 * array.  There are two ways to call it:  The first example
 * reallocates the array A to N elements each of SIZE but does not
 * clear the newly allocated elements:
 *
 *  p = gpgrt_reallocarray (a, n, n, nsize);
 *
 * Note that when NOLD is larger than N no cleaning is needed anyway.
 * The second example reallocates an array of size NOLD to N elements
 * each of SIZE but clear the newly allocated elements:
 *
 *  p = gpgrt_reallocarray (a, nold, n, nsize);
 *
 * Note that gnupg_reallocarray (NULL, 0, n, nsize) is equivalent to
 * gcry_calloc (n, nsize).
 */
void *
gnupg_reallocarray (void *a, size_t oldnmemb, size_t nmemb, size_t size)
{
  size_t oldbytes, bytes;
  char *p;

  bytes = nmemb * size; /* size_t is unsigned so the behavior on overflow
                         * is defined. */
  if (size && bytes / size != nmemb)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }

  p = gcry_realloc (a, bytes);
  if (p && oldnmemb < nmemb)
    {
      /* OLDNMEMBS is lower than NMEMB thus the user asked for a
         calloc.  Clear all newly allocated members.  */
      oldbytes = oldnmemb * size;
      if (size && oldbytes / size != oldnmemb)
        {
          xfree (p);
          gpg_err_set_errno (ENOMEM);
          return NULL;
        }
      memset (p + oldbytes, 0, bytes - oldbytes);
    }
  return p;
}


/* Die-on-error version of gnupg_reallocarray.   */
void *
xreallocarray (void *a, size_t oldnmemb, size_t nmemb, size_t size)
{
  void *p = gnupg_reallocarray (a, oldnmemb, nmemb, size);
  if (!p)
    xoutofcore ();
  return p;
}


/* A wrapper around gcry_cipher_algo_name to return the string
   "AES-128" instead of "AES".  Given that we have an alias in
   libgcrypt for it, it does not harm to too much to return this other
   string.  Some users complained that we print "AES" but "AES192"
   and "AES256".  We can't fix that in libgcrypt but it is pretty
   safe to do it in an application. */
const char *
gnupg_cipher_algo_name (int algo)
{
  const char *s;

  s = gcry_cipher_algo_name (algo);
  if (!strcmp (s, "AES"))
    s = "AES128";
  return s;
}


void
obsolete_option (const char *configname, unsigned int configlineno,
                 const char *name)
{
  if (configname)
    log_info (_("%s:%u: obsolete option \"%s\" - it has no effect\n"),
              configname, configlineno, name);
  else
    log_info (_("WARNING: \"%s%s\" is an obsolete option - it has no effect\n"),
              "--", name);
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


static int
do_print_utf8_buffer (estream_t stream,
                      const void *buffer, size_t length,
                      const char *delimiters, size_t *bytes_written)
{
  const char *p = buffer;
  size_t i;

  /* We can handle plain ascii simpler, so check for it first. */
  for (i=0; i < length; i++ )
    {
      if ( (p[i] & 0x80) )
        break;
    }
  if (i < length)
    {
      int delim = delimiters? *delimiters : 0;
      char *buf;
      int ret;

      /*(utf8 conversion already does the control character quoting). */
      buf = utf8_to_native (p, length, delim);
      if (bytes_written)
        *bytes_written = strlen (buf);
      ret = es_fputs (buf, stream);
      xfree (buf);
      return ret == EOF? ret : (int)i;
    }
  else
    return es_write_sanitized (stream, p, length, delimiters, bytes_written);
}


void
print_utf8_buffer3 (estream_t stream, const void *p, size_t n,
                    const char *delim)
{
  do_print_utf8_buffer (stream, p, n, delim, NULL);
}


void
print_utf8_buffer2 (estream_t stream, const void *p, size_t n, int delim)
{
  char tmp[2];

  tmp[0] = delim;
  tmp[1] = 0;
  do_print_utf8_buffer (stream, p, n, tmp, NULL);
}


void
print_utf8_buffer (estream_t stream, const void *p, size_t n)
{
  do_print_utf8_buffer (stream, p, n, NULL, NULL);
}


void
print_utf8_string (estream_t stream, const char *p)
{
  if (!p)
    p = "";
  do_print_utf8_buffer (stream, p, strlen (p), NULL, NULL);
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


/* Create a string from the buffer P_ARG of length N which is suitable
 * for printing.  Caller must release the created string using xfree.
 * On error ERRNO is set and NULL returned.  Errors are only possible
 * due to malloc failure.  */
char *
try_make_printable_string (const void *p_arg, size_t n, int delim)
{
  const unsigned char *p = p_arg;
  size_t save_n, buflen;
  const unsigned char *save_p;
  char *buffer, *d;

  /* First count length. */
  for (save_n = n, save_p = p, buflen=1 ; n; n--, p++ )
    {
      if ( *p < 0x20 || *p == 0x7f || *p == delim  || (delim && *p=='\\'))
        {
          if ( *p=='\n' || *p=='\r' || *p=='\f'
               || *p=='\v' || *p=='\b' || !*p )
            buflen += 2;
          else
            buflen += 5;
	}
      else
        buflen++;
    }
  p = save_p;
  n = save_n;
  /* And now make the string */
  d = buffer = xtrymalloc (buflen);
  for ( ; n; n--, p++ )
    {
      if (*p < 0x20 || *p == 0x7f || *p == delim || (delim && *p=='\\')) {
        *d++ = '\\';
        if( *p == '\n' )
          *d++ = 'n';
        else if( *p == '\r' )
          *d++ = 'r';
        else if( *p == '\f' )
          *d++ = 'f';
        else if( *p == '\v' )
          *d++ = 'v';
        else if( *p == '\b' )
          *d++ = 'b';
        else if( !*p )
          *d++ = '0';
        else {
          sprintf(d, "x%02x", *p );
          d += 3;
        }
      }
      else
        *d++ = *p;
    }
  *d = 0;
  return buffer;
}


/* Same as try_make_printable_string but terminates the process on
 * memory shortage.  */
char *
make_printable_string (const void *p, size_t n, int delim )
{
  char *string = try_make_printable_string (p, n, delim);
  if (!string)
    xoutofcore ();
  return string;
}


/* Decode the C formatted string SRC and return the result in a newly
 * allocated buffer.  In error returns NULL and sets ERRNO. */
char *
decode_c_string (const char *src)
{
  char *buffer, *dst;
  int val;

  /* The converted string will never be larger than the original
     string.  */
  buffer = dst = xtrymalloc (strlen (src) + 1);
  if (!buffer)
    return NULL;

  while (*src)
    {
      if (*src != '\\')
	{
	  *dst++ = *src++;
	  continue;
	}

#define DECODE_ONE(_m,_r) case _m: src += 2; *dst++ = _r; break;

      switch (src[1])
	{
	  DECODE_ONE ('n', '\n');
	  DECODE_ONE ('r', '\r');
	  DECODE_ONE ('f', '\f');
	  DECODE_ONE ('v', '\v');
	  DECODE_ONE ('b', '\b');
	  DECODE_ONE ('t', '\t');
	  DECODE_ONE ('\\', '\\');
	  DECODE_ONE ('\'', '\'');
	  DECODE_ONE ('\"', '\"');

	case 'x':
          val = hextobyte (src+2);
          if (val == -1)  /* Bad coding, keep as is. */
            {
              *dst++ = *src++;
              *dst++ = *src++;
              if (*src)
                *dst++ = *src++;
              if (*src)
                *dst++ = *src++;
            }
          else if (!val)
            {
              /* A binary zero is not representable in a C string thus
               * we keep the C-escaping.  Note that this will also
               * never be larger than the source string.  */
              *dst++ = '\\';
              *dst++ = '0';
              src += 4;
            }
          else
            {
              *(unsigned char *)dst++ = val;
              src += 4;
            }
	  break;

	default: /* Bad coding; keep as is..  */
          *dst++ = *src++;
          *dst++ = *src++;
          break;
        }
#undef DECODE_ONE
    }
  *dst++ = 0;

  return buffer;
}


/* Check whether (BUF,LEN) is valid header for an OpenPGP compressed
 * packet.  LEN should be at least 6.  */
static int
is_openpgp_compressed_packet (unsigned char *buf, size_t len)
{
  int c, ctb, pkttype;
  int lenbytes;

  ctb = *buf++; len--;
  if (!(ctb & 0x80))
    return 0; /* Invalid packet.  */

  if ((ctb & 0x40)) /* New style (OpenPGP) CTB.  */
    {
      pkttype = (ctb & 0x3f);
      if (!len)
        return 0; /* Expected first length octet missing.  */
      c = *buf++; len--;
      if (c < 192)
        ;
      else if (c < 224)
        {
          if (!len)
            return 0; /* Expected second length octet missing. */
        }
      else if (c == 255)
        {
          if (len < 4)
            return 0; /* Expected length octets missing */
        }
    }
  else /* Old style CTB.  */
    {
      pkttype = (ctb>>2)&0xf;
      lenbytes = ((ctb&3)==3)? 0 : (1<<(ctb & 3));
      if (len < lenbytes)
        return 0; /* Not enough length bytes.  */
    }

  return (pkttype == 8);
}



/*
 * Check if the file is compressed.
 */
int
is_file_compressed (const char *s, int *ret_rc)
{
    iobuf_t a;
    byte buf[6];
    int i;
    int rc = 0;
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
    iobuf_ioctl (a, IOBUF_IOCTL_NO_CACHE, 1, NULL);

    if ( iobuf_get_filelength( a, &overflow ) < 6 && !overflow) {
        *ret_rc = 0;
        goto leave;
    }

    if ( iobuf_read( a, buf, 6 ) == -1 ) {
        *ret_rc = a->error;
        goto leave;
    }

    for ( i = 0; i < DIM( magic ); i++ ) {
        if ( !memcmp( buf, magic[i].magic, magic[i].len ) ) {
            *ret_rc = 0;
            rc = 1;
            goto leave;
        }
    }

    if (is_openpgp_compressed_packet (buf, 6))
      {
        *ret_rc = 0;
        rc = 1;
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



/* Parse the first portion of the version number S and store it at
   NUMBER.  On success, the function returns a pointer into S starting
   with the first character, which is not part of the initial number
   portion; on failure, NULL is returned.  */
static const char*
parse_version_number (const char *s, int *number)
{
  int val = 0;

  if (*s == '0' && digitp (s+1))
    return NULL; /* Leading zeros are not allowed.  */
  for (; digitp (s); s++ )
    {
      val *= 10;
      val += *s - '0';
    }
  *number = val;
  return val < 0? NULL : s;
}

/* Break up the complete string representation of the version number S,
   which is expected to have this format:

      <major number>.<minor number>.<micro number><patch level>.

   The major, minor and micro number components will be stored at
   MAJOR, MINOR and MICRO. On success, a pointer to the last
   component, the patch level, will be returned; on failure, NULL will
   be returned.  */
static const char *
parse_version_string (const char *s, int *major, int *minor, int *micro)
{
  s = parse_version_number (s, major);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, minor);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, micro);
  if (!s)
    return NULL;
  return s; /* Patchlevel.  */
}

/* Return true if version string is at least version B. */
int
gnupg_compare_version (const char *a, const char *b)
{
  int a_major, a_minor, a_micro;
  int b_major, b_minor, b_micro;
  const char *a_plvl, *b_plvl;

  if (!a || !b)
    return 0;

  /* Parse version A.  */
  a_plvl = parse_version_string (a, &a_major, &a_minor, &a_micro);
  if (!a_plvl )
    return 0; /* Invalid version number.  */

  /* Parse version B.  */
  b_plvl = parse_version_string (b, &b_major, &b_minor, &b_micro);
  if (!b_plvl )
    return 0; /* Invalid version number.  */

  /* Compare version numbers.  */
  return (a_major > b_major
          || (a_major == b_major && a_minor > b_minor)
          || (a_major == b_major && a_minor == b_minor
              && a_micro > b_micro)
          || (a_major == b_major && a_minor == b_minor
              && a_micro == b_micro
              && strcmp (a_plvl, b_plvl) >= 0));
}



/* Parse an --debug style argument.  We allow the use of number values
 * in the usual C notation or a string with comma separated keywords.
 *
 * Returns: 0 on success or -1 and ERRNO set on error.  On success the
 *          supplied variable is updated by the parsed flags.
 *
 * If STRING is NULL the enabled debug flags are printed.
 *
 * See doc/DETAILS for a summary of used debug options.
 */
int
parse_debug_flag (const char *string, unsigned int *debugvar,
                  const struct debug_flags_s *flags)

{
  unsigned long result = 0;
  int i, j;

  if (!string)
    {
      if (debugvar)
        {
          log_info ("enabled debug flags:");
          for (i=0; flags[i].name; i++)
            if ((*debugvar & flags[i].flag))
              log_printf (" %s", flags[i].name);
          log_printf ("\n");
        }
      return 0;
    }

  while (spacep (string))
    string++;
  if (*string == '-')
    {
      errno = EINVAL;
      return -1;
    }

  if (!strcmp (string, "?") || !strcmp (string, "help"))
    {
      log_info ("available debug flags:\n");
      for (i=0; flags[i].name; i++)
        log_info (" %5u %s\n", flags[i].flag, flags[i].name);
      if (flags[i].flag != 77)
        exit (0);
    }
  else if (digitp (string))
    {
      errno = 0;
      result = strtoul (string, NULL, 0);
      if (result == ULONG_MAX && errno == ERANGE)
        return -1;
    }
  else
    {
      char **words;
      words = strtokenize (string, ",");
      if (!words)
        return -1;
      for (i=0; words[i]; i++)
        {
          if (*words[i])
            {
              for (j=0; flags[j].name; j++)
                if (!strcmp (words[i], flags[j].name))
                  {
                    result |= flags[j].flag;
                    break;
                  }
              if (!flags[j].name)
                {
                  if (!strcmp (words[i], "none"))
                    {
                      *debugvar = 0;
                      result = 0;
                    }
                  else if (!strcmp (words[i], "all"))
                    result = ~0;
                  else
                    log_info (_("unknown debug flag '%s' ignored\n"), words[i]);
                }
            }
        }
      xfree (words);
    }

  *debugvar |= result;
  return 0;
}



/* Parse an --comaptibility_flags style argument consisting of comma
 * separated strings.
 *
 * Returns: 0 on success or -1 and ERRNO set on error.  On success the
 *          supplied variable is updated by the parsed flags.
 *
 * If STRING is NULL the enabled flags are printed.
 */
int
parse_compatibility_flags (const char *string, unsigned int *flagvar,
                           const struct compatibility_flags_s *flags)

{
  unsigned long result = 0;
  int i, j;

  if (!string)
    {
      if (flagvar)
        {
          log_info ("enabled compatibility flags:");
          for (i=0; flags[i].name; i++)
            if ((*flagvar & flags[i].flag))
              log_printf (" %s", flags[i].name);
          log_printf ("\n");
        }
      return 0;
    }

  while (spacep (string))
    string++;

  if (!strcmp (string, "?") || !strcmp (string, "help"))
    {
      log_info ("available compatibility flags:\n");
      for (i=0; flags[i].name; i++)
        log_info (" %s\n", flags[i].name);
      if (flags[i].flag != 77)
        exit (0);
    }
  else
    {
      char **words;
      words = strtokenize (string, ",");
      if (!words)
        return -1;
      for (i=0; words[i]; i++)
        {
          if (*words[i])
            {
              for (j=0; flags[j].name; j++)
                if (!strcmp (words[i], flags[j].name))
                  {
                    result |= flags[j].flag;
                    break;
                  }
              if (!flags[j].name)
                {
                  if (!strcmp (words[i], "none"))
                    {
                      *flagvar = 0;
                      result = 0;
                    }
                  else if (!strcmp (words[i], "all"))
                    result = ~0;
                  else
                    log_info ("unknown compatibility flag '%s' ignored\n",
                              words[i]);
                }
            }
        }
      xfree (words);
    }

  *flagvar |= result;
  return 0;
}

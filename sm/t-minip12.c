/* t-minip12.c - Test driver for minip12.c
 * Copyright (C) 2020, 2023 g10 Code GmbH
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>

#include "../common/util.h"
#include "minip12.h"


#define PGM "t-minip12"

static int verbose;
static int debug;
static int any_error;

static void die (const char *format, ...) GPGRT_ATTR_NR_PRINTF(1,2);
static void err (const char *format, ...) GPGRT_ATTR_PRINTF(1,2);
static void inf (const char *format, ...) GPGRT_ATTR_PRINTF(1,2);
/* static void dbg (const char *format, ...) GPGRT_ATTR_PRINTF(1,2); */
static void printresult (const char *format, ...) GPGRT_ATTR_PRINTF(1,2);
static char *my_xstrconcat (const char *s1, ...) GPGRT_ATTR_SENTINEL(0);

#define xstrconcat my_xstrconcat
#define trim_spaces(a) my_trim_spaces ((a))
#define my_isascii(c) (!((c) & 0x80))





/* Print diagnostic message and exit with failure. */
static void
die (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  if (!*format || format[strlen(format)-1] != '\n')
    putc ('\n', stderr);

  exit (1);
}


/* Print diagnostic message. */
static void
err (const char *format, ...)
{
  va_list arg_ptr;

  any_error = 1;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  if (!*format || format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
}


/* Print an info message. */
static void
inf (const char *format, ...)
{
  va_list arg_ptr;

  if (verbose)
    {
      fprintf (stderr, "%s: ", PGM);

      va_start (arg_ptr, format);
      vfprintf (stderr, format, arg_ptr);
      va_end (arg_ptr);
      if (!*format || format[strlen(format)-1] != '\n')
        putc ('\n', stderr);
    }
}


/* Print a debug message. */
/* static void */
/* dbg (const char *format, ...) */
/* { */
/*   va_list arg_ptr; */

/*   if (debug) */
/*     { */
/*       fprintf (stderr, "%s: DBG: ", PGM); */

/*       va_start (arg_ptr, format); */
/*       vfprintf (stderr, format, arg_ptr); */
/*       va_end (arg_ptr); */
/*       if (!*format || format[strlen(format)-1] != '\n') */
/*         putc ('\n', stderr); */
/*     } */
/* } */


/* Print a result line to stdout.  */
static void
printresult (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
#ifdef HAVE_FLOCKFILE
  flockfile (stdout);
#endif
  va_start (arg_ptr, format);
  vfprintf (stdout, format, arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stdout);
  va_end (arg_ptr);
  fflush (stdout);
#ifdef HAVE_FLOCKFILE
  funlockfile (stdout);
#endif
}


/* Helper for xstrconcat and strconcat.  */
static char *
do_strconcat (int xmode, const char *s1, va_list arg_ptr)
{
  const char *argv[48];
  size_t argc;
  size_t needed;
  char *buffer, *p;

  argc = 0;
  argv[argc++] = s1;
  needed = strlen (s1);
  while (((argv[argc] = va_arg (arg_ptr, const char *))))
    {
      needed += strlen (argv[argc]);
      if (argc >= DIM (argv)-1)
        die ("too may args for strconcat\n");
      argc++;
    }
  needed++;
  buffer = xmode? xmalloc (needed) : malloc (needed);
  for (p = buffer, argc=0; argv[argc]; argc++)
    p = stpcpy (p, argv[argc]);

  return buffer;
}


/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer with the new string or dies on error. */
static char *
my_xstrconcat (const char *s1, ...)
{
  va_list arg_ptr;
  char *result;

  if (!s1)
    result = xstrdup ("");
  else
    {
      va_start (arg_ptr, s1);
      result = do_strconcat (1, s1, arg_ptr);
      va_end (arg_ptr);
    }
  return result;
}


static char *
my_trim_spaces (char *str )
{
  char *string, *p, *mark;

  string = str;
  for (p=string; *p && isspace (*(unsigned char *)p) ; p++)
    ;
  for (mark=NULL; (*string = *p); string++, p++ )
    if (isspace (*(unsigned char *)p))
      {
        if (!mark)
          mark = string;
      }
    else
      mark = NULL;
  if (mark)
    *mark = '\0';

  return str ;
}


/* Prepend FNAME with the srcdir environment variable's value and
 * return an allocated filename.  */
static char *
prepend_srcdir (const char *fname)
{
  static const char *srcdir;

  if (!srcdir && !(srcdir = getenv ("srcdir")))
    return xstrdup (fname);
  else
    return xstrconcat (srcdir, "/", fname, NULL);
}


/* (BUFFER,BUFLEN) and return a malloced hexstring.  */
static char *
hash_buffer (const void *buffer, size_t buflen)
{
  unsigned char hash[20];
  char *result;
  int i;

  gcry_md_hash_buffer (GCRY_MD_SHA1, hash, buffer, buflen);
  result = xmalloc (41);
  for (i=0; i < 20; i++)
    snprintf (result + 2*i, 3, "%02x", hash[i]);
  return result;
}


/* Read next line but skip over empty and comment lines.  Caller must
   xfree the result.  */
static char *
read_textline (FILE *fp, int *lineno)
{
  char line[4096];
  char *p;

  do
    {
      if (!fgets (line, sizeof line, fp))
        {
          if (feof (fp))
            return NULL;
          die ("error reading input line: %s\n", strerror (errno));
        }
      ++*lineno;
      p = strchr (line, '\n');
      if (!p)
        die ("input line %d not terminated or too long\n", *lineno);
      *p = 0;
      for (p--;p > line && my_isascii (*p) && isspace (*p); p--)
        *p = 0;
    }
  while (!*line || *line == '#');
  return xstrdup (line);
}


/* Copy the data after the tag to BUFFER.  BUFFER will be allocated as
   needed.  */
static void
copy_data (char **buffer, const char *line, int lineno)
{
  const char *s;

  xfree (*buffer);
  *buffer = NULL;

  s = strchr (line, ':');
  if (!s)
    {
      err ("syntax error at input line %d", lineno);
      return;
    }
  for (s++; my_isascii (*s) && isspace (*s); s++)
    ;
  *buffer = xstrdup (s);
}


static void
hexdowncase (char *string)
{
  char *p;

  if (string)
    for (p=string; *p; p++)
      if (my_isascii (*p))
        *p = tolower (*p);
}


/* Return the value of the variable VARNAME from ~/.gnupg-autogen.rc
 * or NULL if it does not exists or is empty.  */
static char *
value_from_gnupg_autogen_rc (const char *varname)
{
  const char *home;
  char *fname;
  FILE *fp;
  char *line = NULL;
  char *p;
  int lineno = 0;

  if (!(home = getenv ("HOME")))
    home = "";
  fname = xstrconcat (home, "/.gnupg-autogen.rc", NULL);
  fp = fopen (fname, "r");
  if (!fp)
    goto leave;

  while ((line = read_textline (fp, &lineno)))
    {
      p = strchr (line, '=');
      if (p)
        {
          *p++ = 0;
          trim_spaces (line);
          if (!strcmp (line, varname))
            {
              trim_spaces (p);
              if (*p)
                {
                  memmove (line, p, strlen (p)+1);
                  if (*line == '~' && line[1] == '/')
                    {
                      p = xstrconcat (home, line+1, NULL);
                      xfree (line);
                      line = p;
                    }
                  break; /* found.  */
                }
            }
        }
      xfree (line);
    }

 leave:
  if (fp)
    fclose (fp);
  xfree (fname);
  return line;
}


static void
cert_cb (void *opaque, const unsigned char *cert, size_t certlen)
{
  (void)opaque;
  (void)cert;

  if (verbose)
    log_info ("got a certificate of %zu bytes length\n", certlen);
}


/* Parse one PKCS#12 file.   Returns zero on success.  */
static int
one_file (const char *name, const char *pass)
{
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen;
  gcry_mpi_t *result;
  int badpass;
  char *curve = NULL;

  fp = fopen (name, "rb");
  if (!fp)
    {
      fprintf (stderr, PGM": can't open '%s': %s\n", name, strerror (errno));
      return 1;
    }

  if (fstat (fileno(fp), &st))
    {
      fprintf (stderr, PGM": can't stat '%s': %s\n", name, strerror (errno));
      return 1;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      fprintf (stderr, "error reading '%s': %s\n", name, strerror (errno));
      return 1;
    }
  fclose (fp);

  result = p12_parse (buf, buflen, pass, cert_cb, NULL, &badpass, &curve);
  if (result)
    {
      int i, rc;
      unsigned char *tmpbuf;

      if (curve)
        log_info ("curve: %s\n", curve);
      for (i=0; result[i]; i++)
        {
          rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &tmpbuf, NULL, result[i]);
          if (rc)
            log_error ("%d: [error printing number: %s]\n",
                       i, gpg_strerror (rc));
          else
            {
              log_info ("%d: %s\n", i, tmpbuf);
              gcry_free (tmpbuf);
            }
        }
    }
  if (badpass)
    log_error ("Bad password given?\n");

  xfree (buf);
  return 0;
}


static void
cert_collect_cb (void *opaque, const unsigned char *cert, size_t certlen)
{
  char **certstr = opaque;
  char *hash, *save;

  hash = hash_buffer (cert, certlen);
  if (*certstr)
    {
      save = *certstr;
      *certstr = xstrconcat (save, ",", hash, NULL);
      xfree (save);
      xfree (hash);
    }
  else
    *certstr = hash;
}


static int
run_one_test (const char *name, const char *desc, const char *pass,
              const char *certexpected, const char *keyexpected)
{
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen;
  gcry_mpi_t *result;
  int badpass;
  char *curve = NULL;
  char *resulthash = NULL;
  char *p;
  char *certstr = NULL;
  int ret;

  inf ("testing '%s' (%s)", name , desc? desc:"");
  fp = fopen (name, "rb");
  if (!fp)
    {
      err ("can't open '%s': %s\n", name, strerror (errno));
      printresult ("FAIL: %s - test file not found\n", name);
      return 1;
    }

  if (fstat (fileno (fp), &st))
    {
      err ("can't stat '%s': %s\n", name, strerror (errno));
      printresult ("FAIL: %s - error stating test file\n", name);
      fclose (fp);
      return 1;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      err ("error reading '%s': %s\n", name, strerror (errno));
      printresult ("FAIL: %s - error reading test file\n", name);
      fclose (fp);
      xfree (buf);
      return 1;
    }
  fclose (fp);

  result = p12_parse (buf, buflen, pass? pass:"", cert_collect_cb, &certstr,
                      &badpass, &curve);
  if (result)
    {
      int i, rc;
      char *tmpstring;
      unsigned char *tmpbuf;
      char numbuf[20];

      if (curve)
        {
          if (verbose > 1)
            inf ("curve: %s\n", curve);
          tmpstring = xstrconcat ("curve:", curve, "\n", NULL);
        }
      else
        tmpstring = xstrdup ("\n");
      for (i=0; result[i]; i++)
        {
          rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &tmpbuf, NULL, result[i]);
          if (rc)
            die ("result %d: [error printing number: %s]\n",
                 i, gpg_strerror (rc));
          else
            {
              if (verbose > 1)
                inf ("result %d: %s\n", i, tmpbuf);
              snprintf (numbuf, sizeof numbuf, "%d:", i);
              p = xstrconcat (tmpstring, numbuf, tmpbuf, "\n", NULL);
              xfree (tmpstring);
              tmpstring = p;
              gcry_free (tmpbuf);
            }
        }

      /* Hash only if we have at least one parameter; i.e. the curve
       * alone is not sufficient.  */
      if (result[0])
        resulthash = hash_buffer (tmpstring, strlen (tmpstring));
      xfree (tmpstring);
    }

  if (verbose > 1)
    {
      inf ("cert(exp)=%s", certexpected);
      inf ("cert(got)=%s", certstr? certstr:"[null]");
      inf ("key(exp)=%s", keyexpected);
      inf ("key(got)=%s", resulthash? resulthash:"[null]");
    }

  ret = 1;
  if (!result)
    printresult ("FAIL: %s - error from parser\n", name);
  else if (certexpected && !certstr)
    printresult ("FAIL: %s - expected certs but got none\n", name);
  else if (!certexpected && certstr)
    printresult ("FAIL: %s - no certs expected but got one\n", name);
  else if (certexpected && certstr && strcmp (certexpected, certstr))
    {
      printresult ("FAIL: %s - certs not as expected\n", name);
      inf ("cert(exp)=%s", certexpected);
      inf ("cert(got)=%s", certstr? certstr:"[null]");
    }
  else if (keyexpected && !resulthash)
    printresult ("FAIL: %s - expected key but got none\n", name);
  else if (!keyexpected && resulthash)
    printresult ("FAIL: %s - key not expected but got one\n", name);
  else if (keyexpected && resulthash && strcmp (keyexpected, resulthash))
    {
      printresult ("FAIL: %s - keys not as expected\n", name);
      inf ("key(exp)=%s", keyexpected);
      inf ("key(got)=%s", resulthash? resulthash:"[null]");
    }
  else
    {
      printresult ("PASS: %s\n", name);
      ret = 0;
    }

  if (result)
    {
      int i;
      for (i=0; result[i]; i++)
        gcry_mpi_release (result[i]);
      gcry_free (result);
    }
  xfree (certstr);
  xfree (resulthash);
  xfree (curve);
  xfree (buf);
  return ret;
}


/* Run a regression test using the Info take from DESCFNAME.  */
static int
run_tests_from_file (const char *descfname)
{
  FILE *fp;
  char *descdir;
  int lineno, ntests;
  char *line;
  char *name = NULL;
  char *desc = NULL;
  char *pass = NULL;
  char *cert = NULL;
  char *key = NULL;
  int ret = 0;
  char *p;

  inf ("Running tests from '%s'", descfname);
  descdir = xstrdup (descfname);
  p = strrchr (descdir, '/');
  if (p)
    *p = 0;
  else
    {
      xfree (descdir);
      descdir = xstrdup (".");
    }

  fp = fopen (descfname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", descfname, strerror (errno));

  lineno = ntests = 0;
  while ((line = read_textline (fp, &lineno)))
    {
      if (!strncmp (line, "Name:", 5))
        {
          if (name)
            ret |= run_one_test (name, desc, pass, cert, key);
          xfree (cert); cert = NULL;
          xfree (desc); desc = NULL;
          xfree (pass); pass = NULL;
          xfree (key);  key = NULL;
          copy_data (&name, line, lineno);
          if (name)
            {
              p = xstrconcat (descdir, "/", name, NULL);
              xfree (name);
              name = p;
            }
        }
      else if (!strncmp (line, "Desc:", 5))
        copy_data (&desc, line, lineno);
      else if (!strncmp (line, "Pass:", 5))
        copy_data (&pass, line, lineno);
      else if (!strncmp (line, "Cert:", 5))
        {
          p = NULL;
          copy_data (&p, line, lineno);
          hexdowncase (p);
          if (p && cert)
            {
              char *save = cert;
              cert = xstrconcat (save, ",", p, NULL);
              xfree (save);
              xfree (p);
            }
          else
            cert = p;
        }
      else if (!strncmp (line, "Key:", 4))
        {
          copy_data (&key, line, lineno);
          hexdowncase (key);
        }
      else
        inf ("%s:%d: unknown tag ignored", descfname, lineno);

      xfree (line);
    }
  if (name)
    ret |= run_one_test (name, desc, pass, cert, key);
  xfree (name);
  xfree (desc);
  xfree (pass);
  xfree (cert);
  xfree (key);

  fclose (fp);
  xfree (descdir);
  return ret;
}



int
main (int argc, char **argv)
{
  int last_argc = -1;
  char const *name = NULL;
  char const *pass = NULL;
  int ret;
  int no_extra = 0;

  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " <pkcs12file> [<passphrase>]\n"
                 "Without <pkcs12file> a regression test is run\n"
                 "Options:\n"
                 "  --no-extra          do not run extra tests\n"
                 "  --verbose           print timings etc.\n"
                 "                      given twice shows more\n"
                 "  --debug             flyswatter\n"
                 , stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--no-extra"))
        {
          no_extra = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (!argc)
    {
      name = NULL;
      pass = NULL;
    }
  else if (argc == 1)
    {
      name = argv[0];
      pass = "";
    }
  else if (argc == 2)
    {
      name = argv[0];
      pass = argv[1];
    }
  else
    {
      fprintf (stderr, "usage: " PGM " [<file> [<passphrase>]]\n");
      exit (1);
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, NULL);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL);

  if (name)
    {
      p12_set_verbosity (verbose, debug);
      ret = one_file (name, pass);
    }
  else
    {
      char *descfname, *p;

      if (verbose > 1)
        p12_set_verbosity (verbose > 1? (verbose - 1):0, debug);
      descfname = prepend_srcdir ("../tests/samplekeys/Description-p12");
      ret = run_tests_from_file (descfname);
      xfree (descfname);

      /* Check whether we have non-public regression test cases. */
      p = no_extra? NULL:value_from_gnupg_autogen_rc ("GNUPG_EXTRA_TESTS_DIR");
      if (p)
        {
          descfname = xstrconcat  (p, "/pkcs12/Description", NULL);
          xfree (p);
          ret |= run_tests_from_file (descfname);
          xfree (descfname);
        }
    }

  return ret;
}

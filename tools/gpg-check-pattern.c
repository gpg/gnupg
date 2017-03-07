/* gpg-check-pattern.c - A tool to check passphrases against pattern.
 * Copyright (C) 2007 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
# include <langinfo.h>
#endif
#ifdef HAVE_DOSISH_SYSTEM
# include <fcntl.h> /* for setmode() */
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <regex.h>
#include <ctype.h>

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/init.h"


enum cmd_and_opt_values
{ aNull = 0,
  oVerbose	  = 'v',
  oArmor          = 'a',
  oPassphrase     = 'P',

  oProtect        = 'p',
  oUnprotect      = 'u',
  oNull           = '0',

  oNoVerbose = 500,
  oCheck,

  oHomedir
};


/* The list of commands and options.  */
static ARGPARSE_OPTS opts[] = {

  { 301, NULL, 0, N_("@Options:\n ") },

  { oVerbose, "verbose",   0, "verbose" },

  { oHomedir, "homedir", 2, "@" },
  { oCheck,   "check", 0,  "run only a syntax check on the patternfile" },
  { oNull,    "null", 0,   "input is expected to be null delimited" },

  {0}
};


/* Global options are accessed through the usual OPT structure. */
static struct
{
  int verbose;
  const char *homedir;
  int checkonly;
  int null;
} opt;


enum {
  PAT_NULL,    /* Indicates end of the array.  */
  PAT_STRING,  /* The pattern is a simple string.  */
  PAT_REGEX    /* The pattern is an extended regualr expression. */
};


/* An object to decibe an item of our pattern table. */
struct pattern_s
{
  int type;
  unsigned int lineno;     /* Line number of the pattern file.  */
  union {
    struct {
      const char *string;  /* Pointer to the actual string (nul termnated).  */
      size_t length;       /* The length of this string (strlen).  */
    } s; /*PAT_STRING*/
    struct {
      /* We allocate the regex_t because this type is larger than what
         we need for PAT_STRING and we expect only a few regex in a
         patternfile.  It would be a waste of core to have so many
         unused stuff in the table.  */
      regex_t *regex;
    } r; /*PAT_REGEX*/
  } u;
};
typedef struct pattern_s pattern_t;



/*** Local prototypes ***/
static char *read_file (const char *fname, size_t *r_length);
static pattern_t *parse_pattern_file (char *data, size_t datalen);
static void process (FILE *fp, pattern_t *patarray);




/* Info function for usage().  */
static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "gpg-check-pattern (@GnuPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p =  _("Usage: gpg-check-pattern [options] patternfile (-h for help)\n");
      break;
    case 41:
      p =  _("Syntax: gpg-check-pattern [options] patternfile\n"
             "Check a passphrase given on stdin against the patternfile\n");
    break;

    default: p = NULL;
    }
  return p;
}


int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  char *raw_pattern;
  size_t raw_pattern_length;
  pattern_t *patternarray;

  early_system_init ();
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix ("gpg-check-pattern", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_INIT_SECMEM, 4096, 0);

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* (do not remove the args) */
  while (arg_parse (&pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;
        case oCheck: opt.checkonly = 1; break;
        case oNull: opt.null = 1; break;

        default : pargs.err = 2; break;
	}
    }
  if (log_get_errorcount(0))
    exit (2);

  if (argc != 1)
    usage (1);

  /* We read the entire pattern file into our memory and parse it
     using a separate function.  This allows us to eventual do the
     reading while running setuid so that the pattern file can be
     hidden from regular users.  I am not sure whether this makes
     sense, but lets be prepared for it.  */
  raw_pattern = read_file (*argv, &raw_pattern_length);
  if (!raw_pattern)
    exit (2);

  patternarray = parse_pattern_file (raw_pattern, raw_pattern_length);
  if (!patternarray)
    exit (1);
  if (opt.checkonly)
    return 0;

#ifdef HAVE_DOSISH_SYSTEM
  setmode (fileno (stdin) , O_BINARY );
#endif
  process (stdin, patternarray);

  return log_get_errorcount(0)? 1 : 0;
}



/* Read a file FNAME into a buffer and return that malloced buffer.
   Caller must free the buffer.  On error NULL is returned, on success
   the valid length of the buffer is stored at R_LENGTH.  The returned
   buffer is guarnteed to be nul terminated.  */
static char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  char *buf;
  size_t buflen;

  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = stdin;
#ifdef HAVE_DOSISH_SYSTEM
      setmode ( fileno(fp) , O_BINARY );
#endif
      buf = NULL;
      buflen = 0;
#define NCHUNK 8192
      do
        {
          bufsize += NCHUNK;
          if (!buf)
            buf = xmalloc (bufsize+1);
          else
            buf = xrealloc (buf, bufsize+1);

          nread = fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && ferror (fp))
            {
              log_error ("error reading '[stdin]': %s\n", strerror (errno));
              xfree (buf);
              return NULL;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK

    }
  else
    {
      struct stat st;

      fp = fopen (fname, "rb");
      if (!fp)
        {
          log_error ("can't open '%s': %s\n", fname, strerror (errno));
          return NULL;
        }

      if (fstat (fileno(fp), &st))
        {
          log_error ("can't stat '%s': %s\n", fname, strerror (errno));
          fclose (fp);
          return NULL;
        }

      buflen = st.st_size;
      buf = xmalloc (buflen+1);
      if (fread (buf, buflen, 1, fp) != 1)
        {
          log_error ("error reading '%s': %s\n", fname, strerror (errno));
          fclose (fp);
          xfree (buf);
          return NULL;
        }
      fclose (fp);
    }
  buf[buflen] = 0;
  *r_length = buflen;
  return buf;
}



static char *
get_regerror (int errcode, regex_t *compiled)
{
  size_t length = regerror (errcode, compiled, NULL, 0);
  char *buffer = xmalloc (length);
  regerror (errcode, compiled, buffer, length);
  return buffer;
}

/* Parse the pattern given in the memory aread DATA/DATALEN and return
   a new pattern array.  The end of the array is indicated by a NULL
   entry.  On error an error message is printed and the function
   returns NULL.  Note that the function modifies DATA and assumes
   that data is nul terminated (even if this is one byte past
   DATALEN).  */
static pattern_t *
parse_pattern_file (char *data, size_t datalen)
{
  char *p, *p2;
  size_t n;
  pattern_t *array;
  size_t arraysize, arrayidx;
  unsigned int lineno = 0;

  /* Estimate the number of entries by counting the non-comment lines.  */
  arraysize = 0;
  p = data;
  for (n = datalen; n && (p2 = memchr (p, '\n', n)); p2++, n -= p2 - p, p = p2)
    if (*p != '#')
      arraysize++;
  arraysize += 2; /* For the terminating NULL and a last line w/o a LF.  */

  array = xcalloc (arraysize, sizeof *array);
  arrayidx = 0;

  /* Loop over all lines.  */
  while (datalen && data)
    {
      lineno++;
      p = data;
      p2 = data = memchr (p, '\n', datalen);
      if (p2)
        {
          *data++ = 0;
          datalen -= data - p;
        }
      else
        p2 = p + datalen;
      assert (!*p2);
      p2--;
      while (isascii (*p) && isspace (*p))
        p++;
      if (*p == '#')
        continue;
      while (p2 > p && isascii (*p2) && isspace (*p2))
        *p2-- = 0;
      if (!*p)
        continue;
      assert (arrayidx < arraysize);
      array[arrayidx].lineno = lineno;
      if (*p == '/')
        {
          int rerr;

          p++;
          array[arrayidx].type = PAT_REGEX;
          if (*p && p[strlen(p)-1] == '/')
            p[strlen(p)-1] = 0;  /* Remove optional delimiter.  */
          array[arrayidx].u.r.regex = xcalloc (1, sizeof (regex_t));
          rerr = regcomp (array[arrayidx].u.r.regex, p,
                          REG_ICASE|REG_NOSUB|REG_EXTENDED);
          if (rerr)
            {
              char *rerrbuf = get_regerror (rerr, array[arrayidx].u.r.regex);
              log_error ("invalid r.e. at line %u: %s\n", lineno, rerrbuf);
              xfree (rerrbuf);
              if (!opt.checkonly)
                exit (1);
            }
        }
      else
        {
          array[arrayidx].type = PAT_STRING;
          array[arrayidx].u.s.string = p;
          array[arrayidx].u.s.length = strlen (p);
        }
      arrayidx++;
    }
  assert (arrayidx < arraysize);
  array[arrayidx].type = PAT_NULL;

  return array;
}


/* Check whether string macthes any of the pattern in PATARRAY and
   returns the matching pattern item or NULL.  */
static pattern_t *
match_p (const char *string, pattern_t *patarray)
{
  pattern_t *pat;

  if (!*string)
    {
      if (opt.verbose)
        log_info ("zero length input line - ignored\n");
      return NULL;
    }

  for (pat = patarray; pat->type != PAT_NULL; pat++)
    {
      if (pat->type == PAT_STRING)
        {
          if (!strcasecmp (pat->u.s.string, string))
            return pat;
        }
      else if (pat->type == PAT_REGEX)
        {
          int rerr;

          rerr = regexec (pat->u.r.regex, string, 0, NULL, 0);
          if (!rerr)
            return pat;
          else if (rerr != REG_NOMATCH)
            {
              char *rerrbuf = get_regerror (rerr, pat->u.r.regex);
              log_error ("matching r.e. failed: %s\n", rerrbuf);
              xfree (rerrbuf);
              return pat;  /* Better indicate a match on error.  */
            }
        }
      else
        BUG ();
    }
  return NULL;
}


/* Actual processing of the input.  This function does not return an
   error code but exits as soon as a match has been found.  */
static void
process (FILE *fp, pattern_t *patarray)
{
  char buffer[2048];
  size_t idx;
  int c;
  unsigned long lineno = 0;
  pattern_t *pat;

  idx = 0;
  c = 0;
  while (idx < sizeof buffer -1 && c != EOF )
    {
      if ((c = getc (fp)) != EOF)
        buffer[idx] = c;
      if ((c == '\n' && !opt.null) || (!c && opt.null) || c == EOF)
        {
          lineno++;
          if (!opt.null)
            {
              while (idx && isascii (buffer[idx-1]) && isspace (buffer[idx-1]))
                idx--;
            }
          buffer[idx] = 0;
          pat = match_p (buffer, patarray);
          if (pat)
            {
              if (opt.verbose)
                log_error ("input line %lu matches pattern at line %u"
                           " - rejected\n",
                           lineno, pat->lineno);
              exit (1);
            }
          idx = 0;
        }
      else
        idx++;
    }
  if (c != EOF)
    {
      log_error ("input line %lu too long - rejected\n", lineno+1);
      exit (1);
    }
  if (ferror (fp))
    {
      log_error ("input read error at line %lu: %s - rejected\n",
                 lineno+1, strerror (errno));
      exit (1);
    }
  if (opt.verbose)
    log_info ("no input line matches the pattern - accepted\n");
}


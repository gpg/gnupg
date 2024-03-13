/* gpg-check-pattern.c - A tool to check passphrases against pattern.
 * Copyright (C) 2021 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
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
#include <ctype.h>

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/init.h"
#include "../regexp/jimregexp.h"


enum cmd_and_opt_values
{ aNull = 0,
  oVerbose	  = 'v',

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

  ARGPARSE_end ()
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
  unsigned int newblock;   /* First pattern in a new block.     */
  unsigned int icase:1;    /* Case insensitive match.  */
  unsigned int accept:1;   /* In accept mode. */
  unsigned int reverse:1;  /* Reverse the outcome of a regexp match.  */
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
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "gpg-check-pattern (@GnuPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
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
  pargs.flags= ARGPARSE_FLAG_KEEP;
  while (gnupg_argparse (NULL, &pargs, opts))
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
  gnupg_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (log_get_errorcount(0))
    exit (2);

  if (argc != 1)
    usage (1);

  /* We read the entire pattern file into our memory and parse it
     using a separate function.  This allows us to eventually do the
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

  return 4; /*NOTREACHED*/
}



/* Read a file FNAME into a buffer and return that malloced buffer.
   Caller must free the buffer.  On error NULL is returned, on success
   the valid length of the buffer is stored at R_LENGTH.  The returned
   buffer is guarnteed to be nul terminated.  */
static char *
read_file (const char *fname, size_t *r_length)
{
  estream_t fp;
  char *buf;
  size_t buflen;

  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = es_stdin;
      es_set_binary (fp);
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

          nread = es_fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && es_ferror (fp))
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

      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          log_error ("can't open '%s': %s\n", fname, strerror (errno));
          return NULL;
        }

      if (fstat (es_fileno (fp), &st))
        {
          log_error ("can't stat '%s': %s\n", fname, strerror (errno));
          es_fclose (fp);
          return NULL;
        }

      buflen = st.st_size;
      buf = xmalloc (buflen+1);
      if (buflen && es_fread (buf, buflen, 1, fp) != 1)
        {
          log_error ("error reading '%s': %s\n", fname, strerror (errno));
          es_fclose (fp);
          xfree (buf);
          return NULL;
        }
      es_fclose (fp);
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
  unsigned int icase_mode = 1;
  unsigned int accept_mode = 0;
  unsigned int newblock = 1;  /* The first implict block.  */

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
      log_assert (!*p2);
      p2--;
      while (isascii (*p) && isspace (*p))
        p++;
      if (*p == '#')
        continue;
      while (p2 > p && isascii (*p2) && isspace (*p2))
        *p2-- = 0;
      if (!*p)
        continue;
      if (!strcmp (p, "[case]"))
        {
          icase_mode = 0;
          continue;
        }
      if (!strcmp (p, "[icase]"))
        {
          icase_mode = 1;
          continue;
        }
      if (!strcmp (p, "[accept]"))
        {
          accept_mode = 1;
          newblock = 1;
          continue;
        }
      if (!strcmp (p, "[reject]"))
        {
          accept_mode = 0;
          newblock = 1;
          continue;
        }

      log_assert (arrayidx < arraysize);
      array[arrayidx].lineno = lineno;
      array[arrayidx].icase = icase_mode;
      array[arrayidx].accept = accept_mode;
      array[arrayidx].reverse = 0;
      array[arrayidx].newblock = newblock;
      newblock = 0;

      if (*p == '/' || (*p == '!' && p[1] == '/'))
        {
          int rerr;
          int reverse;

          reverse = (*p == '!');
          p++;
          if (reverse)
            p++;
          array[arrayidx].type = PAT_REGEX;
          if (*p && p[strlen(p)-1] == '/')
            p[strlen(p)-1] = 0;  /* Remove optional delimiter.  */
          array[arrayidx].u.r.regex = xcalloc (1, sizeof (regex_t));
          array[arrayidx].reverse = reverse;
          rerr = regcomp (array[arrayidx].u.r.regex, p,
                          (array[arrayidx].icase? REG_ICASE:0)|REG_EXTENDED);
          if (rerr)
            {
              char *rerrbuf = get_regerror (rerr, array[arrayidx].u.r.regex);
              log_error ("invalid regexp at line %u: %s\n", lineno, rerrbuf);
              xfree (rerrbuf);
              if (!opt.checkonly)
                exit (1);
            }
        }
      else
        {
          if (*p == '[')
            {
              static int shown;

              if (!shown)
                {
                  log_info ("future warning: do no start a string with '['"
                            " but use a regexp (line %u)\n", lineno);
                  shown = 1;
                }
            }
          array[arrayidx].type = PAT_STRING;
          array[arrayidx].u.s.string = p;
          array[arrayidx].u.s.length = strlen (p);
        }

      arrayidx++;
    }
  log_assert (arrayidx < arraysize);
  array[arrayidx].type = PAT_NULL;

  if (lineno && newblock)
    log_info ("warning: pattern list ends with a singleton"
              " accept or reject tag\n");

  return array;
}


/* Check whether string matches any of the pattern in PATARRAY and
   returns the matching pattern item or NULL.  */
static pattern_t *
match_p (const char *string, pattern_t *patarray)
{
  pattern_t *pat;
  int match;
  int accept_match;  /* Tracks matchinf state in an accept block.  */
  int accept_skip;   /* Skip remaining patterns in an accept block.  */

  if (!*string)
    {
      if (opt.verbose)
        log_info ("zero length input line - ignored\n");
      return NULL;
    }

  accept_match = 0;
  accept_skip = 0;
  for (pat = patarray; pat->type != PAT_NULL; pat++)
    {
      match = 0;
      if (pat->newblock)
        accept_match = accept_skip = 0;

      if (pat->type == PAT_STRING)
        {
          if (pat->icase)
            {
              if (!strcasecmp (pat->u.s.string, string))
                match = 1;
            }
          else
            {
              if (!strcmp (pat->u.s.string, string))
                match = 1;
            }
        }
      else if (pat->type == PAT_REGEX)
        {
          int rerr;

          rerr = regexec (pat->u.r.regex, string, 0, NULL, 0);
          if (pat->reverse)
            {
              if (!rerr)
                rerr = REG_NOMATCH;
              else if (rerr == REG_NOMATCH)
                rerr = 0;
            }

          if (!rerr)
            match = 1;
          else if (rerr != REG_NOMATCH)
            {
              char *rerrbuf = get_regerror (rerr, pat->u.r.regex);
              log_error ("matching regexp failed: %s\n", rerrbuf);
              xfree (rerrbuf);
              if (pat->accept)
                match = 0;  /* Better indicate no match on error.  */
              else
                match = 1;  /* Better indicate a match on error.  */
            }
        }
      else
        BUG ();

      if (pat->accept)
        {
          /* Accept mode: all patterns in the accept block must match.
           * Thus we need to check whether the next pattern has a
           * transition and act only then. */
          if (match && !accept_skip)
            accept_match = 1;
          else
            {
              accept_match = 0;
              accept_skip = 1;
            }

          if (pat[1].type == PAT_NULL || pat[1].newblock)
            {
              /* Transition detected.  Note that this also handles the
               * end of pattern loop case.  */
              if (accept_match)
                return pat;
              /* The next is not really but we do it for clarity.  */
              accept_match = accept_skip = 0;
            }
        }
      else  /* Reject mode: Return true on the first match.  */
        {
          if (match)
            return pat;
        }
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
  int last_is_accept;

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
              /* Note that the accept mode works correctly only with
               * one input line.  */
              if (opt.verbose)
                log_info ("input line %lu matches pattern at line %u"
                          " - %s\n",
                          lineno, pat->lineno,
                          pat->accept? "accepted":"rejected");
            }
          idx = 0;
          wipememory (buffer, sizeof buffer);
          if (pat)
            {
              if (pat->accept)
                exit (0);
              else
                exit (1);
            }
        }
      else
        idx++;
    }
  wipememory (buffer, sizeof buffer);
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

  /* Check last pattern to see whether we are in accept mode.  */
  last_is_accept = 0;
  for (pat = patarray; pat->type != PAT_NULL; pat++)
    last_is_accept = pat->accept;

  if (opt.verbose)
    log_info ("no input line matches the pattern - %s\n",
              last_is_accept? "rejected":"accepted");

  if (log_get_errorcount(0))
    exit (2);  /* Ooops - reject.  */
  else if (last_is_accept)
    exit (1);  /* Reject */
  else
    exit (0);  /* Accept */
}

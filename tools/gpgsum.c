/* gpgsum.c - A simple hash sum tool mainly useful for Windows.
 * Copyright (C) 2023 g10 Code GmbH
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

#include <gpg-error.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
# include <fcntl.h>
# include <windows.h>
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "../common/util.h"
#include "../common/init.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"

#include <gcrypt.h>

static unsigned int filecount;
static unsigned int readerrors;
static unsigned int checkcount;
static unsigned int matcherrors;

struct {
  int algo;
  int check;
  int filenames;
} opt;

enum cmd_and_opt_values
  {
    aNull = 0,
    aCheck = 'c',
    oFileNamesFromStdIn = '0',
  };

static gpgrt_opt_t opts[] = {
  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aCheck, "check",
              N_("Read checksums from files and check them")),
  ARGPARSE_group (301, N_("@\nOptions:\n ")),
  ARGPARSE_s_n (oFileNamesFromStdIn, "filenames",
                N_("Read file names from stdin")),
  ARGPARSE_end ()
};

static void
parse_arguments (gpgrt_argparse_t *pargs, gpgrt_opt_t *popts)
{
  while (gpgrt_argparse (NULL, pargs, popts))
    {
      switch (pargs->r_opt)
        {
        case aCheck:
          opt.check = 1;
          break;
        case oFileNamesFromStdIn:
          opt.filenames = 1;
          break;
        default: pargs->err = 2; break;
        }
    }
}

static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "gpgsum (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    //case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    //case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = _("Usage: gpgsum [-c|-0] [--] FILENAMES|-");
      break;
    case 41:
      p = _("Syntax: gpgsum [-c|-0] [--] FILENAMES|-\n"
            "Create or verify hash sums for files.\n"
            "The executable must be named for the desired hash algorithm "
            "(i.e., \"sha2sum\").");
      break;

    default: p = NULL; break;
    }
  return p;
}

/* We need to escape the fname so that included linefeeds etc don't
   mess up the the output file.  On windows we also turn backslashes
   into slashes so that we don't get into conflicts with the escape
   character.  Note that the GNU version escapes the backslash and the
   LF but we also escape the CR.  */
static char *
escapefname (const char *fname, int *escaped)
{
  const char *s;
  char *buffer;
  char *d;
  size_t n;

  *escaped = 0;
  for (n = 0, s = fname; *s; s++)
    {
      if (*s == '\n' || *s == '\r')
        n += 2;
      else if (*s == '\\')
        {
#ifdef _WIN32
          n++;
#else
          n += 2;
#endif
        }
      else
        n++;
    }
  n++;
  buffer = xmalloc (n);
  d = buffer;
  for (s = fname; *s; s++)
    {
      if (*s == '\n')
        {
          *d++ = '\\';
          *d++ = 'n' ;
          *escaped = 1;
        }
      else if (*s == '\r')
        {
          *d++ = '\\';
          *d++ = 'r' ;
          *escaped = 1;
        }
      else if (*s == '\\')
        {
#ifdef _WIN32
          *d++ = '/';
#else
          *d++ = '\\';
          *d++ = '\\' ;
          *escaped = 1;
#endif
        }
      else
        *d++ = *s;
    }
  *d = 0;
  return buffer;
}


/* Revert the escaping in-place.  We handle some more of the standard
   escaping characters but not all. */
static void
unescapefname (char *fname)
{
  char *s, *d;

  for (s=d=fname; *s; s++)
    {
      if (*s == '\\' && s[1])
        {
          s++;
          switch (*s)
            {
            case '\\': *d++ = '\\'; break;
            case 'n': *d++ = '\n'; break;
            case 'r': *d++ = '\r'; break;
            case 'f': *d++ = '\f'; break;
            case 'v': *d++ = '\v'; break;
            case 'b': *d++ = '\b'; break;
            default: *d++ = '\\'; *d++ = *s; break;
            }
        }
      else
        *d++ = *s;
    }
  *d = 0;
}

static gpg_error_t
hash_file (const char *fname, const char *expected)
{
  gpg_error_t err;
  estream_t fp;
  char buffer[4096];
  size_t n;
  char *p;
  char *fnamebuf;
  int escaped;
  gcry_md_hd_t hd;
  unsigned char *result;
  unsigned int digest_length;


  digest_length = gcry_md_get_algo_dlen(opt.algo);

  filecount++;
  if (!expected && *fname == '-' && !fname[1])
    {
      /* Not in check mode and asked to read from stdin.  */
      fp = es_stdin;
      es_set_binary (es_stdin);
    }
  else
    fp = es_fopen (fname, "rb");

  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("Can't open '%s': %s\n",
               fname, gpg_strerror (err));
      if (expected)
        log_error ("%s: FAILED open\n", fname);
      readerrors++;
      return gpg_error(GPG_ERR_GENERAL);
    }

  err = gcry_md_open(&hd, opt.algo, 0);
  if (err) {
    log_error("Failed to open md: %s\n", gcry_strerror(err));
  }

  while ( (n = es_fread (buffer, 1, sizeof buffer, fp)))
    gcry_md_write(hd, buffer, n);
  if (es_ferror (fp))
    {
      log_error ("Error reading `%s': %s\n",
               fname, strerror (errno));
      if (fp != es_stdin)
        es_fclose (fp);
      if (expected)
        es_printf ("%s: FAILED read\n", fname);
      readerrors++;
      return gpg_error(GPG_ERR_GENERAL);
    }
  if (fp != es_stdin)
    es_fclose (fp);

  fnamebuf = escapefname (fname, &escaped);
  fname = fnamebuf;

  result = gcry_md_read(hd, opt.algo);
  if (!result) {
    log_error("Failed to read digest\n");
    return gpg_error(GPG_ERR_GENERAL);
  }
  checkcount++;
  bin2hex(result, digest_length, buffer);
  if (expected)
    {
      /* Lowercase the checksum.  */
      buffer[strlen(expected)] = 0;
      for (p=buffer; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
          *p |= 0x20;
      if (strcmp (buffer, expected))
        {
          es_printf ("%s: FAILED\n", fname);
          matcherrors++;
          return -1;
        }
      es_printf ("%s: OK\n", fname);
    }
  else
    es_printf ("%s%s  %s\n", escaped? "\\":"", buffer, fname);
  xfree (fnamebuf);
  return 0;
}

static gpg_error_t
check_file (const char *fname)
{
  estream_t fp;
  char *linebuf = NULL;
  char *line;
  char *p;
  size_t n;
  int rc = 0;
  int escaped;
  unsigned int digest_length;
  unsigned int name_offset;
  size_t line_length;
  size_t max_length;

  digest_length = gcry_md_get_algo_dlen(opt.algo);
  name_offset = digest_length * 2 + 2;

  if (*fname == '-' && !fname[1])
    fp = es_stdin;
  else
    fp = es_fopen (fname, "r");
  if (!fp)
    {
      log_error ("Can't open '%s': %s\n", fname, strerror(errno));
      return -1;
    }

  max_length = 4096;
  while ( es_read_line (fp, &linebuf, &line_length, &max_length) )
    {
      escaped = (*linebuf == '\\');
      line = linebuf + escaped;
      n = strlen(line);
      if (!n || line[n-1] != '\n')
        {
          log_error ("Error reading '%s': %s\n", fname,
                     es_feof (fp)? "last linefeed missing":"line too long");
          rc = -1;
          break;
        }
      line[--n] = 0;
      if (n && line[n-1] == '\r')
        line[--n] = 0;
      if (!*line)
        continue;  /* Ignore empty lines.  */
      if (n < name_offset || line[name_offset-2] != ' ')
        {
          fprintf (stderr, "Error parsing `%s': %s\n", fname,
                   "invalid line");
          rc = -1;
          continue;
        }

      /* Note that we ignore the binary flag ('*') used by GNU
         versions of this tool: It does not make sense to compute a
         digest over some transformation of a file - we always want a
         reliable checksum.  The flag does not work: On Unix a
         checksum file is created without the flag because it is the
         default there.  When checking it on Windows the missing flag
         would indicate that it has been created in text mode and thus
         the checksums will differ.  */

      /* Lowercase the checksum.  */
      line[name_offset-2] = 0;
      for (p=line; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
          *p |= 0x20;
      /* Unescape the fname.  */
      if (escaped)
        unescapefname (line+name_offset);
      /* Hash the file.  */
      if (hash_file (line+name_offset, line))
        rc = -1;
    }

  if (es_ferror (fp))
    {
      fprintf (stderr, "Error reading `%s': %s\n",
               fname, strerror (errno));
      rc = -1;
    }
  if (fp != stdin)
    es_fclose (fp);

  return rc;
}

static gpg_error_t
hash_list (void)
{
  int rc = 0;
  int ready = 0;
  int c;
  char namebuf[4096];
  size_t n = 0;
  unsigned long lastoff = 0;
  unsigned long off = 0;

  es_set_binary(es_stdin);
  do
    {
      if ((c = es_getc (es_stdin)) == EOF)
        {
          if (es_ferror (es_stdin))
            {
              log_error ("Error reading '%s' at offset %lu: %s\n",
                       "[stdin]", off, strerror (errno));
              rc = -1;
              break;
            }
          /* Note: The Nul is a delimiter and not a terminator.  */
          c = 0;
          ready = 1;
        }
      if (n >= sizeof namebuf)
        {
          log_error ("Error reading '%s': "
                   "filename at offset %lu too long\n",
                   "[stdin]", lastoff);
          rc = -1;
          break;
        }
      namebuf[n++] = c;
      off++;
      if (!c)
        {
          if (*namebuf && hash_file (namebuf, NULL))
            rc = -1;
          n = 0;
          lastoff = off;
        }
    }
  while (!ready);

  return rc;
}

int
main (int argc, char **argv)
{
  gpgrt_argparse_t pargs;
  char *executable = argv[0];
  char *maybe_executable;
  char *algo_str;

  int rc = 0;

  gnupg_reopen_std ("gpgsum");
  i18n_init();
  init_common_subsystems(&argc, &argv);

  gpgrt_set_strusage (my_strusage);
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  parse_arguments (&pargs, opts);
  gpgrt_argparse (NULL, &pargs, NULL);

#ifdef _WIN32
  maybe_executable = strrchr(executable, '\\');
#else
  maybe_executable = strrchr(executable, '/');
#endif
  if (maybe_executable)
    {
      executable = ++maybe_executable;
    }

  algo_str = executable;
  if (strlen(executable) > 3)
   {
      algo_str = gpgrt_strdup(executable);
      if (strstr(algo_str, ".exe") != NULL)
          algo_str[strlen(algo_str) - 7] = 0;
      else
          algo_str[strlen(algo_str) - 3] = 0;
   }

  opt.algo = gcry_md_map_name(algo_str);

  if (!opt.algo)
    {
        //unknown algo
        gpgrt_usage (1);
    }
  gpgrt_free(algo_str);
  if (opt.filenames && opt.check) {
    gpgrt_usage (1);
  }

  if (opt.filenames)
    {
      /* With option -0 a dash must be given as filename.  */
      if (argc != 1 || strcmp (argv[0], "-"))
        gpgrt_usage (1);
      if (hash_list ())
        rc = 1;
    }
  else
    {
      for (; argc; argv++, argc--)
        {
          if (opt.check)
            {
              if (check_file (*argv))
                rc = 1;
            }
          else
            {
              if (hash_file (*argv, NULL))
                rc = 1;
            }
        }
    }

  if (opt.check && readerrors)
    log_error ("WARNING: %u of %u listed files could not be read\n",
               readerrors, filecount);
  if (opt.check && matcherrors)
    log_error ("WARNING: %u of %u computed checksums did NOT match\n",
               matcherrors, checkcount);

  return rc;
}

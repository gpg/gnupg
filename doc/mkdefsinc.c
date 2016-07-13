/* mkdefsinc.c - Tool to create defs.inc
 * Copyright (C) 2015 g10 Code GmbH
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* This tool needs to be build with command line supplied -D options
   for the various directory variables.  See ../am/cmacros.am.  It is
   easier to do this in build file than to use fragile make rules and
   a template file.  */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PGM "mkdefsinc"

/* We include config.h after all include files because the config.h
   values are not valid for the build platform but we need some values
   nevertheless.  */
#include "config.h"
/* When building for Windows the -D macros do not have appropriate
   values.  We provide replacements here.  */
#ifdef HAVE_W32_SYSTEM
# undef  GNUPG_BINDIR
# undef  GNUPG_LIBEXECDIR
# undef  GNUPG_LIBDIR
# undef  GNUPG_DATADIR
# undef  GNUPG_SYSCONFDIR
# undef  GNUPG_LOCALSTATEDIR
# define GNUPG_BINDIR        "INSTDIR/bin"
# define GNUPG_LIBEXECDIR    "INSTDIR/bin"
# define GNUPG_LIBDIR        "INSTDIR/lib/" PACKAGE_NAME
# define GNUPG_DATADIR       "INSTDIR/share/" PACKAGE_NAME
# define GNUPG_SYSCONFDIR    "APPDATA/GNU/etc/" PACKAGE_NAME
# define GNUPG_LOCALSTATEDIR "APPDATA/GNU"
#endif /*HAVE_W32_SYSTEM*/


#if USE_GPG2_HACK
# define gpg2_suffix "2"
#else
# define gpg2_suffix ""
#endif


static int verbose;


/* The usual free wrapper.  */
static void
xfree (void *a)
{
  if (a)
    free (a);
}


static char *
xmalloc (size_t n)
{
  char *p;

  p = malloc (n);
  if (!p)
    {
      fputs (PGM ": out of core\n", stderr);
      exit (1);
    }
  return p;
}


static char *
xstrdup (const char *string)
{
  char *p;

  p = xmalloc (strlen (string)+1);
  strcpy (p, string);
  return p;
}


/* Return a malloced string with the last modification date of the
   FILES.  Returns NULL on error.  */
static char *
get_date_from_files (char **files)
{
  const char *file;
  const char *usedfile = NULL;
  struct stat sb;
  struct tm *tp;
  int errors = 0;
  time_t stamp = 0;
  char *result;

  for (; (file = *files); files++)
    {
      if (!*file || !strcmp (file, ".") || !strcmp (file, ".."))
        continue;
      if (stat (file, &sb))
        {
          fprintf (stderr, PGM ": stat failed for '%s': %s\n",
                   file, strerror (errno));
          errors = 1;
          continue;
        }
      if (sb.st_mtime > stamp)
        {
          stamp = sb.st_mtime;
          usedfile = file;
        }
    }
  if (errors)
    exit (1);

  if (usedfile)
    fprintf (stderr, PGM ": taking date from '%s'\n", usedfile);

  tp = gmtime (&stamp);
  if (!tp)
    return NULL;
  result = xmalloc (4+1+2+1+2+1);
  snprintf (result, 4+1+2+1+2+1, "%04d-%02d-%02d",
            tp->tm_year + 1900, tp->tm_mon+1, tp->tm_mday);
  return result;
}


/* We need to escape file names for Texinfo.  */
static void
print_filename (const char *prefix, const char *name)
{
  const char *s;

  fputs (prefix, stdout);
  for (s=name; *s; s++)
    switch (*s)
      {
      case '@': fputs ("@atchar{}",        stdout); break;
      case '{': fputs ("@lbracechar{}",    stdout); break;
      case '}': fputs ("@rbracechar{}",    stdout); break;
      case ',': fputs ("@comma{}",         stdout); break;
      case '\\':fputs ("@backslashchar{}", stdout); break;
      case '#': fputs ("@hashchar{}",      stdout); break;
      default: putchar (*s); break;
      }
  putchar('\n');
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  char *opt_date = NULL;
  int monthoff;
  char *p, *pend;
  size_t n;

  /* Option parsing.  */
  if (argc)
    {
      argc--; argv++;
    }
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
          fputs ("Usage: " PGM " [OPTION] [FILES]\n"
                 "Create defs.inc file.\nOptions:\n"
                 "  -C DIR         Change to DIR before doing anything\n"
                 "  --date STRING  Take publication date from STRING\n"
                 "  --verbose      Enable extra informational output\n"
                 "  --help         Display this help and exit\n"
                 , stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "-C"))
        {
          argc--; argv++;
          if (argc)
            {
              if (chdir (*argv))
                {
                  fprintf (stderr, PGM ": chdir to '%s' failed: %s\n",
                           *argv, strerror (errno));
                  exit (1);
                }
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "--date"))
        {
          argc--; argv++;
          if (argc)
            {
              opt_date = xstrdup (*argv);
              argc--; argv++;
            }
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (opt_date && *opt_date)
    {
      time_t stamp;
      struct tm *tp;

      if (*opt_date == '2' && strlen (opt_date) >= 10
          && opt_date[4] == '-' && opt_date[7] == '-')
        {
          opt_date[10] = 0;
        }
      else if ((stamp = strtoul (opt_date, NULL, 10)) > 0
               && (tp = gmtime (&stamp)))
        {
          p = xmalloc (4+1+2+1+2+1);
          snprintf (p, 4+1+2+1+2+1, "%04d-%02d-%02d",
                    tp->tm_year + 1900, tp->tm_mon+1, tp->tm_mday);
          xfree (opt_date);
          opt_date = p;
        }
      else
        {
          fprintf (stderr, PGM ": bad date '%s'\n", opt_date);
          exit (1);
        }
    }
  else
    {
      xfree (opt_date);
      opt_date = argc? get_date_from_files (argv) : NULL;
    }
  if (!opt_date)
    {
      opt_date = xstrdup ("unknown");
      monthoff = 0;
    }
  else
    {
      const char *month = "?";

      switch (atoi (opt_date+5))
        {
        case  1: month = "January"; break;
        case  2: month = "February"; break;
        case  3: month = "March"; break;
        case  4: month = "April"; break;
        case  5: month = "May"; break;
        case  6: month = "June"; break;
        case  7: month = "July"; break;
        case  8: month = "August"; break;
        case  9: month = "September"; break;
        case 10: month = "October"; break;
        case 11: month = "November"; break;
        case 12: month = "December"; break;
        }
      n = strlen (opt_date) + strlen (month) + 2 + 1;
      p = xmalloc (n);
      snprintf (p, n, "%d %n%s %d",
                atoi (opt_date+8), &monthoff, month, atoi (opt_date));
      xfree (opt_date);
      opt_date = p;
    }


  fputs ("@c defs.inc                         -*- texinfo -*-\n"
         "@c Common and build specific constants for the manuals.\n"
         "@c This file has been created by " PGM ".\n\n", stdout);

  fputs ("@ifclear defsincincluded\n"
         "@set defsincincluded 1\n\n", stdout);


  fputs ("\n@c Flags\n\n", stdout);

#if USE_GPG2_HACK
  fputs ("@set gpgtwohack 1\n\n", stdout);
#endif

  fputs ("\n@c Directories\n\n", stdout);

  print_filename ("@set BINDIR         ", GNUPG_BINDIR );
  print_filename ("@set LIBEXECDIR     ", GNUPG_LIBEXECDIR );
  print_filename ("@set LIBDIR         ", GNUPG_LIBDIR );
  print_filename ("@set DATADIR        ", GNUPG_DATADIR );
  print_filename ("@set SYSCONFDIR     ", GNUPG_SYSCONFDIR );
  print_filename ("@set LOCALSTATEDIR  ", GNUPG_LOCALSTATEDIR );
  print_filename ("@set LOCALCACHEDIR  ", (GNUPG_LOCALSTATEDIR
                                           "/cache/" PACKAGE_NAME));
  print_filename ("@set LOCALRUNDIR    ", (GNUPG_LOCALSTATEDIR
                                           "/run/"   PACKAGE_NAME));

  p = xstrdup (GNUPG_SYSCONFDIR);
  pend = strrchr (p, '/');
  fputs ("@set SYSCONFSKELDIR ", stdout);
  if (pend)
    {
      *pend = 0;
      fputs (p, stdout);
    }
  fputs ("/skel/." PACKAGE_NAME "\n", stdout);
  xfree (p);

  fputs ("\n@c Version information a la version.texi\n\n", stdout);

  printf ("@set UPDATED %s\n", opt_date);
  printf ("@set UPDATED-MONTH %s\n", opt_date + monthoff);
  printf ("@set EDITION %s\n", PACKAGE_VERSION);
  printf ("@set VERSION %s\n", PACKAGE_VERSION);

  fputs ("\n@c Algorithm defaults\n\n", stdout);

  /* Fixme: Use a config.h macro here:  */
  fputs ("@set GPGSYMENCALGO AES-128\n", stdout);

  fputs ("\n@c Macros\n\n", stdout);

  printf ("@macro gpgname\n%s%s\n@end macro\n", GPG_NAME, gpg2_suffix);
  printf ("@macro gpgvname\n%sv%s\n@end macro\n", GPG_NAME, gpg2_suffix);


  /* Trailer.  */
  fputs ("\n"
         "@end ifclear\n"
         "\n"
         "@c Loc" "al Variables:\n"
         "@c buffer-read-only: t\n"
         "@c End:\n", stdout);

  if (ferror (stdout))
    {
      fprintf (stderr, PGM ": error writing to stdout: %s\n", strerror (errno));
      return 1;
    }

  return 0;
}

/* TinyScheme-based test driver.
 *
 * Copyright (C) 2016 g10 code GmbH
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <gpg-error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#if HAVE_MMAP
#include <sys/mman.h>
#endif

#include "private.h"
#include "scheme.h"
#include "scheme-private.h"
#include "ffi.h"
#include "../common/i18n.h"
#include "../../common/argparse.h"
#include "../../common/init.h"
#include "../../common/logging.h"
#include "../../common/strlist.h"
#include "../../common/sysutils.h"
#include "../../common/util.h"

/* The TinyScheme banner.  Unfortunately, it isn't in the header
   file.  */
#define ts_banner "TinyScheme 1.41"

int verbose;



/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull	= 0,
    oVerbose	= 'v',
  };

/* The list of commands and options. */
static ARGPARSE_OPTS opts[] =
  {
    ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
    ARGPARSE_end (),
  };

char *scmpath = "";
size_t scmpath_len = 0;

/* Command line parsing.  */
static void
parse_arguments (ARGPARSE_ARGS *pargs, ARGPARSE_OPTS *popts)
{
  int no_more_options = 0;

  while (!no_more_options && optfile_parse (NULL, NULL, NULL, pargs, popts))
    {
      switch (pargs->r_opt)
        {
        case oVerbose:
          verbose++;
          break;

        default:
	  pargs->err = 2;
	  break;
	}
    }
}

/* Print usage information and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "gpgscm (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40:
      p = _("Usage: gpgscm [options] [file] (-h for help)");
      break;
    case 41:
      p = _("Syntax: gpgscm [options] [file]\n"
            "Execute the given Scheme program, or spawn interactive shell.\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


/* Load the Scheme program from FILE_NAME.  If FILE_NAME is not an
   absolute path, and LOOKUP_IN_PATH is given, then it is qualified
   with the values in scmpath until the file is found.  */
static gpg_error_t
load (scheme *sc, char *file_name,
      int lookup_in_cwd, int lookup_in_path)
{
  gpg_error_t err = 0;
  size_t n;
  const char *directory;
  char *qualified_name = file_name;
  int use_path;
  FILE *h = NULL;

  use_path =
    lookup_in_path && ! (file_name[0] == '/' || scmpath_len == 0);

  if (file_name[0] == '/' || lookup_in_cwd || scmpath_len == 0)
    {
      h = fopen (file_name, "r");
      if (! h)
        err = gpg_error_from_syserror ();
    }

  if (h == NULL && use_path)
    for (directory = scmpath, n = scmpath_len; n;
         directory += strlen (directory) + 1, n--)
      {
        if (asprintf (&qualified_name, "%s/%s", directory, file_name) < 0)
          return gpg_error_from_syserror ();

        h = fopen (qualified_name, "r");
        if (h)
          {
            err = 0;
            break;
          }

        if (n > 1)
          {
            free (qualified_name);
            continue; 	/* Try again!  */
          }

        err = gpg_error_from_syserror ();
      }

  if (h == NULL)
    {
      /* Failed and no more elements in scmpath to try.  */
      fprintf (stderr, "Could not read %s: %s.\n",
               qualified_name, gpg_strerror (err));
      if (lookup_in_path)
        fprintf (stderr,
                 "Consider using GPGSCM_PATH to specify the location "
                 "of the Scheme library.\n");
      goto leave;
    }
  if (verbose > 1)
    fprintf (stderr, "Loading %s...\n", qualified_name);

#if HAVE_MMAP
  /* Always try to mmap the file.  This allows the pages to be shared
   * between processes.  If anything fails, we fall back to using
   * buffered streams.  */
  if (1)
    {
      struct stat st;
      void *map;
      size_t len;
      int fd = fileno (h);

      if (fd < 0)
        goto fallback;

      if (fstat (fd, &st))
        goto fallback;

      len = (size_t) st.st_size;
      if ((off_t) len != st.st_size)
        goto fallback;	/* Truncated.  */

      map = mmap (NULL, len, PROT_READ, MAP_SHARED, fd, 0);
      if (map == MAP_FAILED)
        goto fallback;

      scheme_load_memory (sc, map, len, qualified_name);
      munmap (map, len);
    }
  else
  fallback:
#endif
    scheme_load_named_file (sc, h, qualified_name);
  fclose (h);

  if (sc->retcode && sc->nesting)
    {
      fprintf (stderr, "%s: Unbalanced parenthesis\n", qualified_name);
      err = gpg_error (GPG_ERR_GENERAL);
    }

 leave:
  if (file_name != qualified_name)
    free (qualified_name);
  return err;
}



int
main (int argc, char **argv)
{
  int retcode;
  gpg_error_t err;
  char *argv0;
  ARGPARSE_ARGS pargs;
  scheme *sc;
  char *p;
#if _WIN32
  char pathsep = ';';
#else
  char pathsep = ':';
#endif
  char *script = NULL;

  /* Save argv[0] so that we can re-exec.  */
  argv0 = argv[0];

  /* Parse path.  */
  if (getenv ("GPGSCM_PATH"))
    scmpath = getenv ("GPGSCM_PATH");

  p = scmpath = strdup (scmpath);
  if (p == NULL)
    return 2;

  if (*p)
    scmpath_len++;
  for (; *p; p++)
    if (*p == pathsep)
      *p = 0, scmpath_len++;

  set_strusage (my_strusage);
  log_set_prefix ("gpgscm", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION))
    {
      fputs ("libgcrypt version mismatch\n", stderr);
      exit (2);
    }

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = 0;
  parse_arguments (&pargs, opts);

  if (log_get_errorcount (0))
    exit (2);

  sc = scheme_init_new_custom_alloc (gcry_malloc, gcry_free);
  if (! sc) {
    fprintf (stderr, "Could not initialize TinyScheme!\n");
    return 2;
  }
  scheme_set_input_port_file (sc, stdin);
  scheme_set_output_port_file (sc, stderr);

  if (argc)
    {
      script = argv[0];
      argc--, argv++;
    }

  err = load (sc, "init.scm", 0, 1);
  if (! err)
    err = load (sc, "ffi.scm", 0, 1);
  if (! err)
    err = ffi_init (sc, argv0, script ? script : "interactive",
                    argc, (const char **) argv);
  if (! err)
    err = load (sc, "lib.scm", 0, 1);
  if (! err)
    err = load (sc, "repl.scm", 0, 1);
  if (! err)
    err = load (sc, "xml.scm", 0, 1);
  if (! err)
    err = load (sc, "tests.scm", 0, 1);
  if (! err)
    err = load (sc, "gnupg.scm", 0, 1);
  if (err)
    {
      fprintf (stderr, "Error initializing gpgscm: %s.\n",
               gpg_strerror (err));
      exit (2);
    }

  if (script == NULL)
    {
      /* Interactive shell.  */
      fprintf (stderr, "gpgscm/"ts_banner".\n");
      scheme_load_string (sc, "(interactive-repl)");
    }
  else
    {
      err = load (sc, script, 1, 1);
      if (err)
        log_fatal ("%s: %s", script, gpg_strerror (err));
    }

  retcode = sc->retcode;
  scheme_load_string (sc, "(*run-atexit-handlers*)");
  scheme_deinit (sc);
  xfree (sc);
  return retcode;
}

/* gpgconf.c - Configuration utility for GnuPG
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpgconf.h"
#include "i18n.h"

/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
    oDryRun	= 'n',
    oOutput	= 'o',
    oQuiet	= 'q',
    oVerbose	= 'v',
    oNoVerbose	= 500,
    oHomedir,
    
    aDummy
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] =
  {
    { 300, NULL, 0, N_("@Commands:\n ") },
    
    { 301, NULL, 0, N_("@\nOptions:\n ") },
    
    { oOutput, "output",    2, N_("use as output file")},
    { oVerbose, "verbose",  0, N_("verbose") },
    { oQuiet,	"quiet",    0, N_("be somewhat more quiet") },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
    
    /* hidden options */
    { oNoVerbose, "no-verbose",  0, "@"},
    { oHomedir,   "homedir",     2, "@" },   /* defaults to "~/.gnupg" */
    {0}
  };


/* Print usage information and and provide strings for help. */
static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "gpgconf (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p = _("Usage: gpgconf [options] (-h for help)");
      break;
    case 41:
      p = _("Syntax: gpgconf [options]\n"
            "Manage configuration options for tools of the GnuPG system\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


/* Initialize the gettext system. */
static void
i18n_init(void)
{
#ifdef USE_SIMPLE_GETTEXT
  set_gettext_file (PACKAGE);
#else
# ifdef ENABLE_NLS
#  ifdef HAVE_LC_MESSAGES
  setlocale (LC_TIME, "");
  setlocale (LC_MESSAGES, "");
#  else
  setlocale (LC_ALL, "" );
#  endif
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
# endif
#endif
}


/* gpgconf main. */
int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  const char *fname;
  int no_more_options = 0;
  enum cmd_and_opt_values cmd = 0;

  set_strusage (my_strusage);
  log_set_prefix ("gpgconf", 1);

  i18n_init();

  /* Setup the default homedir. */
#ifdef __MINGW32__
  opt.homedir = read_w32_registry_string ( NULL,
                                           "Software\\GNU\\GnuPG", "HomeDir" );
#else
  opt.homedir = getenv ("GNUPGHOME");
#endif
  if (!opt.homedir || !*opt.homedir ) 
    opt.homedir = GNUPG_DEFAULT_HOMEDIR;

  /* Patrse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags =  1;  /* do not remove the args */
  while (!no_more_options && optfile_parse (NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oOutput:    opt.outfile = pargs.r.ret_str; break;
          
        case oQuiet:     opt.quiet = 1; break;
        case oDryRun:    opt.dry_run = 1; break;
        case oVerbose:   opt.verbose++; break;
        case oNoVerbose: opt.verbose = 0; break;
        case oHomedir:   opt.homedir = pargs.r.ret_str; break;

        case aDummy: break;
        default: pargs.err = 2; break;
	}
    }
  
  if (log_get_errorcount (0))
    exit (2);
  
  fname = argc? *argv : NULL;
  
  switch (cmd)
    {
    default:
      /* List all standard options. */
      gpgconf_list_standard_options ();
      break;
    }
  
  return 0; 
}




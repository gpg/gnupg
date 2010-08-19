/* gpgconf.c - Configuration utility for GnuPG
 * Copyright (C) 2003, 2007, 2009 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpgconf.h"
#include "i18n.h"
#include "sysutils.h"

/* Constants to identify the commands and options. */
enum cmd_and_opt_values
  {
    aNull = 0,
    oDryRun	= 'n',
    oOutput	= 'o',
    oQuiet      = 'q',
    oVerbose	= 'v',
    oRuntime    = 'r',
    oComponent  = 'c',
    oNoVerbose	= 500,
    oHomedir,

    aListComponents,
    aCheckPrograms,
    aListOptions,
    aChangeOptions,
    aCheckOptions,
    aApplyDefaults,
    aListConfig,
    aCheckConfig,
    aListDirs,
    aReload

  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] =
  {
    { 300, NULL, 0, N_("@Commands:\n ") },
    
    { aListComponents, "list-components", 256, N_("list all components") },
    { aCheckPrograms, "check-programs", 256, N_("check all programs") },
    { aListOptions, "list-options", 256, N_("|COMPONENT|list options") },
    { aChangeOptions, "change-options", 256, N_("|COMPONENT|change options") },
    { aCheckOptions, "check-options", 256, N_("|COMPONENT|check options") },
    { aApplyDefaults, "apply-defaults", 256,
      N_("apply global default values") },
    { aListDirs, "list-dirs", 256,
      N_("get the configuration directories for gpgconf") },
    { aListConfig,   "list-config", 256,
      N_("list global configuration file") },
    { aCheckConfig,   "check-config", 256,
      N_("check global configuration file") },
    { aReload,        "reload", 256, "@" },

    { 301, NULL, 0, N_("@\nOptions:\n ") },
    
    { oOutput, "output",    2, N_("use as output file") },
    { oVerbose, "verbose",  0, N_("verbose") },
    { oQuiet, "quiet",      0, N_("quiet") },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
    { oRuntime, "runtime",  0, N_("activate changes at runtime, if possible") },
    /* hidden options */
    { oNoVerbose, "no-verbose",  0, "@"},
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
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

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


/* Return the fp for the output.  This is usually stdout unless
   --output has been used.  In the latter case this function opens
   that file.  */
static FILE *
get_outfp (FILE **fp)
{
  if (!*fp)
    {
      if (opt.outfile)
        {
          *fp = fopen (opt.outfile, "w");
          if (!*fp)
            gc_error (1, errno, "can not open `%s'", opt.outfile);
        }
      else
        *fp = stdout;
    }
  return *fp;
}


/* gpgconf main. */
int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  const char *fname;
  int no_more_options = 0;
  enum cmd_and_opt_values cmd = 0;
  FILE *outfp = NULL;

  gnupg_reopen_std ("gpgconf");
  set_strusage (my_strusage);
  log_set_prefix ("gpgconf", 1);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems ();

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags =  1;  /* Do not remove the args.  */
  while (!no_more_options && optfile_parse (NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oOutput:    opt.outfile = pargs.r.ret_str; break;
	case oQuiet:     opt.quiet = 1; break;
        case oDryRun:    opt.dry_run = 1; break;
        case oRuntime:
	  opt.runtime = 1;
	  break;
        case oVerbose:   opt.verbose++; break;
        case oNoVerbose: opt.verbose = 0; break;

	case aListDirs:
        case aListComponents:
        case aCheckPrograms:
        case aListOptions:
        case aChangeOptions:
        case aCheckOptions:
        case aApplyDefaults:
        case aListConfig:
        case aCheckConfig:
        case aReload:
	  cmd = pargs.r_opt;
	  break;

        default: pargs.err = 2; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);
  
  fname = argc ? *argv : NULL;
  
  switch (cmd)
    {
    case aListComponents:
    default:
      /* List all components. */
      gc_component_list_components (get_outfp (&outfp));
      break;

    case aCheckPrograms:
      /* Check all programs. */
      gc_check_programs (get_outfp (&outfp));
      break;

    case aListOptions:
    case aChangeOptions:
    case aCheckOptions:
      if (!fname)
	{
	  fputs (_("usage: gpgconf [options] "), stderr);
	  putc ('\n',stderr);
	  fputs (_("Need one component argument"), stderr);
	  putc ('\n',stderr);
	  exit (2);
	}
      else
	{
	  int idx = gc_component_find (fname);
	  if (idx < 0)
	    {
	      fputs (_("Component not found"), stderr);
	      putc ('\n', stderr);
	      exit (1);
	    }
	  if (cmd == aCheckOptions)
	    gc_component_check_options (idx, get_outfp (&outfp), NULL);
          else
            {
              gc_component_retrieve_options (idx);
              if (gc_process_gpgconf_conf (NULL, 1, 0, NULL))
                exit (1);
              if (cmd == aListOptions)
                gc_component_list_options (idx, get_outfp (&outfp));
              else if (cmd == aChangeOptions)
                gc_component_change_options (idx, stdin, get_outfp (&outfp));
            }
	}
      break;

    case aReload:
      if (!fname)
	{
          /* Reload all.  */
          gc_component_reload (-1);
	}
      else
        {
          /* Reload given component.  */
          int idx;

          idx = gc_component_find (fname);
          if (idx < 0)
            {
              fputs (_("Component not found"), stderr);
              putc ('\n', stderr);
              exit (1);
            }
          else
            {
              gc_component_reload (idx);
            }
        }
      break;

    case aListConfig:
      if (gc_process_gpgconf_conf (fname, 0, 0, get_outfp (&outfp)))
        exit (1);
      break;

    case aCheckConfig:
      if (gc_process_gpgconf_conf (fname, 0, 0, NULL))
        exit (1);
      break;

    case aApplyDefaults:
      if (fname)
	{
	  fputs (_("usage: gpgconf [options] "), stderr);
	  putc ('\n',stderr);
	  fputs (_("No argument allowed"), stderr);
	  putc ('\n',stderr);
	  exit (2);
	}
      gc_component_retrieve_options (-1);
      if (gc_process_gpgconf_conf (NULL, 1, 1, NULL))
        exit (1);
      break;
      
    case aListDirs:
      /* Show the system configuration directories for gpgconf.  */
      get_outfp (&outfp);
      fprintf (outfp, "sysconfdir:%s\n",
	       gc_percent_escape (gnupg_sysconfdir ()));
      fprintf (outfp, "bindir:%s\n",
	       gc_percent_escape (gnupg_bindir ()));
      fprintf (outfp, "libexecdir:%s\n",
	       gc_percent_escape (gnupg_libexecdir ()));
      fprintf (outfp, "libdir:%s\n",
	       gc_percent_escape (gnupg_libdir ()));
      fprintf (outfp, "datadir:%s\n",
	       gc_percent_escape (gnupg_datadir ()));
      fprintf (outfp, "localedir:%s\n",
	       gc_percent_escape (gnupg_localedir ()));
      fprintf (outfp, "dirmngr-socket:%s\n",
	       gc_percent_escape (dirmngr_socket_name ()));
      {
        char *infostr = getenv ("GPG_AGENT_INFO");

        if (!infostr || !*infostr)
          infostr = make_filename (default_homedir (), "S.gpg-agent", NULL);
        else
          {
            char *tmp;

            infostr = xstrdup (infostr);
            tmp = strchr (infostr, PATHSEP_C);
            if (!tmp || tmp == infostr)
              {
                xfree (infostr);
                infostr = NULL;
              }
            else
              *tmp = 0;
          }
        fprintf (outfp, "agent-socket:%s\n",
                 infostr? gc_percent_escape (infostr) : "");
        xfree (infostr);
      }
      {
        /* We need to use make_filename to expand a possible "~/".  */
        char *tmp = make_filename (default_homedir (), NULL);
        fprintf (outfp, "homedir:%s\n", gc_percent_escape (tmp));
        xfree (tmp);
      }
      break;
    }

  if (outfp && outfp != stdout)
    if (fclose (outfp))
      gc_error (1, errno, "error closing `%s'", opt.outfile);

  return 0; 
}


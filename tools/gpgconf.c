/* gpgconf.c - Configuration utility for GnuPG
 * Copyright (C) 2003, 2007, 2009, 2011 Free Software Foundation, Inc.
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
#include <unistd.h>

#include "gpgconf.h"
#include "i18n.h"
#include "sysutils.h"
#include "../common/init.h"


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
    oNull       = '0',
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
    aLaunch,
    aKill,
    aCreateSocketDir,
    aRemoveSocketDir,
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
      N_("get the configuration directories for @GPGCONF@") },
    { aListConfig,   "list-config", 256,
      N_("list global configuration file") },
    { aCheckConfig,   "check-config", 256,
      N_("check global configuration file") },
    { aReload,        "reload", 256, N_("reload all or a given component")},
    { aLaunch,        "launch", 256, N_("launch a given component")},
    { aKill,          "kill", 256,   N_("kill a given component")},
    { aCreateSocketDir, "create-socketdir", 256, "@"},
    { aRemoveSocketDir, "remove-socketdir", 256, "@"},

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { oOutput, "output",    2, N_("use as output file") },
    { oVerbose, "verbose",  0, N_("verbose") },
    { oQuiet, "quiet",      0, N_("quiet") },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
    { oRuntime, "runtime",  0, N_("activate changes at runtime, if possible") },
    /* hidden options */
    { oHomedir, "homedir", 2, "@" },
    { oNull, "null", 0, "@" },
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
    case 11: p = "@GPGCONF@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p = _("Usage: @GPGCONF@ [options] (-h for help)");
      break;
    case 41:
      p = _("Syntax: @GPGCONF@ [options]\n"
            "Manage configuration options for tools of the @GNUPG@ system\n");
      break;

    default: p = NULL; break;
    }
  return p;
}


/* Return the fp for the output.  This is usually stdout unless
   --output has been used.  In the latter case this function opens
   that file.  */
static estream_t
get_outfp (estream_t *fp)
{
  if (!*fp)
    {
      if (opt.outfile)
        {
          *fp = es_fopen (opt.outfile, "w");
          if (!*fp)
            gc_error (1, errno, "can not open '%s'", opt.outfile);
        }
      else
        *fp = es_stdout;
    }
  return *fp;
}


static void
list_dirs (estream_t fp, char **names)
{
  static struct {
    const char *name;
    const char *(*fnc)(void);
    const char *extra;
  } list[] = {
    { "sysconfdir",         gnupg_sysconfdir, NULL },
    { "bindir",             gnupg_bindir,     NULL },
    { "libexecdir",         gnupg_libexecdir, NULL },
    { "libdir",             gnupg_libdir,     NULL },
    { "datadir",            gnupg_datadir,    NULL },
    { "localedir",          gnupg_localedir,  NULL },
    { "socketdir",          gnupg_socketdir,  NULL },
    { "dirmngr-socket",     dirmngr_socket_name, NULL,},
    { "agent-ssh-socket",   gnupg_socketdir,  GPG_AGENT_SSH_SOCK_NAME },
    { "agent-extra-socket", gnupg_socketdir,  GPG_AGENT_EXTRA_SOCK_NAME },
    { "agent-browser-socket",gnupg_socketdir, GPG_AGENT_BROWSER_SOCK_NAME },
    { "agent-socket",       gnupg_socketdir,  GPG_AGENT_SOCK_NAME },
    { "homedir",            gnupg_homedir,    NULL }
  };
  int idx, j;
  char *tmp;
  const char *s;


  for (idx = 0; idx < DIM (list); idx++)
    {
      s = list[idx].fnc ();
      if (list[idx].extra)
        {
          tmp = make_filename (s, list[idx].extra, NULL);
          s = tmp;
        }
      else
        tmp = NULL;
      if (!names)
        es_fprintf (fp, "%s:%s\n", list[idx].name, gc_percent_escape (s));
      else
        {
          for (j=0; names[j]; j++)
            if (!strcmp (names[j], list[idx].name))
              {
                es_fputs (s, fp);
                es_putc (opt.null? '\0':'\n', fp);
              }
        }

      xfree (tmp);
    }
}


/* gpgconf main. */
int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  const char *fname;
  int no_more_options = 0;
  enum cmd_and_opt_values cmd = 0;
  estream_t outfp = NULL;

  early_system_init ();
  gnupg_reopen_std (GPGCONF_NAME);
  set_strusage (my_strusage);
  log_set_prefix (GPGCONF_NAME, GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

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
        case oHomedir:   gnupg_set_homedir (pargs.r.ret_str); break;
        case oNull:      opt.null = 1; break;

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
        case aLaunch:
        case aKill:
        case aCreateSocketDir:
        case aRemoveSocketDir:
	  cmd = pargs.r_opt;
	  break;

        default: pargs.err = 2; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }

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
	  es_fprintf (es_stderr, _("usage: %s [options] "), GPGCONF_NAME);
	  es_putc ('\n', es_stderr);
	  es_fputs (_("Need one component argument"), es_stderr);
	  es_putc ('\n', es_stderr);
	  exit (2);
	}
      else
	{
	  int idx = gc_component_find (fname);
	  if (idx < 0)
	    {
	      es_fputs (_("Component not found"), es_stderr);
	      es_putc ('\n', es_stderr);
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
                gc_component_change_options (idx, es_stdin, get_outfp (&outfp));
            }
	}
      break;

    case aLaunch:
    case aKill:
      if (!fname)
	{
	  es_fprintf (es_stderr, _("usage: %s [options] "), GPGCONF_NAME);
	  es_putc ('\n', es_stderr);
	  es_fputs (_("Need one component argument"), es_stderr);
	  es_putc ('\n', es_stderr);
	  exit (2);
	}
      else
        {
          /* Launch/Kill a given component.  */
          int idx;

          idx = gc_component_find (fname);
          if (idx < 0)
            {
              es_fputs (_("Component not found"), es_stderr);
              es_putc ('\n', es_stderr);
              exit (1);
            }
          else if (cmd == aLaunch)
            {
              if (gc_component_launch (idx))
                exit (1);
            }
          else
            {
              /* We don't error out if the kill failed because this
                 command should do nothing if the component is not
                 running.  */
              gc_component_kill (idx);
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
              es_fputs (_("Component not found"), es_stderr);
              es_putc ('\n', es_stderr);
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
	  es_fprintf (es_stderr, _("usage: %s [options] "), GPGCONF_NAME);
	  es_putc ('\n', es_stderr);
	  es_fputs (_("No argument allowed"), es_stderr);
	  es_putc ('\n', es_stderr);
	  exit (2);
	}
      gc_component_retrieve_options (-1);
      if (gc_process_gpgconf_conf (NULL, 1, 1, NULL))
        exit (1);
      break;

    case aListDirs:
      /* Show the system configuration directories for gpgconf.  */
      get_outfp (&outfp);
      list_dirs (outfp, argc? argv : NULL);
      break;

    case aCreateSocketDir:
      {
        char *socketdir;
        unsigned int flags;

        /* Make sure that the top /run/user/UID/gnupg dir has been
         * created.  */
        gnupg_socketdir ();

        /* Check the /var/run dir.  */
        socketdir = _gnupg_socketdir_internal (1, &flags);
        if ((flags & 64) && !opt.dry_run)
          {
            /* No sub dir - create it. */
            if (gnupg_mkdir (socketdir, "-rwx"))
              gc_error (1, errno, "error creating '%s'", socketdir);
            /* Try again.  */
            socketdir = _gnupg_socketdir_internal (1, &flags);
          }

        /* Give some info.  */
        if ( (flags & ~32) || opt.verbose || opt.dry_run)
          {
            log_info ("socketdir is '%s'\n", socketdir);
            if ((flags &   1)) log_info ("\tgeneral error\n");
            if ((flags &   2)) log_info ("\tno /run/user dir\n");
            if ((flags &   4)) log_info ("\tbad permissions\n");
            if ((flags &   8)) log_info ("\tbad permissions (subdir)\n");
            if ((flags &  16)) log_info ("\tmkdir failed\n");
            if ((flags &  32)) log_info ("\tnon-default homedir\n");
            if ((flags &  64)) log_info ("\tno such subdir\n");
            if ((flags & 128)) log_info ("\tusing homedir as fallback\n");
          }

        if ((flags & ~32) && !opt.dry_run)
          gc_error (1, 0, "error creating socket directory");

        xfree (socketdir);
      }
      break;

    case aRemoveSocketDir:
      {
        char *socketdir;
        unsigned int flags;

        /* Check the /var/run dir.  */
        socketdir = _gnupg_socketdir_internal (1, &flags);
        if ((flags & 128))
          log_info ("ignoring request to remove non /run/user socket dir\n");
        else if (opt.dry_run)
          ;
        else if (rmdir (socketdir))
          gc_error (1, errno, "error removing '%s'", socketdir);

        xfree (socketdir);
      }
      break;

    }

  if (outfp != es_stdout)
    if (es_fclose (outfp))
      gc_error (1, errno, "error closing '%s'", opt.outfile);

  return 0;
}

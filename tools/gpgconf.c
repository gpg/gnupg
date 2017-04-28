/* gpgconf.c - Configuration utility for GnuPG
 * Copyright (C) 2003, 2007, 2009, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2016 g10 Code GmbH.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gpgconf.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
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
    oBuilddir,

    aListComponents,
    aCheckPrograms,
    aListOptions,
    aChangeOptions,
    aCheckOptions,
    aApplyDefaults,
    aListConfig,
    aCheckConfig,
    aQuerySWDB,
    aListDirs,
    aLaunch,
    aKill,
    aCreateSocketDir,
    aRemoveSocketDir,
    aApplyProfile,
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
    { aApplyProfile, "apply-profile", 256,
      N_("|FILE|update configuration files using FILE") },
    { aListDirs, "list-dirs", 256,
      N_("get the configuration directories for @GPGCONF@") },
    { aListConfig,   "list-config", 256,
      N_("list global configuration file") },
    { aCheckConfig,   "check-config", 256,
      N_("check global configuration file") },
    { aQuerySWDB,     "query-swdb", 256,
      N_("query the software version database") },
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
    { oBuilddir, "build-prefix", 2, "@" },
    { oNull, "null", 0, "@" },
    { oNoVerbose, "no-verbose",  0, "@"},
    {0}
  };


/* Print usage information and provide strings for help. */
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



/* Check whether NAME is valid argument for query_swdb().  Valid names
 * start with a letter and contain only alphanumeric characters or an
 * underscore.  */
static int
valid_swdb_name_p (const char *name)
{
  if (!name || !*name || !alphap (name))
    return 0;

  for (name++; *name; name++)
    if (!alnump (name) && *name != '_')
      return 0;

  return 1;
}


/* Query the SWDB file.  If necessary and possible this functions asks
 * the dirmngr to load an updated version of that file.  The caller
 * needs to provide the NAME to query (e.g. "gnupg", "libgcrypt") and
 * optional the currently installed version in CURRENT_VERSION.  The
 * output written to OUT is a colon delimited line with these fields:
 *
 * name   :: The name of the package
 * curvers:: The installed version if given.
 * status :: This value tells the status of the software package
 *           '-' :: No information available
 *                  (error or CURRENT_VERSION not given)
 *           '?' :: Unknown NAME
 *           'u' :: Update available
 *           'c' :: The version is Current
 *           'n' :: The current version is already Newer than the
 *                  available one.
 * urgency :: If the value is greater than zero an urgent update is required.
 * error   :: 0 on success or an gpg_err_code_t
 *            Common codes seen:
 *            GPG_ERR_TOO_OLD :: The SWDB file is to old to be used.
 *            GPG_ERR_ENOENT  :: The SWDB file is not available.
 *            GPG_ERR_BAD_SIGNATURE :: Currupted SWDB file.
 * filedate:: Date of the swdb file (yyyymmddThhmmss)
 * verified:: Date we checked the validity of the file (yyyyymmddThhmmss)
 * version :: The version string from the swdb.
 * reldate :: Release date of that version (yyyymmddThhmmss)
 * size    :: Size of the package in bytes.
 * hash    :: SHA-2 hash of the package.
 *
 */
static void
query_swdb (estream_t out, const char *name, const char *current_version)
{
  gpg_error_t err;
  const char *search_name;
  char *fname = NULL;
  estream_t fp = NULL;
  char *line = NULL;
  char *self_version = NULL;
  size_t length_of_line = 0;
  size_t  maxlen;
  ssize_t len;
  char *fields[2];
  char *p;
  gnupg_isotime_t filedate = {0};
  gnupg_isotime_t verified = {0};
  char *value_ver = NULL;
  gnupg_isotime_t value_date = {0};
  char *value_size = NULL;
  char *value_sha2 = NULL;
  unsigned long value_size_ul = 0;
  int status, i;


  if (!valid_swdb_name_p (name))
    {
      log_error ("error in package name '%s': %s\n",
                 name, gpg_strerror (GPG_ERR_INV_NAME));
      goto leave;
    }
  if (!strcmp (name, "gnupg"))
    search_name = "gnupg21";
  else if (!strcmp (name, "gnupg1"))
    search_name = "gnupg1";
  else
    search_name = name;

  if (!current_version && !strcmp (name, "gnupg"))
    {
      /* Use our own version but string a possible beta string.  */
      self_version = xstrdup (PACKAGE_VERSION);
      p = strchr (self_version, '-');
      if (p)
        *p = 0;
      current_version = self_version;
    }

  if (current_version && (strchr (current_version, ':')
                          || compare_version_strings (current_version, NULL)))
    {
      log_error ("error in version string '%s': %s\n",
                 current_version, gpg_strerror (GPG_ERR_INV_ARG));
      goto leave;
    }

  fname = make_filename (gnupg_homedir (), "swdb.lst", NULL);
  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      es_fprintf (out, "%s:%s:-::%u:::::::\n",
                  name,
                  current_version? current_version : "",
                  gpg_err_code (err));
      if (gpg_err_code (err) != GPG_ERR_ENOENT)
        log_error (_("error opening '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }

  /* Note that the parser uses the first occurrence of a matching
   * values and ignores possible duplicated values.  */

  maxlen = 2048; /* Set limit.  */
  while ((len = es_read_line (fp, &line, &length_of_line, &maxlen)) > 0)
    {
      if (!maxlen)
        {
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
          goto leave;
        }
      /* Strip newline and carriage return, if present.  */
      while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
	line[--len] = '\0';

      if (split_fields (line, fields, DIM (fields)) < DIM(fields))
        continue; /* Skip empty lines and names w/o a value.  */
      if (*fields[0] == '#')
        continue; /* Skip comments.  */

      /* Record the meta data.  */
      if (!*filedate && !strcmp (fields[0], ".filedate"))
        {
          string2isotime (filedate, fields[1]);
          continue;
        }
      if (!*verified && !strcmp (fields[0], ".verified"))
        {
          string2isotime (verified, fields[1]);
          continue;
        }

      /* Tokenize the name.  */
      p = strrchr (fields[0], '_');
      if (!p)
        continue; /* Name w/o an underscore.  */
      *p++ = 0;

      /* Wait for the requested name.  */
      if (!strcmp (fields[0], search_name))
        {
          if (!strcmp (p, "ver") && !value_ver)
            value_ver = xstrdup (fields[1]);
          else if (!strcmp (p, "date") && !*value_date)
            string2isotime (value_date, fields[1]);
          else if (!strcmp (p, "size") && !value_size)
            value_size = xstrdup (fields[1]);
          else if (!strcmp (p, "sha2") && !value_sha2)
            value_sha2 = xstrdup (fields[1]);
        }
    }
  if (len < 0 || es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }

  if (!*filedate || !*verified)
    {
      err = gpg_error (GPG_ERR_INV_TIME);
      es_fprintf (out, "%s:%s:-::%u:::::::\n",
                  name,
                  current_version? current_version : "",
                  gpg_err_code (err));
      goto leave;
    }

  if (!value_ver)
    {
      es_fprintf (out, "%s:%s:?:::::::::\n",
                  name,
                  current_version? current_version : "");
      goto leave;
    }

  if (value_size)
    {
      gpg_err_set_errno (0);
      value_size_ul = strtoul (value_size, &p, 10);
      if (errno)
        value_size_ul = 0;
      else if (*p == 'k')
        value_size_ul *= 1024;
    }

  err = 0;
  status = '-';
  if (compare_version_strings (value_ver, NULL))
    err = gpg_error (GPG_ERR_INV_VALUE);
  else if (!current_version)
    ;
  else if (!(i = compare_version_strings (value_ver, current_version)))
    status = 'c';
  else if (i > 0)
    status = 'u';
  else
    status = 'n';

  es_fprintf (out, "%s:%s:%c::%d:%s:%s:%s:%s:%lu:%s:\n",
              name,
              current_version? current_version : "",
              status,
              err,
              filedate,
              verified,
              value_ver,
              value_date,
              value_size_ul,
              value_sha2? value_sha2 : "");

 leave:
  xfree (value_ver);
  xfree (value_size);
  xfree (value_sha2);
  xfree (line);
  es_fclose (fp);
  xfree (fname);
  xfree (self_version);
}


/* gpgconf main. */
int
main (int argc, char **argv)
{
  gpg_error_t err;
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
  gc_components_init ();

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
        case oBuilddir:  gnupg_set_builddir (pargs.r.ret_str); break;
        case oNull:      opt.null = 1; break;

	case aListDirs:
        case aListComponents:
        case aCheckPrograms:
        case aListOptions:
        case aChangeOptions:
        case aCheckOptions:
        case aApplyDefaults:
        case aApplyProfile:
        case aListConfig:
        case aCheckConfig:
        case aQuerySWDB:
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
                gc_component_change_options (idx, es_stdin,
                                             get_outfp (&outfp), 0);
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
      else if (!strcmp (fname, "all"))
        {
          if (cmd == aLaunch)
            {
              if (gc_component_launch (-1))
                exit (1);
            }
          else
            {
              gc_component_kill (-1);
            }
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
      if (!fname || !strcmp (fname, "all"))
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

    case aApplyProfile:
      gc_component_retrieve_options (-1);
      if (gc_apply_profile (fname))
        exit (1);
      break;

    case aListDirs:
      /* Show the system configuration directories for gpgconf.  */
      get_outfp (&outfp);
      list_dirs (outfp, argc? argv : NULL);
      break;

    case aQuerySWDB:
      /* Query the software version database.  */
      if (!fname || argc > 2)
	{
	  es_fprintf (es_stderr, "usage: %s --query-swdb NAME [VERSION]\n",
                      GPGCONF_NAME);
	  exit (2);
	}
      get_outfp (&outfp);
      query_swdb (outfp, fname, argc > 1? argv[1] : NULL);
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
            xfree (socketdir);
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
          {
            /* If the director is not empty we first try to delet
             * socket files.  */
            err = gpg_error_from_syserror ();
            if (gpg_err_code (err) == GPG_ERR_ENOTEMPTY
                || gpg_err_code (err) == GPG_ERR_EEXIST)
              {
                static const char * const names[] = {
                  GPG_AGENT_SOCK_NAME,
                  GPG_AGENT_EXTRA_SOCK_NAME,
                  GPG_AGENT_BROWSER_SOCK_NAME,
                  GPG_AGENT_SSH_SOCK_NAME,
                  SCDAEMON_SOCK_NAME,
                  DIRMNGR_SOCK_NAME
                };
                int i;
                char *p;

                for (i=0; i < DIM(names); i++)
                  {
                    p = strconcat (socketdir , "/", names[i], NULL);
                    if (p)
                      gnupg_remove (p);
                    xfree (p);
                  }
                if (rmdir (socketdir))
                  gc_error (1, 0, "error removing '%s': %s",
                            socketdir, gpg_strerror (err));
              }
            else if (gpg_err_code (err) == GPG_ERR_ENOENT)
              gc_error (0, 0, "warning: removing '%s' failed: %s",
                        socketdir, gpg_strerror (err));
            else
              gc_error (1, 0, "error removing '%s': %s",
                        socketdir, gpg_strerror (err));
          }

        xfree (socketdir);
      }
      break;

    }

  if (outfp != es_stdout)
    if (es_fclose (outfp))
      gc_error (1, errno, "error closing '%s'", opt.outfile);

  return 0;
}

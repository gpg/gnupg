/* g13-syshelp.c - Helper for disk key management with GnuPG
 * Copyright (C) 2015 Werner Koch
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
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif
#include <unistd.h>

#include "g13-syshelp.h"

#include <gcrypt.h>
#include <assuan.h>

#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/asshelp.h"
#include "../common/init.h"
#include "keyblob.h"


enum cmd_and_opt_values {
  aNull = 0,
  oQuiet	= 'q',
  oVerbose	= 'v',
  oRecipient	= 'r',

  aGPGConfList  = 500,

  oDebug,
  oDebugLevel,
  oDebugAll,
  oDebugNone,
  oDebugWait,
  oDebugAllowCoreDump,
  oLogFile,
  oNoLogFile,
  oAuditLog,

  oOutput,

  oAgentProgram,
  oGpgProgram,
  oType,

  oDisplay,
  oTTYname,
  oTTYtype,
  oLCctype,
  oLCmessages,
  oXauthority,

  oStatusFD,
  oLoggerFD,

  oNoVerbose,
  oNoSecmemWarn,
  oHomedir,
  oDryRun,
  oNoDetach,

  oNoRandomSeedFile,
  oFakedSystemTime
 };


static ARGPARSE_OPTS opts[] = {

  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  N_("be somewhat more quiet")),

  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level",
                N_("|LEVEL|set the debugging level to LEVEL")),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugNone, "debug-none", "@"),
  ARGPARSE_s_i (oDebugWait, "debug-wait", "@"),
  ARGPARSE_s_n (oDebugAllowCoreDump, "debug-allow-core-dump", "@"),

  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MOUNT_VALUE  , "mount"  },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_IPC_VALUE    , "ipc"     },
    { 0, NULL }
  };


/* The timer tick interval used by the idle task.  */
#define TIMERTICK_INTERVAL_SEC     (1)

/* It is possible that we are currently running under setuid permissions.  */
static int maybe_setuid = 1;

/* Helper to implement --debug-level and --debug.  */
static const char *debug_level;
static unsigned int debug_value;


/* Local prototypes.  */
static void g13_syshelp_deinit_default_ctrl (ctrl_t ctrl);
static void release_tab_items (tab_item_t tab);
static tab_item_t parse_g13tab (const char *username);



static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "@G13@-syshelp (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p = _("Usage: @G13@-syshelp [options] [files] (-h for help)");
      break;
    case 41:
      p = _("Syntax: @G13@-syshelp [options] [files]\n"
            "Helper to perform root-only tasks for g13\n");
      break;

    case 31: p = "\nHome: "; break;
    case 32: p = gnupg_homedir (); break;

    default: p = NULL; break;
    }
  return p;
}


/* Setup the debugging.  With a DEBUG_LEVEL of NULL only the active
   debug flags are propagated to the subsystems.  With DEBUG_LEVEL
   set, a specific set of debug flags is set; and individual debugging
   flags will be added on top.  */
static void
set_debug (void)
{
  int numok = (debug_level && digitp (debug_level));
  int numlvl = numok? atoi (debug_level) : 0;

  if (!debug_level)
    ;
  else if (!strcmp (debug_level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp (debug_level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_IPC_VALUE|DBG_MOUNT_VALUE;
  else if (!strcmp (debug_level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_IPC_VALUE|DBG_MOUNT_VALUE;
  else if (!strcmp (debug_level, "expert") || (numok && numlvl <= 8))
    opt.debug = (DBG_IPC_VALUE|DBG_MOUNT_VALUE|DBG_CRYPTO_VALUE);
  else if (!strcmp (debug_level, "guru") || numok)
    {
      opt.debug = ~0;
      /* if (numok) */
      /*   opt.debug &= ~(DBG_HASHING_VALUE); */
    }
  else
    {
      log_error (_("invalid debug-level '%s' given\n"), debug_level);
      g13_exit(2);
    }

  opt.debug |= debug_value;

  if (opt.debug && !opt.verbose)
    opt.verbose = 1;
  if (opt.debug)
    opt.quiet = 0;

  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}


int
main ( int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  gpg_error_t err = 0;
  /* const char *fname; */
  int may_coredump;
  FILE *configfp = NULL;
  char *configname = NULL;
  unsigned configlineno;
  int parse_debug = 0;
  int no_more_options = 0;
  int default_config =1;
  char *logfile = NULL;
  /* int debug_wait = 0; */
  int use_random_seed = 1;
  /* int nodetach = 0; */
  /* int nokeysetup = 0; */
  struct server_control_s ctrl;

  /*mtrace();*/

  early_system_init ();
  gnupg_reopen_std (G13_NAME "-syshelp");
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

  log_set_prefix (G13_NAME "-syshelp", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  /* Take extra care of the random pool.  */
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  g13_init_signals ();

  dotlock_create (NULL, 0); /* Register locking cleanup.  */

  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));

  /* Fixme: We enable verbose mode here because there is currently no
     way to do this when starting g13-syshelp.  To fix that we should
     add a g13-syshelp.conf file in /etc/gnupg.  */
  opt.verbose = 1;

  /* First check whether we have a debug option on the commandline.  */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);
  while (arg_parse( &pargs, opts))
    {
      if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
        parse_debug++;
    }

  /* Initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  maybe_setuid = 0;

  /*
     Now we are now working under our real uid
  */

  /* Setup malloc hooks. */
  {
    struct assuan_malloc_hooks malloc_hooks;

    malloc_hooks.malloc = gcry_malloc;
    malloc_hooks.realloc = gcry_realloc;
    malloc_hooks.free = gcry_free;
    assuan_set_malloc_hooks (&malloc_hooks);
  }

  /* Prepare libassuan.  */
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  /*assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);*/
  setup_libassuan_logging (&opt.debug, NULL);

  /* Setup a default control structure for command line mode.  */
  memset (&ctrl, 0, sizeof ctrl);
  g13_syshelp_init_default_ctrl (&ctrl);
  ctrl.no_server = 1;
  ctrl.status_fd = -1; /* No status output. */

  if (default_config )
    configname = make_filename (gnupg_sysconfdir (),
                                G13_NAME"-syshelp.conf", NULL);

  argc        = orig_argc;
  argv        = orig_argv;
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags =  1;  /* Do not remove the args.  */

 next_pass:
  if (configname)
    {
      configlineno = 0;
      configfp = fopen (configname, "r");
      if (!configfp)
        {
          if (default_config)
            {
              if (parse_debug)
                log_info (_("NOTE: no default option file '%s'\n"), configname);
            }
          else
            {
              log_error (_("option file '%s': %s\n"),
                         configname, strerror(errno));
              g13_exit(2);
            }
          xfree (configname);
          configname = NULL;
        }
      if (parse_debug && configname)
        log_info (_("reading options from '%s'\n"), configname);
      default_config = 0;
    }

  while (!no_more_options
         && optfile_parse (configfp, configname, &configlineno, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oQuiet: opt.quiet = 1; break;

        case oDryRun: opt.dry_run = 1; break;

        case oVerbose:
          opt.verbose++;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;
        case oNoVerbose:
          opt.verbose = 0;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;

        case oLogFile: logfile = pargs.r.ret_str; break;
        case oNoLogFile: logfile = NULL; break;

        case oNoDetach: /*nodetach = 1; */break;

        case oDebug:
          if (parse_debug_flag (pargs.r.ret_str, &opt.debug, debug_flags))
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err = ARGPARSE_PRINT_ERROR;
            }
            break;
        case oDebugAll: debug_value = ~0; break;
        case oDebugNone: debug_value = 0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugWait: /*debug_wait = pargs.r.ret_int; */break;
        case oDebugAllowCoreDump:
          may_coredump = enable_core_dumps ();
          break;

        case oStatusFD: ctrl.status_fd = pargs.r.ret_int; break;
        case oLoggerFD: log_set_fd (pargs.r.ret_int ); break;

        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;

        case oFakedSystemTime:
          {
            time_t faked_time = isotime2epoch (pargs.r.ret_str);
            if (faked_time == (time_t)(-1))
              faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
            gnupg_set_time (faked_time, 0);
          }
          break;

        case oNoSecmemWarn: gcry_control (GCRYCTL_DISABLE_SECMEM_WARN); break;

        case oNoRandomSeedFile: use_random_seed = 0; break;

        default:
          pargs.err = configfp? ARGPARSE_PRINT_WARNING:ARGPARSE_PRINT_ERROR;
          break;
	}
    }

  if (configfp)
    {
      fclose (configfp);
      configfp = NULL;
      /* Keep a copy of the config filename. */
      opt.config_filename = configname;
      configname = NULL;
      goto next_pass;
    }
  xfree (configname);
  configname = NULL;

  if (!opt.config_filename)
    opt.config_filename = make_filename (gnupg_homedir (),
                                         G13_NAME".conf", NULL);

  if (log_get_errorcount(0))
    g13_exit(2);

  /* Now that we have the options parsed we need to update the default
     control structure.  */
  g13_syshelp_init_default_ctrl (&ctrl);

  if (may_coredump && !opt.quiet)
    log_info (_("WARNING: program may create a core file!\n"));

  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, GPGRT_LOG_WITH_PREFIX | GPGRT_LOG_WITH_TIME | GPGRT_LOG_WITH_PID);
    }

  if (gnupg_faked_time_p ())
    {
      gnupg_isotime_t tbuf;

      log_info (_("WARNING: running with faked system time: "));
      gnupg_get_isotime (tbuf);
      dump_isotime (tbuf);
      log_printf ("\n");
    }

  /* Print any pending secure memory warnings.  */
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  /* Setup the debug flags for all subsystems.  */
  set_debug ();

  /* Install a regular exit handler to make real sure that the secure
     memory gets wiped out.  */
  g13_install_emergency_cleanup ();

  /* Terminate if we found any error until now.  */
  if (log_get_errorcount(0))
    g13_exit (2);

  /* Set the standard GnuPG random seed file.  */
  if (use_random_seed)
    {
      char *p = make_filename (gnupg_homedir (), "random_seed", NULL);
      gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, p);
      xfree(p);
    }

  /* Get the UID of the caller.  */
#if defined(HAVE_PWD_H) && defined(HAVE_GETPWUID)
  {
    const char *uidstr;
    struct passwd *pwd = NULL;

    uidstr = getenv ("USERV_UID");

    /* Print a quick note if we are not started via userv.  */
    if (!uidstr)
      {
        if (getuid ())
          {
            log_info ("WARNING: Not started via userv\n");
            ctrl.fail_all_cmds = 1;
          }
        ctrl.client.uid = getuid ();
      }
    else
      {
        unsigned long myuid;

        errno = 0;
        myuid = strtoul (uidstr, NULL, 10);
        if (myuid == ULONG_MAX && errno)
          {
            log_info ("WARNING: Started via broken userv: %s\n",
                      strerror (errno));
            ctrl.fail_all_cmds = 1;
            ctrl.client.uid = getuid ();
          }
        else
          ctrl.client.uid = (uid_t)myuid;
      }

    pwd = getpwuid (ctrl.client.uid);
    if (!pwd || !*pwd->pw_name)
      {
        log_info ("WARNING: Name for UID not found: %s\n", strerror (errno));
        ctrl.fail_all_cmds = 1;
        ctrl.client.uname = xstrdup ("?");
      }
    else
      ctrl.client.uname = xstrdup (pwd->pw_name);

    /* Check that the user name does not contain a directory
       separator. */
    if (strchr (ctrl.client.uname, '/'))
      {
        log_info ("WARNING: Invalid user name passed\n");
        ctrl.fail_all_cmds = 1;
      }
  }
#else /*!HAVE_PWD_H || !HAVE_GETPWUID*/
  log_info ("WARNING: System does not support required syscalls\n");
  ctrl.fail_all_cmds = 1;
  ctrl.client.uid = getuid ();
  ctrl.client.uname = xstrdup ("?");
#endif /*!HAVE_PWD_H || !HAVE_GETPWUID*/

  /* Read the table entries for this user.  */
  if (!ctrl.fail_all_cmds
      && !(ctrl.client.tab = parse_g13tab (ctrl.client.uname)))
    ctrl.fail_all_cmds = 1;

  /* Start the server.  */
  err = syshelp_server (&ctrl);
  if (err)
    log_error ("server exited with error: %s <%s>\n",
               gpg_strerror (err), gpg_strsource (err));

  /* Cleanup.  */
  g13_syshelp_deinit_default_ctrl (&ctrl);
  g13_exit (0);
  return 8; /*NOTREACHED*/
}


/* Store defaults into the per-connection CTRL object.  */
void
g13_syshelp_init_default_ctrl (ctrl_t ctrl)
{
  ctrl->conttype = CONTTYPE_DM_CRYPT;
}

/* Release all resources allocated by default in the CTRl object.  */
static void
g13_syshelp_deinit_default_ctrl (ctrl_t ctrl)
{
  xfree (ctrl->client.uname);
  release_tab_items (ctrl->client.tab);
}


/* Release the list of g13tab itejms at TAB.  */
static void
release_tab_items (tab_item_t tab)
{
  while (tab)
    {
      tab_item_t next = tab->next;
      xfree (tab->mountpoint);
      xfree (tab);
      tab = next;
    }
}


void
g13_syshelp_i_know_what_i_am_doing (void)
{
  const char * const yesfile = "Yes-g13-I-know-what-I-am-doing";
  char *fname;

  fname = make_filename (gnupg_sysconfdir (), yesfile, NULL);
  if (access (fname, F_OK))
    {
      log_info ("*******************************************************\n");
      log_info ("* The G13 support for DM-Crypt is new and not matured.\n");
      log_info ("* Bugs or improper use may delete all your disks!\n");
      log_info ("* To confirm that you are ware of this risk, create\n");
      log_info ("* the file '%s'.\n", fname);
      log_info ("*******************************************************\n");
      exit (1);
    }
  xfree (fname);
}


/* Parse the /etc/gnupg/g13tab for user USERNAME.  Return a table for
   the user on success.  Return NULL on error and print
   diagnostics. */
static tab_item_t
parse_g13tab (const char *username)
{
  gpg_error_t err;
  int c, n;
  char line[512];
  char *p;
  char *fname;
  estream_t fp;
  int lnr;
  char **words = NULL;
  tab_item_t table = NULL;
  tab_item_t *tabletail, ti;

  fname = make_filename (gnupg_sysconfdir (), G13_NAME"tab", NULL);
  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error opening '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }

  tabletail = &table;
  err = 0;
  lnr = 0;
  while (es_fgets (line, DIM(line)-1, fp))
    {
      lnr++;
      n = strlen (line);
      if (!n || line[n-1] != '\n')
        {
          /* Eat until end of line. */
          while ((c=es_getc (fp)) != EOF && c != '\n')
            ;
          err = gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                           : GPG_ERR_INCOMPLETE_LINE);
          log_error (_("file '%s', line %d: %s\n"),
                     fname, lnr, gpg_strerror (err));
          continue;
        }
      line[--n] = 0; /* Chop the LF. */
      if (n && line[n-1] == '\r')
        line[--n] = 0; /* Chop an optional CR. */

      /* Allow for empty lines and spaces */
      for (p=line; spacep (p); p++)
        ;
      if (!*p || *p == '#')
        continue;

      /* Parse the line.  The format is
       * <username> <blockdev> [<label>|"-" [<mountpoint>]]
       */
      xfree (words);
      words = strtokenize (p, " \t");
      if (!words)
        {
          err = gpg_error_from_syserror ();
          break;
        }
      if (!words[0] || !words[1])
        {
          log_error (_("file '%s', line %d: %s\n"),
                     fname, lnr, gpg_strerror (GPG_ERR_SYNTAX));
          continue;
        }
      if (!(*words[1] == '/'
            || !strncmp (words[1], "PARTUUID=", 9)
            || !strncmp (words[1], "partuuid=", 9)))
        {
          log_error (_("file '%s', line %d: %s\n"),
                     fname, lnr, "Invalid block device syntax");
          continue;
        }
      if (words[2])
        {
          if (strlen (words[2]) > 16 || strchr (words[2], '/'))
            {
              log_error (_("file '%s', line %d: %s\n"),
                         fname, lnr, "Label too long or invalid syntax");
              continue;
            }

          if (words[3] && *words[3] != '/')
            {
              log_error (_("file '%s', line %d: %s\n"),
                         fname, lnr, "Invalid mountpoint syntax");
              continue;
            }
        }
      if (strcmp (words[0], username))
        continue; /* Skip entries for other usernames!  */

      ti = xtrymalloc (sizeof *ti + strlen (words[1]));
      if (!ti)
        {
          err = gpg_error_from_syserror ();
          break;
        }
      ti->next = NULL;
      ti->label = NULL;
      ti->mountpoint = NULL;
      strcpy (ti->blockdev, *words[1]=='/'? words[1] : words[1]+9);
      if (words[2])
        {
          if (strcmp (words[2], "-")
              && !(ti->label = xtrystrdup (words[2])))
            {
              err = gpg_error_from_syserror ();
              xfree (ti);
              break;
            }
          if (words[3] && !(ti->mountpoint = xtrystrdup (words[3])))
            {
              err = gpg_error_from_syserror ();
              xfree (ti->label);
              xfree (ti);
              break;
            }
        }
      *tabletail = ti;
      tabletail = &ti->next;
    }

  if (!err && !es_feof (fp))
    err = gpg_error_from_syserror ();
  if (err)
    log_error (_("error reading '%s', line %d: %s\n"),
               fname, lnr, gpg_strerror (err));

 leave:
  xfree (words);
  es_fclose (fp);
  xfree (fname);
  if (err)
    {
      release_tab_items (table);
      return NULL;
    }
  return table;
}

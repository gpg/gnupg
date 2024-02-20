/* g13.c - Disk Key management with GnuPG
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <npth.h>

#define INCLUDED_BY_MAIN_MODULE 1
#include "g13.h"

#include <gcrypt.h>
#include <assuan.h>

#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/gc-opt-flags.h"
#include "../common/asshelp.h"
#include "../common/init.h"
#include "keyblob.h"
#include "server.h"
#include "runner.h"
#include "create.h"
#include "mount.h"
#include "suspend.h"
#include "mountinfo.h"
#include "backend.h"
#include "call-syshelp.h"


enum cmd_and_opt_values {
  aNull = 0,
  oQuiet	= 'q',
  oVerbose	= 'v',
  oRecipient	= 'r',

  aGPGConfList  = 500,
  aGPGConfTest,
  aCreate,
  aMount,
  aUmount,
  aSuspend,
  aResume,
  aServer,
  aFindDevice,

  oOptions,
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
  oNoGreeting,
  oNoTTY,
  oNoOptions,
  oHomedir,
  oWithColons,
  oDryRun,
  oNoDetach,
  oNoMount,

  oNoRandomSeedFile,
  oFakedSystemTime
 };


static gpgrt_opt_t opts[] = {

  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aCreate, "create", N_("Create a new file system container")),
  ARGPARSE_c (aMount,  "mount",  N_("Mount a file system container") ),
  ARGPARSE_c (aUmount, "umount", N_("Unmount a file system container") ),
  ARGPARSE_c (aSuspend, "suspend", N_("Suspend a file system container") ),
  ARGPARSE_c (aResume,  "resume",  N_("Resume a file system container") ),
  ARGPARSE_c (aServer, "server", N_("Run in server mode")),
  ARGPARSE_c (aFindDevice, "find-device", "@"),

  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
  ARGPARSE_s_s (oType, "type", N_("|NAME|use container format NAME")),

  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  N_("be somewhat more quiet")),
  ARGPARSE_s_n (oNoTTY, "no-tty", N_("don't use the terminal at all")),
  ARGPARSE_s_n (oNoDetach, "no-detach", N_("do not detach from the console")),
  ARGPARSE_s_s (oLogFile, "log-file",  N_("|FILE|write log output to FILE")),
  ARGPARSE_s_n (oNoLogFile, "no-log-file", "@"),
  ARGPARSE_s_i (oLoggerFD, "logger-fd", "@"),
  ARGPARSE_s_n (oNoMount, "no-mount", N_("stop right before running mount")),

  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),

  ARGPARSE_conffile (oOptions, "options", N_("|FILE|read options from FILE")),

  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level",
                N_("|LEVEL|set the debugging level to LEVEL")),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugNone, "debug-none", "@"),
  ARGPARSE_s_i (oDebugWait, "debug-wait", "@"),
  ARGPARSE_s_n (oDebugAllowCoreDump, "debug-allow-core-dump", "@"),

  ARGPARSE_s_i (oStatusFD, "status-fd",
                N_("|FD|write status info to this FD")),

  ARGPARSE_group (302, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
  )),

  ARGPARSE_group (303, N_("@\nExamples:\n\n"
    " blurb\n"
                          " blurb\n")),

  /* Hidden options. */
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),
  ARGPARSE_s_n (oNoSecmemWarn, "no-secmem-warning", "@"),
  ARGPARSE_s_n (oNoGreeting, "no-greeting", "@"),
  ARGPARSE_noconffile (oNoOptions, "no-options", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg-program", "@"),
  ARGPARSE_s_s (oDisplay,    "display", "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname", "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype", "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype", "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages", "@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oNoRandomSeedFile,  "no-random-seed-file", "@"),

  /* Command aliases.  */

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

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* The thread id of the idle task.  */
static npth_t idle_task_thread;


/* The container type as specified on the command line.  */
static int cmdline_conttype;



static void set_cmd (enum cmd_and_opt_values *ret_cmd,
                     enum cmd_and_opt_values new_cmd );

static void start_idle_task (void);
static void join_idle_task (void);


/* Begin NPth wrapper functions. */
ASSUAN_SYSTEM_NPTH_IMPL;


static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "@G13@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p = _("Usage: @G13@ [options] [files] (-h for help)");
      break;
    case 41:
      p = _("Syntax: @G13@ [options] [files]\n"
            "Create, mount or unmount an encrypted file system container\n");
      break;

    case 31: p = "\nHome: "; break;
    case 32: p = gnupg_homedir (); break;

    default: p = NULL; break;
    }
  return p;
}


static void
wrong_args (const char *text)
{
  fprintf (stderr, _("usage: %s [options] "), G13_NAME);
  fputs (text, stderr);
  putc ('\n', stderr);
  g13_exit (2);
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



static void
set_cmd (enum cmd_and_opt_values *ret_cmd, enum cmd_and_opt_values new_cmd)
{
  enum cmd_and_opt_values cmd = *ret_cmd;

  if (!cmd || cmd == new_cmd)
    cmd = new_cmd;
  else
    {
      log_error (_("conflicting commands\n"));
      g13_exit (2);
    }

  *ret_cmd = cmd;
}


int
main (int argc, char **argv)
{
  gpgrt_argparse_t pargs;
  int orig_argc;
  char **orig_argv;
  gpg_error_t err = 0;
  /* const char *fname; */
  int may_coredump;
  char *last_configname = NULL;
  const char *configname = NULL;
  int debug_argparser = 0;
  int no_more_options = 0;
  char *logfile = NULL;
  int greeting = 0;
  int nogreeting = 0;
  /* int debug_wait = 0; */
  int use_random_seed = 1;
  /* int nodetach = 0; */
  /* int nokeysetup = 0; */
  enum cmd_and_opt_values cmd = 0;
  struct server_control_s ctrl;
  strlist_t recipients = NULL;

  /*mtrace();*/

  early_system_init ();
  gnupg_reopen_std (G13_NAME);
  gpgrt_set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

  log_set_prefix (G13_NAME, GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  npth_init ();

  /* Take extra care of the random pool.  */
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  g13_init_signals ();

  dotlock_create (NULL, 0); /* Register locking cleanup.  */

  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));

  /* First check whether we have a config file on the commandline.  */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);
  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oDebug:
        case oDebugAll:
          debug_argparser++;
          break;

        case oHomedir:
          gnupg_set_homedir (pargs.r.ret_str);
          break;
        }
    }
  /* Reset the flags.  */
  pargs.flags &= ~(ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);

  /* Initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  maybe_setuid = 0;

  /*
   *  Now we are now working under our real uid
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
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  setup_libassuan_logging (&opt.debug, NULL);

  /* Setup a default control structure for command line mode.  */
  memset (&ctrl, 0, sizeof ctrl);
  g13_init_default_ctrl (&ctrl);
  ctrl.no_server = 1;
  ctrl.status_fd = -1; /* No status output. */

  /* The configuraton directories for use by gpgrt_argparser.  */
  gpgrt_set_confdir (GPGRT_CONFDIR_SYS, gnupg_sysconfdir ());
  gpgrt_set_confdir (GPGRT_CONFDIR_USER, gnupg_homedir ());

  /* We are re-using the struct, thus the reset flag.  We OR the
   * flags so that the internal intialized flag won't be cleared. */
  argc        = orig_argc;
  argv        = orig_argv;
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags |=  (ARGPARSE_FLAG_RESET
                   | ARGPARSE_FLAG_KEEP
#if GPGRT_VERSION_NUMBER >= 0x013000 /* >= 1.48 */
                   | ARGPARSE_FLAG_COMMAND
#endif
                   | ARGPARSE_FLAG_SYS
                   | ARGPARSE_FLAG_USER);

  while (!no_more_options
         && gpgrt_argparser (&pargs, opts, G13_NAME EXTSEP_S "conf"))
    {
      switch (pargs.r_opt)
        {
        case ARGPARSE_CONFFILE:
          {
            if (debug_argparser)
              log_info (_("reading options from '%s'\n"),
                        pargs.r_type? pargs.r.ret_str: "[cmdline]");
            if (pargs.r_type)
              {
                xfree (last_configname);
                last_configname = xstrdup (pargs.r.ret_str);
                configname = last_configname;
              }
            else
              configname = NULL;
          }
          break;

	case aGPGConfList:
	case aGPGConfTest:
          set_cmd (&cmd, pargs.r_opt);
          nogreeting = 1;
          /* nokeysetup = 1; */
          break;

        case aServer:
        case aMount:
        case aUmount:
        case aSuspend:
        case aResume:
        case aCreate:
        case aFindDevice:
          set_cmd (&cmd, pargs.r_opt);
          break;

        case oOutput: opt.outfile = pargs.r.ret_str; break;

        case oQuiet: opt.quiet = 1; break;
        case oNoGreeting: nogreeting = 1; break;
        case oNoTTY:  break;

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

        case oNoMount: opt.no_mount = 1; break;

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

        case oAgentProgram: opt.agent_program = pargs.r.ret_str;  break;
        case oGpgProgram: opt.gpg_program = pargs.r.ret_str;  break;
        case oDisplay: opt.display = xstrdup (pargs.r.ret_str); break;
        case oTTYname: opt.ttyname = xstrdup (pargs.r.ret_str); break;
        case oTTYtype: opt.ttytype = xstrdup (pargs.r.ret_str); break;
        case oLCctype: opt.lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: opt.lc_messages = xstrdup (pargs.r.ret_str); break;
        case oXauthority: opt.xauthority = xstrdup (pargs.r.ret_str); break;

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

        case oRecipient: /* Store the encryption key.  */
          add_to_strlist (&recipients, pargs.r.ret_str);
          break;

        case oType:
          if (!strcmp (pargs.r.ret_str, "help"))
            {
              be_parse_conttype_name (NULL);
              g13_exit (0);
            }
          cmdline_conttype = be_parse_conttype_name (pargs.r.ret_str);
          if (!cmdline_conttype)
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err = ARGPARSE_PRINT_ERROR;
            }
          break;

        default:
          if (configname)
            pargs.err = ARGPARSE_PRINT_WARNING;
          else
            pargs.err = ARGPARSE_PRINT_ERROR;
          break;
	}
    }

  gpgrt_argparse (NULL, &pargs, NULL);

  /* Construct GPG arguments.  */
  {
    strlist_t last;
    last = append_to_strlist (&opt.gpg_arguments, "-z");
    last = append_to_strlist (&last, "0");
    last = append_to_strlist (&last, "--trust-model");
    last = append_to_strlist (&last, "always");
    (void) last;
  }

  if (!last_configname)
    opt.config_filename = gpgrt_fnameconcat (gnupg_homedir (),
                                             G13_NAME EXTSEP_S "conf",
                                             NULL);
  else
    {
      opt.config_filename = last_configname;
      last_configname = NULL;
    }

  if (log_get_errorcount(0))
    g13_exit(2);

  /* Now that we have the options parsed we need to update the default
     control structure.  */
  g13_init_default_ctrl (&ctrl);
  ctrl.recipients = recipients;
  recipients = NULL;

  if (nogreeting)
    greeting = 0;

  if (greeting)
    {
      fprintf (stderr, "%s %s; %s\n",
               gpgrt_strusage(11), gpgrt_strusage(13), gpgrt_strusage(14) );
      fprintf (stderr, "%s\n", gpgrt_strusage(15));
    }

  if (may_coredump && !opt.quiet)
    log_info (_("WARNING: program may create a core file!\n"));

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }


  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, (GPGRT_LOG_WITH_PREFIX
                             | GPGRT_LOG_WITH_TIME
                             | GPGRT_LOG_WITH_PID));
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

  /* Install emergency cleanup handler.  */
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

  /* Store given filename into FNAME. */
  /* fname = argc? *argv : NULL; */

  /* Parse all given encryption keys.  This does a lookup of the keys
     and stops if any of the given keys was not found. */
#if 0 /* Currently not implemented.  */
  if (!nokeysetup)
    {
      strlist_t sl;
      int failed = 0;

      for (sl = ctrl->recipients; sl; sl = sl->next)
        if (check_encryption_key ())
          failed = 1;
      if (failed)
        g13_exit (1);
    }
#endif /*0*/

  /* Dispatch command.  */
  err = 0;
  switch (cmd)
    {
    case aGPGConfList:
      { /* List options and default values in the GPG Conf format.  */
	char *config_filename_esc = percent_escape (opt.config_filename, NULL);

        printf ("gpgconf-g13.conf:%lu:\"%s\n",
                GC_OPT_FLAG_DEFAULT, config_filename_esc);
        xfree (config_filename_esc);

        printf ("verbose:%lu:\n", GC_OPT_FLAG_NONE);
	printf ("quiet:%lu:\n", GC_OPT_FLAG_NONE);
	printf ("debug-level:%lu:\"none:\n", GC_OPT_FLAG_DEFAULT);
	printf ("log-file:%lu:\n", GC_OPT_FLAG_NONE);
      }
      break;
    case aGPGConfTest:
      /* This is merely a dummy command to test whether the
         configuration file is valid.  */
      break;

    case aServer:
      {
        start_idle_task ();
        ctrl.no_server = 0;
        err = g13_server (&ctrl);
        if (err)
          log_error ("server exited with error: %s <%s>\n",
                     gpg_strerror (err), gpg_strsource (err));
        else
          g13_request_shutdown ();
      }
      break;

    case aFindDevice:
      {
        char *blockdev;

        if (argc != 1)
          wrong_args ("--find-device name");

        err = call_syshelp_find_device (&ctrl, argv[0], &blockdev);
        if (err)
          log_error ("error finding device '%s': %s <%s>\n",
                     argv[0], gpg_strerror (err), gpg_strsource (err));
        else
          puts (blockdev);
      }
      break;

    case aCreate: /* Create a new container. */
      {
        if (argc != 1)
          wrong_args ("--create filename");
        start_idle_task ();
        err = g13_create_container (&ctrl, argv[0]);
        if (err)
          log_error ("error creating a new container: %s <%s>\n",
                     gpg_strerror (err), gpg_strsource (err));
        else
          g13_request_shutdown ();
      }
      break;

    case aMount: /* Mount a container. */
      {
        if (argc != 1 && argc != 2 )
          wrong_args ("--mount filename [mountpoint]");
        start_idle_task ();
        err = g13_mount_container (&ctrl, argv[0], argc == 2?argv[1]:NULL);
        if (err)
          log_error ("error mounting container '%s': %s <%s>\n",
                     *argv, gpg_strerror (err), gpg_strsource (err));
      }
      break;

    case aUmount: /* Unmount a mounted container.  */
      {
        if (argc != 1)
          wrong_args ("--umount filename");
        err = g13_umount_container (&ctrl, argv[0], NULL);
        if (err)
          log_error ("error unmounting container '%s': %s <%s>\n",
                     *argv, gpg_strerror (err), gpg_strsource (err));
      }
      break;

    case aSuspend: /* Suspend a container. */
      {
        /* Fixme: Should we add a suspend all container option?  */
        if (argc != 1)
          wrong_args ("--suspend filename");
        err = g13_suspend_container (&ctrl, argv[0]);
        if (err)
          log_error ("error suspending container '%s': %s <%s>\n",
                     *argv, gpg_strerror (err), gpg_strsource (err));
      }
      break;

    case aResume: /* Resume a suspended container. */
      {
        /* Fixme: Should we add a resume all container option?  */
        if (argc != 1)
          wrong_args ("--resume filename");
        err = g13_resume_container (&ctrl, argv[0]);
        if (err)
          log_error ("error resuming container '%s': %s <%s>\n",
                     *argv, gpg_strerror (err), gpg_strsource (err));
      }
      break;

    default:
      log_error (_("invalid command (there is no implicit command)\n"));
      break;
    }

  g13_deinit_default_ctrl (&ctrl);

  if (!err)
    join_idle_task ();

  /* Cleanup.  */
  g13_exit (0);
  return 8; /*NOTREACHED*/
}


/* Store defaults into the per-connection CTRL object.  */
void
g13_init_default_ctrl (ctrl_t ctrl)
{
  ctrl->conttype = cmdline_conttype? cmdline_conttype : CONTTYPE_ENCFS;
}


/* Release remaining resources allocated in the CTRL object.  */
void
g13_deinit_default_ctrl (ctrl_t ctrl)
{
  call_syshelp_release (ctrl);
  FREE_STRLIST (ctrl->recipients);
}


/* Request a shutdown.  This can be used when the process should
 * finish instead of running the idle task.  */
void
g13_request_shutdown (void)
{
  shutdown_pending++;
}


/* This function is called for each signal we catch.  It is run in the
   main context or the one of a NPth thread and thus it is not
   restricted in what it may do.  */
static void
handle_signal (int signo)
{
  switch (signo)
    {
#ifndef HAVE_W32_SYSTEM
    case SIGHUP:
      log_info ("SIGHUP received - re-reading configuration\n");
      /* Fixme:  Not yet implemented.  */
      break;

    case SIGUSR1:
      log_info ("SIGUSR1 received - printing internal information:\n");
      /* Fixme: We need to see how to integrate pth dumping into our
         logging system.  */
      /* pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ()); */
      mountinfo_dump_all ();
      break;

    case SIGUSR2:
      log_info ("SIGUSR2 received - no action defined\n");
      break;

    case SIGTERM:
      if (!shutdown_pending)
        log_info ("SIGTERM received - shutting down ...\n");
      else
        log_info ("SIGTERM received - still %u runners active\n",
                  runner_get_threads ());
      shutdown_pending++;
      if (shutdown_pending > 2)
        {
          log_info ("shutdown forced\n");
          log_info ("%s %s stopped\n", gpgrt_strusage(11), gpgrt_strusage(13) );
          g13_exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      log_info( "%s %s stopped\n", gpgrt_strusage(11), gpgrt_strusage(13));
      g13_exit (0);
      break;
#endif /*!HAVE_W32_SYSTEM*/

    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}


/* This ticker function is called about every TIMERTICK_INTERVAL_SEC
   seconds. */
static void
handle_tick (void)
{
  /* log_debug ("TICK\n"); */
}


/* The idle task.  We use a separate thread to do idle stuff and to
   catch signals.  */
static void *
idle_task (void *dummy_arg)
{
  int signo;           /* The number of a raised signal is stored here.  */
  int saved_errno;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
  int ret;

  (void)dummy_arg;

  /* Create the event to catch the signals. */
#ifndef HAVE_W32_SYSTEM
  npth_sigev_init ();
  npth_sigev_add (SIGHUP);
  npth_sigev_add (SIGUSR1);
  npth_sigev_add (SIGUSR2);
  npth_sigev_add (SIGINT);
  npth_sigev_add (SIGTERM);
  npth_sigev_fini ();
#endif

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL_SEC;

  for (;;)
    {
      /* The shutdown flag allows us to terminate the idle task.  */
      if (shutdown_pending)
        {
          runner_cancel_all ();

          if (!runner_get_threads ())
            break; /* ready */
	}

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  /* Timeout.  */
	  handle_tick ();
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL_SEC;
	}
      npth_timersub (&abstime, &curtime, &timeout);

#ifndef HAVE_W32_SYSTEM
      ret = npth_pselect (0, NULL, NULL, NULL, &timeout, npth_sigev_sigmask());
      saved_errno = errno;

      while (npth_sigev_get_pending(&signo))
	handle_signal (signo);
#else
      ret = npth_eselect (0, NULL, NULL, NULL, &timeout, NULL, NULL);
      saved_errno = errno;
#endif

      if (ret == -1 && saved_errno != EINTR)
	{
          log_error (_("npth_pselect failed: %s - waiting 1s\n"),
                     strerror (saved_errno));
          npth_sleep (1);
          continue;
	}

      if (ret <= 0)
        {
          /* Interrupt or timeout.  Will be handled when calculating the
             next timeout.  */
          continue;
        }

      /* Here one would add processing of file descriptors.  */
    }

  log_info (_("%s %s stopped\n"), gpgrt_strusage(11), gpgrt_strusage(13));
  return NULL;
}


/* Start the idle task.   */
static void
start_idle_task (void)
{
  npth_attr_t tattr;
  npth_t thread;
  sigset_t sigs;       /* The set of signals we want to catch.  */
  int err;

#ifndef HAVE_W32_SYSTEM
  /* These signals should always go to the idle task, so they need to
     be blocked everywhere else.  We assume start_idle_task is called
     from the main thread before any other threads are created.  */
  sigemptyset (&sigs);
  sigaddset (&sigs, SIGHUP);
  sigaddset (&sigs, SIGUSR1);
  sigaddset (&sigs, SIGUSR2);
  sigaddset (&sigs, SIGINT);
  sigaddset (&sigs, SIGTERM);
  npth_sigmask (SIG_BLOCK, &sigs, NULL);
#endif

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  err = npth_create (&thread, &tattr, idle_task, NULL);
  if (err)
    {
      log_fatal ("error starting idle task: %s\n", strerror (err));
      return; /*NOTREACHED*/
    }
  npth_setname_np (thread, "idle-task");
  idle_task_thread = thread;
  npth_attr_destroy (&tattr);
}


/* Wait for the idle task to finish.  */
static void
join_idle_task (void)
{
  int err;

  /* FIXME: This assumes that a valid pthread_t is non-null.  That is
     not guaranteed.  */
  if (idle_task_thread)
    {
      err = npth_join (idle_task_thread, NULL);
      if (err)
        log_error ("waiting for idle task thread failed: %s\n",
                   strerror (err));
    }
}

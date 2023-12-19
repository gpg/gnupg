/* keyboxd.c  -  The GnuPG Keybox Daemon
 * Copyright (C) 2000-2020 Free Software Foundation, Inc.
 * Copyright (C) 2000-2019 Werner Koch
 * Copyright (C) 2015-2020 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_W32_SYSTEM
# ifndef WINVER
#  define WINVER 0x0500  /* Same as in common/sysutils.c */
# endif
# include <winsock2.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/socket.h>
# include <sys/un.h>
#endif /*!HAVE_W32_SYSTEM*/
#include <unistd.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <npth.h>

#define INCLUDED_BY_MAIN_MODULE 1
#define GNUPG_COMMON_NEED_AFLOCAL
#include "keyboxd.h"
#include <assuan.h> /* Malloc hooks and socket wrappers. */

#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/asshelp.h"
#include "../common/init.h"
#include "../common/gc-opt-flags.h"
#include "../common/exechelp.h"
#include "../common/comopt.h"
#include "frontend.h"


/* Urrgs: Put this into a separate header - but it needs assuan.h first.  */
extern int kbxd_assuan_log_monitor (assuan_context_t ctx, unsigned int cat,
                                    const char *msg);


enum cmd_and_opt_values
  {
    aNull = 0,
    oQuiet	  = 'q',
    oVerbose	  = 'v',

    oNoVerbose = 500,
    aGPGConfList,
    aGPGConfTest,
    oOptions,
    oDebug,
    oDebugAll,
    oDebugWait,
    oNoGreeting,
    oNoOptions,
    oHomedir,
    oNoDetach,
    oStealSocket,
    oLogFile,
    oServer,
    oDaemon,
    oFakedSystemTime,
    oListenBacklog,
    oDisableCheckOwnSocket,

    oDummy
  };


static gpgrt_opt_t opts[] = {
  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),

  ARGPARSE_header (NULL, N_("Options used for startup")),

  ARGPARSE_s_n (oDaemon,  "daemon", N_("run in daemon mode (background)")),
  ARGPARSE_s_n (oServer,  "server", N_("run in server mode (foreground)")),
  ARGPARSE_s_n (oNoDetach,  "no-detach", N_("do not detach from the console")),
  ARGPARSE_s_n (oStealSocket, "steal-socket", "@"),
  ARGPARSE_s_s (oHomedir,    "homedir",      "@"),
  ARGPARSE_conffile (oOptions, "options", N_("|FILE|read options from FILE")),

  ARGPARSE_header ("Monitor", N_("Options controlling the diagnostic output")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	  "quiet",     N_("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug,	    "debug",      "@"),
  ARGPARSE_s_n (oDebugAll,  "debug-all",  "@"),
  ARGPARSE_s_i (oDebugWait, "debug-wait", "@"),
  ARGPARSE_s_s (oLogFile,   "log-file",  N_("use a log file for the server")),

  ARGPARSE_header ("Configuration",
                   N_("Options controlling the configuration")),

  ARGPARSE_s_n (oDisableCheckOwnSocket, "disable-check-own-socket", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),
  ARGPARSE_s_i (oListenBacklog, "listen-backlog", "@"),

  ARGPARSE_end () /* End of list */
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MPI_VALUE    , "mpi"     },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_CACHE_VALUE  , "cache"   },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_HASHING_VALUE, "hashing" },
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_CLOCK_VALUE  , "clock"   },
    { DBG_LOOKUP_VALUE , "lookup"  },
    { 77, NULL } /* 77 := Do not exit on "help" or "?".  */
  };

/* The timer tick used for housekeeping stuff.  Note that on Windows
 * we use a SetWaitableTimer seems to signal earlier than about 2
 * seconds.  Thus we use 4 seconds on all platforms.
 * CHECK_OWN_SOCKET_INTERVAL defines how often we check
 * our own socket in standard socket mode.  If that value is 0 we
 * don't check at all.  All values are in seconds. */
# define TIMERTICK_INTERVAL          (4)
# define CHECK_OWN_SOCKET_INTERVAL  (60)

/* The list of open file descriptors at startup.  Note that this list
 * has been allocated using the standard malloc.  */
#ifndef HAVE_W32_SYSTEM
static int *startup_fd_list;
#endif

/* The signal mask at startup and a flag telling whether it is valid.  */
#ifdef HAVE_SIGPROCMASK
static sigset_t startup_signal_mask;
static int startup_signal_mask_valid;
#endif

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* Flag indicating to start the daemon even if one already runs.  */
static int steal_socket;

/* Counter for the currently running own socket checks.  */
static int check_own_socket_running;

/* Flag to indicate that we shall not watch our own socket. */
static int disable_check_own_socket;

/* Flag to inhibit socket removal in cleanup.  */
static int inhibit_socket_removal;

/* Name of the communication socket used for client requests.  */
static char *socket_name;

/* We need to keep track of the server's nonces (these are dummies for
 * POSIX systems). */
static assuan_sock_nonce_t socket_nonce;

/* Value for the listen() backlog argument.  We use the same value for
 * all sockets - 64 is on current Linux half of the default maximum.
 * Let's try this as default.  Change at runtime with --listen-backlog.  */
static int listen_backlog = 64;

/* Name of a config file, which will be reread on a HUP if it is not NULL. */
static char *config_filename;

/* Keep track of the current log file so that we can avoid updating
 * the log file after a SIGHUP if it didn't changed.  Malloced. */
static char *current_logfile;

/* This flag is true if the inotify mechanism for detecting the
 * removal of the homedir is active.  This flag is used to disable the
 * alternative but portable stat based check.  */
static int have_homedir_inotify;

/* Depending on how keyboxd was started, the homedir inotify watch may
 * not be reliable.  This flag is set if we assume that inotify works
 * reliable.  */
static int reliable_homedir_inotify;

/* Number of active connections.  */
static int active_connections;

/* This object is used to dispatch progress messages from Libgcrypt to
 * the right thread.  Given that we will have at max only a few dozen
 * connections at a time, using a linked list is the easiest way to
 * handle this. */
struct progress_dispatch_s
{
  struct progress_dispatch_s *next;
  /* The control object of the connection.  If this is NULL no
   * connection is associated with this item and it is free for reuse
   * by new connections.  */
  ctrl_t ctrl;

  /* The thread id of (npth_self) of the connection.  */
  npth_t tid;

  /* The callback set by the connection.  This is similar to the
   * Libgcrypt callback but with the control object passed as the
   * first argument.  */
  void (*cb)(ctrl_t ctrl,
             const char *what, int printchar,
             int current, int total);
};
struct progress_dispatch_s *progress_dispatch_list;




/*
 * Local prototypes.
 */

static char *create_socket_name (char *standard_name, int with_homedir);
static gnupg_fd_t create_server_socket (char *name, int cygwin,
                                        assuan_sock_nonce_t *nonce);
static void create_directories (void);

static void kbxd_libgcrypt_progress_cb (void *data, const char *what,
                                        int printchar,
                                        int current, int total);
static void kbxd_init_default_ctrl (ctrl_t ctrl);
static void kbxd_deinit_default_ctrl (ctrl_t ctrl);

static void handle_connections (gnupg_fd_t listen_fd);
static void check_own_socket (void);
static int check_for_running_kbxd (int silent);

/* Pth wrapper function definitions. */
ASSUAN_SYSTEM_NPTH_IMPL;


/*
 * Functions.
 */

/* Allocate a string describing a library version by calling a GETFNC.
 * This function is expected to be called only once.  GETFNC is
 * expected to have a semantic like gcry_check_version ().  */
static char *
make_libversion (const char *libname, const char *(*getfnc)(const char*))
{
  return xstrconcat (libname, " ", getfnc (NULL), NULL);
}


/* Return strings describing this program.  The case values are
 * described in Libgpg-error.  The values here override the default
 * values given by strusage.  */
static const char *
my_strusage (int level)
{
  static char *ver_gcry;
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "keyboxd (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
      /* TRANSLATORS: @EMAIL@ will get replaced by the actual bug
         reporting address.  This is so that we can change the
         reporting address without breaking the translations.  */
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;

    case 1:
    case 40: p =  _("Usage: keyboxd [options] (-h for help)");
      break;
    case 41: p =  _("Syntax: keyboxd [options] [command [args]]\n"
                    "Public key management for @GNUPG@\n");
    break;

    default: p = NULL;
    }
  return p;
}



/* Setup the debugging.  Note that we don't fail here, because it is
 * important to keep keyboxd running even after re-reading the options
 * due to a SIGHUP. */
static void
set_debug (void)
{
  if (opt.debug && !opt.verbose)
    opt.verbose = 1;
  if (opt.debug && opt.quiet)
    opt.quiet = 0;

  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}


/* Helper for cleanup to remove one socket with NAME.  */
static void
remove_socket (char *name)
{
  if (name && *name)
    {
      gnupg_remove (name);
      *name = 0;
    }
}


/* Cleanup code for this program.  This is either called has an atexit
   handler or directly.  */
static void
cleanup (void)
{
  static int done;

  if (done)
    return;
  done = 1;
  if (!inhibit_socket_removal)
    remove_socket (socket_name);
}


/* Handle options which are allowed to be reset after program start.
 * Return true when the current option in PARGS could be handled and
 * false if not.  As a special feature, passing a value of NULL for
 * PARGS, resets the options to the default.  REREAD should be set
 * true if it is not the initial option parsing. */
static int
parse_rereadable_options (gpgrt_argparse_t *pargs, int reread)
{
  if (!pargs)
    { /* reset mode */
      opt.quiet = 0;
      opt.verbose = 0;
      opt.debug = 0;
      disable_check_own_socket = 0;
      return 1;
    }

  switch (pargs->r_opt)
    {
    case oQuiet: opt.quiet = 1; break;
    case oVerbose: opt.verbose++; break;

    case oDebug:
      parse_debug_flag (pargs->r.ret_str, &opt.debug, debug_flags);
      break;
    case oDebugAll: opt.debug = ~0; break;

    case oLogFile:
      if (!reread)
        return 0; /* not handled */
      if (!current_logfile || !pargs->r.ret_str
          || strcmp (current_logfile, pargs->r.ret_str))
        {
          log_set_file (pargs->r.ret_str);
          xfree (current_logfile);
          current_logfile = xtrystrdup (pargs->r.ret_str);
        }
      break;

    case oDisableCheckOwnSocket: disable_check_own_socket = 1; break;

    default:
      return 0; /* not handled */
    }

  return 1; /* handled */
}


/* Fixup some options after all have been processed.  */
static void
finalize_rereadable_options (void)
{
}


static void
thread_init_once (void)
{
  static int npth_initialized = 0;

  if (!npth_initialized)
    {
      npth_initialized++;
      npth_init ();
    }
  gpgrt_set_syscall_clamp (npth_unprotect, npth_protect);
  /* Now that we have set the syscall clamp we need to tell Libgcrypt
   * that it should get them from libgpg-error.  Note that Libgcrypt
   * has already been initialized but at that point nPth was not
   * initialized and thus Libgcrypt could not set its system call
   * clamp.  */
  gcry_control (GCRYCTL_REINIT_SYSCALL_CLAMP, 0, 0);
}


static void
initialize_modules (void)
{
  thread_init_once ();
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
}


/* The main entry point.  */
int
main (int argc, char **argv )
{
  gpgrt_argparse_t pargs;
  int orig_argc;
  char **orig_argv;
  char *last_configname = NULL;
  char *configname = NULL;
  int debug_argparser = 0;
  int pipe_server = 0;
  int is_daemon = 0;
  int nodetach = 0;
  char *logfile = NULL;
  int gpgconf_list = 0;
  int debug_wait = 0;
  struct assuan_malloc_hooks malloc_hooks;

  early_system_init ();

  /* Before we do anything else we save the list of currently open
   * file descriptors and the signal mask.  This info is required to
   * do the exec call properly.  We don't need it on Windows.  */
#ifndef HAVE_W32_SYSTEM
  startup_fd_list = get_all_open_fds ();
#endif /*!HAVE_W32_SYSTEM*/
#ifdef HAVE_SIGPROCMASK
  if (!sigprocmask (SIG_UNBLOCK, NULL, &startup_signal_mask))
    startup_signal_mask_valid = 1;
#endif /*HAVE_SIGPROCMASK*/

  /* Set program name etc.  */
  gpgrt_set_strusage (my_strusage);
  log_set_prefix ("keyboxd", GPGRT_LOG_WITH_PREFIX|GPGRT_LOG_WITH_PID);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks (&malloc_hooks);
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  assuan_sock_init ();
  assuan_sock_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  setup_libassuan_logging (&opt.debug, kbxd_assuan_log_monitor);

  setup_libgcrypt_logging ();
  gcry_set_progress_handler (kbxd_libgcrypt_progress_cb, NULL);

  /* Set default options.  */
  parse_rereadable_options (NULL, 0); /* Reset them to default values. */

  /* Check whether we have a config file on the commandline */
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

  /* The configuraton directories for use by gpgrt_argparser.  */
  gpgrt_set_confdir (GPGRT_CONFDIR_SYS, gnupg_sysconfdir ());
  gpgrt_set_confdir (GPGRT_CONFDIR_USER, gnupg_homedir ());

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags |=  (ARGPARSE_FLAG_RESET
                   | ARGPARSE_FLAG_KEEP
                   | ARGPARSE_FLAG_SYS
                   | ARGPARSE_FLAG_USER);

  while (gpgrt_argparser (&pargs, opts, "keyboxd" EXTSEP_S "conf"))
    {
      if (pargs.r_opt == ARGPARSE_CONFFILE)
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
          continue;
        }
      if (parse_rereadable_options (&pargs, 0))
        continue; /* Already handled */
      switch (pargs.r_opt)
        {
        case aGPGConfList: gpgconf_list = 1; break;
        case aGPGConfTest: gpgconf_list = 2; break;
        case oDebugWait: debug_wait = pargs.r.ret_int; break;
        case oNoGreeting: /* Dummy option.  */ break;
        case oNoVerbose: opt.verbose = 0; break;
        case oNoOptions: break; /* no-options */
        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;
        case oNoDetach: nodetach = 1; break;
        case oStealSocket: steal_socket = 1; break;
        case oLogFile: logfile = pargs.r.ret_str; break;
        case oServer: pipe_server = 1; break;
        case oDaemon: is_daemon = 1; break;
        case oFakedSystemTime:
          {
            time_t faked_time = isotime2epoch (pargs.r.ret_str);
            if (faked_time == (time_t)(-1))
              faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
            gnupg_set_time (faked_time, 0);
          }
          break;

        case oListenBacklog:
          listen_backlog = pargs.r.ret_int;
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

  if (!last_configname)
    config_filename = gpgrt_fnameconcat (gnupg_homedir (),
                                             "keyboxd" EXTSEP_S "conf",
                                             NULL);
  else
    {
      config_filename = last_configname;
      last_configname = NULL;
    }


  if (log_get_errorcount(0))
    exit (2);

    /* Get a default log file from common.conf.  */
  if (!logfile && !parse_comopt (GNUPG_MODULE_NAME_KEYBOXD, debug_argparser))
    {
      logfile = comopt.logfile;
      comopt.logfile = NULL;
    }


  finalize_rereadable_options ();

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }

#ifdef ENABLE_NLS
  /* keyboxd usually does not output any messages because it runs in
   * the background.  For log files it is acceptable to have messages
   * always encoded in utf-8.  We switch here to utf-8, so that
   * commands like --help still give native messages.  It is far
   * easier to switch only once instead of for every message and it
   * actually helps when more then one thread is active (avoids an
   * extra copy step). */
  bind_textdomain_codeset (PACKAGE_GT, "UTF-8");
#endif

  if (!pipe_server && !is_daemon && !gpgconf_list)
    {
     /* We have been called without any command and thus we merely
      * check whether an instance of us is already running.  We do
      * this right here so that we don't clobber a logfile with this
      * check but print the status directly to stderr.  */
      opt.debug = 0;
      set_debug ();
      check_for_running_kbxd (0);
      kbxd_exit (0);
    }

  set_debug ();

  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  /* Try to create missing directories. */
  create_directories ();

  if (debug_wait && pipe_server)
    {
      thread_init_once ();
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      gnupg_sleep (debug_wait);
      log_debug ("... okay\n");
    }

  if (gpgconf_list == 2)
    kbxd_exit (0);
  else if (gpgconf_list)
    {
      kbxd_exit (0);
    }

  /* Now start with logging to a file if this is desired. */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, (GPGRT_LOG_WITH_PREFIX
                             | GPGRT_LOG_WITH_TIME
                             | GPGRT_LOG_WITH_PID));
      current_logfile = xstrdup (logfile);
    }

  if (pipe_server)
    {
      /* This is the simple pipe based server */
      ctrl_t ctrl;

      initialize_modules ();

      ctrl = xtrycalloc (1, sizeof *ctrl);
      if (!ctrl)
        {
          log_error ("error allocating connection control data: %s\n",
                     strerror (errno) );
          kbxd_exit (1);
        }
      kbxd_init_default_ctrl (ctrl);

      /* kbxd_set_database (ctrl, "pubring.kbx", 0); */
      kbxd_set_database (ctrl, "pubring.db", 0);

      kbxd_start_command_handler (ctrl, GNUPG_INVALID_FD, 0);
      kbxd_deinit_default_ctrl (ctrl);
      xfree (ctrl);
    }
  else if (!is_daemon)
    ; /* NOTREACHED */
  else
    { /* Regular daemon mode.  */
      gnupg_fd_t fd;
#ifndef HAVE_W32_SYSTEM
      pid_t pid;
#endif

      /* Create the sockets.  */
      socket_name = create_socket_name (KEYBOXD_SOCK_NAME, 1);
      fd = create_server_socket (socket_name, 0, &socket_nonce);

      fflush (NULL);

#ifdef HAVE_W32_SYSTEM

      (void)nodetach;
      initialize_modules ();

#else /*!HAVE_W32_SYSTEM*/

      pid = fork ();
      if (pid == (pid_t)-1)
        {
          log_fatal ("fork failed: %s\n", strerror (errno) );
          exit (1);
        }
      else if (pid)
        { /* We are the parent */

          /* Close the socket FD. */
          close (fd);

          /* The signal mask might not be correct right now and thus
           * we restore it.  That is not strictly necessary but some
           * programs falsely assume a cleared signal mask.  */

#ifdef HAVE_SIGPROCMASK
          if (startup_signal_mask_valid)
            {
              if (sigprocmask (SIG_SETMASK, &startup_signal_mask, NULL))
                log_error ("error restoring signal mask: %s\n",
                           strerror (errno));
            }
          else
            log_info ("no saved signal mask\n");
#endif /*HAVE_SIGPROCMASK*/

          *socket_name = 0; /* Don't let cleanup() remove the socket -
                               the child should do this from now on */

          exit (0);
          /*NOTREACHED*/
        } /* End parent */

      /*
       * This is the child
       */

      initialize_modules ();

      /* Detach from tty and put process into a new session */
      if (!nodetach)
        {
          int i;
          unsigned int oldflags;

          /* Close stdin, stdout and stderr unless it is the log stream */
          for (i=0; i <= 2; i++)
            {
              if (!log_test_fd (i) && i != fd )
                {
                  if ( ! close (i)
                       && open ("/dev/null", i? O_WRONLY : O_RDONLY) == -1)
                    {
                      log_error ("failed to open '%s': %s\n",
                                 "/dev/null", strerror (errno));
                      cleanup ();
                      exit (1);
                    }
                }
            }
          if (setsid() == -1)
            {
              log_error ("setsid() failed: %s\n", strerror(errno) );
              cleanup ();
              exit (1);
            }

          log_get_prefix (&oldflags);
          log_set_prefix (NULL, oldflags | GPGRT_LOG_RUN_DETACHED);
          opt.running_detached = 1;

          /* Because we don't support running a program on the command
           * line we can assume that the inotify things works and thus
           * we can avoid the regular stat calls.  */
          reliable_homedir_inotify = 1;
        }

      {
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction (SIGPIPE, &sa, NULL);
      }
#endif /*!HAVE_W32_SYSTEM*/

      if (gnupg_chdir (gnupg_daemon_rootdir ()))
        {
          log_error ("chdir to '%s' failed: %s\n",
                     gnupg_daemon_rootdir (), strerror (errno));
          exit (1);
        }

      {
        ctrl_t ctrl;

        ctrl = xtrycalloc (1, sizeof *ctrl);
        if (!ctrl)
          {
            log_error ("error allocating connection control data: %s\n",
                       strerror (errno) );
            kbxd_exit (1);
          }
        kbxd_init_default_ctrl (ctrl);
        /* kbxd_set_database (ctrl, "pubring.kbx", 0); */
        kbxd_set_database (ctrl, "pubring.db", 0);
        kbxd_deinit_default_ctrl (ctrl);
        xfree (ctrl);
      }

      log_info ("%s %s started\n", gpgrt_strusage(11), gpgrt_strusage(13));
      handle_connections (fd);
      assuan_sock_close (fd);
    }

  return 0;
}


/* Exit entry point.  This function should be called instead of a
   plain exit.  */
void
kbxd_exit (int rc)
{
  /* As usual we run our cleanup handler.  */
  cleanup ();

  /* at this time a bit annoying */
  if ((opt.debug & DBG_MEMSTAT_VALUE))
    gcry_control (GCRYCTL_DUMP_MEMORY_STATS );
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}


/* This is our callback function for gcrypt progress messages.  It is
 * set once at startup and dispatches progress messages to the
 * corresponding threads of ours.  */
static void
kbxd_libgcrypt_progress_cb (void *data, const char *what, int printchar,
                            int current, int total)
{
  struct progress_dispatch_s *dispatch;
  npth_t mytid = npth_self ();

  (void)data;

  for (dispatch = progress_dispatch_list; dispatch; dispatch = dispatch->next)
    if (dispatch->ctrl && dispatch->tid == mytid)
      break;
  if (dispatch && dispatch->cb)
    dispatch->cb (dispatch->ctrl, what, printchar, current, total);
}


/* If a progress dispatcher callback has been associated with the
 * current connection unregister it.  */
static void
unregister_progress_cb (void)
{
  struct progress_dispatch_s *dispatch;
  npth_t mytid = npth_self ();

  for (dispatch = progress_dispatch_list; dispatch; dispatch = dispatch->next)
    if (dispatch->ctrl && dispatch->tid == mytid)
      break;
  if (dispatch)
    {
      dispatch->ctrl = NULL;
      dispatch->cb = NULL;
    }
}


/* Setup a progress callback CB for the current connection.  Using a
 * CB of NULL disables the callback.  */
void
kbxd_set_progress_cb (void (*cb)(ctrl_t ctrl, const char *what,
                                 int printchar, int current, int total),
                      ctrl_t ctrl)
{
  struct progress_dispatch_s *dispatch, *firstfree;
  npth_t mytid = npth_self ();

  firstfree = NULL;
  for (dispatch = progress_dispatch_list; dispatch; dispatch = dispatch->next)
    {
      if (dispatch->ctrl && dispatch->tid == mytid)
        break;
      if (!dispatch->ctrl && !firstfree)
        firstfree = dispatch;
    }
  if (!dispatch) /* None allocated: Reuse or allocate a new one.  */
    {
      if (firstfree)
        {
          dispatch = firstfree;
        }
      else if ((dispatch = xtrycalloc (1, sizeof *dispatch)))
        {
          dispatch->next = progress_dispatch_list;
          progress_dispatch_list = dispatch;
        }
      else
        {
          log_error ("error allocating new progress dispatcher slot: %s\n",
                     gpg_strerror (gpg_error_from_syserror ()));
          return;
        }
      dispatch->ctrl = ctrl;
      dispatch->tid = mytid;
    }

  dispatch->cb = cb;
}


/* Each thread has its own local variables conveyed by a control
 * structure usually identified by an argument named CTRL.  This
 * function is called immediately after allocating the control
 * structure.  Its purpose is to setup the default values for that
 * structure.  Note that some values may have already been set.  */
static void
kbxd_init_default_ctrl (ctrl_t ctrl)
{
  ctrl->magic = SERVER_CONTROL_MAGIC;
}


/* Release all resources allocated by default in the control
   structure.  This is the counterpart to kbxd_init_default_ctrl.  */
static void
kbxd_deinit_default_ctrl (ctrl_t ctrl)
{
  if (!ctrl)
    return;
  kbxd_release_session_info (ctrl);
  ctrl->magic = 0xdeadbeef;
  unregister_progress_cb ();
  xfree (ctrl->lc_messages);
}


/* Reread parts of the configuration.  Note, that this function is
 * obviously not thread-safe and should only be called from the PTH
 * signal handler.
 *
 * Fixme: Due to the way the argument parsing works, we create a
 * memory leak here for all string type arguments.  There is currently
 * no clean way to tell whether the memory for the argument has been
 * allocated or points into the process's original arguments.  Unless
 * we have a mechanism to tell this, we need to live on with this. */
static void
reread_configuration (void)
{
  gpgrt_argparse_t pargs;
  char *twopart;
  int dummy;
  int logfile_seen = 0;

  if (!config_filename)
    goto finish; /* No config file. */

  twopart = strconcat ("keyboxd" EXTSEP_S "conf" PATHSEP_S,
                       config_filename, NULL);
  if (!twopart)
    return;  /* Out of core.  */

  parse_rereadable_options (NULL, 1); /* Start from the default values. */

  memset (&pargs, 0, sizeof pargs);
  dummy = 0;
  pargs.argc = &dummy;
  pargs.flags = (ARGPARSE_FLAG_KEEP
                 |ARGPARSE_FLAG_SYS
                 |ARGPARSE_FLAG_USER);
  while (gpgrt_argparser (&pargs, opts, twopart))
    {
      if (pargs.r_opt == ARGPARSE_CONFFILE)
        {
          log_info (_("reading options from '%s'\n"),
                    pargs.r_type? pargs.r.ret_str: "[cmdline]");
        }
      else if (pargs.r_opt < -1)
        pargs.err = ARGPARSE_PRINT_WARNING;
      else /* Try to parse this option - ignore unchangeable ones. */
        {
          if (pargs.r_opt == oLogFile)
            logfile_seen = 1;
          parse_rereadable_options (&pargs, 1);
        }
    }
  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */
  xfree (twopart);
  finalize_rereadable_options ();
  set_debug ();

 finish:
  /* Get a default log file from common.conf.  */
  if (!logfile_seen && !parse_comopt (GNUPG_MODULE_NAME_KEYBOXD, !!opt.debug))
    {
      if (!current_logfile || !comopt.logfile
          || strcmp (current_logfile, comopt.logfile))
        {
          log_set_file (comopt.logfile);
          xfree (current_logfile);
          current_logfile = comopt.logfile? xtrystrdup (comopt.logfile) : NULL;
        }
    }
}


/* Return the file name of the socket we are using for requests.  */
const char *
get_kbxd_socket_name (void)
{
  const char *s = socket_name;

  return (s && *s)? s : NULL;
}


/* Return the number of active connections. */
int
get_kbxd_active_connection_count (void)
{
  return active_connections;
}


/* Create a name for the socket in the home directory as using
 * STANDARD_NAME.  We also check for valid characters as well as
 * against a maximum allowed length for a Unix domain socket is done.
 * The function terminates the process in case of an error.  The
 * function returns a pointer to an allocated string with the absolute
 * name of the socket used.  */
static char *
create_socket_name (char *standard_name, int with_homedir)
{
  char *name;

  if (with_homedir)
    name = make_filename (gnupg_socketdir (), standard_name, NULL);
  else
    name = make_filename (standard_name, NULL);
  if (strchr (name, PATHSEP_C))
    {
      log_error (("'%s' are not allowed in the socket name\n"), PATHSEP_S);
      kbxd_exit (2);
    }
  return name;
}



/* Create a Unix domain socket with NAME.  Returns the file descriptor
 * or terminates the process in case of an error.  If CYGWIN is set a
 * Cygwin compatible socket is created (Windows only). */
static gnupg_fd_t
create_server_socket (char *name, int cygwin, assuan_sock_nonce_t *nonce)
{
  struct sockaddr *addr;
  struct sockaddr_un *unaddr;
  socklen_t len;
  gnupg_fd_t fd;
  int rc;

  fd = assuan_sock_new (AF_UNIX, SOCK_STREAM, 0);
  if (fd == ASSUAN_INVALID_FD)
    {
      log_error (_("can't create socket: %s\n"), strerror (errno));
      *name = 0; /* Inhibit removal of the socket by cleanup(). */
      kbxd_exit (2);
    }

  if (cygwin)
    assuan_sock_set_flag (fd, "cygwin", 1);

  unaddr = xmalloc (sizeof *unaddr);
  addr = (struct sockaddr*)unaddr;

  if (assuan_sock_set_sockaddr_un (name, addr, NULL))
    {
      if (errno == ENAMETOOLONG)
        log_error (_("socket name '%s' is too long\n"), name);
      else
        log_error ("error preparing socket '%s': %s\n",
                   name, gpg_strerror (gpg_error_from_syserror ()));
      *name = 0; /* Inhibit removal of the socket by cleanup(). */
      xfree (unaddr);
      kbxd_exit (2);
    }

  len = SUN_LEN (unaddr);
  rc = assuan_sock_bind (fd, addr, len);

  if (rc == -1
      && (errno == EADDRINUSE
#ifdef HAVE_W32_SYSTEM
          || errno == EEXIST
#endif
          ))
    {
      /* Check whether a keyboxd is already running.  */
      if (!check_for_running_kbxd (1))
        {
          if (steal_socket)
            log_info (N_("trying to steal socket from running %s\n"),
                      "keyboxd");
          else
            {
              log_set_prefix (NULL, GPGRT_LOG_WITH_PREFIX);
              log_set_file (NULL);
              log_error (_("a keyboxd is already running - "
                           "not starting a new one\n"));
              *name = 0; /* Inhibit removal of the socket by cleanup(). */
              assuan_sock_close (fd);
              xfree (unaddr);
              kbxd_exit (2);
            }
        }
      gnupg_remove (unaddr->sun_path);
      rc = assuan_sock_bind (fd, addr, len);
    }
  if (rc != -1 && (rc=assuan_sock_get_nonce (addr, len, nonce)))
    log_error (_("error getting nonce for the socket\n"));
  if (rc == -1)
    {
      /* We use gpg_strerror here because it allows us to get strings
         for some W32 socket error codes.  */
      log_error (_("error binding socket to '%s': %s\n"),
                 unaddr->sun_path, gpg_strerror (gpg_error_from_syserror ()));

      assuan_sock_close (fd);
      *name = 0; /* Inhibit removal of the socket by cleanup(). */
      xfree (unaddr);
      kbxd_exit (2);
    }

  if (gnupg_chmod (unaddr->sun_path, "-rwx"))
    log_error (_("can't set permissions of '%s': %s\n"),
               unaddr->sun_path, strerror (errno));

  if (listen (FD2INT(fd), listen_backlog ) == -1)
    {
      log_error ("listen(fd,%d) failed: %s\n", listen_backlog, strerror (errno));
      *name = 0; /* Inhibit removal of the socket by cleanup(). */
      assuan_sock_close (fd);
      xfree (unaddr);
      kbxd_exit (2);
    }

  if (opt.verbose)
    log_info (_("listening on socket '%s'\n"), unaddr->sun_path);

  xfree (unaddr);
  return fd;
}


/* Check that the directory for storing the public keys exists and
 * create it if not.  This function won't fail as it is only a
 * convenience function and not strictly necessary.  */
static void
create_public_keys_directory (const char *home)
{
  char *fname;
  struct stat statbuf;

  fname = make_filename (home, GNUPG_PUBLIC_KEYS_DIR, NULL);
  if (gnupg_stat (fname, &statbuf) && errno == ENOENT)
    {
      if (gnupg_mkdir (fname, "-rwxr-x"))
        log_error (_("can't create directory '%s': %s\n"),
                   fname, strerror (errno) );
      else if (!opt.quiet)
        log_info (_("directory '%s' created\n"), fname);
    }
  if (gnupg_chmod (fname, "-rwxr-x"))
    log_error (_("can't set permissions of '%s': %s\n"),
               fname, strerror (errno));
  xfree (fname);
}


/* Create the directory only if the supplied directory name is the
 * same as the default one.  This way we avoid to create arbitrary
 * directories when a non-default home directory is used.  To cope
 * with HOME, we compare only the suffix if we see that the default
 * homedir does start with a tilde.  We don't stop here in case of
 * problems because other functions will throw an error anyway.*/
static void
create_directories (void)
{
  struct stat statbuf;
  const char *defhome = standard_homedir ();
  char *home;

  home = make_filename (gnupg_homedir (), NULL);
  if (gnupg_stat (home, &statbuf))
    {
      if (errno == ENOENT)
        {
          if (
#ifdef HAVE_W32_SYSTEM
              ( !compare_filenames (home, defhome) )
#else
              (*defhome == '~'
                && (strlen (home) >= strlen (defhome+1)
                    && !strcmp (home + strlen(home)
                                - strlen (defhome+1), defhome+1)))
               || (*defhome != '~' && !strcmp (home, defhome) )
#endif
               )
            {
              if (gnupg_mkdir (home, "-rwx"))
                log_error (_("can't create directory '%s': %s\n"),
                           home, strerror (errno) );
              else
                {
                  if (!opt.quiet)
                    log_info (_("directory '%s' created\n"), home);
                  create_public_keys_directory (home);
                }
            }
        }
      else
        log_error (_("stat() failed for '%s': %s\n"), home, strerror (errno));
    }
  else if ( !S_ISDIR(statbuf.st_mode))
    {
      log_error (_("can't use '%s' as home directory\n"), home);
    }
  else /* exists and is a directory. */
    {
      create_public_keys_directory (home);
    }
  xfree (home);
}



/* This is the worker for the ticker.  It is called every few seconds
 * and may only do fast operations. */
static void
handle_tick (void)
{
  static time_t last_minute;
  struct stat statbuf;

  if (!last_minute)
    last_minute = time (NULL);

  /* Code to be run from time to time.  */
#if CHECK_OWN_SOCKET_INTERVAL > 0
  if (last_minute + CHECK_OWN_SOCKET_INTERVAL <= time (NULL))
    {
      check_own_socket ();
      last_minute = time (NULL);
    }
#endif


  /* Check whether the homedir is still available.  */
  if (!shutdown_pending
      && (!have_homedir_inotify || !reliable_homedir_inotify)
      && gnupg_stat (gnupg_homedir (), &statbuf) && errno == ENOENT)
    {
      shutdown_pending = 1;
      log_info ("homedir has been removed - shutting down\n");
    }
}


/* A global function which allows us to call the reload stuff from
 * other places too.  This is only used when build for W32.  */
void
kbxd_sighup_action (void)
{
  log_info ("SIGHUP received - "
            "re-reading configuration and flushing cache\n");

  reread_configuration ();
}


/* A helper function to handle SIGUSR2.  */
static void
kbxd_sigusr2_action (void)
{
  if (opt.verbose)
    log_info ("SIGUSR2 received - no action\n");
  /* Nothing to do right now.  */
}


#ifndef HAVE_W32_SYSTEM
/* The signal handler for this program.  It is expected to be run in
 * its own thread and not in the context of a signal handler.  */
static void
handle_signal (int signo)
{
  switch (signo)
    {
    case SIGHUP:
      kbxd_sighup_action ();
      break;

    case SIGUSR1:
      log_info ("SIGUSR1 received - printing internal information:\n");
      /* Fixme: We need to see how to integrate pth dumping into our
         logging system.  */
      /* pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ()); */
      break;

    case SIGUSR2:
      kbxd_sigusr2_action ();
      break;

    case SIGTERM:
      if (!shutdown_pending)
        log_info ("SIGTERM received - shutting down ...\n");
      else
        log_info ("SIGTERM received - still %i open connections\n",
		  active_connections);
      shutdown_pending++;
      if (shutdown_pending > 2)
        {
          log_info ("shutdown forced\n");
          log_info ("%s %s stopped\n", gpgrt_strusage(11), gpgrt_strusage(13) );
          cleanup ();
          kbxd_exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      log_info( "%s %s stopped\n", gpgrt_strusage(11), gpgrt_strusage(13));
      cleanup ();
      kbxd_exit (0);
      break;

    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}
#endif

/* Check the nonce on a new connection.  This is a NOP unless we
   are using our Unix domain socket emulation under Windows.  */
static int
check_nonce (ctrl_t ctrl, assuan_sock_nonce_t *nonce)
{
  if (assuan_sock_check_nonce (ctrl->thread_startup.fd, nonce))
    {
      log_info (_("error reading nonce on fd %d: %s\n"),
                FD2INT(ctrl->thread_startup.fd), strerror (errno));
      assuan_sock_close (ctrl->thread_startup.fd);
      xfree (ctrl);
      return -1;
    }
  else
    return 0;
}


static void *
do_start_connection_thread (ctrl_t ctrl)
{
  static unsigned int last_session_id;
  unsigned int session_id;

  active_connections++;
  kbxd_init_default_ctrl (ctrl);
  if (opt.verbose && !DBG_IPC)
    log_info (_("handler 0x%lx for fd %d started\n"),
              (unsigned long) npth_self(), FD2INT(ctrl->thread_startup.fd));

  session_id = ++last_session_id;
  if (!session_id)
    session_id = ++last_session_id;
  kbxd_start_command_handler (ctrl, ctrl->thread_startup.fd, session_id);
  if (opt.verbose && !DBG_IPC)
    log_info (_("handler 0x%lx for fd %d terminated\n"),
              (unsigned long) npth_self(), FD2INT(ctrl->thread_startup.fd));

  kbxd_deinit_default_ctrl (ctrl);
  xfree (ctrl);
  active_connections--;
  return NULL;
}


/* This is the standard connection thread's main function.  */
static void *
start_connection_thread (void *arg)
{
  ctrl_t ctrl = arg;

  if (check_nonce (ctrl, &socket_nonce))
    {
      log_error ("handler 0x%lx nonce check FAILED\n",
                 (unsigned long) npth_self());
      return NULL;
    }

  return do_start_connection_thread (ctrl);
}


/* Connection handler loop.  Wait for connection requests and spawn a
 * thread after accepting a connection.  */
static void
handle_connections (gnupg_fd_t listen_fd)
{
  gpg_error_t err;
  npth_attr_t tattr;
  struct sockaddr_un paddr;
  socklen_t plen;
  fd_set fdset, read_fdset;
  int ret;
  gnupg_fd_t fd;
  int nfd;
  int saved_errno;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
#ifdef HAVE_W32_SYSTEM
  HANDLE events[2];
  unsigned int events_set;
#endif
  int sock_inotify_fd = -1;
  int home_inotify_fd = -1;
  struct {
    const char *name;
    void *(*func) (void *arg);
    gnupg_fd_t l_fd;
  } listentbl[] = {
    { "std",     start_connection_thread },
  };


  ret = npth_attr_init(&tattr);
  if (ret)
    log_fatal ("error allocating thread attributes: %s\n", strerror (ret));
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

#ifndef HAVE_W32_SYSTEM
  npth_sigev_init ();
  npth_sigev_add (SIGHUP);
  npth_sigev_add (SIGUSR1);
  npth_sigev_add (SIGUSR2);
  npth_sigev_add (SIGINT);
  npth_sigev_add (SIGTERM);
  npth_sigev_fini ();
#else
  events[0] = INVALID_HANDLE_VALUE;
#endif

  if (disable_check_own_socket)
    sock_inotify_fd = -1;
  else if ((err = gnupg_inotify_watch_socket (&sock_inotify_fd, socket_name)))
    {
      if (gpg_err_code (err) != GPG_ERR_NOT_SUPPORTED)
        log_info ("error enabling daemon termination by socket removal: %s\n",
                  gpg_strerror (err));
    }

  if (disable_check_own_socket)
    home_inotify_fd = -1;
  else if ((err = gnupg_inotify_watch_delete_self (&home_inotify_fd,
                                                   gnupg_homedir ())))
    {
      if (gpg_err_code (err) != GPG_ERR_NOT_SUPPORTED)
        log_info ("error enabling daemon termination by homedir removal: %s\n",
                  gpg_strerror (err));
    }
  else
    have_homedir_inotify = 1;

  FD_ZERO (&fdset);
  FD_SET (FD2INT (listen_fd), &fdset);
  nfd = FD2INT (listen_fd);
  if (sock_inotify_fd != -1)
    {
      FD_SET (sock_inotify_fd, &fdset);
      if (sock_inotify_fd > nfd)
        nfd = sock_inotify_fd;
    }
  if (home_inotify_fd != -1)
    {
      FD_SET (home_inotify_fd, &fdset);
      if (home_inotify_fd > nfd)
        nfd = home_inotify_fd;
    }

  listentbl[0].l_fd = listen_fd;

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL;

  for (;;)
    {
      /* Shutdown test.  */
      if (shutdown_pending)
        {
          if (!active_connections)
            break; /* ready */

          /* Do not accept new connections but keep on running the
           * loop to cope with the timer events.
           *
           * Note that we do not close the listening socket because a
           * client trying to connect to that socket would instead
           * restart a new keyboxd instance - which is unlikely the
           * intention of a shutdown. */
          FD_ZERO (&fdset);
          nfd = -1;
          if (sock_inotify_fd != -1)
            {
              FD_SET (sock_inotify_fd, &fdset);
              nfd = sock_inotify_fd;
            }
          if (home_inotify_fd != -1)
            {
              FD_SET (home_inotify_fd, &fdset);
              if (home_inotify_fd > nfd)
                nfd = home_inotify_fd;
            }
	}

      read_fdset = fdset;

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  /* Timeout.  */
	  handle_tick ();
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL;
	}
      npth_timersub (&abstime, &curtime, &timeout);

#ifndef HAVE_W32_SYSTEM
      ret = npth_pselect (nfd+1, &read_fdset, NULL, NULL, &timeout,
                          npth_sigev_sigmask ());
      saved_errno = errno;

      {
        int signo;
        while (npth_sigev_get_pending (&signo))
          handle_signal (signo);
      }
#else
      ret = npth_eselect (nfd+1, &read_fdset, NULL, NULL, &timeout,
                          events, &events_set);
      saved_errno = errno;

      /* This is valid even if npth_eselect returns an error.  */
      if ((events_set & 1))
	kbxd_sigusr2_action ();
#endif

      if (ret == -1 && saved_errno != EINTR)
	{
          log_error (_("npth_pselect failed: %s - waiting 1s\n"),
                     strerror (saved_errno));
          gnupg_sleep (1);
          continue;
	}
      if (ret <= 0)
        {
          /* Interrupt or timeout.  Will be handled when calculating the
           * next timeout.  */
          continue;
        }

      /* The inotify fds are set even when a shutdown is pending (see
       * above).  So we must handle them in any case.  To avoid that
       * they trigger a second time we close them immediately.  */
      if (sock_inotify_fd != -1
          && FD_ISSET (sock_inotify_fd, &read_fdset)
          && gnupg_inotify_has_name (sock_inotify_fd, KEYBOXD_SOCK_NAME))
        {
          shutdown_pending = 1;
          close (sock_inotify_fd);
          sock_inotify_fd = -1;
          log_info ("socket file has been removed - shutting down\n");
        }

      if (home_inotify_fd != -1
          && FD_ISSET (home_inotify_fd, &read_fdset))
        {
          shutdown_pending = 1;
          close (home_inotify_fd);
          home_inotify_fd = -1;
          log_info ("homedir has been removed - shutting down\n");
        }

      if (!shutdown_pending)
        {
          int idx;
          ctrl_t ctrl;
          npth_t thread;

          for (idx=0; idx < DIM(listentbl); idx++)
            {
              if (listentbl[idx].l_fd == GNUPG_INVALID_FD)
                continue;
              if (!FD_ISSET (FD2INT (listentbl[idx].l_fd), &read_fdset))
                continue;

              plen = sizeof paddr;
              fd = INT2FD (npth_accept (FD2INT(listentbl[idx].l_fd),
                                        (struct sockaddr *)&paddr, &plen));
              if (fd == GNUPG_INVALID_FD)
                {
                  log_error ("accept failed for %s: %s\n",
                             listentbl[idx].name, strerror (errno));
                }
              else if ( !(ctrl = xtrycalloc (1, sizeof *ctrl)))
                {
                  log_error ("error allocating connection data for %s: %s\n",
                             listentbl[idx].name, strerror (errno) );
                  assuan_sock_close (fd);
                }
              else
                {
                  ctrl->thread_startup.fd = fd;
                  ret = npth_create (&thread, &tattr,
                                     listentbl[idx].func, ctrl);
                  if (ret)
                    {
                      log_error ("error spawning connection handler for %s:"
                                 " %s\n", listentbl[idx].name, strerror (ret));
                      assuan_sock_close (fd);
                      xfree (ctrl);
                    }
                }
            }
        }
    }

  if (sock_inotify_fd != -1)
    close (sock_inotify_fd);
  if (home_inotify_fd != -1)
    close (home_inotify_fd);
  cleanup ();
  log_info (_("%s %s stopped\n"), gpgrt_strusage(11), gpgrt_strusage(13));
  npth_attr_destroy (&tattr);
}



/* Helper for check_own_socket.  */
static gpg_error_t
check_own_socket_pid_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *mb = opaque;
  put_membuf (mb, buffer, length);
  return 0;
}


/* The thread running the actual check.  We need to run this in a
 * separate thread so that check_own_thread can be called from the
 * timer tick.  */
static void *
check_own_socket_thread (void *arg)
{
  int rc;
  char *sockname = arg;
  assuan_context_t ctx = NULL;
  membuf_t mb;
  char *buffer;

  check_own_socket_running++;

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (rc));
      goto leave;
    }
  assuan_set_flag (ctx, ASSUAN_NO_LOGGING, 1);

  rc = assuan_socket_connect (ctx, sockname, (pid_t)(-1), 0);
  if (rc)
    {
      log_error ("can't connect my own socket: %s\n", gpg_strerror (rc));
      goto leave;
    }

  init_membuf (&mb, 100);
  rc = assuan_transact (ctx, "GETINFO pid", check_own_socket_pid_cb, &mb,
                        NULL, NULL, NULL, NULL);
  put_membuf (&mb, "", 1);
  buffer = get_membuf (&mb, NULL);
  if (rc || !buffer)
    {
      log_error ("sending command \"%s\" to my own socket failed: %s\n",
                 "GETINFO pid", gpg_strerror (rc));
      rc = 1;
    }
  else if ( (pid_t)strtoul (buffer, NULL, 10) != getpid ())
    {
      log_error ("socket is now serviced by another server\n");
      rc = 1;
    }
  else if (opt.verbose > 1)
    log_error ("socket is still served by this server\n");

  xfree (buffer);

 leave:
  xfree (sockname);
  if (ctx)
    assuan_release (ctx);
  if (rc)
    {
      /* We may not remove the socket as it is now in use by another
       * server. */
      inhibit_socket_removal = 1;
      shutdown_pending = 2;
      log_info ("this process is useless - shutting down\n");
    }
  check_own_socket_running--;
  return NULL;
}


/* Check whether we are still listening on our own socket.  In case
 * another keyboxd process started after us has taken ownership of our
 * socket, we would linger around without any real task.  Thus we
 * better check once in a while whether we are really needed.  */
static void
check_own_socket (void)
{
  char *sockname;
  npth_t thread;
  npth_attr_t tattr;
  int err;

  if (disable_check_own_socket)
    return;

  if (check_own_socket_running || shutdown_pending)
    return;  /* Still running or already shutting down.  */

  sockname = make_filename_try (gnupg_socketdir (), KEYBOXD_SOCK_NAME, NULL);
  if (!sockname)
    return; /* Out of memory.  */

  err = npth_attr_init (&tattr);
  if (err)
    {
      xfree (sockname);
      return;
    }
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);
  err = npth_create (&thread, &tattr, check_own_socket_thread, sockname);
  if (err)
    log_error ("error spawning check_own_socket_thread: %s\n", strerror (err));
  npth_attr_destroy (&tattr);
}



/* Figure out whether a keyboxd is available and running.  Prints an
 * error if not.  If SILENT is true, no messages are printed.  Returns
 * 0 if the agent is running. */
static int
check_for_running_kbxd (int silent)
{
  gpg_error_t err;
  char *sockname;
  assuan_context_t ctx = NULL;

  sockname = make_filename_try (gnupg_socketdir (), KEYBOXD_SOCK_NAME, NULL);
  if (!sockname)
    return gpg_error_from_syserror ();

  err = assuan_new (&ctx);
  if (!err)
    err = assuan_socket_connect (ctx, sockname, (pid_t)(-1), 0);
  xfree (sockname);
  if (err)
    {
      if (!silent)
        log_error (_("no keyboxd running in this session\n"));

      if (ctx)
	assuan_release (ctx);
      return -1;
    }

  if (!opt.quiet && !silent)
    log_info ("keyboxd running and available\n");

  assuan_release (ctx);
  return 0;
}

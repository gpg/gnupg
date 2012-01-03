/* gpg-agent.c  -  The GnuPG Agent
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006, 2007, 2009, 2010 Free Software Foundation, Inc.
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
#ifndef HAVE_W32_SYSTEM
# include <sys/socket.h>
# include <sys/un.h>
#endif /*!HAVE_W32_SYSTEM*/
#include <unistd.h>
#include <signal.h>
#include <pth.h>

#define JNLIB_NEED_LOG_LOGV
#define JNLIB_NEED_AFLOCAL
#include "agent.h"
#include <assuan.h> /* Malloc hooks  and socket wrappers. */

#include "i18n.h"
#include "mkdtemp.h" /* Gnulib replacement. */
#include "sysutils.h"
#include "setenv.h"
#include "gc-opt-flags.h"
#include "exechelp.h"
#include "../common/estream.h"

enum cmd_and_opt_values
{ aNull = 0,
  oCsh		  = 'c',
  oQuiet	  = 'q',
  oSh		  = 's',
  oVerbose	  = 'v',

  oNoVerbose = 500,
  aGPGConfList,
  aGPGConfTest,
  aUseStandardSocketP,
  oOptions,
  oDebug,
  oDebugAll,
  oDebugLevel,
  oDebugWait,
  oNoGreeting,
  oNoOptions,
  oHomedir,
  oNoDetach,
  oNoGrab,
  oLogFile,
  oServer,
  oDaemon,
  oBatch,

  oPinentryProgram,
  oPinentryTouchFile,
  oDisplay,
  oTTYname,
  oTTYtype,
  oLCctype,
  oLCmessages,
  oXauthority,
  oScdaemonProgram,
  oDefCacheTTL,
  oDefCacheTTLSSH,
  oMaxCacheTTL,
  oMaxCacheTTLSSH,
  oEnforcePassphraseConstraints,
  oMinPassphraseLen,
  oMinPassphraseNonalpha,
  oCheckPassphrasePattern,
  oMaxPassphraseDays,
  oEnablePassphraseHistory,
  oUseStandardSocket,
  oNoUseStandardSocket,
  oFakedSystemTime,

  oIgnoreCacheForSigning,
  oAllowMarkTrusted,
  oAllowPresetPassphrase,
  oKeepTTY,
  oKeepDISPLAY,
  oSSHSupport,
  oDisableScdaemon,
  oWriteEnvFile
};



static ARGPARSE_OPTS opts[] = {

  { aGPGConfList, "gpgconf-list", 256, "@" },
  { aGPGConfTest, "gpgconf-test", 256, "@" },
  { aUseStandardSocketP, "use-standard-socket-p", 256, "@" },

  { 301, NULL, 0, N_("@Options:\n ") },

  { oServer,   "server",     0, N_("run in server mode (foreground)") },
  { oDaemon,   "daemon",     0, N_("run in daemon mode (background)") },
  { oVerbose, "verbose",     0, N_("verbose") },
  { oQuiet,	"quiet",     0, N_("be somewhat more quiet") },
  { oSh,	"sh",        0, N_("sh-style command output") },
  { oCsh,	"csh",       0, N_("csh-style command output") },
  { oOptions, "options"  , 2, N_("|FILE|read options from FILE")},
  { oDebug,	"debug"     ,4|16, "@"},
  { oDebugAll, "debug-all"     ,0, "@"},
  { oDebugLevel, "debug-level" ,2, "@"},
  { oDebugWait,"debug-wait",1, "@"},
  { oNoDetach, "no-detach" ,0, N_("do not detach from the console")},
  { oNoGrab, "no-grab"     ,0, N_("do not grab keyboard and mouse")},
  { oLogFile, "log-file"   ,2, N_("use a log file for the server")},
  { oUseStandardSocket, "use-standard-socket", 0,
                      N_("use a standard location for the socket")},
  { oNoUseStandardSocket, "no-use-standard-socket", 0, "@"},
  { oPinentryProgram, "pinentry-program", 2 ,
                               N_("|PGM|use PGM as the PIN-Entry program") },
  { oPinentryTouchFile, "pinentry-touch-file", 2 , "@" },
  { oScdaemonProgram, "scdaemon-program", 2 ,
                               N_("|PGM|use PGM as the SCdaemon program") },
  { oDisableScdaemon, "disable-scdaemon", 0, N_("do not use the SCdaemon") },
  { oFakedSystemTime, "faked-system-time", 2, "@" }, /* (epoch time) */

  { oBatch,      "batch",       0, "@" },
  { oHomedir,    "homedir",     2, "@"},

  { oDisplay,    "display",     2, "@" },
  { oTTYname,    "ttyname",     2, "@" },
  { oTTYtype,    "ttytype",     2, "@" },
  { oLCctype,    "lc-ctype",    2, "@" },
  { oLCmessages, "lc-messages", 2, "@" },
  { oXauthority, "xauthority",  2, "@" },
  { oKeepTTY,    "keep-tty",    0,  N_("ignore requests to change the TTY")},
  { oKeepDISPLAY, "keep-display",
                          0, N_("ignore requests to change the X display")},

  { oDefCacheTTL, "default-cache-ttl", 4,
                               N_("|N|expire cached PINs after N seconds")},
  { oDefCacheTTLSSH, "default-cache-ttl-ssh", 4, "@" },
  { oMaxCacheTTL, "max-cache-ttl", 4, "@" },
  { oMaxCacheTTLSSH, "max-cache-ttl-ssh", 4, "@" },

  { oEnforcePassphraseConstraints, "enforce-passphrase-constraints", 0, "@"},
  { oMinPassphraseLen, "min-passphrase-len", 4, "@" },
  { oMinPassphraseNonalpha, "min-passphrase-nonalpha", 4, "@" },
  { oCheckPassphrasePattern, "check-passphrase-pattern", 2, "@" },
  { oMaxPassphraseDays, "max-passphrase-days", 4, "@" },
  { oEnablePassphraseHistory, "enable-passphrase-history", 0, "@" },

  { oIgnoreCacheForSigning, "ignore-cache-for-signing", 0,
                               N_("do not use the PIN cache when signing")},
  { oAllowMarkTrusted, "allow-mark-trusted", 0,
                             N_("allow clients to mark keys as \"trusted\"")},
  { oAllowPresetPassphrase, "allow-preset-passphrase", 0,
                             N_("allow presetting passphrase")},
  { oSSHSupport, "enable-ssh-support", 0, N_("enable ssh-agent emulation") },
  { oWriteEnvFile, "write-env-file", 2|8,
            N_("|FILE|write environment settings also to FILE")},
  {0}
};


#define DEFAULT_CACHE_TTL     (10*60)  /* 10 minutes */
#define DEFAULT_CACHE_TTL_SSH (30*60)  /* 30 minutes */
#define MAX_CACHE_TTL         (120*60) /* 2 hours */
#define MAX_CACHE_TTL_SSH     (120*60) /* 2 hours */
#define MIN_PASSPHRASE_LEN    (8)
#define MIN_PASSPHRASE_NONALPHA (1)
#define MAX_PASSPHRASE_DAYS   (0)

/* The timer tick used for housekeeping stuff.  For Windows we use a
   longer period as the SetWaitableTimer seems to signal earlier than
   the 2 seconds.  */
#ifdef HAVE_W32_SYSTEM
#define TIMERTICK_INTERVAL    (4)
#else
#define TIMERTICK_INTERVAL    (2)    /* Seconds.  */
#endif


/* The list of open file descriptors at startup.  Note that this list
   has been allocated using the standard malloc.  */
static int *startup_fd_list;

/* The signal mask at startup and a flag telling whether it is valid.  */
#ifdef HAVE_SIGPROCMASK
static sigset_t startup_signal_mask;
static int startup_signal_mask_valid;
#endif

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* Counter for the currently running own socket checks.  */
static int check_own_socket_running;

/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Name of the communication socket used for native gpg-agent requests.  */
static char *socket_name;

/* Name of the communication socket used for ssh-agent-emulation.  */
static char *socket_name_ssh;

/* We need to keep track of the server's nonces (these are dummies for
   POSIX systems). */
static assuan_sock_nonce_t socket_nonce;
static assuan_sock_nonce_t socket_nonce_ssh;


/* Default values for options passed to the pinentry. */
static char *default_display;
static char *default_ttyname;
static char *default_ttytype;
static char *default_lc_ctype;
static char *default_lc_messages;
static char *default_xauthority;

/* Name of a config file, which will be reread on a HUP if it is not NULL. */
static char *config_filename;

/* Helper to implement --debug-level */
static const char *debug_level;

/* Keep track of the current log file so that we can avoid updating
   the log file after a SIGHUP if it didn't changed. Malloced. */
static char *current_logfile;

/* The handle_tick() function may test whether a parent is still
   running.  We record the PID of the parent here or -1 if it should be
   watched. */
static pid_t parent_pid = (pid_t)(-1);


/*
   Local prototypes.
 */

static char *create_socket_name (char *standard_name, char *template);
static gnupg_fd_t create_server_socket (char *name, int is_ssh,
                                        assuan_sock_nonce_t *nonce);
static void create_directories (void);

static void agent_init_default_ctrl (ctrl_t ctrl);
static void agent_deinit_default_ctrl (ctrl_t ctrl);

static void handle_connections (gnupg_fd_t listen_fd,
                                gnupg_fd_t listen_fd_ssh);
static void check_own_socket (void);
static int check_for_running_agent (int silent, int mode);

/* Pth wrapper function definitions. */
ASSUAN_SYSTEM_PTH_IMPL;

GCRY_THREAD_OPTION_PTH_IMPL;
static int fixed_gcry_pth_init (void)
{
  return pth_self ()? 0 : (pth_init () == FALSE) ? errno : 0;
}


#ifndef PTH_HAVE_PTH_THREAD_ID
static unsigned long pth_thread_id (void)
{
  return (unsigned long)pth_self ();
}
#endif



/*
   Functions.
 */

static char *
make_libversion (const char *libname, const char *(*getfnc)(const char*))
{
  const char *s;
  char *result;

  if (maybe_setuid)
    {
      gcry_control (GCRYCTL_INIT_SECMEM, 0, 0);  /* Drop setuid. */
      maybe_setuid = 0;
    }
  s = getfnc (NULL);
  result = xmalloc (strlen (libname) + 1 + strlen (s) + 1);
  strcpy (stpcpy (stpcpy (result, libname), " "), s);
  return result;
}


static const char *
my_strusage (int level)
{
  static char *ver_gcry;
  const char *p;

  switch (level)
    {
    case 11: p = "gpg-agent (GnuPG)";
      break;
    case 13: p = VERSION; break;
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
    case 40: p =  _("Usage: gpg-agent [options] (-h for help)");
      break;
    case 41: p =  _("Syntax: gpg-agent [options] [command [args]]\n"
                    "Secret key management for GnuPG\n");
    break;

    default: p = NULL;
    }
  return p;
}



/* Setup the debugging.  With the global variable DEBUG_LEVEL set to NULL
   only the active debug flags are propagated to the subsystems.  With
   DEBUG_LEVEL set, a specific set of debug flags is set; thus overriding
   all flags already set. Note that we don't fail here, because it is
   important to keep gpg-agent running even after re-reading the
   options due to a SIGHUP. */
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
    opt.debug = DBG_ASSUAN_VALUE;
  else if (!strcmp (debug_level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_ASSUAN_VALUE|DBG_COMMAND_VALUE;
  else if (!strcmp (debug_level, "expert") || (numok && numlvl <= 8))
    opt.debug = (DBG_ASSUAN_VALUE|DBG_COMMAND_VALUE
                 |DBG_CACHE_VALUE);
  else if (!strcmp (debug_level, "guru") || numok)
    {
      opt.debug = ~0;
      /* Unless the "guru" string has been used we don't want to allow
         hashing debugging.  The rationale is that people tend to
         select the highest debug value and would then clutter their
         disk with debug files which may reveal confidential data.  */
      if (numok)
        opt.debug &= ~(DBG_HASHING_VALUE);
    }
  else
    {
      log_error (_("invalid debug-level `%s' given\n"), debug_level);
      opt.debug = 0; /* Reset debugging, so that prior debug
                        statements won't have an undesired effect. */
    }

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
    log_info ("enabled debug flags:%s%s%s%s%s%s%s%s\n",
              (opt.debug & DBG_COMMAND_VALUE)? " command":"",
              (opt.debug & DBG_MPI_VALUE    )? " mpi":"",
              (opt.debug & DBG_CRYPTO_VALUE )? " crypto":"",
              (opt.debug & DBG_MEMORY_VALUE )? " memory":"",
              (opt.debug & DBG_CACHE_VALUE  )? " cache":"",
              (opt.debug & DBG_MEMSTAT_VALUE)? " memstat":"",
              (opt.debug & DBG_HASHING_VALUE)? " hashing":"",
              (opt.debug & DBG_ASSUAN_VALUE )? " assuan":"");
}


/* Helper for cleanup to remove one socket with NAME.  */
static void
remove_socket (char *name)
{
  if (name && *name)
    {
      char *p;

      remove (name);
      p = strrchr (name, '/');
      if (p)
	{
	  *p = 0;
	  rmdir (name);
	  *p = '/';
	}
      *name = 0;
    }
}

static void
cleanup (void)
{
  remove_socket (socket_name);
  remove_socket (socket_name_ssh);
}



/* Handle options which are allowed to be reset after program start.
   Return true when the current option in PARGS could be handled and
   false if not.  As a special feature, passing a value of NULL for
   PARGS, resets the options to the default.  REREAD should be set
   true if it is not the initial option parsing. */
static int
parse_rereadable_options (ARGPARSE_ARGS *pargs, int reread)
{
  if (!pargs)
    { /* reset mode */
      opt.quiet = 0;
      opt.verbose = 0;
      opt.debug = 0;
      opt.no_grab = 0;
      opt.pinentry_program = NULL;
      opt.pinentry_touch_file = NULL;
      opt.scdaemon_program = NULL;
      opt.def_cache_ttl = DEFAULT_CACHE_TTL;
      opt.def_cache_ttl_ssh = DEFAULT_CACHE_TTL_SSH;
      opt.max_cache_ttl = MAX_CACHE_TTL;
      opt.max_cache_ttl_ssh = MAX_CACHE_TTL_SSH;
      opt.enforce_passphrase_constraints = 0;
      opt.min_passphrase_len = MIN_PASSPHRASE_LEN;
      opt.min_passphrase_nonalpha = MIN_PASSPHRASE_NONALPHA;
      opt.check_passphrase_pattern = NULL;
      opt.max_passphrase_days = MAX_PASSPHRASE_DAYS;
      opt.enable_passhrase_history = 0;
      opt.ignore_cache_for_signing = 0;
      opt.allow_mark_trusted = 0;
      opt.disable_scdaemon = 0;
      return 1;
    }

  switch (pargs->r_opt)
    {
    case oQuiet: opt.quiet = 1; break;
    case oVerbose: opt.verbose++; break;

    case oDebug: opt.debug |= pargs->r.ret_ulong; break;
    case oDebugAll: opt.debug = ~0; break;
    case oDebugLevel: debug_level = pargs->r.ret_str; break;

    case oLogFile:
      if (!reread)
        return 0; /* not handeld */
      if (!current_logfile || !pargs->r.ret_str
          || strcmp (current_logfile, pargs->r.ret_str))
        {
          log_set_file (pargs->r.ret_str);
	  if (DBG_ASSUAN)
	    assuan_set_assuan_log_stream (log_get_stream ());
          xfree (current_logfile);
          current_logfile = xtrystrdup (pargs->r.ret_str);
        }
      break;

    case oNoGrab: opt.no_grab = 1; break;

    case oPinentryProgram: opt.pinentry_program = pargs->r.ret_str; break;
    case oPinentryTouchFile: opt.pinentry_touch_file = pargs->r.ret_str; break;
    case oScdaemonProgram: opt.scdaemon_program = pargs->r.ret_str; break;
    case oDisableScdaemon: opt.disable_scdaemon = 1; break;

    case oDefCacheTTL: opt.def_cache_ttl = pargs->r.ret_ulong; break;
    case oDefCacheTTLSSH: opt.def_cache_ttl_ssh = pargs->r.ret_ulong; break;
    case oMaxCacheTTL: opt.max_cache_ttl = pargs->r.ret_ulong; break;
    case oMaxCacheTTLSSH: opt.max_cache_ttl_ssh = pargs->r.ret_ulong; break;

    case oEnforcePassphraseConstraints:
      opt.enforce_passphrase_constraints=1;
      break;
    case oMinPassphraseLen: opt.min_passphrase_len = pargs->r.ret_ulong; break;
    case oMinPassphraseNonalpha:
      opt.min_passphrase_nonalpha = pargs->r.ret_ulong;
      break;
    case oCheckPassphrasePattern:
      opt.check_passphrase_pattern = pargs->r.ret_str;
      break;
    case oMaxPassphraseDays:
      opt.max_passphrase_days = pargs->r.ret_ulong;
      break;
    case oEnablePassphraseHistory:
      opt.enable_passhrase_history = 1;
      break;

    case oIgnoreCacheForSigning: opt.ignore_cache_for_signing = 1; break;

    case oAllowMarkTrusted: opt.allow_mark_trusted = 1; break;

    case oAllowPresetPassphrase: opt.allow_preset_passphrase = 1; break;

    default:
      return 0; /* not handled */
    }

  return 1; /* handled */
}


/* The main entry point.  */
int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  FILE *configfp = NULL;
  char *configname = NULL;
  const char *shell;
  unsigned configlineno;
  int parse_debug = 0;
  int default_config =1;
  int greeting = 0;
  int nogreeting = 0;
  int pipe_server = 0;
  int is_daemon = 0;
  int nodetach = 0;
  int csh_style = 0;
  char *logfile = NULL;
  int debug_wait = 0;
  int gpgconf_list = 0;
  gpg_error_t err;
  const char *env_file_name = NULL;
  struct assuan_malloc_hooks malloc_hooks;

  /* Before we do anything else we save the list of currently open
     file descriptors and the signal mask.  This info is required to
     do the exec call properly. */
  startup_fd_list = get_all_open_fds ();
#ifdef HAVE_SIGPROCMASK
  if (!sigprocmask (SIG_UNBLOCK, NULL, &startup_signal_mask))
    startup_signal_mask_valid = 1;
#endif /*HAVE_SIGPROCMASK*/

  /* Set program name etc.  */
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix ("gpg-agent", JNLIB_LOG_WITH_PREFIX|JNLIB_LOG_WITH_PID);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems ();


  /* Libgcrypt requires us to register the threading model first.
     Note that this will also do the pth_init. */
  gcry_threads_pth.init = fixed_gcry_pth_init;
  err = gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pth);
  if (err)
    {
      log_fatal ("can't register GNU Pth with Libgcrypt: %s\n",
                 gpg_strerror (err));
    }


  /* Check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library. */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal( _("%s is too old (need %s, have %s)\n"), "libgcrypt",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks (&malloc_hooks);
  assuan_set_assuan_log_prefix (log_get_prefix (NULL));
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  assuan_set_system_hooks (ASSUAN_SYSTEM_PTH);
  assuan_sock_init ();

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  disable_core_dumps ();

  /* Set default options.  */
  parse_rereadable_options (NULL, 0); /* Reset them to default values. */
#ifdef USE_STANDARD_SOCKET
  opt.use_standard_socket = 1;  /* Under Windows we always use a standard
                                   socket.  */
#endif

  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;

  opt.homedir = default_homedir ();

  /* Record some of the original environment strings. */
  {
    const char *s;
    int idx;
    static const char *names[] =
      { "DISPLAY", "TERM", "XAUTHORITY", "PINENTRY_USER_DATA", NULL };

    err = 0;
    opt.startup_env = session_env_new ();
    if (!opt.startup_env)
      err = gpg_error_from_syserror ();
    for (idx=0; !err && names[idx]; idx++)
      {
        s = getenv (names[idx]);
        if (s)
          err = session_env_setenv (opt.startup_env, names[idx], s);
      }
    if (!err)
      {
        s = ttyname (0);
        if (s)
          err = session_env_setenv (opt.startup_env, "GPG_TTY", s);
      }
    if (err)
      log_fatal ("error recording startup environment: %s\n",
                 gpg_strerror (err));

    /* Fixme: Better use the locale function here.  */
    opt.startup_lc_ctype = getenv ("LC_CTYPE");
    if (opt.startup_lc_ctype)
      opt.startup_lc_ctype = xstrdup (opt.startup_lc_ctype);
    opt.startup_lc_messages = getenv ("LC_MESSAGES");
    if (opt.startup_lc_messages)
      opt.startup_lc_messages = xstrdup (opt.startup_lc_messages);
  }

  /* Check whether we have a config file on the commandline */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
  while (arg_parse( &pargs, opts))
    {
      if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
        parse_debug++;
      else if (pargs.r_opt == oOptions)
        { /* yes there is one, so we do not try the default one, but
	     read the option file when it is encountered at the
	     commandline */
          default_config = 0;
	}
	else if (pargs.r_opt == oNoOptions)
          default_config = 0; /* --no-options */
	else if (pargs.r_opt == oHomedir)
          opt.homedir = pargs.r.ret_str;
    }

  /* Initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 32768, 0);
  maybe_setuid = 0;

  /*
     Now we are now working under our real uid
  */

  if (default_config)
    configname = make_filename (opt.homedir, "gpg-agent.conf", NULL );

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
 next_pass:
  if (configname)
    {
      configlineno = 0;
      configfp = fopen (configname, "r");
      if (!configfp)
        {
          if (default_config)
            {
              if( parse_debug )
                log_info (_("NOTE: no default option file `%s'\n"),
                          configname );
              /* Save the default conf file name so that
                 reread_configuration is able to test whether the
                 config file has been created in the meantime.  */
              xfree (config_filename);
              config_filename = configname;
              configname = NULL;
	    }
          else
            {
              log_error (_("option file `%s': %s\n"),
                         configname, strerror(errno) );
              exit(2);
	    }
          xfree (configname);
          configname = NULL;
	}
      if (parse_debug && configname )
        log_info (_("reading options from `%s'\n"), configname );
      default_config = 0;
    }

  while (optfile_parse( configfp, configname, &configlineno, &pargs, opts) )
    {
      if (parse_rereadable_options (&pargs, 0))
        continue; /* Already handled */
      switch (pargs.r_opt)
        {
        case aGPGConfList: gpgconf_list = 1; break;
        case aGPGConfTest: gpgconf_list = 2; break;
        case aUseStandardSocketP: gpgconf_list = 3; break;
        case oBatch: opt.batch=1; break;

        case oDebugWait: debug_wait = pargs.r.ret_int; break;

        case oOptions:
          /* config files may not be nested (silently ignore them) */
          if (!configfp)
            {
		xfree(configname);
		configname = xstrdup(pargs.r.ret_str);
		goto next_pass;
	    }
          break;
        case oNoGreeting: nogreeting = 1; break;
        case oNoVerbose: opt.verbose = 0; break;
        case oNoOptions: break; /* no-options */
        case oHomedir: opt.homedir = pargs.r.ret_str; break;
        case oNoDetach: nodetach = 1; break;
        case oLogFile: logfile = pargs.r.ret_str; break;
        case oCsh: csh_style = 1; break;
        case oSh: csh_style = 0; break;
        case oServer: pipe_server = 1; break;
        case oDaemon: is_daemon = 1; break;

        case oDisplay: default_display = xstrdup (pargs.r.ret_str); break;
        case oTTYname: default_ttyname = xstrdup (pargs.r.ret_str); break;
        case oTTYtype: default_ttytype = xstrdup (pargs.r.ret_str); break;
        case oLCctype: default_lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: default_lc_messages = xstrdup (pargs.r.ret_str);
        case oXauthority: default_xauthority = xstrdup (pargs.r.ret_str);
          break;

        case oUseStandardSocket:   opt.use_standard_socket = 1; break;
        case oNoUseStandardSocket: opt.use_standard_socket = 0; break;

        case oFakedSystemTime:
          {
            time_t faked_time = isotime2epoch (pargs.r.ret_str);
            if (faked_time == (time_t)(-1))
              faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
            gnupg_set_time (faked_time, 0);
          }
          break;

        case oKeepTTY: opt.keep_tty = 1; break;
        case oKeepDISPLAY: opt.keep_display = 1; break;

	case oSSHSupport:  opt.ssh_support = 1; break;
        case oWriteEnvFile:
          if (pargs.r_type)
            env_file_name = pargs.r.ret_str;
          else
            env_file_name = make_filename ("~/.gpg-agent-info", NULL);
          break;

        default : pargs.err = configfp? 1:2; break;
	}
    }
  if (configfp)
    {
      fclose( configfp );
      configfp = NULL;
      /* Keep a copy of the name so that it can be read on SIGHUP. */
      if (config_filename != configname)
        {
          xfree (config_filename);
          config_filename = configname;
        }
      configname = NULL;
      goto next_pass;
    }

  xfree (configname);
  configname = NULL;
  if (log_get_errorcount(0))
    exit(2);
  if (nogreeting )
    greeting = 0;

  if (greeting)
    {
      fprintf (stderr, "%s %s; %s\n",
                 strusage(11), strusage(13), strusage(14) );
      fprintf (stderr, "%s\n", strusage(15) );
    }
#ifdef IS_DEVELOPMENT_VERSION
  /* We don't want to print it here because gpg-agent is useful of its
     own and quite matured.  */
  /*log_info ("NOTE: this is a development version!\n");*/
#endif

  set_debug ();

  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  initialize_module_call_pinentry ();
  initialize_module_call_scd ();
  initialize_module_trustlist ();

  /* Try to create missing directories. */
  create_directories ();

  if (debug_wait && pipe_server)
    {
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      gnupg_sleep (debug_wait);
      log_debug ("... okay\n");
    }

  if (gpgconf_list == 3)
    agent_exit (!opt.use_standard_socket);
  if (gpgconf_list == 2)
    agent_exit (0);
  if (gpgconf_list)
    {
      char *filename;
      char *filename_esc;

      /* List options and default values in the GPG Conf format.  */
      filename = make_filename (opt.homedir, "gpg-agent.conf", NULL );
      filename_esc = percent_escape (filename, NULL);

      printf ("gpgconf-gpg-agent.conf:%lu:\"%s\n",
              GC_OPT_FLAG_DEFAULT, filename_esc);
      xfree (filename);
      xfree (filename_esc);

      printf ("verbose:%lu:\n"
              "quiet:%lu:\n"
              "debug-level:%lu:\"none:\n"
              "log-file:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME );
      printf ("default-cache-ttl:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, DEFAULT_CACHE_TTL );
      printf ("default-cache-ttl-ssh:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, DEFAULT_CACHE_TTL_SSH );
      printf ("max-cache-ttl:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, MAX_CACHE_TTL );
      printf ("max-cache-ttl-ssh:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, MAX_CACHE_TTL_SSH );
      printf ("enforce-passphrase-constraints:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      printf ("min-passphrase-len:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, MIN_PASSPHRASE_LEN );
      printf ("min-passphrase-nonalpha:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME,
              MIN_PASSPHRASE_NONALPHA);
      printf ("check-passphrase-pattern:%lu:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME);
      printf ("max-passphrase-days:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME,
              MAX_PASSPHRASE_DAYS);
      printf ("enable-passphrase-history:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      printf ("no-grab:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      printf ("ignore-cache-for-signing:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      printf ("allow-mark-trusted:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      printf ("disable-scdaemon:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);

      agent_exit (0);
    }

  /* If this has been called without any options, we merely check
     whether an agent is already running.  We do this here so that we
     don't clobber a logfile but print it directly to stderr. */
  if (!pipe_server && !is_daemon)
    {
      log_set_prefix (NULL, JNLIB_LOG_WITH_PREFIX);
      check_for_running_agent (0, 0);
      agent_exit (0);
    }

#ifdef ENABLE_NLS
  /* gpg-agent usually does not output any messages because it runs in
     the background.  For log files it is acceptable to have messages
     always encoded in utf-8.  We switch here to utf-8, so that
     commands like --help still give native messages.  It is far
     easier to switch only once instead of for every message and it
     actually helps when more then one thread is active (avoids an
     extra copy step). */
    bind_textdomain_codeset (PACKAGE_GT, "UTF-8");
#endif

  /* Now start with logging to a file if this is desired. */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, (JNLIB_LOG_WITH_PREFIX
                             |JNLIB_LOG_WITH_TIME
                             |JNLIB_LOG_WITH_PID));
      current_logfile = xstrdup (logfile);
    }
  if (DBG_ASSUAN)
    assuan_set_assuan_log_stream (log_get_stream ());

  /* Make sure that we have a default ttyname. */
  if (!default_ttyname && ttyname (1))
    default_ttyname = xstrdup (ttyname (1));
  if (!default_ttytype && getenv ("TERM"))
    default_ttytype = xstrdup (getenv ("TERM"));


  if (pipe_server)
    {
      /* This is the simple pipe based server */
      ctrl_t ctrl;

      ctrl = xtrycalloc (1, sizeof *ctrl);
      if (!ctrl)
        {
          log_error ("error allocating connection control data: %s\n",
                     strerror (errno) );
          agent_exit (1);
        }
      ctrl->session_env = session_env_new ();
      if (!ctrl->session_env)
        {
          log_error ("error allocating session environment block: %s\n",
                     strerror (errno) );
          xfree (ctrl);
          agent_exit (1);
        }
      agent_init_default_ctrl (ctrl);
      start_command_handler (ctrl, GNUPG_INVALID_FD, GNUPG_INVALID_FD);
      agent_deinit_default_ctrl (ctrl);
      xfree (ctrl);
    }
  else if (!is_daemon)
    ; /* NOTREACHED */
  else
    { /* Regular server mode */
      gnupg_fd_t fd;
      gnupg_fd_t fd_ssh;
      pid_t pid;

      /* Remove the DISPLAY variable so that a pinentry does not
         default to a specific display.  There is still a default
         display when gpg-agent was started using --display or a
         client requested this using an OPTION command.  Note, that we
         don't do this when running in reverse daemon mode (i.e. when
         exec the program given as arguments). */
#ifndef HAVE_W32_SYSTEM
      if (!opt.keep_display && !argc)
        unsetenv ("DISPLAY");
#endif


      /* Create the sockets.  */
      socket_name = create_socket_name
        ("S.gpg-agent", "/tmp/gpg-XXXXXX/S.gpg-agent");
      if (opt.ssh_support)
	socket_name_ssh = create_socket_name
          ("S.gpg-agent.ssh", "/tmp/gpg-XXXXXX/S.gpg-agent.ssh");

      fd = create_server_socket (socket_name, 0, &socket_nonce);
      if (opt.ssh_support)
	fd_ssh = create_server_socket (socket_name_ssh, 1, &socket_nonce_ssh);
      else
	fd_ssh = GNUPG_INVALID_FD;

      /* If we are going to exec a program in the parent, we record
         the PID, so that the child may check whether the program is
         still alive. */
      if (argc)
        parent_pid = getpid ();

      fflush (NULL);
#ifdef HAVE_W32_SYSTEM
      pid = getpid ();
      printf ("set GPG_AGENT_INFO=%s;%lu;1\n", socket_name, (ulong)pid);
#else /*!HAVE_W32_SYSTEM*/
      pid = fork ();
      if (pid == (pid_t)-1)
        {
          log_fatal ("fork failed: %s\n", strerror (errno) );
          exit (1);
        }
      else if (pid)
        { /* We are the parent */
          char *infostr, *infostr_ssh_sock, *infostr_ssh_pid;

          /* Close the socket FD. */
          close (fd);

          /* Note that we used a standard fork so that Pth runs in
             both the parent and the child.  The pth_fork would
             terminate Pth in the child but that is not the way we
             want it.  Thus we use a plain fork and terminate Pth here
             in the parent.  The pth_kill may or may not work reliable
             but it should not harm to call it.  Because Pth fiddles
             with the signal mask the signal mask might not be correct
             right now and thus we restore it.  That is not strictly
             necessary but some programs falsely assume a cleared
             signal mask.  es_pth_kill is a wrapper around pth_kill to
             take care not to use any Pth functions in the estream
             code after Pth has been killed.  */
          if ( !es_pth_kill () )
            log_error ("pth_kill failed in forked process\n");

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

          /* Create the info string: <name>:<pid>:<protocol_version> */
          if (asprintf (&infostr, "GPG_AGENT_INFO=%s:%lu:1",
                        socket_name, (ulong)pid ) < 0)
            {
              log_error ("out of core\n");
              kill (pid, SIGTERM);
              exit (1);
            }
	  if (opt.ssh_support)
	    {
	      if (asprintf (&infostr_ssh_sock, "SSH_AUTH_SOCK=%s",
			    socket_name_ssh) < 0)
		{
		  log_error ("out of core\n");
		  kill (pid, SIGTERM);
		  exit (1);
		}
	      if (asprintf (&infostr_ssh_pid, "SSH_AGENT_PID=%u",
			    pid) < 0)
		{
		  log_error ("out of core\n");
		  kill (pid, SIGTERM);
		  exit (1);
		}
	    }

          *socket_name = 0; /* Don't let cleanup() remove the socket -
                               the child should do this from now on */
	  if (opt.ssh_support)
	    *socket_name_ssh = 0;

          if (env_file_name)
            {
              FILE *fp;

              fp = fopen (env_file_name, "w");
              if (!fp)
                log_error (_("error creating `%s': %s\n"),
                             env_file_name, strerror (errno));
              else
                {
                  fputs (infostr, fp);
                  putc ('\n', fp);
                  if (opt.ssh_support)
                    {
                      fputs (infostr_ssh_sock, fp);
                      putc ('\n', fp);
                      fputs (infostr_ssh_pid, fp);
                      putc ('\n', fp);
                    }
                  fclose (fp);
                }
            }


          if (argc)
            { /* Run the program given on the commandline.  */
              if (putenv (infostr))
                {
                  log_error ("failed to set environment: %s\n",
                             strerror (errno) );
                  kill (pid, SIGTERM );
                  exit (1);
                }
              if (opt.ssh_support && putenv (infostr_ssh_sock))
                {
                  log_error ("failed to set environment: %s\n",
                             strerror (errno) );
                  kill (pid, SIGTERM );
                  exit (1);
                }
              if (opt.ssh_support && putenv (infostr_ssh_pid))
                {
                  log_error ("failed to set environment: %s\n",
                             strerror (errno) );
                  kill (pid, SIGTERM );
                  exit (1);
                }

              /* Close all the file descriptors except the standard
                 ones and those open at startup.  We explicitly don't
                 close 0,1,2 in case something went wrong collecting
                 them at startup.  */
              close_all_fds (3, startup_fd_list);

              /* Run the command.  */
              execvp (argv[0], argv);
              log_error ("failed to run the command: %s\n", strerror (errno));
              kill (pid, SIGTERM);
              exit (1);
            }
          else
            {
              /* Print the environment string, so that the caller can use
                 shell's eval to set it */
              if (csh_style)
                {
                  *strchr (infostr, '=') = ' ';
                  printf ("setenv %s;\n", infostr);
		  if (opt.ssh_support)
		    {
		      *strchr (infostr_ssh_sock, '=') = ' ';
		      printf ("setenv %s;\n", infostr_ssh_sock);
		      *strchr (infostr_ssh_pid, '=') = ' ';
		      printf ("setenv %s;\n", infostr_ssh_pid);
		    }
                }
              else
                {
                  printf ( "%s; export GPG_AGENT_INFO;\n", infostr);
		  if (opt.ssh_support)
		    {
		      printf ("%s; export SSH_AUTH_SOCK;\n", infostr_ssh_sock);
		      printf ("%s; export SSH_AGENT_PID;\n", infostr_ssh_pid);
		    }
                }
              xfree (infostr);
	      if (opt.ssh_support)
		{
		  xfree (infostr_ssh_sock);
		  xfree (infostr_ssh_pid);
		}
              exit (0);
            }
          /*NOTREACHED*/
        } /* End parent */

      /*
         This is the child
       */

      /* Detach from tty and put process into a new session */
      if (!nodetach )
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
                      log_error ("failed to open `%s': %s\n",
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
          log_set_prefix (NULL, oldflags | JNLIB_LOG_RUN_DETACHED);
          opt.running_detached = 1;
        }

      if (chdir("/"))
        {
          log_error ("chdir to / failed: %s\n", strerror (errno));
          exit (1);
        }

      {
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction (SIGPIPE, &sa, NULL);
      }
#endif /*!HAVE_W32_SYSTEM*/

      log_info ("%s %s started\n", strusage(11), strusage(13) );
      handle_connections (fd, opt.ssh_support ? fd_ssh : GNUPG_INVALID_FD);
      assuan_sock_close (fd);
    }

  return 0;
}


void
agent_exit (int rc)
{
  /*FIXME: update_random_seed_file();*/
#if 1
  /* at this time a bit annoying */
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
#endif
  gcry_control (GCRYCTL_TERM_SECMEM );
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}


static void
agent_init_default_ctrl (ctrl_t ctrl)
{
  /* Note we ignore malloc errors because we can't do much about it
     and the request will fail anyway shortly after this
     initialization. */
  session_env_setenv (ctrl->session_env, "DISPLAY", default_display);
  session_env_setenv (ctrl->session_env, "GPG_TTY", default_ttyname);
  session_env_setenv (ctrl->session_env, "TERM", default_ttytype);
  session_env_setenv (ctrl->session_env, "XAUTHORITY", default_xauthority);
  session_env_setenv (ctrl->session_env, "PINENTRY_USER_DATA", NULL);

  if (ctrl->lc_ctype)
    xfree (ctrl->lc_ctype);
  ctrl->lc_ctype = default_lc_ctype? xtrystrdup (default_lc_ctype) : NULL;

  if (ctrl->lc_messages)
    xfree (ctrl->lc_messages);
  ctrl->lc_messages = default_lc_messages? xtrystrdup (default_lc_messages)
                                    /**/ : NULL;

}


static void
agent_deinit_default_ctrl (ctrl_t ctrl)
{
  session_env_release (ctrl->session_env);

  if (ctrl->lc_ctype)
    xfree (ctrl->lc_ctype);
  if (ctrl->lc_messages)
    xfree (ctrl->lc_messages);
}


/* Reread parts of the configuration.  Note, that this function is
   obviously not thread-safe and should only be called from the PTH
   signal handler.

   Fixme: Due to the way the argument parsing works, we create a
   memory leak here for all string type arguments.  There is currently
   no clean way to tell whether the memory for the argument has been
   allocated or points into the process' original arguments.  Unless
   we have a mechanism to tell this, we need to live on with this. */
static void
reread_configuration (void)
{
  ARGPARSE_ARGS pargs;
  FILE *fp;
  unsigned int configlineno = 0;
  int dummy;

  if (!config_filename)
    return; /* No config file. */

  fp = fopen (config_filename, "r");
  if (!fp)
    {
      log_info (_("option file `%s': %s\n"),
                config_filename, strerror(errno) );
      return;
    }

  parse_rereadable_options (NULL, 1); /* Start from the default values. */

  memset (&pargs, 0, sizeof pargs);
  dummy = 0;
  pargs.argc = &dummy;
  pargs.flags = 1;  /* do not remove the args */
  while (optfile_parse (fp, config_filename, &configlineno, &pargs, opts) )
    {
      if (pargs.r_opt < -1)
        pargs.err = 1; /* Print a warning. */
      else /* Try to parse this option - ignore unchangeable ones. */
        parse_rereadable_options (&pargs, 1);
    }
  fclose (fp);
  set_debug ();
}


/* Return the file name of the socket we are using for native
   requests.  */
const char *
get_agent_socket_name (void)
{
  const char *s = socket_name;

  return (s && *s)? s : NULL;
}

/* Return the file name of the socket we are using for SSH
   requests.  */
const char *
get_agent_ssh_socket_name (void)
{
  const char *s = socket_name_ssh;

  return (s && *s)? s : NULL;
}


/* Under W32, this function returns the handle of the scdaemon
   notification event.  Calling it the first time creates that
   event.  */
#ifdef HAVE_W32_SYSTEM
void *
get_agent_scd_notify_event (void)
{
  static HANDLE the_event;

  if (!the_event)
    {
      HANDLE h, h2;
      SECURITY_ATTRIBUTES sa = { sizeof (SECURITY_ATTRIBUTES), NULL, TRUE};

      /* We need to use manual reset evet object due to the way our
         w32-pth wait function works: If we would use an automatic
         reset event we are not able to figure out which handle has
         been signaled because at the time we single out the signaled
         handles using WFSO the event has already been reset due to
         the WFMO.  */
      h = CreateEvent (&sa, TRUE, FALSE, NULL);
      if (!h)
        log_error ("can't create scd notify event: %s\n", w32_strerror (-1) );
      else if (!DuplicateHandle (GetCurrentProcess(), h,
                                 GetCurrentProcess(), &h2,
                                 EVENT_MODIFY_STATE|SYNCHRONIZE, TRUE, 0))
        {
          log_error ("setting syncronize for scd notify event failed: %s\n",
                     w32_strerror (-1) );
          CloseHandle (h);
        }
      else
        {
          CloseHandle (h);
          the_event = h2;
        }
    }

  log_debug  ("returning notify handle %p\n", the_event);
  return the_event;
}
#endif /*HAVE_W32_SYSTEM*/



/* Create a name for the socket.  With USE_STANDARD_SOCKET given as
   true using STANDARD_NAME in the home directory or if given as
   false from the mkdir type name TEMPLATE.  In the latter case a
   unique name in a unique new directory will be created.  In both
   cases check for valid characters as well as against a maximum
   allowed length for a unix domain socket is done.  The function
   terminates the process in case of an error.  Returns: Pointer to an
   allocated string with the absolute name of the socket used.  */
static char *
create_socket_name (char *standard_name, char *template)
{
  char *name, *p;

  if (opt.use_standard_socket)
    name = make_filename (opt.homedir, standard_name, NULL);
  else
    {
      name = xstrdup (template);
      p = strrchr (name, '/');
      if (!p)
	BUG ();
      *p = 0;
      if (!mkdtemp (name))
	{
	  log_error (_("can't create directory `%s': %s\n"),
		     name, strerror (errno));
	  agent_exit (2);
	}
      *p = '/';
    }

  if (strchr (name, PATHSEP_C))
    {
      log_error (("`%s' are not allowed in the socket name\n"), PATHSEP_S);
      agent_exit (2);
    }
  if (strlen (name) + 1 >= DIMof (struct sockaddr_un, sun_path) )
    {
      log_error (_("name of socket too long\n"));
      agent_exit (2);
    }
  return name;
}



/* Create a Unix domain socket with NAME.  Returns the file descriptor
   or terminates the process in case of an error.  Not that this
   function needs to be used for the regular socket first and only
   then for the ssh socket.  */
static gnupg_fd_t
create_server_socket (char *name, int is_ssh, assuan_sock_nonce_t *nonce)
{
  struct sockaddr_un *serv_addr;
  socklen_t len;
  gnupg_fd_t fd;
  int rc;

  fd = assuan_sock_new (AF_UNIX, SOCK_STREAM, 0);
  if (fd == ASSUAN_INVALID_FD)
    {
      log_error (_("can't create socket: %s\n"), strerror (errno));
      agent_exit (2);
    }

  serv_addr = xmalloc (sizeof (*serv_addr));
  memset (serv_addr, 0, sizeof *serv_addr);
  serv_addr->sun_family = AF_UNIX;
  if (strlen (name) + 1 >= sizeof (serv_addr->sun_path))
    {
      log_error (_("socket name `%s' is too long\n"), name);
      agent_exit (2);
    }
  strcpy (serv_addr->sun_path, name);
  len = SUN_LEN (serv_addr);
  rc = assuan_sock_bind (fd, (struct sockaddr*) serv_addr, len);
  if (opt.use_standard_socket && rc == -1 && errno == EADDRINUSE)
    {
      /* Check whether a gpg-agent is already running on the standard
         socket.  We do this test only if this is not the ssh socket.
         For ssh we assume that a test for gpg-agent has already been
         done and reuse the requested ssh socket.  Testing the
         ssh-socket is not possible because at this point, though we
         know the new Assuan socket, the Assuan server and thus the
         ssh-agent server is not yet operational.  This would lead to
         a hang.  */
      if (!is_ssh && !check_for_running_agent (1, 1))
        {
          log_error (_("a gpg-agent is already running - "
                       "not starting a new one\n"));
          *name = 0; /* Inhibit removal of the socket by cleanup(). */
          assuan_sock_close (fd);
          agent_exit (2);
        }
      remove (name);
      rc = assuan_sock_bind (fd, (struct sockaddr*) serv_addr, len);
    }
  if (rc != -1
      && (rc=assuan_sock_get_nonce ((struct sockaddr*)serv_addr, len, nonce)))
    log_error (_("error getting nonce for the socket\n"));
  if (rc == -1)
    {
      /* We use gpg_strerror here because it allows us to get strings
         for some W32 socket error codes.  */
      log_error (_("error binding socket to `%s': %s\n"),
		 serv_addr->sun_path,
                 gpg_strerror (gpg_error_from_errno (errno)));

      assuan_sock_close (fd);
      if (opt.use_standard_socket)
        *name = 0; /* Inhibit removal of the socket by cleanup(). */
      agent_exit (2);
    }

  if (listen (FD2INT(fd), 5 ) == -1)
    {
      log_error (_("listen() failed: %s\n"), strerror (errno));
      assuan_sock_close (fd);
      agent_exit (2);
    }

  if (opt.verbose)
    log_info (_("listening on socket `%s'\n"), serv_addr->sun_path);

  return fd;
}


/* Check that the directory for storing the private keys exists and
   create it if not.  This function won't fail as it is only a
   convenience function and not strictly necessary.  */
static void
create_private_keys_directory (const char *home)
{
  char *fname;
  struct stat statbuf;

  fname = make_filename (home, GNUPG_PRIVATE_KEYS_DIR, NULL);
  if (stat (fname, &statbuf) && errno == ENOENT)
    {
#ifdef HAVE_W32_SYSTEM  /*FIXME: Setup proper permissions.  */
      if (!CreateDirectory (fname, NULL))
        log_error (_("can't create directory `%s': %s\n"),
                   fname, w32_strerror (-1) );
#else
      if (mkdir (fname, S_IRUSR|S_IWUSR|S_IXUSR ))
        log_error (_("can't create directory `%s': %s\n"),
                   fname, strerror (errno) );
#endif
      else if (!opt.quiet)
        log_info (_("directory `%s' created\n"), fname);
    }
  xfree (fname);
}

/* Create the directory only if the supplied directory name is the
   same as the default one.  This way we avoid to create arbitrary
   directories when a non-default home directory is used.  To cope
   with HOME, we compare only the suffix if we see that the default
   homedir does start with a tilde.  We don't stop here in case of
   problems because other functions will throw an error anyway.*/
static void
create_directories (void)
{
  struct stat statbuf;
  const char *defhome = standard_homedir ();
  char *home;

  home = make_filename (opt.homedir, NULL);
  if ( stat (home, &statbuf) )
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
#ifdef HAVE_W32_SYSTEM
              if (!CreateDirectory (home, NULL))
                log_error (_("can't create directory `%s': %s\n"),
                           home, w32_strerror (-1) );
#else
              if (mkdir (home, S_IRUSR|S_IWUSR|S_IXUSR ))
                log_error (_("can't create directory `%s': %s\n"),
                           home, strerror (errno) );
#endif
              else
                {
                  if (!opt.quiet)
                    log_info (_("directory `%s' created\n"), home);
                  create_private_keys_directory (home);
                }
            }
        }
      else
        log_error (_("stat() failed for `%s': %s\n"), home, strerror (errno));
    }
  else if ( !S_ISDIR(statbuf.st_mode))
    {
      log_error (_("can't use `%s' as home directory\n"), home);
    }
  else /* exists and is a directory. */
    {
      create_private_keys_directory (home);
    }
  xfree (home);
}



/* This is the worker for the ticker.  It is called every few seconds
   and may only do fast operations. */
static void
handle_tick (void)
{
  static time_t last_minute;

  if (!last_minute)
    last_minute = time (NULL);

  /* Check whether the scdaemon has died and cleanup in this case. */
  agent_scd_check_aliveness ();

  /* If we are running as a child of another process, check whether
     the parent is still alive and shutdown if not. */
#ifndef HAVE_W32_SYSTEM
  if (parent_pid != (pid_t)(-1))
    {
      if (kill (parent_pid, 0))
        {
          shutdown_pending = 2;
          if (!opt.quiet)
            {
              log_info ("parent process died - shutting down\n");
              log_info ("%s %s stopped\n", strusage(11), strusage(13) );
            }
          cleanup ();
          agent_exit (0);
        }
    }
#endif /*HAVE_W32_SYSTEM*/

  /* Code to be run every minute.  */
  if (last_minute + 60 <= time (NULL))
    {
      check_own_socket ();
      last_minute = time (NULL);
    }

}


/* A global function which allows us to call the reload stuff from
   other places too.  This is only used when build for W32.  */
void
agent_sighup_action (void)
{
  log_info ("SIGHUP received - "
            "re-reading configuration and flushing cache\n");
  agent_flush_cache ();
  reread_configuration ();
  agent_reload_trustlist ();
}


static void
agent_sigusr2_action (void)
{
  if (opt.verbose)
    log_info ("SIGUSR2 received - updating card event counter\n");
  /* Nothing to check right now.  We only increment a counter.  */
  bump_card_eventcounter ();
}


static void
handle_signal (int signo)
{
  switch (signo)
    {
#ifndef HAVE_W32_SYSTEM
    case SIGHUP:
      agent_sighup_action ();
      break;

    case SIGUSR1:
      log_info ("SIGUSR1 received - printing internal information:\n");
      pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ());
      agent_query_dump_state ();
      agent_scd_dump_state ();
      break;

    case SIGUSR2:
      agent_sigusr2_action ();
      break;

    case SIGTERM:
      if (!shutdown_pending)
        log_info ("SIGTERM received - shutting down ...\n");
      else
        log_info ("SIGTERM received - still %ld running threads\n",
                  pth_ctrl( PTH_CTRL_GETTHREADS ));
      shutdown_pending++;
      if (shutdown_pending > 2)
        {
          log_info ("shutdown forced\n");
          log_info ("%s %s stopped\n", strusage(11), strusage(13) );
          cleanup ();
          agent_exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      log_info( "%s %s stopped\n", strusage(11), strusage(13));
      cleanup ();
      agent_exit (0);
      break;
#endif
    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}


/* Check the nonce on a new connection.  This is a NOP unless we we
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


/* This is the standard connection thread's main function.  */
static void *
start_connection_thread (void *arg)
{
  ctrl_t ctrl = arg;

  if (check_nonce (ctrl, &socket_nonce))
    return NULL;

  agent_init_default_ctrl (ctrl);
  if (opt.verbose)
    log_info (_("handler 0x%lx for fd %d started\n"),
              pth_thread_id (), FD2INT(ctrl->thread_startup.fd));

  start_command_handler (ctrl, GNUPG_INVALID_FD, ctrl->thread_startup.fd);
  if (opt.verbose)
    log_info (_("handler 0x%lx for fd %d terminated\n"),
              pth_thread_id (), FD2INT(ctrl->thread_startup.fd));

  agent_deinit_default_ctrl (ctrl);
  xfree (ctrl);
  return NULL;
}


/* This is the ssh connection thread's main function.  */
static void *
start_connection_thread_ssh (void *arg)
{
  ctrl_t ctrl = arg;

  if (check_nonce (ctrl, &socket_nonce_ssh))
    return NULL;

  agent_init_default_ctrl (ctrl);
  if (opt.verbose)
    log_info (_("ssh handler 0x%lx for fd %d started\n"),
              pth_thread_id (), FD2INT(ctrl->thread_startup.fd));

  start_command_handler_ssh (ctrl, ctrl->thread_startup.fd);
  if (opt.verbose)
    log_info (_("ssh handler 0x%lx for fd %d terminated\n"),
              pth_thread_id (), FD2INT(ctrl->thread_startup.fd));

  agent_deinit_default_ctrl (ctrl);
  xfree (ctrl);
  return NULL;
}


/* Connection handler loop.  Wait for connection requests and spawn a
   thread after accepting a connection.  */
static void
handle_connections (gnupg_fd_t listen_fd, gnupg_fd_t listen_fd_ssh)
{
  pth_attr_t tattr;
  pth_event_t ev, time_ev;
  sigset_t sigs;
  int signo;
  struct sockaddr_un paddr;
  socklen_t plen;
  fd_set fdset, read_fdset;
  int ret;
  gnupg_fd_t fd;
  int nfd;

  tattr = pth_attr_new();
  pth_attr_set (tattr, PTH_ATTR_JOINABLE, 0);
  pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 256*1024);

#ifndef HAVE_W32_SYSTEM /* fixme */
  /* Make sure that the signals we are going to handle are not blocked
     and create an event object for them.  We also set the default
     action to ignore because we use an Pth event to get notified
     about signals.  This avoids that the default action is taken in
     case soemthing goes wrong within Pth.  The problem might also be
     a Pth bug.  */
  sigemptyset (&sigs );
  {
    static const int mysigs[] = { SIGHUP, SIGUSR1, SIGUSR2, SIGINT, SIGTERM };
    struct sigaction sa;
    int i;

    for (i=0; i < DIM (mysigs); i++)
      {
        sigemptyset (&sa.sa_mask);
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = 0;
        sigaction (mysigs[i], &sa, NULL);

        sigaddset (&sigs, mysigs[i]);
      }
  }

  pth_sigmask (SIG_UNBLOCK, &sigs, NULL);
  ev = pth_event (PTH_EVENT_SIGS, &sigs, &signo);
#else
# ifdef PTH_EVENT_HANDLE
  sigs = 0;
  ev = pth_event (PTH_EVENT_HANDLE, get_agent_scd_notify_event ());
  signo = 0;
# else
  /* Use a dummy event. */
  sigs = 0;
  ev = pth_event (PTH_EVENT_SIGS, &sigs, &signo);
# endif
#endif
  time_ev = NULL;

  /* Set a flag to tell call-scd.c that it may enable event
     notifications.  */
  opt.sigusr2_enabled = 1;

  FD_ZERO (&fdset);
  FD_SET (FD2INT (listen_fd), &fdset);
  nfd = FD2INT (listen_fd);
  if (listen_fd_ssh != GNUPG_INVALID_FD)
    {
      FD_SET ( FD2INT(listen_fd_ssh), &fdset);
      if (FD2INT (listen_fd_ssh) > nfd)
        nfd = FD2INT (listen_fd_ssh);
    }

  for (;;)
    {
      /* Make sure that our signals are not blocked.  */
      pth_sigmask (SIG_UNBLOCK, &sigs, NULL);

      /* Shutdown test.  */
      if (shutdown_pending)
        {
          if (pth_ctrl (PTH_CTRL_GETTHREADS) == 1)
            break; /* ready */

          /* Do not accept new connections but keep on running the
             loop to cope with the timer events.  */
          FD_ZERO (&fdset);
	}

      /* Create a timeout event if needed.  To help with power saving
         we syncronize the ticks to the next full second.  */
      if (!time_ev)
        {
          pth_time_t nexttick;

          nexttick = pth_timeout (TIMERTICK_INTERVAL, 0);
          if (nexttick.tv_usec > 10)  /* Use a 10 usec threshhold.  */
            {
              nexttick.tv_sec++;
              nexttick.tv_usec = 0;
            }
          time_ev = pth_event (PTH_EVENT_TIME, nexttick);
        }

      /* POSIX says that fd_set should be implemented as a structure,
         thus a simple assignment is fine to copy the entire set.  */
      read_fdset = fdset;

      if (time_ev)
        pth_event_concat (ev, time_ev, NULL);
      ret = pth_select_ev (nfd+1, &read_fdset, NULL, NULL, NULL, ev);
      if (time_ev)
        pth_event_isolate (time_ev);

      if (ret == -1)
	{
          if (pth_event_occurred (ev)
              || (time_ev && pth_event_occurred (time_ev)))
            {
              if (pth_event_occurred (ev))
                {
#if defined(HAVE_W32_SYSTEM) && defined(PTH_EVENT_HANDLE)
                  agent_sigusr2_action ();
#else
                  handle_signal (signo);
#endif
                }
              if (time_ev && pth_event_occurred (time_ev))
                {
                  pth_event_free (time_ev, PTH_FREE_ALL);
                  time_ev = NULL;
                  handle_tick ();
                }
              continue;
            }
          log_error (_("pth_select failed: %s - waiting 1s\n"),
                     strerror (errno));
          pth_sleep (1);
          continue;
	}

      if (pth_event_occurred (ev))
        {
#if defined(HAVE_W32_SYSTEM) && defined(PTH_EVENT_HANDLE)
          agent_sigusr2_action ();
#else
          handle_signal (signo);
#endif
        }

      if (time_ev && pth_event_occurred (time_ev))
        {
          pth_event_free (time_ev, PTH_FREE_ALL);
          time_ev = NULL;
          handle_tick ();
        }


      /* We now might create new threads and because we don't want any
         signals (as we are handling them here) to be delivered to a
         new thread.  Thus we need to block those signals. */
      pth_sigmask (SIG_BLOCK, &sigs, NULL);

      if (!shutdown_pending && FD_ISSET (FD2INT (listen_fd), &read_fdset))
	{
          ctrl_t ctrl;

          plen = sizeof paddr;
	  fd = INT2FD (pth_accept (FD2INT(listen_fd),
                                   (struct sockaddr *)&paddr, &plen));
	  if (fd == GNUPG_INVALID_FD)
	    {
	      log_error ("accept failed: %s\n", strerror (errno));
	    }
          else if ( !(ctrl = xtrycalloc (1, sizeof *ctrl)) )
            {
              log_error ("error allocating connection control data: %s\n",
                         strerror (errno) );
              assuan_sock_close (fd);
            }
          else if ( !(ctrl->session_env = session_env_new ()) )
            {
              log_error ("error allocating session environment block: %s\n",
                         strerror (errno) );
              xfree (ctrl);
              assuan_sock_close (fd);
            }
          else
            {
              char threadname[50];

              snprintf (threadname, sizeof threadname-1,
                        "conn fd=%d (gpg)", FD2INT(fd));
              threadname[sizeof threadname -1] = 0;
              pth_attr_set (tattr, PTH_ATTR_NAME, threadname);
              ctrl->thread_startup.fd = fd;
              if (!pth_spawn (tattr, start_connection_thread, ctrl))
                {
                  log_error ("error spawning connection handler: %s\n",
                             strerror (errno) );
                  assuan_sock_close (fd);
                  xfree (ctrl);
                }
            }
          fd = GNUPG_INVALID_FD;
	}

      if (!shutdown_pending && listen_fd_ssh != GNUPG_INVALID_FD
          && FD_ISSET ( FD2INT (listen_fd_ssh), &read_fdset))
	{
          ctrl_t ctrl;

          plen = sizeof paddr;
	  fd = INT2FD(pth_accept (FD2INT(listen_fd_ssh),
                                  (struct sockaddr *)&paddr, &plen));
	  if (fd == GNUPG_INVALID_FD)
	    {
	      log_error ("accept failed for ssh: %s\n", strerror (errno));
	    }
          else if ( !(ctrl = xtrycalloc (1, sizeof *ctrl)) )
            {
              log_error ("error allocating connection control data: %s\n",
                         strerror (errno) );
              assuan_sock_close (fd);
            }
          else if ( !(ctrl->session_env = session_env_new ()) )
            {
              log_error ("error allocating session environment block: %s\n",
                         strerror (errno) );
              xfree (ctrl);
              assuan_sock_close (fd);
            }
          else
            {
              char threadname[50];

              agent_init_default_ctrl (ctrl);
              snprintf (threadname, sizeof threadname-1,
                        "conn fd=%d (ssh)", FD2INT(fd));
              threadname[sizeof threadname -1] = 0;
              pth_attr_set (tattr, PTH_ATTR_NAME, threadname);
              ctrl->thread_startup.fd = fd;
              if (!pth_spawn (tattr, start_connection_thread_ssh, ctrl) )
                {
                  log_error ("error spawning ssh connection handler: %s\n",
                             strerror (errno) );
                  assuan_sock_close (fd);
                  xfree (ctrl);
                }
            }
          fd = GNUPG_INVALID_FD;
	}
    }

  pth_event_free (ev, PTH_FREE_ALL);
  if (time_ev)
    pth_event_free (time_ev, PTH_FREE_ALL);
  cleanup ();
  log_info (_("%s %s stopped\n"), strusage(11), strusage(13));
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
   separate thread so that check_own_thread can be called from the
   timer tick.  */
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
         server.  Setting the name to empty does this.  */
      if (socket_name)
        *socket_name = 0;
      if (socket_name_ssh)
        *socket_name_ssh = 0;
      shutdown_pending = 2;
      log_info ("this process is useless - shutting down\n");
    }
  check_own_socket_running--;
  return NULL;
}


/* Check whether we are still listening on our own socket.  In case
   another gpg-agent process started after us has taken ownership of
   our socket, we woul linger around without any real taks.  Thus we
   better check once in a while whether we are really needed.  */
static void
check_own_socket (void)
{
  char *sockname;
  pth_attr_t tattr;

  if (!opt.use_standard_socket)
    return; /* This check makes only sense in standard socket mode.  */

  if (check_own_socket_running || shutdown_pending)
    return;  /* Still running or already shutting down.  */

  sockname = make_filename (opt.homedir, "S.gpg-agent", NULL);
  if (!sockname)
    return; /* Out of memory.  */

  tattr = pth_attr_new();
  pth_attr_set (tattr, PTH_ATTR_JOINABLE, 0);
  pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 256*1024);
  pth_attr_set (tattr, PTH_ATTR_NAME, "check-own-socket");

  if (!pth_spawn (tattr, check_own_socket_thread, sockname))
      log_error ("error spawning check_own_socket_thread: %s\n",
                 strerror (errno) );
  pth_attr_destroy (tattr);
}



/* Figure out whether an agent is available and running. Prints an
   error if not.  If SILENT is true, no messages are printed.  Usually
   started with MODE 0.  Returns 0 if the agent is running. */
static int
check_for_running_agent (int silent, int mode)
{
  int rc;
  char *infostr, *p;
  assuan_context_t ctx = NULL;
  int prot, pid;

  if (!mode)
    {
      infostr = getenv ("GPG_AGENT_INFO");
      if (!infostr || !*infostr)
        {
          if (!check_for_running_agent (silent, 1))
            return 0; /* Okay, its running on the standard socket. */
          if (!silent)
            log_error (_("no gpg-agent running in this session\n"));
          return -1;
        }

      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, PATHSEP_C)) || p == infostr)
        {
          xfree (infostr);
          if (!check_for_running_agent (silent, 1))
            return 0; /* Okay, its running on the standard socket. */
          if (!silent)
            log_error (_("malformed GPG_AGENT_INFO environment variable\n"));
          return -1;
        }

      *p++ = 0;
      pid = atoi (p);
      while (*p && *p != PATHSEP_C)
        p++;
      prot = *p? atoi (p+1) : 0;
      if (prot != 1)
        {
          xfree (infostr);
          if (!silent)
            log_error (_("gpg-agent protocol version %d is not supported\n"),
                       prot);
          if (!check_for_running_agent (silent, 1))
            return 0; /* Okay, its running on the standard socket. */
          return -1;
        }
    }
  else /* MODE != 0 */
    {
      infostr = make_filename (opt.homedir, "S.gpg-agent", NULL);
      pid = (pid_t)(-1);
    }

  rc = assuan_new (&ctx);
  if (! rc)
    rc = assuan_socket_connect (ctx, infostr, pid, 0);
  xfree (infostr);
  if (rc)
    {
      if (!mode && !check_for_running_agent (silent, 1))
        return 0; /* Okay, its running on the standard socket. */

      if (!mode && !silent)
        log_error ("can't connect to the agent: %s\n", gpg_strerror (rc));

      if (ctx)
	assuan_release (ctx);
      return -1;
    }

  if (!opt.quiet && !silent)
    log_info ("gpg-agent running and available\n");

  assuan_release (ctx);
  return 0;
}

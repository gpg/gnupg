/* gpg-agent.c  -  The GnuPG Agent
 *	Copyright (C) 2000, 2001, 2002, 2003, 2004,
 *                    2005 Free Software Foundation, Inc.
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
#include <sys/socket.h>
#include <sys/un.h>
#endif /*HAVE_W32_SYSTEM*/
#include <unistd.h>
#include <signal.h>
#include <pth.h>

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"
#include <assuan.h> /* Malloc hooks */

#include "i18n.h"
#include "sysutils.h"
#ifdef HAVE_W32_SYSTEM
#include "../jnlib/w32-afunix.h"
#endif
#include "setenv.h"


enum cmd_and_opt_values 
{ aNull = 0,
  oCsh		  = 'c',
  oQuiet	  = 'q',
  oSh		  = 's',
  oVerbose	  = 'v',

  oNoVerbose = 500,
  aGPGConfList,
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
  oDisplay,
  oTTYname,
  oTTYtype,
  oLCctype,
  oLCmessages,
  oScdaemonProgram,
  oDefCacheTTL,
  oMaxCacheTTL,
  oUseStandardSocket,
  oNoUseStandardSocket,

  oIgnoreCacheForSigning,
  oAllowMarkTrusted,
  oAllowPresetPassphrase,
  oKeepTTY,
  oKeepDISPLAY,
  oSSHSupport,
  oDisableScdaemon
};



static ARGPARSE_OPTS opts[] = {

  { aGPGConfList, "gpgconf-list", 256, "@" },
  
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
  { oScdaemonProgram, "scdaemon-program", 2 ,
                               N_("|PGM|use PGM as the SCdaemon program") },
  { oDisableScdaemon, "disable-scdaemon", 0, N_("do not use the SCdaemon") },

  { oDisplay,    "display",     2, "@" },
  { oTTYname,    "ttyname",     2, "@" },
  { oTTYtype,    "ttytype",     2, "@" },
  { oLCctype,    "lc-ctype",    2, "@" },
  { oLCmessages, "lc-messages", 2, "@" },
  { oKeepTTY, "keep-tty", 0,  N_("ignore requests to change the TTY")},
  { oKeepDISPLAY, "keep-display",
                          0, N_("ignore requests to change the X display")},

  { oDefCacheTTL, "default-cache-ttl", 4,
                               N_("|N|expire cached PINs after N seconds")},
  { oMaxCacheTTL, "max-cache-ttl", 4, "@" },
  { oIgnoreCacheForSigning, "ignore-cache-for-signing", 0,
                               N_("do not use the PIN cache when signing")},
  { oAllowMarkTrusted, "allow-mark-trusted", 0,
                             N_("allow clients to mark keys as \"trusted\"")},
  { oAllowPresetPassphrase, "allow-preset-passphrase", 0,
                             N_("allow presetting passphrase")},
  { oSSHSupport, "enable-ssh-support", 0, N_("enable ssh-agent emulation") },
  {0}
};


#define DEFAULT_CACHE_TTL (10*60)  /* 10 minutes */
#define MAX_CACHE_TTL     (120*60) /* 2 hours */


/* flag to indicate that a shutdown was requested */
static int shutdown_pending;


/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Name of the communication socket used for native gpg-agent requests.  */
static char *socket_name;

/* Name of the communication socket used for ssh-agent-emulation.  */
static char *socket_name_ssh;

/* Default values for options passed to the pinentry. */
static char *default_display;
static char *default_ttyname;
static char *default_ttytype;
static char *default_lc_ctype;
static char *default_lc_messages;

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

static char *create_socket_name (int use_standard_socket,
                                 char *standard_name, char *template);
static int create_server_socket (int is_standard_name, const char *name);
static void create_directories (void);

static void handle_connections (int listen_fd, int listen_fd_ssh);
static int check_for_running_agent (int);

/* Pth wrapper function definitions. */
GCRY_THREAD_OPTION_PTH_IMPL;




/*
   Functions. 
 */


static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "gpg-agent (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
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



static void
i18n_init (void)
{
#ifdef USE_SIMPLE_GETTEXT
    set_gettext_file( PACKAGE_GT );
#else
#ifdef ENABLE_NLS
    setlocale (LC_ALL, "");
    bindtextdomain (PACKAGE_GT, LOCALEDIR);
    textdomain (PACKAGE_GT);
#endif
#endif
}



/* Used by gcry for logging */
static void
my_gcry_logger (void *dummy, int level, const char *fmt, va_list arg_ptr)
{
  /* translate the log levels */
  switch (level)
    {
    case GCRY_LOG_CONT: level = JNLIB_LOG_CONT; break;
    case GCRY_LOG_INFO: level = JNLIB_LOG_INFO; break;
    case GCRY_LOG_WARN: level = JNLIB_LOG_WARN; break;
    case GCRY_LOG_ERROR:level = JNLIB_LOG_ERROR; break;
    case GCRY_LOG_FATAL:level = JNLIB_LOG_FATAL; break;
    case GCRY_LOG_BUG:  level = JNLIB_LOG_BUG; break;
    case GCRY_LOG_DEBUG:level = JNLIB_LOG_DEBUG; break;
    default:            level = JNLIB_LOG_ERROR; break;  
    }
  log_logv (level, fmt, arg_ptr);
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
  if (!debug_level)
    ;
  else if (!strcmp (debug_level, "none"))
    opt.debug = 0;
  else if (!strcmp (debug_level, "basic"))
    opt.debug = DBG_ASSUAN_VALUE;
  else if (!strcmp (debug_level, "advanced"))
    opt.debug = DBG_ASSUAN_VALUE|DBG_COMMAND_VALUE;
  else if (!strcmp (debug_level, "expert"))
    opt.debug = (DBG_ASSUAN_VALUE|DBG_COMMAND_VALUE
                 |DBG_CACHE_VALUE);
  else if (!strcmp (debug_level, "guru"))
    opt.debug = ~0;
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
      opt.scdaemon_program = NULL;
      opt.def_cache_ttl = DEFAULT_CACHE_TTL;
      opt.max_cache_ttl = MAX_CACHE_TTL;
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
          xfree (current_logfile);
          current_logfile = xtrystrdup (pargs->r.ret_str);
        }
      break;

    case oNoGrab: opt.no_grab = 1; break;
      
    case oPinentryProgram: opt.pinentry_program = pargs->r.ret_str; break;
    case oScdaemonProgram: opt.scdaemon_program = pargs->r.ret_str; break;
    case oDisableScdaemon: opt.disable_scdaemon = 1; break;

    case oDefCacheTTL: opt.def_cache_ttl = pargs->r.ret_ulong; break;
    case oMaxCacheTTL: opt.max_cache_ttl = pargs->r.ret_ulong; break;
      
    case oIgnoreCacheForSigning: opt.ignore_cache_for_signing = 1; break;

    case oAllowMarkTrusted: opt.allow_mark_trusted = 1; break;

    case oAllowPresetPassphrase: opt.allow_preset_passphrase = 1; break;

    default:
      return 0; /* not handled */
    }
  return 1; /* handled */
}


int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  int may_coredump;
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
  int standard_socket = 0;
  gpg_error_t err;

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix ("gpg-agent", JNLIB_LOG_WITH_PREFIX|JNLIB_LOG_WITH_PID); 

  /* Try to auto set the character set.  */
  set_native_charset (NULL); 

  i18n_init ();

  /* Libgcrypt requires us to register the threading model first.
     Note that this will also do the pth_init. */
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
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  assuan_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);
  assuan_set_assuan_log_stream (log_get_stream ());
  assuan_set_assuan_log_prefix (log_get_prefix (NULL));

  gcry_set_log_handler (my_gcry_logger, NULL);
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  /* Set default options.  */
  parse_rereadable_options (NULL, 0); /* Reset them to default values. */
#ifdef HAVE_W32_SYSTEM
  standard_socket = 1;  /* Under Windows we always use a standard
                           socket.  */
#endif
  
  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;

  opt.homedir = default_homedir ();

  /* Record some of the original environment strings. */
  opt.startup_display = getenv ("DISPLAY");
  if (opt.startup_display)
    opt.startup_display = xstrdup (opt.startup_display);
  opt.startup_ttyname = ttyname (0);
  if (opt.startup_ttyname)
    opt.startup_ttyname = xstrdup (opt.startup_ttyname);
  opt.startup_ttytype = getenv ("TERM");
  if (opt.startup_ttytype)
    opt.startup_ttytype = xstrdup (opt.startup_ttytype);
  /* Fixme: Neen to use the locale fucntion here.  */
  opt.startup_lc_ctype = getenv ("LC_CTYPE");
  if (opt.startup_lc_ctype) 
    opt.startup_lc_ctype = xstrdup (opt.startup_lc_ctype);
  opt.startup_lc_messages = getenv ("LC_MESSAGES");
  if (opt.startup_lc_messages)
    opt.startup_lc_messages = xstrdup (opt.startup_lc_messages);

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

  /* initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
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
          break;

        case oUseStandardSocket: standard_socket = 1; break;
        case oNoUseStandardSocket: standard_socket = 0; break;

        case oKeepTTY: opt.keep_tty = 1; break;
        case oKeepDISPLAY: opt.keep_display = 1; break;

	case oSSHSupport:  opt.ssh_support = 1; break;

        default : pargs.err = configfp? 1:2; break;
	}
    }
  if (configfp)
    {
      fclose( configfp );
      configfp = NULL;
      /* Keep a copy of the name so that it can be read on SIGHUP. */
      config_filename = configname;
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

  initialize_module_query ();
  initialize_module_call_scd ();
  
  /* Try to create missing directories. */
  create_directories ();

  if (debug_wait && pipe_server)
    {
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      sleep (debug_wait);
      log_debug ("... okay\n");
    }
  
  if (gpgconf_list)
    {
      char *filename;

      /* List options and default values in the GPG Conf format.  */

      /* The following list is taken from gnupg/tools/gpgconf-comp.c.  */
      /* Option flags.  YOU MUST NOT CHANGE THE NUMBERS OF THE EXISTING
         FLAGS, AS THEY ARE PART OF THE EXTERNAL INTERFACE.  */
#define GC_OPT_FLAG_NONE	0UL
      /* The RUNTIME flag for an option indicates that the option can be
         changed at runtime.  */
#define GC_OPT_FLAG_RUNTIME	(1UL << 3)
      /* The DEFAULT flag for an option indicates that the option has a
         default value.  */
#define GC_OPT_FLAG_DEFAULT	(1UL << 4)
      /* The DEF_DESC flag for an option indicates that the option has a
         default, which is described by the value of the default field.  */
#define GC_OPT_FLAG_DEF_DESC	(1UL << 5)
      /* The NO_ARG_DESC flag for an option indicates that the argument has
         a default, which is described by the value of the ARGDEF field.  */
#define GC_OPT_FLAG_NO_ARG_DESC	(1UL << 6)

      filename = make_filename (opt.homedir, "gpg-agent.conf", NULL );
      printf ("gpgconf-gpg-agent.conf:%lu:\"%s\n",
              GC_OPT_FLAG_DEFAULT, filename);
      xfree (filename);

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
      check_for_running_agent (0);
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

  /* Make sure that we have a default ttyname. */
  if (!default_ttyname && ttyname (1))
    default_ttyname = xstrdup (ttyname (1));
  if (!default_ttytype && getenv ("TERM"))
    default_ttytype = xstrdup (getenv ("TERM"));


  if (pipe_server)
    { /* this is the simple pipe based server */
      start_command_handler (-1, -1);
    }
  else if (!is_daemon)
    ; /* NOTREACHED */
  else
    { /* Regular server mode */
      int fd;
      int fd_ssh;
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
      socket_name = create_socket_name (standard_socket,
                                        "S.gpg-agent",
                                        "/tmp/gpg-XXXXXX/S.gpg-agent");
      if (opt.ssh_support)
	socket_name_ssh = create_socket_name (standard_socket, 
                                            "S.gpg-agent.ssh",
                                            "/tmp/gpg-XXXXXX/S.gpg-agent.ssh");

      fd = create_server_socket (standard_socket, socket_name);
      if (opt.ssh_support)
	fd_ssh = create_server_socket (standard_socket, socket_name_ssh);
      else
	fd_ssh = -1;

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
          
          close (fd);
          
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
                  printf ("setenv %s\n", infostr);
		  if (opt.ssh_support)
		    {
		      *strchr (infostr_ssh_sock, '=') = ' ';
		      printf ("setenv %s\n", infostr_ssh_sock);
		      *strchr (infostr_ssh_pid, '=') = ' ';
		      printf ("setenv %s\n", infostr_ssh_pid);
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
              free (infostr); /* (Note that a vanilla free is here correct.) */
	      if (opt.ssh_support)
		{
		  free (infostr_ssh_sock);
		  free (infostr_ssh_pid);
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
                close (i);
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

      handle_connections (fd, opt.ssh_support ? fd_ssh : -1);
      close (fd);
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


void
agent_init_default_ctrl (struct server_control_s *ctrl)
{
  ctrl->connection_fd = -1;

  /* Note we ignore malloc errors because we can't do much about it
     and the request will fail anyway shortly after this
     initialization. */
  if (ctrl->display)
    free (ctrl->display);
  ctrl->display = default_display? strdup (default_display) : NULL;

  if (ctrl->ttyname)
    free (ctrl->ttyname);
  ctrl->ttyname = default_ttyname? strdup (default_ttyname) : NULL;

  if (ctrl->ttytype)
    free (ctrl->ttytype);
  ctrl->ttytype = default_ttytype? strdup (default_ttytype) : NULL;

  if (ctrl->lc_ctype)
    free (ctrl->lc_ctype);
  ctrl->lc_ctype = default_lc_ctype? strdup (default_lc_ctype) : NULL;

  if (ctrl->lc_messages)
    free (ctrl->lc_messages);
  ctrl->lc_messages = default_lc_messages? strdup (default_lc_messages) : NULL;
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
      log_error (_("option file `%s': %s\n"),
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




/* Create a name for the socket.  With USE_STANDARD_SOCKET given as
   true using STANDARD_NAME in the home directory or if given has
   false from the mkdir type name TEMPLATE.  In the latter case a
   unique name in a unique new directory will be created.  In both
   cases check for valid characters as well as against a maximum
   allowed length for a unix domain socket is done.  The function
   terminates the process in case of an error.  Retunrs: Pointer to an
   allcoated string with the absolute name of the socket used.  */
static char *
create_socket_name (int use_standard_socket,
		    char *standard_name, char *template)
{
  char *name, *p;

  if (use_standard_socket)
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



/* Create a Unix domain socket with NAME.  IS_STANDARD_NAME indicates
   whether a non-random socket is used.  Returns the filedescriptor or
   terminates the process in case of an error. */
static int
create_server_socket (int is_standard_name, const char *name)
{
  struct sockaddr_un *serv_addr;
  socklen_t len;
  int fd;
  int rc;

#ifdef HAVE_W32_SYSTEM
  fd = _w32_sock_new (AF_UNIX, SOCK_STREAM, 0);
#else
  fd = socket (AF_UNIX, SOCK_STREAM, 0);
#endif
  if (fd == -1)
    {
      log_error (_("can't create socket: %s\n"), strerror (errno));
      agent_exit (2);
    }

  serv_addr = xmalloc (sizeof (*serv_addr)); 
  memset (serv_addr, 0, sizeof *serv_addr);
  serv_addr->sun_family = AF_UNIX;
  assert (strlen (name) + 1 < sizeof (serv_addr->sun_path));
  strcpy (serv_addr->sun_path, name);
  len = (offsetof (struct sockaddr_un, sun_path)
	 + strlen (serv_addr->sun_path) + 1);

#ifdef HAVE_W32_SYSTEM
  rc = _w32_sock_bind (fd, (struct sockaddr*) serv_addr, len);
  if (is_standard_name && rc == -1 )
    {
      remove (name);
      rc = bind (fd, (struct sockaddr*) serv_addr, len);
    }
#else
  rc = bind (fd, (struct sockaddr*) serv_addr, len);
  if (is_standard_name && rc == -1 && errno == EADDRINUSE)
    {
      remove (name);
      rc = bind (fd, (struct sockaddr*) serv_addr, len);
    }
#endif
  if (rc == -1)
    {
      log_error (_("error binding socket to `%s': %s\n"),
		 serv_addr->sun_path, strerror (errno));
      close (fd);
      agent_exit (2);
    }

  if (listen (fd, 5 ) == -1)
    {
      log_error (_("listen() failed: %s\n"), strerror (errno));
      close (fd);
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
  const char *defhome = GNUPG_DEFAULT_HOMEDIR;
  char *home;

  home = make_filename (opt.homedir, NULL);
  if ( stat (home, &statbuf) )
    {
      if (errno == ENOENT)
        {
          if ( (*defhome == '~'
                && (strlen (home) >= strlen (defhome+1)
                    && !strcmp (home + strlen(home)
                                - strlen (defhome+1), defhome+1)))
               || (*defhome != '~' && !strcmp (home, defhome) )
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
  /* Check whether the scdaemon has dies and cleanup in this case. */
  agent_scd_check_aliveness ();

  /* If we are running as a child of another process, check whether
     the parent is still alive and shutdwon if now. */
#ifndef HAVE_W32_SYSTEM
  if (parent_pid != (pid_t)(-1))
    {
      if (kill (parent_pid, 0))
        {
          shutdown_pending = 2;
          log_info ("parent process died - shutting down\n");
          log_info ("%s %s stopped\n", strusage(11), strusage(13) );
          cleanup ();
          agent_exit (0);
        }
    }
#endif /*HAVE_W32_SYSTEM*/
}


static void
handle_signal (int signo)
{
  switch (signo)
    {
#ifndef HAVE_W32_SYSTEM
    case SIGHUP:
      log_info ("SIGHUP received - "
                "re-reading configuration and flushing cache\n");
      agent_flush_cache ();
      reread_configuration ();
      agent_reload_trustlist ();
      break;
      
    case SIGUSR1:
      log_info ("SIGUSR1 received - printing internal information:\n");
      pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ());
      break;
      
    case SIGUSR2:
      log_info ("SIGUSR2 received - checking smartcard status\n");
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


/* This is the standard connection thread's main function.  */
static void *
start_connection_thread (void *arg)
{
  int fd = (int)arg;

  if (opt.verbose)
    log_info (_("handler for fd %d started\n"), fd);

  /* FIXME: Move this housekeeping into a ticker function.  Calling it
     for each connection should work but won't work anymore if our
     clients start to keep connections. */
  agent_trustlist_housekeeping ();

  start_command_handler (-1, fd);
  if (opt.verbose)
    log_info (_("handler for fd %d terminated\n"), fd);
  
  return NULL;
}


/* This is the ssh connection thread's main function.  */
static void *
start_connection_thread_ssh (void *arg)
{
  int fd = (int)arg;

  if (opt.verbose)
    log_info (_("ssh handler for fd %d started\n"), fd);

  agent_trustlist_housekeeping ();

  start_command_handler_ssh (fd);
  if (opt.verbose)
    log_info (_("ssh handler for fd %d terminated\n"), fd);
  
  return NULL;
}


/* Connection handler loop.  Wait for coecntion requests and spawn a
   thread after accepting a connection.  */
static void
handle_connections (int listen_fd, int listen_fd_ssh)
{
  pth_attr_t tattr;
  pth_event_t ev, time_ev;
  sigset_t sigs;
  int signo;
  struct sockaddr_un paddr;
  socklen_t plen;
  fd_set fdset, read_fdset;
  int ret;
  int fd;

  tattr = pth_attr_new();
  pth_attr_set (tattr, PTH_ATTR_JOINABLE, 0);
  pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 256*1024);
  pth_attr_set (tattr, PTH_ATTR_NAME, "gpg-agent");

#ifndef HAVE_W32_SYSTEM /* fixme */
  sigemptyset (&sigs );
  sigaddset (&sigs, SIGHUP);
  sigaddset (&sigs, SIGUSR1);
  sigaddset (&sigs, SIGUSR2);
  sigaddset (&sigs, SIGINT);
  sigaddset (&sigs, SIGTERM);
  ev = pth_event (PTH_EVENT_SIGS, &sigs, &signo);
#else
  ev = NULL;
#endif
  time_ev = NULL;

  FD_ZERO (&fdset);
  FD_SET (listen_fd, &fdset);
  if (listen_fd_ssh != -1)
    FD_SET (listen_fd_ssh, &fdset);

  for (;;)
    {
      if (shutdown_pending)
        {
          if (pth_ctrl (PTH_CTRL_GETTHREADS) == 1)
            break; /* ready */

          /* Do not accept anymore connections and wait for existing
             connections to terminate */
          signo = 0;
          pth_wait (ev);
          if (pth_event_occurred (ev) && signo)
            handle_signal (signo);
          continue;
	}

      /* Create a timeout event if needed. */
      if (!time_ev)
        time_ev = pth_event (PTH_EVENT_TIME, pth_timeout (2, 0));

      /* POSIX says that fd_set should be implemented as a structure,
         thus a simple assignment is fine to copy the entire set.  */
      read_fdset = fdset;

      if (time_ev)
        pth_event_concat (ev, time_ev, NULL);
      ret = pth_select_ev (FD_SETSIZE, &read_fdset, NULL, NULL, NULL, ev);
      if (time_ev)
        pth_event_isolate (time_ev);

      if (ret == -1)
	{
          if (pth_event_occurred (ev)
              || (time_ev && pth_event_occurred (time_ev)))
            {
              if (pth_event_occurred (ev))
                handle_signal (signo);
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
          handle_signal (signo);
        }

      if (time_ev && pth_event_occurred (time_ev))
        {
          pth_event_free (time_ev, PTH_FREE_ALL);
          time_ev = NULL;
          handle_tick ();
        }

      if (FD_ISSET (listen_fd, &read_fdset))
	{
          plen = sizeof paddr;
	  fd = pth_accept (listen_fd, (struct sockaddr *)&paddr, &plen);
	  if (fd == -1)
	    {
	      log_error ("accept failed: %s\n", strerror (errno));
	    }
          else if (!pth_spawn (tattr, start_connection_thread, (void*)fd))
	    {
	      log_error ("error spawning connection handler: %s\n",
			 strerror (errno) );
	      close (fd);
	    }
          fd = -1;
	}

      if (listen_fd_ssh != -1 && FD_ISSET (listen_fd_ssh, &read_fdset))
	{
          plen = sizeof paddr;
	  fd = pth_accept (listen_fd_ssh, (struct sockaddr *)&paddr, &plen);
	  if (fd == -1)
	    {
	      log_error ("accept failed for ssh: %s\n", strerror (errno));
	    }
          else if (!pth_spawn (tattr, start_connection_thread_ssh, (void*)fd))
	    {
	      log_error ("error spawning ssh connection handler: %s\n",
			 strerror (errno) );
	      close (fd);
	    }
          fd = -1;
	}
    }

  pth_event_free (ev, PTH_FREE_ALL);
  if (time_ev)
    pth_event_free (time_ev, PTH_FREE_ALL);
  cleanup ();
  log_info (_("%s %s stopped\n"), strusage(11), strusage(13));
}


/* Figure out whether an agent is available and running. Prints an
   error if not.  Usually started with MODE 0. */
static int
check_for_running_agent (int mode)
{
  int rc;
  char *infostr, *p;
  assuan_context_t ctx;
  int prot, pid;

  if (!mode)
    {
      infostr = getenv ("GPG_AGENT_INFO");
      if (!infostr || !*infostr)
        {
          if (!check_for_running_agent (1))
            return 0; /* Okay, its running on the standard socket. */
          log_error (_("no gpg-agent running in this session\n"));
          return -1;
        }

      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, PATHSEP_C)) || p == infostr)
        {
          xfree (infostr);
          if (!check_for_running_agent (1))
            return 0; /* Okay, its running on the standard socket. */
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
          log_error (_("gpg-agent protocol version %d is not supported\n"),
                     prot);
          if (!check_for_running_agent (1))
            return 0; /* Okay, its running on the standard socket. */
          return -1;
        }
    }
  else /* MODE != 0 */
    {
      infostr = make_filename (opt.homedir, "S.gpg-agent", NULL);
      pid = (pid_t)(-1);
    }


  rc = assuan_socket_connect (&ctx, infostr, pid);
  xfree (infostr);
  if (rc)
    {
      if (!mode && !check_for_running_agent (1))
        return 0; /* Okay, its running on the standard socket. */

      if (!mode)
        log_error ("can't connect to the agent: %s\n", assuan_strerror (rc));
      return -1;
    }

  if (!opt.quiet)
    log_info ("gpg-agent running and available\n");

  assuan_disconnect (ctx);
  return 0;
}

/* gpg-agent.c  -  The GnuPG Agent
 *	Copyright (C) 2000, 2001, 2002, 2003 Free Software Foundation, Inc.
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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#ifdef USE_GNU_PTH
# include <pth.h>
#endif

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"
#include <assuan.h> /* malloc hooks */

#include "i18n.h"
#include "sysutils.h"


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
  oDisablePth,

  oIgnoreCacheForSigning,
  oKeepTTY,
  oKeepDISPLAY,

aTest };



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
  { oDisablePth, "disable-pth", 0, N_("do not allow multiple connections")},

  { oPinentryProgram, "pinentry-program", 2 , "path to PIN Entry program" },
  { oDisplay,    "display",     2, "set the display" },
  { oTTYname,    "ttyname",     2, "set the tty terminal node name" },
  { oTTYtype,    "ttytype",     2, "set the tty terminal type" },
  { oLCctype,    "lc-ctype",    2, "set the tty LC_CTYPE value" },
  { oLCmessages, "lc-messages", 2, "set the tty LC_MESSAGES value" },

  { oScdaemonProgram, "scdaemon-program", 2 , "path to SCdaemon program" },
  { oDefCacheTTL, "default-cache-ttl", 4,
                                 "|N|expire cached PINs after N seconds"},
  { oIgnoreCacheForSigning, "ignore-cache-for-signing", 0,
                                 "do not use the PIN cache when signing"},
  { oKeepTTY, "keep-tty", 0,  N_("ignore requests to change the TTY")},
  { oKeepDISPLAY, "keep-display",
                          0, N_("ignore requests to change the X display")},
  {0}
};


#define DEFAULT_CACHE_TTL (10*60) /* 10 minutes */

static volatile int caught_fatal_sig = 0;

/* flag to indicate that a shutdown was requested */
static int shutdown_pending;


/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Name of the communication socket */
static char socket_name[128];

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

/* Local prototypes. */
static void create_directories (void);
#ifdef USE_GNU_PTH
static void handle_connections (int listen_fd);
#endif



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
    set_gettext_file( PACKAGE );
#else
#ifdef ENABLE_NLS
    setlocale (LC_ALL, "");
    bindtextdomain (PACKAGE, LOCALEDIR);
    textdomain (PACKAGE);
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


/* Setup the debugging.  With a LEVEL of NULL only the active debug
   flags are propagated to the subsystems.  With LEVEL set, a specific
   set of debug flags is set; thus overriding all flags already
   set. Note that we don't fail here, because it is important to keep
   gpg-agent running even after re-reading the options due to a
   SIGHUP. */
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
 

static void
cleanup (void)
{
  if (*socket_name)
    {
      char *p;

      remove (socket_name);
      p = strrchr (socket_name, '/');
      if (p)
        {
          *p = 0;
          rmdir (socket_name);
          *p = '/';
        }
      *socket_name = 0;
    }
}


static RETSIGTYPE
cleanup_sh (int sig)
{
  if (caught_fatal_sig)
    raise (sig);
  caught_fatal_sig = 1;

  /* gcry_control( GCRYCTL_TERM_SECMEM );*/
  cleanup ();

#ifndef HAVE_DOSISH_SYSTEM
  {	/* reset action to default action and raise signal again */
    struct sigaction nact;
    nact.sa_handler = SIG_DFL;
    sigemptyset( &nact.sa_mask );
    nact.sa_flags = 0;
    sigaction( sig, &nact, NULL);
  }
#endif
  raise( sig );
}


/* Handle options which are allowed to be reset after program start.
   Return true when the current option in PARGS could be handled and
   false if not.  As a special feature, passing a value of NULL for
   PARGS, resets the options to the default. */
static int
parse_rereadable_options (ARGPARSE_ARGS *pargs)
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
      opt.ignore_cache_for_signing = 0;
      return 1;
    }

  switch (pargs->r_opt)
    {
    case oQuiet: opt.quiet = 1; break;
    case oVerbose: opt.verbose++; break;

    case oDebug: opt.debug |= pargs->r.ret_ulong; break;
    case oDebugAll: opt.debug = ~0; break;
    case oDebugLevel: debug_level = pargs->r.ret_str; break;

    case oNoGrab: opt.no_grab = 1; break;
      
    case oPinentryProgram: opt.pinentry_program = pargs->r.ret_str; break;
    case oScdaemonProgram: opt.scdaemon_program = pargs->r.ret_str; break;

    case oDefCacheTTL: opt.def_cache_ttl = pargs->r.ret_ulong; break;
      
    case oIgnoreCacheForSigning: opt.ignore_cache_for_signing = 1; break;

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
  int disable_pth = 0;
  int gpgconf_list = 0;

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix ("gpg-agent", 1|4); 

  /* Try to auto set the character set.  */
  set_native_charset (NULL); 

  i18n_init ();

  /* We need to initialize Pth before libgcrypt, because the libgcrypt
     initialization done by gcry_check_version internally sets up its
     mutex system.  Note that one must not link against pth if
     USE_GNU_PTH is not defined. */
#ifdef USE_GNU_PTH
  if (!pth_init ())
    {
      log_error ("failed to initialize the Pth library\n");
      exit (1);
    }
#endif /*USE_GNU_PTH*/

  /* check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library */
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

  parse_rereadable_options (NULL); /* Reset them to default values. */

  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;
  
  opt.homedir = getenv("GNUPGHOME");
  if (!opt.homedir || !*opt.homedir)
    opt.homedir = GNUPG_DEFAULT_HOMEDIR;


  /* check whether we have a config file on the commandline */
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
      if (parse_rereadable_options (&pargs))
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
        case oDisablePth: disable_pth = 1; break;

        case oDisplay: default_display = xstrdup (pargs.r.ret_str); break;
        case oTTYname: default_ttyname = xstrdup (pargs.r.ret_str); break;
        case oTTYtype: default_ttytype = xstrdup (pargs.r.ret_str); break;
        case oLCctype: default_lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: default_lc_messages = xstrdup (pargs.r.ret_str); break;

        case oKeepTTY: opt.keep_tty = 1; break;
        case oKeepDISPLAY: opt.keep_display = 1; break;

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
  log_info ("NOTE: this is a development version!\n");
#endif

  set_debug ();
  
  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  create_directories ();

  if (debug_wait && pipe_server)
    {
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      sleep (debug_wait);
      log_debug ("... okay\n");
    }
  
  if (gpgconf_list)
    { /* List options and default values in the GPG Conf format.  */

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

      printf ("gpgconf-gpg-agent.conf:%lu:\"%s\n",
              GC_OPT_FLAG_DEFAULT, config_filename);
      
      printf ("verbose:%lu:\n"
              "quiet:%lu:\n"
              "debug-level:%lu:\"none\":\n"
              "log-file:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME,
              GC_OPT_FLAG_NONE );
      printf ("default-cache-ttl:%lu:%d:\n",
              GC_OPT_FLAG_DEFAULT|GC_OPT_FLAG_RUNTIME, DEFAULT_CACHE_TTL );
      printf ("no-grab:%lu:\n", 
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);
      printf ("ignore-cache-for-signing:%lu:\n",
              GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME);

      agent_exit (0);
    }

  if (!pipe_server && !is_daemon)
    log_info (_("please use the option `--daemon'"
                " to run the program in the background\n"));
  
#ifdef ENABLE_NLS
  /* gpg-agent usually does not output any messages because it runs in
     the background.  For log files it is acceptable to have messages
     always encoded in utf-8.  We switch here to utf-8, so that
     commands like --help still give native messages.  It is far
     easier to switch only once instead of for every message and it
     actually helps when more then one thread is active (avoids an
     extra copy step). */
    bind_textdomain_codeset (PACKAGE, "UTF-8");
#endif

  /* now start with logging to a file if this is desired */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, 1|2|4);
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
    ;
  else
    { /* regular server mode */
      int fd;
      pid_t pid;
      int len;
      struct sockaddr_un serv_addr;
      char *p;

      /* Remove the DISPLAY variable so that a pinentry does not
         default to a specific display.  There is still a default
         display when gpg-agent weas started using --display or a
         client requested this using an OPTION command. */
      if (!opt.keep_display)
        unsetenv ("DISPLAY");

      *socket_name = 0;
      snprintf (socket_name, DIM(socket_name)-1,
                "/tmp/gpg-XXXXXX/S.gpg-agent");
      socket_name[DIM(socket_name)-1] = 0;
      p = strrchr (socket_name, '/');
      if (!p)
        BUG ();
      *p = 0;;
      if (!mkdtemp(socket_name))
        {
          log_error ("can't create directory `%s': %s\n",
	             socket_name, strerror(errno) );
          exit (1);
        }
      *p = '/';

      if (strchr (socket_name, ':') )
        {
          log_error ("colons are not allowed in the socket name\n");
          exit (1);
        }
      if (strlen (socket_name)+1 >= sizeof serv_addr.sun_path ) 
        {
          log_error ("name of socket too long\n");
          exit (1);
        }
   

      fd = socket (AF_UNIX, SOCK_STREAM, 0);
      if (fd == -1)
        {
          log_error ("can't create socket: %s\n", strerror(errno) );
          exit (1);
        }

      memset (&serv_addr, 0, sizeof serv_addr);
      serv_addr.sun_family = AF_UNIX;
      strcpy (serv_addr.sun_path, socket_name);
      len = (offsetof (struct sockaddr_un, sun_path)
             + strlen(serv_addr.sun_path) + 1);

      if (bind (fd, (struct sockaddr*)&serv_addr, len) == -1)
        {
          log_error ("error binding socket to `%s': %s\n",
                     serv_addr.sun_path, strerror (errno) );
          close (fd);
          exit (1);
        }
  
      if (listen (fd, 5 ) == -1)
        {
          log_error ("listen() failed: %s\n", strerror (errno));
          close (fd);
          exit (1);
        }

      if (opt.verbose)
        log_info ("listening on socket `%s'\n", socket_name );


      fflush (NULL);
      pid = fork ();
      if (pid == (pid_t)-1) 
        {
          log_fatal ("fork failed: %s\n", strerror (errno) );
          exit (1);
        }
      else if (pid) 
        { /* we are the parent */
          char *infostr;
          
          close (fd);
          
          /* create the info string: <name>:<pid>:<protocol_version> */
          if (asprintf (&infostr, "GPG_AGENT_INFO=%s:%lu:1",
                        socket_name, (ulong)pid ) < 0)
            {
              log_error ("out of core\n");
              kill (pid, SIGTERM);
              exit (1);
            }
          *socket_name = 0; /* don't let cleanup() remove the socket -
                               the child should do this from now on */
          if (argc) 
            { /* run the program given on the commandline */
              if (putenv (infostr))
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
              /* print the environment string, so that the caller can use
                 shell's eval to set it */
              if (csh_style)
                {
                  *strchr (infostr, '=') = ' ';
                  printf ( "setenv %s\n", infostr);
                }
              else
                {
                  printf ( "%s; export GPG_AGENT_INFO;\n", infostr);
                }
              free (infostr);
              exit (0); 
            }
          /*NEVER REACHED*/
        } /* end parent */
      

      /* this is the child */

      /* detach from tty and put process into a new session */
      if (!nodetach )
        { 
          int i;

          /* close stdin, stdout and stderr unless it is the log stream */
          for (i=0; i <= 2; i++) 
            {
              if ( log_get_fd () != i)
                close (i);
            }
          if (setsid() == -1)
            {
              log_error ("setsid() failed: %s\n", strerror(errno) );
              cleanup ();
              exit (1);
            }
          opt.running_detached = 1;
        }

      if (chdir("/"))
        {
          log_error ("chdir to / failed: %s\n", strerror (errno));
          exit (1);
        }


#ifdef USE_GNU_PTH
      if (!disable_pth)
        {
	  struct sigaction sa;

	  sa.sa_handler = SIG_IGN;
	  sigemptyset (&sa.sa_mask);
	  sa.sa_flags = 0;
	  sigaction (SIGPIPE, &sa, NULL);
          handle_connections (fd);
        }
      else
#endif /*!USE_GNU_PTH*/
      /* setup signals */
        {
          struct sigaction oact, nact;
          
          nact.sa_handler = cleanup_sh;
          sigemptyset (&nact.sa_mask);
          nact.sa_flags = 0;
          
          sigaction (SIGHUP, NULL, &oact);
          if (oact.sa_handler != SIG_IGN)
            sigaction (SIGHUP, &nact, NULL);
          sigaction( SIGTERM, NULL, &oact );
          if (oact.sa_handler != SIG_IGN)
            sigaction (SIGTERM, &nact, NULL);
          nact.sa_handler = SIG_IGN;
          sigaction (SIGPIPE, &nact, NULL);
          sigaction (SIGINT, &nact, NULL);

          start_command_handler (fd, -1);
        }
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

  parse_rereadable_options (NULL); /* Start from the default values. */

  memset (&pargs, 0, sizeof pargs);
  dummy = 0;
  pargs.argc = &dummy;
  pargs.flags = 1;  /* do not remove the args */
  while (optfile_parse (fp, config_filename, &configlineno, &pargs, opts) )
    {
      if (pargs.r_opt < -1)
        pargs.err = 1; /* Print a warning. */
      else /* Try to parse this option - ignore unchangeable ones. */
        parse_rereadable_options (&pargs);
    }
  fclose (fp);
  set_debug ();
}


static void
create_private_keys_directory (const char *home)
{
  char *fname;
  struct stat statbuf;

  fname = make_filename (home, GNUPG_PRIVATE_KEYS_DIR, NULL);
  if (stat (fname, &statbuf) && errno == ENOENT)
    {
      if (mkdir (fname, S_IRUSR|S_IWUSR|S_IXUSR ))
        log_error (_("can't create directory `%s': %s\n"),
                   fname,	strerror(errno) );
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

  home  = make_filename (opt.homedir, NULL);
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
              if (mkdir (home, S_IRUSR|S_IWUSR|S_IXUSR ))
                log_error (_("can't create directory `%s': %s\n"),
                           home, strerror(errno) );
              else 
                {
                  if (!opt.quiet)
                    log_info (_("directory `%s' created\n"), home);
                  create_private_keys_directory (home);
                }
            }
        }
      else
        log_error ("error stat-ing `%s': %s\n", home, strerror (errno));
    }
  else if ( !S_ISDIR(statbuf.st_mode))
    {
      log_error ("can't use `%s' as home directory\n", home);
    }
  else /* exists and is a directory. */
    {
      create_private_keys_directory (home);
    }
  xfree (home);
}



#ifdef USE_GNU_PTH
static void
handle_signal (int signo)
{
  switch (signo)
    {
    case SIGHUP:
      log_info ("SIGHUP received - "
                "re-reading configuration and flushing cache\n");
      agent_flush_cache ();
      reread_configuration ();
      break;
      
    case SIGUSR1:
      if (opt.verbose < 5)
        opt.verbose++;
      log_info ("SIGUSR1 received - verbosity set to %d\n", opt.verbose);
      break;

    case SIGUSR2:
      if (opt.verbose)
        opt.verbose--;
      log_info ("SIGUSR2 received - verbosity set to %d\n", opt.verbose );
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

    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}


static void *
start_connection_thread (void *arg)
{
  int fd = (int)arg;

  if (opt.verbose)
    log_info ("handler for fd %d started\n", fd);
  start_command_handler (-1, fd);
  if (opt.verbose)
    log_info ("handler for fd %d terminated\n", fd);
  
  return NULL;
}


static void
handle_connections (int listen_fd)
{
  pth_attr_t tattr;
  pth_event_t ev;
  sigset_t sigs;
  int signo;
  struct sockaddr_un paddr;
  socklen_t plen = sizeof( paddr );
  int fd;

  tattr = pth_attr_new();
  pth_attr_set (tattr, PTH_ATTR_JOINABLE, 0);
  pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 32*1024);
  pth_attr_set (tattr, PTH_ATTR_NAME, "gpg-agent");

  sigemptyset (&sigs );
  sigaddset (&sigs, SIGHUP);
  sigaddset (&sigs, SIGUSR1);
  sigaddset (&sigs, SIGUSR2);
  sigaddset (&sigs, SIGINT);
  sigaddset (&sigs, SIGTERM);
  ev = pth_event (PTH_EVENT_SIGS, &sigs, &signo);

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

      fd = pth_accept_ev (listen_fd, (struct sockaddr *)&paddr, &plen, ev);
      if (fd == -1)
        {
#ifdef PTH_STATUS_OCCURRED     /* This is Pth 2 */
          if (pth_event_status (ev) == PTH_STATUS_OCCURRED)
#else
          if (pth_event_occurred (ev))
#endif
            {
              handle_signal (signo);
              continue;
	    }
          log_error ("accept failed: %s - waiting 1s\n", strerror (errno));
          pth_sleep(1);
          continue;
	}

      if (!pth_spawn (tattr, start_connection_thread, (void*)fd))
        {
          log_error ("error spawning connection handler: %s\n",
                     strerror (errno) );
          close (fd);
	}
    }

  pth_event_free (ev, PTH_FREE_ALL);
  cleanup ();
  log_info ("%s %s stopped\n", strusage(11), strusage(13));
}
#endif /*USE_GNU_PTH*/

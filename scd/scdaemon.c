/* scdaemon.c  -  The GnuPG Smartcard Daemon
 *	Copyright (C) 2001, 2002, 2004 Free Software Foundation, Inc.
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
#include "scdaemon.h"
#include <ksba.h>
#include <gcrypt.h>

#include <assuan.h> /* malloc hooks */

#include "i18n.h"
#include "sysutils.h"
#include "app-common.h"


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
  oDebugSC,
  oNoGreeting,
  oNoOptions,
  oHomedir,
  oNoDetach,
  oNoGrab,
  oLogFile,
  oServer,
  oDaemon,
  oBatch,
  oReaderPort,
  octapiDriver,
  opcscDriver,
  oDisableCCID,
  oDisableOpenSC,
  oAllowAdmin,
  oDenyAdmin,

aTest };



static ARGPARSE_OPTS opts[] = {

  { aGPGConfList, "gpgconf-list", 256, "@" },
  
  { 301, NULL, 0, N_("@Options:\n ") },

  { oServer,   "server",     0, N_("run in server mode (foreground)") },
  { oDaemon,   "daemon",     0, N_("run in daemon mode (background)") },
  { oVerbose, "verbose",   0, N_("verbose") },
  { oQuiet,	"quiet",     0, N_("be somewhat more quiet") },
  { oSh,	"sh",        0, N_("sh-style command output") },
  { oCsh,	"csh",       0, N_("csh-style command output") },
  { oOptions, "options"  , 2, N_("read options from file")},
  { oDebug,	"debug"     ,4|16, "@"},
  { oDebugAll, "debug-all"     ,0, "@"},
  { oDebugLevel, "debug-level" ,2, "@"},
  { oDebugWait,"debug-wait",1, "@"},
  { oDebugSC,  "debug-sc",  1, N_("|N|set OpenSC debug level to N")},
  { oNoDetach, "no-detach" ,0, N_("do not detach from the console")},
  { oLogFile,  "log-file"   ,2, N_("use a log file for the server")},
  { oReaderPort, "reader-port", 2, N_("|N|connect to reader at port N")},
  { octapiDriver, "ctapi-driver", 2, N_("|NAME|use NAME as ct-API driver")},
  { opcscDriver, "pcsc-driver", 2, N_("|NAME|use NAME as PC/SC driver")},
  { oDisableCCID, "disable-ccid", 0,
#ifdef HAVE_LIBUSB
                                    N_("do not use the internal CCID driver")
#else
                                    "@"
#endif
                                         /* end --disable-ccid */},
  { oDisableOpenSC, "disable-opensc", 0,
#ifdef HAVE_OPENSC
                                    N_("do not use the OpenSC layer")
#else
                                    "@"
#endif
                                         /* end --disable-opensc */},
  { oAllowAdmin, "allow-admin", 0, N_("allow the use of admin card commands")},
  { oDenyAdmin,  "deny-admin",  0, "@" },  

  {0}
};


#define DEFAULT_PCSC_DRIVER "libpcsclite.so"


static volatile int caught_fatal_sig = 0;

/* Flag to indicate that a shutdown was requested. */
static int shutdown_pending;

/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Name of the communication socket */
static char socket_name[128];


#ifdef USE_GNU_PTH
/* Pth wrapper function definitions. */
GCRY_THREAD_OPTION_PTH_IMPL;

static void *ticker_thread (void *arg);
#endif /*USE_GNU_PTH*/


static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "scdaemon (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p =  _("Usage: scdaemon [options] (-h for help)");
      break;
    case 41: p =  _("Syntax: scdaemon [options] [command [args]]\n"
                    "Smartcard daemon for GnuPG\n");
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


/* Setup the debugging.  With a LEVEL of NULL only the active debug
   flags are propagated to the subsystems.  With LEVEL set, a specific
   set of debug flags is set; thus overriding all flags already
   set. */
static void
set_debug (const char *level)
{
  if (!level)
    ;
  else if (!strcmp (level, "none"))
    opt.debug = 0;
  else if (!strcmp (level, "basic"))
    opt.debug = DBG_ASSUAN_VALUE;
  else if (!strcmp (level, "advanced"))
    opt.debug = DBG_ASSUAN_VALUE|DBG_COMMAND_VALUE;
  else if (!strcmp (level, "expert"))
    opt.debug = (DBG_ASSUAN_VALUE|DBG_COMMAND_VALUE
                 |DBG_CACHE_VALUE|DBG_CARD_IO_VALUE);
  else if (!strcmp (level, "guru"))
    opt.debug = ~0;
  else
    {
      log_error (_("invalid debug-level `%s' given\n"), level);
      scd_exit(2);
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

int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  gpg_error_t err;
  int may_coredump;
  char **orig_argv;
  FILE *configfp = NULL;
  char *configname = NULL;
  const char *shell;
  unsigned configlineno;
  int parse_debug = 0;
  const char *debug_level = NULL;
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
  const char *config_filename = NULL;

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix ("scdaemon", 1|4); 
  /* Try to auto set the character set.  */
  set_native_charset (NULL); 

  i18n_init ();

  /* Libgcrypt requires us to register the threading model first.
     Note that this will also do the pth_init. */
#ifdef USE_GNU_PTH
  err = gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pth);
  if (err)
    {
      log_fatal ("can't register GNU Pth with Libgcrypt: %s\n",
                 gpg_strerror (err));
    }
#endif /*USE_GNU_PTH*/

  /* Check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  ksba_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);

  assuan_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);
  assuan_set_assuan_log_stream (log_get_stream ());
  assuan_set_assuan_log_prefix (log_get_prefix (NULL));

  gcry_set_log_handler (my_gcry_logger, NULL);
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  /* Set default options. */
  opt.pcsc_driver = DEFAULT_PCSC_DRIVER; 


  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;
  
  /* FIXME: Using this homedir option does only make sense when not
     running as a system service.  We might want to check for this by
     looking at the uid or ebtter use an explict option for this */
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
     Now we are working under our real uid 
  */


  if (default_config)
    configname = make_filename (opt.homedir, "scdaemon.conf", NULL );

  
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
      switch (pargs.r_opt)
        {
        case aGPGConfList: gpgconf_list = 1; break;
        case oQuiet: opt.quiet = 1; break;
        case oVerbose: opt.verbose++; break;
        case oBatch: opt.batch=1; break;

        case oDebug: opt.debug |= pargs.r.ret_ulong; break;
        case oDebugAll: opt.debug = ~0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugWait: debug_wait = pargs.r.ret_int; break;
        case oDebugSC: opt.debug_sc = pargs.r.ret_int; break;

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

        case oReaderPort: opt.reader_port = pargs.r.ret_str; break;
        case octapiDriver: opt.ctapi_driver = pargs.r.ret_str; break;
        case opcscDriver: opt.pcsc_driver = pargs.r.ret_str; break;
        case oDisableCCID: opt.disable_ccid = 1; break;
        case oDisableOpenSC: opt.disable_opensc = 1; break;

        case oAllowAdmin: opt.allow_admin = 1; break;
        case oDenyAdmin: opt.allow_admin = 0; break;

        default : pargs.err = configfp? 1:2; break;
	}
    }
  if (configfp)
    {
      fclose( configfp );
      configfp = NULL;
      /* Keep a copy of the config name for use by --gpgconf-list. */
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

 
  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  set_debug (debug_level);

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

      printf ("gpgconf-scdaemon.conf:%lu:\"%s\n",
              GC_OPT_FLAG_DEFAULT,
              config_filename?config_filename:"/dev/null");
        
      printf ("verbose:%lu:\n"
              "quiet:%lu:\n"
              "debug-level:%lu:\"none:\n"
              "log-file:%lu:\n",
              GC_OPT_FLAG_NONE,
              GC_OPT_FLAG_NONE,
              GC_OPT_FLAG_DEFAULT,
              GC_OPT_FLAG_NONE );

      printf ("reader-port:%lu:\n", GC_OPT_FLAG_NONE );
      printf ("ctapi-driver:%lu:\n", GC_OPT_FLAG_NONE );
      printf ("pcsc-driver:%lu:\"%s:\n",
              GC_OPT_FLAG_DEFAULT, DEFAULT_PCSC_DRIVER );
#ifdef HAVE_LIBUSB
      printf ("disable-ccid:%lu:\n", GC_OPT_FLAG_NONE );
#endif
#ifdef HAVE_LIBUSB
      printf ("disable-opensc:%lu:\n", GC_OPT_FLAG_NONE );
#endif
      printf ("allow-admin:%lu:\n", GC_OPT_FLAG_NONE );


      scd_exit (0);
    }

  /* now start with logging to a file if this is desired */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, 1|2|4);
    }


  if (pipe_server)
    { /* This is the simple pipe based server */
#ifdef USE_GNU_PTH
      pth_attr_t tattr;
 
      tattr = pth_attr_new();
      pth_attr_set (tattr, PTH_ATTR_JOINABLE, 0);
      pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 64*1024);
      pth_attr_set (tattr, PTH_ATTR_NAME, "ticker");

      if (!pth_spawn (tattr, ticker_thread, NULL))
        {
          log_error ("error spawning ticker thread: %s\n", strerror (errno));
          scd_exit (2);
        }
#endif /*USE_GNU_PTH*/
      scd_command_handler (-1);
    }
  else if (!is_daemon)
    {
      log_info (_("please use the option `--daemon'"
                  " to run the program in the background\n"));
    }
  else
    { /* regular server mode */
      int fd;
      pid_t pid;
      int i;
      int len;
      struct sockaddr_un serv_addr;
      char *p;

      /* fixme: if there is already a running gpg-agent we should
         share the same directory - and vice versa */
      *socket_name = 0;
      snprintf (socket_name, DIM(socket_name)-1,
                "/tmp/gpg-XXXXXX/S.scdaemon");
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
          log_error ("name of socket to long\n");
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
          if (asprintf (&infostr, "SCDAEMON_INFO=%s:%lu:1",
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
                  printf ( "%s; export SCDAEMON_INFO;\n", infostr);
                }
              free (infostr);
              exit (0); 
            }
          /* NOTREACHED */
        } /* end parent */
      
      /* this is the child */

      /* detach from tty and put process into a new session */
      if (!nodetach )
        {  /* close stdin, stdout and stderr unless it is the log stream */
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
        }

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
      }

      if (chdir("/"))
        {
          log_error ("chdir to / failed: %s\n", strerror (errno));
          exit (1);
        }

      scd_command_handler (fd);

      close (fd);
    }
  
  return 0;
}

void
scd_exit (int rc)
{
#if 0
#warning no update_random_seed_file
  update_random_seed_file();
#endif
#if 0
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
scd_init_default_ctrl (CTRL ctrl)
{
  ctrl->reader_slot = -1;
}


#ifdef USE_GNU_PTH

static void
handle_signal (int signo)
{
  switch (signo)
    {
    case SIGHUP:
      log_info ("SIGHUP received - "
                "re-reading configuration and resetting cards\n");
/*       reread_configuration (); */
      break;
      
    case SIGUSR1:
      log_info ("SIGUSR1 received - no action defined\n");
      break;

    case SIGUSR2:
      log_info ("SIGUSR2 received - no action defined\n");
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
          scd_exit (0);
	}
      break;
        
    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      log_info( "%s %s stopped\n", strusage(11), strusage(13));
      cleanup ();
      scd_exit (0);
      break;

    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}

static void
handle_tick (void)
{
  scd_update_reader_status_file ();
}

static void *
ticker_thread (void *dummy_arg)
{
  pth_event_t sigs_ev, time_ev = NULL;
  sigset_t sigs;
  int signo;

  sigemptyset (&sigs );
  sigaddset (&sigs, SIGHUP);
  sigaddset (&sigs, SIGUSR1);
  sigaddset (&sigs, SIGUSR2);
  sigaddset (&sigs, SIGINT);
  sigaddset (&sigs, SIGTERM);
  sigs_ev = pth_event (PTH_EVENT_SIGS, &sigs, &signo);
  
  for (;;)
    {
      if (!time_ev)
        {
          time_ev = pth_event (PTH_EVENT_TIME, pth_timeout (2, 0));
          if (time_ev)
            pth_event_concat (sigs_ev, time_ev, NULL);
        }

      if (pth_wait (sigs_ev) < 1)
        continue;

      if (
#ifdef PTH_STATUS_OCCURRED     /* This is Pth 2 */
          pth_event_status (sigs_ev) == PTH_STATUS_OCCURRED
#else
          pth_event_occurred (sigs_ev)
#endif
          )
        handle_signal (signo);

      /* Always run the ticker. */
      if (!shutdown_pending)
        {
          pth_event_isolate (sigs_ev);
          pth_event_free (time_ev, PTH_FREE_ALL);
          time_ev = NULL;
          handle_tick ();
        }
    }

  pth_event_free (sigs_ev, PTH_FREE_ALL);
}
#endif /*USE_GNU_PTH*/

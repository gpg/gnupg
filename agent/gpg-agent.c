/* gpg-agent.c  -  The GnuPG Agent
 *	Copyright (C) 2000, 2001, 2002 Free Software Foundation, Inc.
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

#include <gcrypt.h>

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"
#include "../assuan/assuan.h" /* malloc hooks */

#include "sysutils.h"


#define N_(a) a
#define _(a) a


enum cmd_and_opt_values 
{ aNull = 0,
  oCsh		  = 'c',
  oQuiet	  = 'q',
  oSh		  = 's',
  oVerbose	  = 'v',
  
  oNoVerbose = 500,
  oOptions,
  oDebug,
  oDebugAll,
  oDebugWait,
  oNoGreeting,
  oNoOptions,
  oHomedir,
  oNoDetach,
  oNoGrab,
  oLogFile,
  oServer,
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

aTest };



static ARGPARSE_OPTS opts[] = {
  
  { 301, NULL, 0, N_("@Options:\n ") },

  { oServer,   "server",     0, N_("run in server mode") },
  { oVerbose, "verbose",   0, N_("verbose") },
  { oQuiet,	"quiet",     0, N_("be somewhat more quiet") },
  { oSh,	"sh",        0, N_("sh-style command output") },
  { oCsh,	"csh",       0, N_("csh-style command output") },
  { oOptions, "options"  , 2, N_("read options from file")},
  { oDebug,	"debug"     ,4|16, N_("set debugging flags")},
  { oDebugAll, "debug-all" ,0, N_("enable full debugging")},
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

  {0}
};


static volatile int caught_fatal_sig = 0;

/* flag to indicate that a shutdown was requested */
static int shutdown_pending;


/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Name of the communication socket */
static char socket_name[128];


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
    /* gtk_set_locale (); HMMM: We have not yet called gtk_init */
    bindtextdomain( PACKAGE, LOCALEDIR );
    textdomain( PACKAGE );
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
  int nodetach = 0;
  int csh_style = 0;
  char *logfile = NULL;
  int debug_wait = 0;
  int disable_pth = 0;

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix ("gpg-agent", 1|4); 
  i18n_init ();

  /* check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library */
  if (!gcry_check_version ( "1.1.5" ) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 "1.1.5", gcry_check_version (NULL) );
    }

  assuan_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);
#ifdef USE_GNU_PTH
    assuan_set_io_func (pth_read, pth_write);
#endif

  gcry_set_log_handler (my_gcry_logger, NULL);
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;
  
  opt.homedir = getenv("GNUPGHOME");
  if (!opt.homedir || !*opt.homedir)
    opt.homedir = GNUPG_DEFAULT_HOMEDIR;
  opt.def_cache_ttl = 10*60; /* default to 10 minutes */


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
      switch (pargs.r_opt)
        {
        case oQuiet: opt.quiet = 1; break;
        case oVerbose: opt.verbose++; break;
        case oBatch: opt.batch=1; break;

        case oDebug: opt.debug |= pargs.r.ret_ulong; break;
        case oDebugAll: opt.debug = ~0; break;
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
        case oNoGrab: opt.no_grab = 1; break;
        case oLogFile: logfile = pargs.r.ret_str; break;
        case oCsh: csh_style = 1; break;
        case oSh: csh_style = 0; break;
        case oServer: pipe_server = 1; break;
        case oDisablePth: disable_pth = 1; break;

        case oPinentryProgram: opt.pinentry_program = pargs.r.ret_str; break;
        case oDisplay: opt.display = xstrdup (pargs.r.ret_str); break;
        case oTTYname: opt.ttyname = xstrdup (pargs.r.ret_str); break;
        case oTTYtype: opt.ttytype = xstrdup (pargs.r.ret_str); break;
        case oLCctype: opt.lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: opt.lc_messages = xstrdup (pargs.r.ret_str); break;
        case oScdaemonProgram: opt.scdaemon_program = pargs.r.ret_str; break;
        case oDefCacheTTL: opt.def_cache_ttl = pargs.r.ret_ulong; break;

        case oIgnoreCacheForSigning: opt.ignore_cache_for_signing = 1; break;

        default : pargs.err = configfp? 1:2; break;
	}
    }
  if (configfp)
    {
      fclose( configfp );
      configfp = NULL;
      xfree(configname);
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

  if (debug_wait && pipe_server)
    {
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      sleep (debug_wait);
      log_debug ("... okay\n");
    }
  
  /* now start with logging to a file if this is desired */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, 1|2|4);
    }


  if (pipe_server)
    { /* this is the simple pipe based server */
      start_command_handler (-1, -1);
    }
  else
    { /* regular server mode */
      int fd;
      pid_t pid;
      int len;
      struct sockaddr_un serv_addr;
      char *p;

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
          if (!pth_init ())
            {
              log_error ("failed to initialize the Pth library\n");
              exit (1);
            }
          signal (SIGPIPE, SIG_IGN);
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


static void
reread_configuration (void)
{
  /* FIXME: Move parts of the option parsing to here. */
}


#ifdef USE_GNU_PTH
static void
handle_signal (int signo)
{
  switch (signo)
    {
    case SIGHUP:
      log_info ("SIGHUP received - re-reading configuration\n");
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
          if (pth_event_occurred (ev))
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

/* gpg-agent.c  -  The GnuPG Agent
 *	Copyright (C) 2000, 2001 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <signal.h>

#include <gcrypt.h>

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"
#include "../assuan/assuan.h" /* malloc hooks */


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
  oClient,
  oShutdown,
  oFlush,
  oLogFile,
  oServer,
  oBatch,
  
  oPinentryProgram,

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
  { oClient, "client"      ,0, N_("run in client mode for testing")},
  { oLogFile, "log-file"   ,2, N_("use a log file for the server")},
  { oShutdown, "shutdown"  ,0, N_("shutdown the agent")},
  { oFlush   , "flush"     ,0, N_("flush the cache")},
  { oBatch   , "batch"     ,0, N_("run without asking a user")},

  { oPinentryProgram, "pinentry-program", 2 , "Path of PIN Entry program" },


  {0}
};



typedef struct {
    int used;
    char fpr[20];
    char *pw;
    size_t pwlen;
    size_t totlen;
} CACHE_SLOT;

#define MAX_CACHE_ENTRIES 10
#define MAX_CACHE_AGE  1000 /* should fit into an integer */
static volatile int caught_fatal_sig = 0;
static volatile int shut_me_down = 0;
/*  static CACHE_SLOT the_cache[MAX_CACHE_ENTRIES]; */
static char *socket_name = NULL;

/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;


#define buftou32( p )  ((*(byte*)(p) << 24) | (*((byte*)(p)+1)<< 16) | \
		       (*((byte*)(p)+2) << 8) | (*((byte*)(p)+3)))
#define u32tobuf( p, a ) do { 			                \
			    ((byte*)p)[0] = (byte)((a) >> 24);	\
			    ((byte*)p)[1] = (byte)((a) >> 16);	\
			    ((byte*)p)[2] = (byte)((a) >>  8);	\
			    ((byte*)p)[3] = (byte)((a) 	    );	\
			} while(0)


static int start_listening ( const char *name );



static const char *
my_strusage( int level )
{
    const char *p;
    switch( level ) {
      case 11: p = "gpg-agent (GnuPG)";
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p =
	    _("Please report bugs to <bug-gnupg@gnu.org>.\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: gpg-agent [options] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: gpg-agent [options] [command [args]]\n"
	      "Secret key management for GnuPG\n");
	break;

      default:	p = NULL;
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
    bindtextdomain( PACKAGE, GNUPG_LOCALEDIR );
    textdomain( PACKAGE );
  #endif
  #endif
}

static void
cleanup (void)
{
  if (socket_name)
    {
      char *p = socket_name;
      socket_name = NULL;
      remove ( p );
      gcry_free (p);
    }
}


/* Use by gcry for logging */
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


static RETSIGTYPE
cleanup_sh (int sig)
{
  if (caught_fatal_sig)
    raise (sig);
  caught_fatal_sig = 1;
  shut_me_down = 1;

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
  int server_mode = 0;
  int client = 0;
  int do_shutdown = 0;
  int do_flush = 0;
  int nodetach = 0;
  int grab = 0;
  int csh_style = 0;
  char *logfile = NULL;
  int debug_wait = 0;

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix ("gpg-agent", 1|4); 
  i18n_init ();

  /* check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library */
  if (!gcry_check_version ( "1.1.4" ) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 VERSION, gcry_check_version (NULL) );
    }

  assuan_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);
  gcry_set_log_handler (my_gcry_logger, NULL);
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = 0/* FIXME: disable_core_dumps()*/;


  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;
  
  opt.homedir = getenv("GNUPGHOME");
  if (!opt.homedir || !*opt.homedir)
    {
#ifdef HAVE_DRIVE_LETTERS
      opt.homedir = "c:/gnupg-test";
#else
      opt.homedir = "~/.gnupg-test";
#endif
    }
  grab = 1;

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
        case oNoGrab: grab = 0; break;
        case oClient: client = 1; break;
        case oShutdown: client = 1; do_shutdown = 1; break;
        case oFlush: client = 1; do_flush = 1; break;
        case oLogFile: logfile = pargs.r.ret_str; break;
        case oCsh: csh_style = 1; break;
        case oSh: csh_style = 0; break;
        case oServer: server_mode = 1; break;

        case oPinentryProgram: opt.pinentry_program = pargs.r.ret_str; break;

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

  socket_name =  make_filename (opt.homedir, "S.gpg-agent", NULL );
  if (strchr ( socket_name, ':') )
    {
      log_error ("colons are not allowed in the socket name\n");
      exit (1);
    }
   
  if (client)
    { /* a client for testing this agent */
#if 0 /* FIXME: We are going to use assuan here */
      int fd;
      struct sockaddr_un client_addr;
      size_t len;
      char buffer[1000];
      int nread;

      if ( strlen (socket_name)+1 >= sizeof client_addr.sun_path ) {
        log_error ("name of socket to long\n");
        exit (1);
      }

      if( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 )
        log_fatal("can't create socket: %s\n", strerror(errno) );

      memset( &client_addr, 0, sizeof client_addr );
      client_addr.sun_family = AF_UNIX;
      strcpy( client_addr.sun_path, socket_name );
      len = offsetof (struct sockaddr_un, sun_path)
        + strlen(client_addr.sun_path) + 1;

      if( connect( fd, (struct sockaddr*)&client_addr, len ) == -1 ) {
        log_error ( "connect() failed: %s\n", strerror (errno) );
        exit (1);
      }

      if ( do_shutdown ) {
        u32tobuf (buffer+4, GPGA_PROT_SHUTDOWN );
        nread = 4;
      }
      else if ( do_flush ) {
        u32tobuf (buffer+4, GPGA_PROT_FLUSH );
        nread = 4;
      }
      else {
        nread =  fread ( buffer+4, 1, DIM(buffer)-4, stdin );
            
        if ( opt.verbose )
          log_info ( "%d bytes read from stdin\n", nread );
      }
      u32tobuf (buffer, nread );
      writen ( fd, "GPGA\0\0\0\x01", 8 );
      writen ( fd, buffer, nread + 4 );
      /* now read the response */
      readn ( fd, buffer, DIM(buffer), &nread );
      if ( opt.verbose )
        log_info ( "%d bytes got from agent\n", nread );

      fwrite ( buffer, 1, nread, stdout );
      close (fd );
#endif
    }
  else if (server_mode)
    { /* for now this is the simple pipe based server */
      if (logfile)
        {
          log_set_file (logfile);
          log_set_prefix (NULL, 1|2|4);
        }
       
      if ( atexit( cleanup ) )
        {
          log_error ("atexit failed\n");
          cleanup ();
          exit (1);
        }

      if (debug_wait)
        {
          log_debug ("waiting for debugger - my pid is %u .....\n",
                     (unsigned int)getpid());
          sleep (debug_wait);
          log_debug ("... okay\n");
         }
      start_command_handler ();
    }
  else
    { /* regular server mode */
      int listen_fd;
      pid_t child;
      int i;
        
      listen_fd = start_listening (socket_name);
      if (listen_fd == -1)
        {
          cleanup ();
          exit (1);
        }


      fflush (NULL);
      child = fork ();
      if (child == -1) 
        {
          log_fatal ("fork failed: %s\n", strerror (errno) );
          cleanup ();
          exit (1);
        }
      else if ( child ) 
        { /* parent */
          char *infostr;
          
          close (listen_fd );
          
          /* create the info string */
          infostr = xmalloc ( 20 + strlen(socket_name) + 30 + 2 );
          sprintf ( infostr, "GPG_AGENT_INFO=%s:%lu",
                    socket_name, (ulong)child );
          if ( argc ) 
            { /* run the program given on the commandline */
              if (putenv (infostr))
                {
                  log_error ("failed to set environment: %s\n",
                             strerror (errno) );
                  kill (child, SIGTERM );
                  cleanup ();
                  exit (1);
                }
              execvp (argv[0], argv);
              log_error ("failed to run the command: %s\n",
                         strerror (errno));    
              kill (child, SIGTERM);
              cleanup ();
              exit (1);
            }
          /* print the environment string, so that the caller can use
             eval to set it */
          if (csh_style)
            {
              *strchr (infostr, '=') = ' ';
              printf ( "setenv %s\n", infostr);
	    }
          else
            {
              printf ( "%s; export GPG_AGENT_INFO;\n", infostr);
	    }
          exit (0); 
        } /* end parent */

      if ( (opt.debug & 1) )
        {
          fprintf (stderr, "... 20 seconds to attach the debugger ...");
          fflush (stderr);
          sleep( 20 ); /* give us some time to attach gdb to the child */
          putc ('\n', stderr);
        }

      if (logfile)
        {
          log_set_file (logfile);
          log_set_prefix (NULL, 1|2|4);
        }
       
      if ( atexit( cleanup ) )
        {
          log_error ("atexit failed\n");
          cleanup ();
          exit (1);
        }

      if ( !nodetach )
        {
          for (i=0 ; i <= 2; i++ ) 
            {
              if ( log_get_fd () != i)
                close ( i );
            }
            
          if (setsid() == -1)
            {
              log_error ("setsid() failed: %s\n", strerror(errno) );
              cleanup ();
              exit (1);
            }
        }

      {
        struct sigaction oact, nact;
        
        nact.sa_handler = cleanup_sh;
        sigemptyset ( &nact.sa_mask );
        nact.sa_flags = 0;
        
        sigaction ( SIGHUP, NULL, &oact );
        if ( oact.sa_handler != SIG_IGN )
          sigaction( SIGHUP, &nact, NULL);
        sigaction( SIGTERM, NULL, &oact );
        if ( oact.sa_handler != SIG_IGN )
          sigaction( SIGTERM, &nact, NULL);
        nact.sa_handler = SIG_IGN;
        sigaction( SIGPIPE, &nact, NULL );
        sigaction( SIGINT, &nact, NULL );
      }

      if ( chdir("/") )
        {
          log_error ("chdir to / failed: %s\n", strerror (errno) );
          exit (1);
        }

      /* for now there is no need for concurrent requests because we
         are asking for passphrases which might pop up a window to get
         the users respond.  In future the agent may provide other
         services which won't need a user interaction */
#if 0
      while (!shut_me_down)
        {
          struct sockaddr_un clnt_addr;
          size_t len = sizeof clnt_addr;
          int fd;
          /* FIXME: convert to assuan */     
          fd = accept ( listen_fd, (struct sockaddr*)&clnt_addr, &len );
          if ( fd == -1 )
            log_error ( "accept() failed: %s\n", strerror (errno));
          else
            {
              process_request ( fd );
              close (fd );
            }
        }
#endif
      close (listen_fd);
    }
  
  return 0;
}

void
agent_exit (int rc)
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


static int
start_listening (const char *name)
{
#if 0
  int len;
  int fd;
  struct sockaddr_un serv_addr;
  
  if (opt.verbose)
    log_info ("using socket `%s'\n", socket_name );

  if (strlen (socket_name)+1 >= sizeof serv_addr.sun_path ) 
    {
      log_error ("name of socket to long\n");
      return -1;
    }

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 )
    log_fatal("can't create socket: %s\n", strerror(errno) );

  memset( &serv_addr, 0, sizeof serv_addr );
  serv_addr.sun_family = AF_UNIX;
  strcpy( serv_addr.sun_path, socket_name );
  len = (offsetof (struct sockaddr_un, sun_path)
         + strlen(serv_addr.sun_path) + 1);
  
  remove (socket_name); errno = 0;
  if (bind( fd, (struct sockaddr*)&serv_addr, len ) == -1 )
    {
      log_error ( "error binding address `%s': %m\n", serv_addr.sun_path );
      close (fd );
      return -1;
    }
  
  if (listen (fd, 5 ) == -1)
    {
      log_error ( "listen() failed: %s\n", strerror (errno) );
      close ( fd );
      return -1;
    }
#endif
  return -1;
}

#if 0
/* Look for the passprase as given by the 20 bytes DATA and return it's
  slot number.  If this passphrase is not in the cache, return -1 */
static int
open_cached_passphrase ( const char *fpr )
{
  int i;
  
  for (i=0; i < MAX_CACHE_ENTRIES; i++ ) 
    {
      if (the_cache[i].used && !memcmp (the_cache[i].fpr, fpr, 20))
        {
          if ( the_cache[i].used < MAX_CACHE_AGE )
            the_cache[i].used++;
          return i;
        }
    }
  
  return -1;
}

/* Get pointers to the cached passphrase and return the real length
   PWLEN as well as the somewhat larger BLOCKLEN */
static const char * 
read_cached_passphrase (int slot, size_t *pwlen, size_t *blocklen)
{
  assert (slot >=0 && slot < MAX_CACHE_ENTRIES);
  *pwlen    = the_cache[slot].pwlen;
  *blocklen = the_cache[slot].totlen;
  return the_cache[slot].pw;
}

static const void
clear_cached_passphrase ( int slot )
{
  assert ( slot >=0 && slot < MAX_CACHE_ENTRIES );
  xfree (the_cache[slot].pw ); 
  the_cache[slot].pw = NULL; 
  the_cache[slot].used = 0;
}

static void
close_cached_passphrase ( int slot )
{
  /* not yet needed */
}


static void
set_cached_passphrase ( const char *fpr, const char *pw )
{
  int i, min_used = MAX_CACHE_AGE, slot = -1;
    
  for (i=0; i < 20 && !fpr[i]; i++ )
    ;
  if (i== 20)
    return; /* never cache an all empty fingerprint */

  /* first see whether we have already cached this one */
  for (i=0; i < MAX_CACHE_ENTRIES; i++ ) 
    {
      if ( the_cache[i].used && !memcmp (the_cache[i].fpr, fpr, 20) )
        {
          slot = i;
          break;
        }
    }

  if (slot == -1)
    { /* Find an unused one or reuse one */
      for (i=0; i < MAX_CACHE_ENTRIES; i++ )
        {
          if ( !the_cache[i].used ) {
            slot = i;
            break;
          }
          if ( the_cache[i].used < min_used )
            {
              min_used = the_cache[i].used;
              slot = i;
            }
        }
      assert ( slot != -1 );
    }
  xfree (the_cache[slot].pw);
  /* fixme: Allocate to fixed sizes */
  the_cache[slot].used = 1;
  memcpy (the_cache[slot].fpr, fpr, 20 );
  the_cache[slot].pw = gcry_xstrdup ( pw );
  the_cache[slot].pwlen = strlen ( pw );
  the_cache[slot].totlen = strlen ( pw );
}



static int
passphrase_dialog ( const byte *fpr, const char *user_string )
{
  /* FIXME: call the PIN-ENtry */

  return 0;
}


static int
writen ( int fd, const void *buf, size_t nbytes )
{
  size_t nleft = nbytes;
  ssize_t nwritten;
  
  while (nleft > 0)
    {
      nwritten = write( fd, buf, nleft );
      if ( nwritten < 0 )
        {
          log_error ( "writen() failed: %s\n", strerror (errno) );
          return -1;
        }
      nleft -= nwritten;
      buf = (const char*)buf + nwritten;
    }
  return 0;
}


static int
readn ( int fd, void *buf, size_t buflen, size_t *ret_nread )
{
  size_t nleft = buflen;
  int nread;
  char *p;
  
  p = buf;
  while (nleft > 0 )
    {
      nread = read ( fd, buf, nleft );
      if ( nread < 0 )
        {
          log_error ( "read() error: %s\n", strerror (errno) );
          return -1;
        }
      else if (!nread )
        break; /* EOF */
        nleft -= nread;
        buf = (char*)buf + nread;
    }
  if (ret_nread )
    *ret_nread = buflen - nleft;
  return 0;
}




static void
reply_error ( int fd, int x )
{
  /*FIXME:*/
}

static void
reply ( int fd, int x, const char *data, size_t datalen )
{
  /*FIXME:*/
}

static void
req_get_version ( int fd, const char *data, size_t datalen )
{
  /*FIXME:*/
}

static void
req_get_passphrase ( int fd, const char *data, size_t datalen )
{
#if 0
  int slot;
  const char *pw;
  size_t pwlen, blocklen;

  if (datalen < 20)
    {
      reply_error ( fd, GPGA_PROT_INVALID_DATA );
      return;
    }

  slot = open_cached_passphrase ( data );
  if ( slot == -1 )
    {
      int rc;
      char *string;
      
      if ( datalen > 20 ) 
        {
          string = xmalloc ( datalen - 20 + 1 );
          memcpy (string, data+20, datalen-20 );
          string[datalen-20] = 0;
        }
      else
        {
          string = xstrdup ("[fingerprint]");
        }
      rc = passphrase_dialog ( data, string ); 
      xfree (string);
      if (rc) 
        {
          reply_error ( fd, rc );
          return;
        }
      slot = open_cached_passphrase ( data );
      if (slot < 0)
        BUG ();
    }
    
  pw = read_cached_passphrase ( slot, &pwlen, &blocklen );
  if (!pw || blocklen < pwlen)
    BUG ();
#if 0 /* FIXME: */
    /* we do a hardcoded reply here to avoid copying of the passphrase
     * from the cache to a temporary buffer */
  {
    byte buf[20]; 
    
    u32tobuf ( buf+0, (8+blocklen) );
    u32tobuf ( buf+4, GPGA_PROT_GOT_PASSPHRASE );
    u32tobuf ( buf+8, pwlen );
    writen ( fd, buf, 12 );
    writen ( fd, pw, blocklen );
  }
#endif
  close_cached_passphrase ( slot );
#endif
}

static void
req_clear_passphrase ( int fd, const char *data, size_t datalen )
{
#if 0
  int slot;
  
  if ( datalen < 20 )
    {
      reply_error ( fd, GPGA_PROT_INVALID_DATA );
      return;
    }

  slot = open_cached_passphrase ( data );
  if ( slot == -1 ) 
    {
      reply_error ( fd, GPGA_PROT_NO_PASSPHRASE );
      return;
    }
         
  clear_cached_passphrase ( slot );
  close_cached_passphrase ( slot );
  reply_error (fd, GPGA_PROT_OKAY );
#endif
}

static void
req_shutdown ( int fd, const char *data, size_t datalen )
{
  shut_me_down = 1;
/*    reply ( fd, GPGA_PROT_OKAY, "", 0 ); */
}


static void
req_flush ( int fd, const char *data, size_t datalen )
{
  int i;
  
  /* FIXME: when using multiple connections we need to cope with locking */
  for (i=0; i < MAX_CACHE_ENTRIES; i++ )
    {
      if ( the_cache[i].used ) {
        xfree ( the_cache[i].pw );
        the_cache[i].pw = NULL;
        the_cache[i].used = 0;
      }
    }
/*    reply ( fd, GPGA_PROT_OKAY, "", 0 ); */
}


static void
process_request ( int fd )
{
#if 0
  byte buf[3000]; /* Below is a hardcoded max. length check */
  byte *data;
  size_t n, nread;    
  
    /* Check the magic and the protocol number */
  if ( readn ( fd, buf, 12, &nread ) )
    goto read_failure;
  if ( nread != 12 || memcmp ( buf, "GPGA\0\0\0\x01", 8 ) ) {
    reply_error ( fd, GPGA_PROT_PROTOCOL_ERROR );
    return;
  }
  n = buftou32 ( buf + 8 ); /* length of following packet */
  if ( n < 4 || n > 2048 ) {
    reply_error ( fd, GPGA_PROT_INVALID_DATA );
    return;
  }
  /* read the request packet */
  if ( readn ( fd, buf, n, &nread ) )
    goto read_failure;
  if ( nread != n ) {
    reply_error ( fd, GPGA_PROT_PROTOCOL_ERROR );
    return;
  }
  /* dispatch the request */
  n -= 4;
  data = buf+4;
  switch ( buftou32 ( buf ) ) {
  case GPGA_PROT_GET_VERSION: 
    req_get_version ( fd, data, n );
    break;
  case GPGA_PROT_GET_PASSPHRASE:
    req_get_passphrase (fd, data, n);
    break;
  case GPGA_PROT_CLEAR_PASSPHRASE:
    req_clear_passphrase (fd, data, n ); 
    break;
  case GPGA_PROT_SHUTDOWN:
    req_shutdown (fd, data, n );
    break;
  case GPGA_PROT_FLUSH:
    req_flush (fd, data, n );
    break;

  default:
    reply_error ( fd, GPGA_PROT_INVALID_REQUEST );
    break;
  }      
    
  return;

 read_failure:
  /* it does not make sense to respond in this case */
  log_error ( "read failure: %s\n", strerror(errno));
  return;
#endif
}
#endif



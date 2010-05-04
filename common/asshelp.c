/* asshelp.c - Helper functions for Assuan
 * Copyright (C) 2002, 2004, 2007, 2009, 2010 Free Software Foundation, Inc.
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#define JNLIB_NEED_LOG_LOGV
#include "i18n.h"
#include "util.h"
#include "exechelp.h"
#include "sysutils.h"
#include "status.h" 
#include "asshelp.h"

/* The type we use for lock_agent_spawning.  */
#ifdef HAVE_W32_SYSTEM
# define lock_agent_t HANDLE
#else
# define lock_agent_t DOTLOCK
#endif


static gpg_error_t
send_one_option (assuan_context_t ctx, gpg_err_source_t errsource,
                 const char *name, const char *value, int use_putenv)
{
  gpg_error_t err;
  char *optstr;

  (void)errsource;

  if (!value || !*value)
    err = 0;  /* Avoid sending empty strings.  */
  else if (asprintf (&optstr, "OPTION %s%s=%s", 
                     use_putenv? "putenv=":"", name, value) < 0)
    err = gpg_error_from_syserror ();
  else
    {
      err = assuan_transact (ctx, optstr, NULL, NULL, NULL, NULL, NULL, NULL);
      xfree (optstr);
    }

  return err;
}


/* Send the assuan commands pertaining to the pinentry environment.  The
   OPT_* arguments are optional and may be used to override the
   defaults taken from the current locale. */
gpg_error_t
send_pinentry_environment (assuan_context_t ctx,
                           gpg_err_source_t errsource,
                           const char *opt_lc_ctype,
                           const char *opt_lc_messages,
                           session_env_t session_env)

{
  gpg_error_t err = 0;
#if defined(HAVE_SETLOCALE)
  char *old_lc = NULL; 
#endif
  char *dft_lc = NULL;
  const char *dft_ttyname;
  int iterator;
  const char *name, *assname, *value;
  int is_default;

  iterator = 0; 
  while ((name = session_env_list_stdenvnames (&iterator, &assname)))
    {
      value = session_env_getenv_or_default (session_env, name, NULL);
      if (!value)
        continue;

      if (assname)
        err = send_one_option (ctx, errsource, assname, value, 0);
      else
        {
          err = send_one_option (ctx, errsource, name, value, 1);
          if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
            err = 0;  /* Server too old; can't pass the new envvars.  */
        }
      if (err)
        return err;
    }


  dft_ttyname = session_env_getenv_or_default (session_env, "GPG_TTY", 
                                               &is_default);
  if (dft_ttyname && !is_default)
    dft_ttyname = NULL;  /* We need the default value.  */

  /* Send the value for LC_CTYPE.  */
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  old_lc = setlocale (LC_CTYPE, NULL);
  if (old_lc)
    {
      old_lc = xtrystrdup (old_lc);
      if (!old_lc)
        return gpg_error_from_syserror ();
    }
  dft_lc = setlocale (LC_CTYPE, "");
#endif
  if (opt_lc_ctype || (dft_ttyname && dft_lc))
    {
      err = send_one_option (ctx, errsource, "lc-ctype", 
                             opt_lc_ctype ? opt_lc_ctype : dft_lc, 0);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  if (old_lc)
    {
      setlocale (LC_CTYPE, old_lc);
      xfree (old_lc);
    }
#endif
  if (err)
    return err;

  /* Send the value for LC_MESSAGES.  */
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  old_lc = setlocale (LC_MESSAGES, NULL);
  if (old_lc)
    {
      old_lc = xtrystrdup (old_lc);
      if (!old_lc)
        return gpg_error_from_syserror ();
    }
  dft_lc = setlocale (LC_MESSAGES, "");
#endif
  if (opt_lc_messages || (dft_ttyname && dft_lc))
    {
      err = send_one_option (ctx, errsource, "lc-messages", 
                             opt_lc_messages ? opt_lc_messages : dft_lc, 0);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  if (old_lc)
    {
      setlocale (LC_MESSAGES, old_lc);
      xfree (old_lc);
    }
#endif
  if (err)
    return err;

  return 0;
}


/* Lock the agent spawning process.  The caller needs to provide the
   address of a variable to store the lock information.  */
static gpg_error_t
lock_agent_spawning (lock_agent_t *lock, const char *homedir)
{
#ifdef HAVE_W32_SYSTEM
  int waitrc;

  (void)homedir; /* Not required. */

  *lock = CreateMutex (NULL, FALSE, "GnuPG_spawn_agent_sentinel");
  if (!*lock)
    {
      log_error ("failed to create the spawn_agent mutex: %s\n",
                 w32_strerror (-1));
      return gpg_error (GPG_ERR_GENERAL);
    }

  waitrc = WaitForSingleObject (*lock, 5000);
  if (waitrc == WAIT_OBJECT_0)
    return 0;

  if (waitrc == WAIT_TIMEOUT)
    log_info ("error waiting for the spawn_agent mutex: timeout\n");
  else
    log_info ("error waiting for the spawn_agent mutex: "
              "(code=%d) %s\n", waitrc, w32_strerror (-1));
  return gpg_error (GPG_ERR_GENERAL);
#else /*!HAVE_W32_SYSTEM*/
  char *fname;

  *lock = NULL;

  fname = make_filename (homedir, "gnupg_spawn_agent_sentinel", NULL);
  if (!fname)
    return gpg_error_from_syserror ();

  *lock = create_dotlock (fname);
  xfree (fname);
  if (!*lock)
    return gpg_error_from_syserror ();

  /* FIXME: We should use a timeout of 5000 here - however
     make_dotlock does not yet support values other than -1 and 0.  */
  if (make_dotlock (*lock, -1))
    return gpg_error_from_syserror ();

  return 0;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Unlock the spawning process.  */
static void
unlock_agent_spawning (lock_agent_t *lock)
{
  if (*lock)
    {
#ifdef HAVE_W32_SYSTEM
      if (!ReleaseMutex (*lock))
        log_error ("failed to release the spawn_agent mutex: %s\n",
                   w32_strerror (-1));
      CloseHandle (*lock);
#else /*!HAVE_W32_SYSTEM*/
      destroy_dotlock (*lock);
#endif /*!HAVE_W32_SYSTEM*/
      *lock = NULL;
    }
}


/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting.  Returns a new assuan
   context at R_CTX or an error code. */
gpg_error_t
start_new_gpg_agent (assuan_context_t *r_ctx,
                     gpg_err_source_t errsource,
                     const char *homedir,
                     const char *agent_program,
                     const char *opt_lc_ctype,
                     const char *opt_lc_messages,
                     session_env_t session_env,
                     int verbose, int debug,
                     gpg_error_t (*status_cb)(ctrl_t, int, ...),
                     ctrl_t status_cb_arg)
{
  /* If we ever failed to connect via a socket we will force the use
     of the pipe based server for the lifetime of the process.  */
  static int force_pipe_server = 0;

  gpg_error_t err = 0;
  char *infostr, *p;
  assuan_context_t ctx;

  *r_ctx = NULL;

  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("error allocating assuan context: %s\n", gpg_strerror (err));
      return err;
    }

 restart:
  infostr = force_pipe_server? NULL : getenv ("GPG_AGENT_INFO");
  if (!infostr || !*infostr)
    {
      char *sockname;
      const char *argv[3];
      pid_t pid;
      int excode;

      /* First check whether we can connect at the standard
         socket.  */
      sockname = make_filename (homedir, "S.gpg-agent", NULL);
      err = assuan_socket_connect (ctx, sockname, 0, 0);

      if (err)
        {
          /* With no success start a new server.  */
          if (verbose)
            log_info (_("no running gpg-agent - starting one\n"));
          
          if (status_cb)
            status_cb (status_cb_arg, STATUS_PROGRESS, 
                       "starting_agent ? 0 0", NULL);
          
          if (fflush (NULL))
            {
              gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
              log_error ("error flushing pending output: %s\n",
                         strerror (errno));
              xfree (sockname);
	      assuan_release (ctx);
              return tmperr;
            }
          
          if (!agent_program || !*agent_program)
            agent_program = gnupg_module_name (GNUPG_MODULE_NAME_AGENT);

          argv[0] = "--use-standard-socket-p"; 
          argv[1] = NULL;  
          err = gnupg_spawn_process_fd (agent_program, argv, -1, -1, -1, &pid);
          if (err)
            log_debug ("starting `%s' for testing failed: %s\n",
                       agent_program, gpg_strerror (err));
          else if ((err = gnupg_wait_process (agent_program, pid, &excode)))
            {
              if (excode == -1)
                log_debug ("running `%s' for testing failed: %s\n",
                           agent_program, gpg_strerror (err));
            }          

          if (!err && !excode)
            {
              /* If the agent has been configured for use with a
                 standard socket, an environment variable is not
                 required and thus we we can savely start the agent
                 here.  */
              lock_agent_t lock;

              argv[0] = "--daemon";
              argv[1] = "--use-standard-socket"; 
              argv[2] = NULL;  

              if (!(err = lock_agent_spawning (&lock, homedir))
                  && assuan_socket_connect (ctx, sockname, 0, 0))
                {
                  err = gnupg_spawn_process_detached (agent_program, argv,NULL);
                  if (err)
                    log_error ("failed to start agent `%s': %s\n",
                               agent_program, gpg_strerror (err));
                  else
                    {
                      int i;

                      if (verbose)
                        log_info (_("waiting %d seconds for the agent "
                                    "to come up\n"), 5);
                      for (i=0; i < 5; i++)
                        {
                          gnupg_sleep (1);
                          err = assuan_socket_connect (ctx, sockname, 0, 0);
                          if (!err)
                            break;
                        }
                    }
                }

              unlock_agent_spawning (&lock);
            }
          else
            {
              /* If using the standard socket is not the default we
                 start the agent as a pipe server which gives us most
                 of the required features except for passphrase
                 caching etc.  */
              const char *pgmname;
              int no_close_list[3];
              int i;
              
              if ( !(pgmname = strrchr (agent_program, '/')))
                pgmname = agent_program;
              else
                pgmname++;
              
              argv[0] = pgmname;
              argv[1] = "--server";
              argv[2] = NULL;
              
              i=0;
              if (log_get_fd () != -1)
                no_close_list[i++] = assuan_fd_from_posix_fd (log_get_fd ());
              no_close_list[i++] = assuan_fd_from_posix_fd (fileno (stderr));
              no_close_list[i] = -1;
              
              /* Connect to the agent and perform initial handshaking. */
              err = assuan_pipe_connect (ctx, agent_program, argv,
                                         no_close_list, NULL, NULL, 0);
            }
        }
      xfree (sockname);
    }
  else
    {
      int prot;
      int pid;

      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, PATHSEP_C)) || p == infostr)
        {
          log_error (_("malformed GPG_AGENT_INFO environment variable\n"));
          xfree (infostr);
          force_pipe_server = 1;
          goto restart;
        }
      *p++ = 0;
      pid = atoi (p);
      while (*p && *p != PATHSEP_C)
        p++;
      prot = *p? atoi (p+1) : 0;
      if (prot != 1)
        {
          log_error (_("gpg-agent protocol version %d is not supported\n"),
                     prot);
          xfree (infostr);
          force_pipe_server = 1;
          goto restart;
        }

      err = assuan_socket_connect (ctx, infostr, pid, 0);
      xfree (infostr);
      if (gpg_err_code (err) == GPG_ERR_ASS_CONNECT_FAILED)
        {
          log_info (_("can't connect to the agent - trying fall back\n"));
          force_pipe_server = 1;
          goto restart;
        }
    }

  if (err)
    {
      log_error ("can't connect to the agent: %s\n", gpg_strerror (err));
      assuan_release (ctx);
      return gpg_error (GPG_ERR_NO_AGENT);
    }

  if (debug)
    log_debug ("connection to agent established\n");

  err = assuan_transact (ctx, "RESET",
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (!err)
    err = send_pinentry_environment (ctx, errsource,
                                    opt_lc_ctype, opt_lc_messages,
                                    session_env);
  if (err)
    {
      assuan_release (ctx);
      return err;
    }

  *r_ctx = ctx;
  return 0;
}


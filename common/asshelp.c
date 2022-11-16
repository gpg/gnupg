/* asshelp.c - Helper functions for Assuan
 * Copyright (C) 2002, 2004, 2007, 2009, 2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
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
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "i18n.h"
#include "util.h"
#include "exechelp.h"
#include "sysutils.h"
#include "status.h"
#include "membuf.h"
#include "asshelp.h"

/* The type we use for lock_agent_spawning.  */
#ifdef HAVE_W32_SYSTEM
# define lock_spawn_t HANDLE
#else
# define lock_spawn_t dotlock_t
#endif

/* The time we wait until the agent or the dirmngr are ready for
   operation after we started them before giving up.  */
#define SECS_TO_WAIT_FOR_AGENT 5
#define SECS_TO_WAIT_FOR_KEYBOXD 5
#define SECS_TO_WAIT_FOR_DIRMNGR 5

/* A bitfield that specifies the assuan categories to log.  This is
   identical to the default log handler of libassuan.  We need to do
   it ourselves because we use a custom log handler and want to use
   the same assuan variables to select the categories to log. */
static int log_cats;
#define TEST_LOG_CAT(x) (!! (log_cats & (1 << (x - 1))))

/* The assuan log monitor used to temporary inhibit log messages from
 * assuan.  */
static int (*my_log_monitor) (assuan_context_t ctx,
                              unsigned int cat,
                              const char *msg);


static int
my_libassuan_log_handler (assuan_context_t ctx, void *hook,
                          unsigned int cat, const char *msg)
{
  unsigned int dbgval;

  if (! TEST_LOG_CAT (cat))
    return 0;

  dbgval = hook? *(unsigned int*)hook : 0;
  if (!(dbgval & 1024))
    return 0; /* Assuan debugging is not enabled.  */

  if (ctx && my_log_monitor && !my_log_monitor (ctx, cat, msg))
    return 0; /* Temporary disabled.  */

  if (msg)
    log_string (GPGRT_LOGLVL_DEBUG, msg);

  return 1;
}


/* Setup libassuan to use our own logging functions.  Should be used
   early at startup.  */
void
setup_libassuan_logging (unsigned int *debug_var_address,
                         int (*log_monitor)(assuan_context_t ctx,
                                            unsigned int cat,
                                            const char *msg))
{
  char *flagstr;

  flagstr = getenv ("ASSUAN_DEBUG");
  if (flagstr)
    log_cats = atoi (flagstr);
  else /* Default to log the control channel.  */
    log_cats = (1 << (ASSUAN_LOG_CONTROL - 1));
  my_log_monitor = log_monitor;
  assuan_set_log_cb (my_libassuan_log_handler, debug_var_address);
}


/* Change the Libassuan log categories to those given by NEWCATS.
   NEWCATS is 0 the default category of ASSUAN_LOG_CONTROL is
   selected.  Note, that setup_libassuan_logging overrides the values
   given here.  */
void
set_libassuan_log_cats (unsigned int newcats)
{
  if (newcats)
    log_cats = newcats;
  else /* Default to log the control channel.  */
    log_cats = (1 << (ASSUAN_LOG_CONTROL - 1));
}



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


/* Lock a spawning process.  The caller needs to provide the address
   of a variable to store the lock information and the name or the
   process.  */
static gpg_error_t
lock_spawning (lock_spawn_t *lock, const char *homedir, const char *name,
               int verbose)
{
  char *fname;
  (void)verbose;

  *lock = NULL;

  fname = make_absfilename_try
    (homedir,
     !strcmp (name, "agent")?   "gnupg_spawn_agent_sentinel":
     !strcmp (name, "dirmngr")? "gnupg_spawn_dirmngr_sentinel":
     !strcmp (name, "keyboxd")? "gnupg_spawn_keyboxd_sentinel":
     /*                    */   "gnupg_spawn_unknown_sentinel",
     NULL);
  if (!fname)
    return gpg_error_from_syserror ();

  *lock = dotlock_create (fname, 0);
  xfree (fname);
  if (!*lock)
    return gpg_error_from_syserror ();

  /* FIXME: We should use a timeout of 5000 here - however
     make_dotlock does not yet support values other than -1 and 0.  */
  if (dotlock_take (*lock, -1))
    return gpg_error_from_syserror ();

  return 0;
}


/* Unlock the spawning process.  */
static void
unlock_spawning (lock_spawn_t *lock, const char *name)
{
  if (*lock)
    {
      (void)name;
      dotlock_destroy (*lock);
      *lock = NULL;
    }
}


/* Helper to start a service.  SECS gives the number of seconds to
 * wait.  SOCKNAME is the name of the socket to connect.  VERBOSE is
 * the usual verbose flag.  CTX is the assuan context.  CONNECT_FLAGS
 * are the assuan connect flags.  DID_SUCCESS_MSG will be set to 1 if
 * a success messages has been printed.
 */
static gpg_error_t
wait_for_sock (int secs, int module_name_id, const char *sockname,
               unsigned int connect_flags,
               int verbose, assuan_context_t ctx, int *did_success_msg)
{
  gpg_error_t err = 0;
  int target_us = secs * 1000000;
  int elapsed_us = 0;
  /*
   * 977us * 1024 = just a little more than 1s.
   * so we will double this timeout 10 times in the first
   * second, and then switch over to 1s checkins.
   */
  int next_sleep_us = 977;
  int lastalert = secs+1;
  int secsleft;

  while (elapsed_us < target_us)
    {
      if (verbose)
        {
          secsleft = (target_us - elapsed_us + 999999)/1000000;
          /* log_clock ("left=%d last=%d targ=%d elap=%d next=%d\n", */
          /*            secsleft, lastalert, target_us, elapsed_us, */
          /*            next_sleep_us); */
          if (secsleft < lastalert)
            {
              log_info (module_name_id == GNUPG_MODULE_NAME_DIRMNGR?
                        _("waiting for the dirmngr to come up ... (%ds)\n"):
                        module_name_id == GNUPG_MODULE_NAME_KEYBOXD?
                        _("waiting for the keyboxd to come up ... (%ds)\n"):
                        _("waiting for the agent to come up ... (%ds)\n"),
                        secsleft);
              lastalert = secsleft;
            }
        }
      gnupg_usleep (next_sleep_us);
      elapsed_us += next_sleep_us;
      err = assuan_socket_connect (ctx, sockname, 0, connect_flags);
      if (!err)
        {
          if (verbose)
            {
              log_info (module_name_id == GNUPG_MODULE_NAME_DIRMNGR?
                        _("connection to the dirmngr established\n"):
                        module_name_id == GNUPG_MODULE_NAME_KEYBOXD?
                        _("connection to the keyboxd established\n"):
                        _("connection to the agent established\n"));
              *did_success_msg = 1;
            }
          break;
        }
      next_sleep_us *= 2;
      if (next_sleep_us > 1000000)
        next_sleep_us = 1000000;
    }
  return err;
}


/* Try to connect to a new service via socket or start it if it is not
 * running and AUTOSTART is set.  Handle the server's initial
 * greeting.  Returns a new assuan context at R_CTX or an error code.
 * MODULE_NAME_ID is one of:
 *     GNUPG_MODULE_NAME_AGENT
 *     GNUPG_MODULE_NAME_DIRMNGR
 */
static gpg_error_t
start_new_service (assuan_context_t *r_ctx,
                   int module_name_id,
                   gpg_err_source_t errsource,
                   const char *program_name,
                   const char *opt_lc_ctype,
                   const char *opt_lc_messages,
                   session_env_t session_env,
                   int autostart, int verbose, int debug,
                   gpg_error_t (*status_cb)(ctrl_t, int, ...),
                   ctrl_t status_cb_arg)
{
  gpg_error_t err;
  assuan_context_t ctx;
  int did_success_msg = 0;
  char *sockname;
  const char *printed_name;
  const char *lock_name;
  const char *status_start_line;
  int no_service_err;
  int seconds_to_wait;
  unsigned int connect_flags = 0;
  const char *argv[6];

  *r_ctx = NULL;

  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("error allocating assuan context: %s\n", gpg_strerror (err));
      return err;
    }

  switch (module_name_id)
    {
    case GNUPG_MODULE_NAME_AGENT:
      sockname = make_filename (gnupg_socketdir (), GPG_AGENT_SOCK_NAME, NULL);
      lock_name = "agent";
      printed_name = "gpg-agent";
      status_start_line = "starting_agent ? 0 0";
      no_service_err = GPG_ERR_NO_AGENT;
      seconds_to_wait = SECS_TO_WAIT_FOR_AGENT;
      break;
    case GNUPG_MODULE_NAME_DIRMNGR:
      sockname = make_filename (gnupg_socketdir (), DIRMNGR_SOCK_NAME, NULL);
      lock_name = "dirmngr";
      printed_name = "dirmngr";
      status_start_line = "starting_dirmngr ? 0 0";
      no_service_err = GPG_ERR_NO_DIRMNGR;
      seconds_to_wait = SECS_TO_WAIT_FOR_DIRMNGR;
      break;
    case GNUPG_MODULE_NAME_KEYBOXD:
      sockname = make_filename (gnupg_socketdir (), KEYBOXD_SOCK_NAME, NULL);
      lock_name = "keyboxd";
      printed_name = "keyboxd";
      status_start_line = "starting_keyboxd ? 0 0";
      no_service_err = GPG_ERR_NO_KEYBOXD;
      seconds_to_wait = SECS_TO_WAIT_FOR_KEYBOXD;
      connect_flags |= ASSUAN_SOCKET_CONNECT_FDPASSING;
      break;
    default:
      err = gpg_error (GPG_ERR_INV_ARG);
      assuan_release (ctx);
      return err;
    }

  err = assuan_socket_connect (ctx, sockname, 0, connect_flags);
  if (err && autostart)
    {
      char *abs_homedir;
      lock_spawn_t lock;
      char *program = NULL;
      const char *program_arg = NULL;
      char *p;
      const char *s;
      int i;

      /* With no success start a new server.  */
      if (!program_name || !*program_name)
        program_name = gnupg_module_name (module_name_id);
      else if ((s=strchr (program_name, '|')) && s[1] == '-' && s[2]=='-')
        {
          /* Hack to insert an additional option on the command line.  */
          program = xtrystrdup (program_name);
          if (!program)
            {
              gpg_error_t tmperr = gpg_err_make (errsource,
                                                 gpg_err_code_from_syserror ());
              xfree (sockname);
              assuan_release (ctx);
              return tmperr;
            }
          p = strchr (program, '|');
          *p++ = 0;
          program_arg = p;
        }

      if (verbose)
        log_info (_("no running %s - starting '%s'\n"),
                  printed_name, program_name);

      if (status_cb)
        status_cb (status_cb_arg, STATUS_PROGRESS, status_start_line, NULL);

      /* We better pass an absolute home directory to the service just
       * in case the service does not convert the passed name to an
       * absolute one (which it should do).  */
      abs_homedir = make_absfilename_try (gnupg_homedir (), NULL);
      if (!abs_homedir)
        {
          gpg_error_t tmperr = gpg_err_make (errsource,
                                             gpg_err_code_from_syserror ());
          log_error ("error building filename: %s\n", gpg_strerror (tmperr));
          xfree (sockname);
          assuan_release (ctx);
          xfree (program);
          return tmperr;
        }

      if (fflush (NULL))
        {
          gpg_error_t tmperr = gpg_err_make (errsource,
                                             gpg_err_code_from_syserror ());
          log_error ("error flushing pending output: %s\n", strerror (errno));
          xfree (sockname);
          assuan_release (ctx);
          xfree (abs_homedir);
          xfree (program);
          return tmperr;
        }

      i = 0;
      argv[i++] = "--homedir";
      argv[i++] = abs_homedir;
      if (module_name_id == GNUPG_MODULE_NAME_AGENT)
        argv[i++] = "--use-standard-socket";
      if (program_arg)
        argv[i++] = program_arg;
      argv[i++] = "--daemon";
      argv[i++] = NULL;

      if (!(err = lock_spawning (&lock, gnupg_homedir (), lock_name, verbose))
          && assuan_socket_connect (ctx, sockname, 0, connect_flags))
        {
#ifdef HAVE_W32_SYSTEM
          err = gnupg_spawn_process_detached (program? program : program_name,
                                              argv, NULL);
#else /*!W32*/
          pid_t pid;

          err = gnupg_spawn_process_fd (program? program : program_name,
                                        argv, -1, -1, -1, &pid);
          if (!err)
            err = gnupg_wait_process (program? program : program_name,
                                      pid, 1, NULL);
#endif /*!W32*/
          if (err)
            log_error ("failed to start %s '%s': %s\n",
                       printed_name, program? program : program_name,
                       gpg_strerror (err));
          else
            err = wait_for_sock (seconds_to_wait, module_name_id,
                                 sockname, connect_flags,
                                 verbose, ctx, &did_success_msg);
        }

      unlock_spawning (&lock, lock_name);
      xfree (abs_homedir);
      xfree (program);
    }
  xfree (sockname);
  if (err)
    {
      if (autostart || gpg_err_code (err) != GPG_ERR_ASS_CONNECT_FAILED)
        log_error ("can't connect to the %s: %s\n",
                   printed_name, gpg_strerror (err));
      assuan_release (ctx);
      return gpg_err_make (errsource, no_service_err);
    }

  if (debug && !did_success_msg)
    log_debug ("connection to the %s established\n", printed_name);

  if (module_name_id == GNUPG_MODULE_NAME_AGENT)
    err = assuan_transact (ctx, "RESET",
                           NULL, NULL, NULL, NULL, NULL, NULL);

  if (!err
      && module_name_id == GNUPG_MODULE_NAME_AGENT)
    {
      err = send_pinentry_environment (ctx, errsource,
                                       opt_lc_ctype, opt_lc_messages,
                                       session_env);
      if (gpg_err_code (err) == GPG_ERR_FORBIDDEN
          && gpg_err_source (err) == GPG_ERR_SOURCE_GPGAGENT)
        {
          /* Check whether the agent is in restricted mode.  */
          if (!assuan_transact (ctx, "GETINFO restricted",
                                NULL, NULL, NULL, NULL, NULL, NULL))
            {
              if (verbose)
                log_info (_("connection to the agent is in restricted mode\n"));
              err = 0;
            }
        }
    }
  if (err)
    {
      assuan_release (ctx);
      return err;
    }

  *r_ctx = ctx;
  return 0;
}


/* Try to connect to the agent or start a new one.  */
gpg_error_t
start_new_gpg_agent (assuan_context_t *r_ctx,
                     gpg_err_source_t errsource,
                     const char *agent_program,
                     const char *opt_lc_ctype,
                     const char *opt_lc_messages,
                     session_env_t session_env,
                     int autostart, int verbose, int debug,
                     gpg_error_t (*status_cb)(ctrl_t, int, ...),
                     ctrl_t status_cb_arg)
{
  return start_new_service (r_ctx, GNUPG_MODULE_NAME_AGENT,
                            errsource, agent_program,
                            opt_lc_ctype, opt_lc_messages, session_env,
                            autostart, verbose, debug,
                            status_cb, status_cb_arg);
}


/* Try to connect to the dirmngr via a socket.  On platforms
   supporting it, start it up if needed and if AUTOSTART is true.
   Returns a new assuan context at R_CTX or an error code. */
gpg_error_t
start_new_keyboxd (assuan_context_t *r_ctx,
                   gpg_err_source_t errsource,
                   const char *keyboxd_program,
                   int autostart, int verbose, int debug,
                   gpg_error_t (*status_cb)(ctrl_t, int, ...),
                   ctrl_t status_cb_arg)
{
  return start_new_service (r_ctx, GNUPG_MODULE_NAME_KEYBOXD,
                            errsource, keyboxd_program,
                            NULL, NULL, NULL,
                            autostart, verbose, debug,
                            status_cb, status_cb_arg);
}


/* Try to connect to the dirmngr via a socket.  On platforms
   supporting it, start it up if needed and if AUTOSTART is true.
   Returns a new assuan context at R_CTX or an error code. */
gpg_error_t
start_new_dirmngr (assuan_context_t *r_ctx,
                   gpg_err_source_t errsource,
                   const char *dirmngr_program,
                   int autostart, int verbose, int debug,
                   gpg_error_t (*status_cb)(ctrl_t, int, ...),
                   ctrl_t status_cb_arg)
{
#ifndef USE_DIRMNGR_AUTO_START
  autostart = 0;
#endif
  return start_new_service (r_ctx, GNUPG_MODULE_NAME_DIRMNGR,
                            errsource, dirmngr_program,
                            NULL, NULL, NULL,
                            autostart, verbose, debug,
                            status_cb, status_cb_arg);
}


/* Return the version of a server using "GETINFO version".  On success
   0 is returned and R_VERSION receives a malloced string with the
   version which must be freed by the caller.  On error NULL is stored
   at R_VERSION and an error code returned.  Mode is in general 0 but
   certain values may be used to modify the used version command:

      MODE == 0 = Use "GETINFO version"
      MODE == 2 - Use "SCD GETINFO version"
 */
gpg_error_t
get_assuan_server_version (assuan_context_t ctx, int mode, char **r_version)
{
  gpg_error_t err;
  membuf_t data;

  init_membuf (&data, 64);
  err = assuan_transact (ctx,
                         mode == 2? "SCD GETINFO version"
                         /**/     : "GETINFO version",
                         put_membuf_cb, &data,
                         NULL, NULL, NULL, NULL);
  if (err)
    {
      xfree (get_membuf (&data, NULL));
      *r_version = NULL;
    }
  else
    {
      put_membuf (&data, "", 1);
      *r_version = get_membuf (&data, NULL);
      if (!*r_version)
        err = gpg_error_from_syserror ();
    }
  return err;
}


/* Print a warning if the server's version number is less than our
 * version number.  Returns an error code on a connection problem.
 * CTX is the Assuan context, SERVERNAME is the name of teh server,
 * STATUS_FUNC and STATUS_FUNC_DATA is a callback to emit status
 * messages.  If PRINT_HINTS is set additional hints are printed.  For
 * MODE see get_assuan_server_version.  */
gpg_error_t
warn_server_version_mismatch (assuan_context_t ctx,
                              const char *servername, int mode,
                              gpg_error_t (*status_func)(ctrl_t ctrl,
                                                         int status_no,
                                                         ...),
                              void *status_func_ctrl,
                              int print_hints)
{
  gpg_error_t err;
  char *serverversion;
  const char *myversion = gpgrt_strusage (13);

  err = get_assuan_server_version (ctx, mode, &serverversion);
  if (err)
    log_log (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED?
             GPGRT_LOGLVL_INFO : GPGRT_LOGLVL_ERROR,
             _("error getting version from '%s': %s\n"),
             servername, gpg_strerror (err));
  else if (compare_version_strings (serverversion, myversion) < 0)
    {
      char *warn;

      warn = xtryasprintf (_("server '%s' is older than us (%s < %s)"),
                           servername, serverversion, myversion);
      if (!warn)
        err = gpg_error_from_syserror ();
      else
        {
          log_info (_("WARNING: %s\n"), warn);
          if (print_hints)
            {
              log_info (_("Note: Outdated servers may lack important"
                          " security fixes.\n"));
              log_info (_("Note: Use the command \"%s\" to restart them.\n"),
                        "gpgconf --kill all");
            }
          if (status_func)
            status_func (status_func_ctrl, STATUS_WARNING,
                         "server_version_mismatch 0", warn, NULL);
          xfree (warn);
        }
    }
  xfree (serverversion);
  return err;
}

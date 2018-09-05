/* kbxserver.c - Handle Assuan commands send to the keyboxd
 * Copyright (C) 2018 g10 Code GmbH
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
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "keyboxd.h"
#include <assuan.h>

#include "../common/i18n.h"
#include "../common/server-help.h"




#define PARM_ERROR(t) assuan_set_error (ctx, \
                                        gpg_error (GPG_ERR_ASS_PARAMETER), (t))
#define set_error(e,t) (ctx ? assuan_set_error (ctx, gpg_error (e), (t)) \
                        /**/: gpg_error (e))



/* Control structure per connection. */
struct server_local_s
{
  /* Data used to associate an Assuan context with local server data */
  assuan_context_t assuan_ctx;

  /* The session id (a counter).  */
  unsigned int session_id;

  /* If this flag is set to true this process will be terminated after
   * the end of this session.  */
  int stopme;

  /* If the first both flags are set the assuan logging of data lines
   * is suppressed.  The count variable is used to show the number of
   * non-logged bytes.  */
  size_t inhibit_data_logging_count;
  unsigned int inhibit_data_logging : 1;
  unsigned int inhibit_data_logging_now : 1;

  /* Dummy option.  */
  int foo;
};




/* Helper to print a message while leaving a command.  */
static gpg_error_t
leave_cmd (assuan_context_t ctx, gpg_error_t err)
{
  if (err)
    {
      const char *name = assuan_get_command_name (ctx);
      if (!name)
        name = "?";
      if (gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
        log_error ("command '%s' failed: %s\n", name,
                   gpg_strerror (err));
      else
        log_error ("command '%s' failed: %s <%s>\n", name,
                   gpg_strerror (err), gpg_strsource (err));
    }
  return err;
}



/* Handle OPTION commands. */
static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  if (!strcmp (key, "foo"))
    {
      ctrl->server_local->foo = 1;
    }
  else if (!strcmp (key, "lc-messages"))
    {
      if (ctrl->lc_messages)
        xfree (ctrl->lc_messages);
      ctrl->lc_messages = xtrystrdup (value);
      if (!ctrl->lc_messages)
        return out_of_core ();
    }
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}



static const char hlp_foo[] =
  "FOO <user_id>\n"
  "\n"
  "Bla bla\n"
  "more bla.";
static gpg_error_t
cmd_foo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  (void)ctrl;
  (void)line;

  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return leave_cmd (ctx, err);
}



static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multi purpose command to return certain information.  \n"
  "Supported values of WHAT are:\n"
  "\n"
  "version     - Return the version of the program.\n"
  "pid         - Return the process id of the server.\n"
  "socket_name - Return the name of the socket.\n"
  "session_id  - Return the current session_id.\n"
  "getenv NAME - Return value of envvar NAME\n";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  char numbuf[50];

  if (!strcmp (line, "version"))
    {
      const char *s = VERSION;
      err = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      err = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "socket_name"))
    {
      const char *s = get_kbxd_socket_name ();
      if (!s)
        s = "[none]";
      err = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "session_id"))
    {
      snprintf (numbuf, sizeof numbuf, "%u", ctrl->server_local->session_id);
      err = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strncmp (line, "getenv", 6)
           && (line[6] == ' ' || line[6] == '\t' || !line[6]))
    {
      line += 6;
      while (*line == ' ' || *line == '\t')
        line++;
      if (!*line)
        err = gpg_error (GPG_ERR_MISSING_VALUE);
      else
        {
          const char *s = getenv (line);
          if (!s)
            err = set_error (GPG_ERR_NOT_FOUND, "No such envvar");
          else
            err = assuan_send_data (ctx, s, strlen (s));
        }
    }
  else
    err = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");

  return leave_cmd (ctx, err);
}



static const char hlp_killkeyboxd[] =
  "KILLKEYBOXD\n"
  "\n"
  "This command allows a user - given sufficient permissions -\n"
  "to kill this keyboxd process.\n";
static gpg_error_t
cmd_killkeyboxd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  ctrl->server_local->stopme = 1;
  assuan_set_flag (ctx, ASSUAN_FORCE_CLOSE, 1);
  return gpg_error (GPG_ERR_EOF);
}


static const char hlp_reloadkeyboxd[] =
  "RELOADKEYBOXD\n"
  "\n"
  "This command is an alternative to SIGHUP\n"
  "to reload the configuration.";
static gpg_error_t
cmd_reloadkeyboxd (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;

  kbxd_sighup_action ();
  return 0;
}



/* Tell the assuan library about our commands. */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    { "FOO",        cmd_foo,        hlp_foo },
    { "GETINFO",    cmd_getinfo,    hlp_getinfo },
    { "KILLKEYBOXD",cmd_killkeyboxd,hlp_killkeyboxd },
    { "RELOADKEYBOXD",cmd_reloadkeyboxd,hlp_reloadkeyboxd },
    { NULL, NULL }
  };
  int i, j, rc;

  for (i=j=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler,
                                    table[i].help);
      if (rc)
        return rc;
    }
  return 0;
}


/* Note that we do not reset the list of configured keyservers.  */
static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;
  (void)ctrl;

  return 0;
}


/* This function is called by our assuan log handler to test whether a
 * log message shall really be printed.  The function must return
 * false to inhibit the logging of MSG.  CAT gives the requested log
 * category.  MSG might be NULL. */
int
kbxd_assuan_log_monitor (assuan_context_t ctx, unsigned int cat,
                         const char *msg)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)cat;
  (void)msg;

  if (!ctrl || !ctrl->server_local)
    return 1; /* Can't decide - allow logging.  */

  if (!ctrl->server_local->inhibit_data_logging)
    return 1; /* Not requested - allow logging.  */

  /* Disallow logging if *_now is true.  */
  return !ctrl->server_local->inhibit_data_logging_now;
}


/* Return the assuan contxt from the local server info in CTRL.  */
static assuan_context_t
get_assuan_ctx_from_ctrl (ctrl_t ctrl)
{
  if (!ctrl || !ctrl->server_local)
    return NULL;
  return ctrl->server_local->assuan_ctx;
}


/* Startup the server and run the main command loop.  With FD = -1,
 * use stdin/stdout.  SESSION_ID is either 0 or a unique number
 * identifying a session. */
void
kbxd_start_command_handler (ctrl_t ctrl, gnupg_fd_t fd, unsigned int session_id)
{
  static const char hello[] = "Keyboxd " VERSION " at your service";
  static char *hello_line;
  int rc;
  assuan_context_t ctx;

  ctrl->server_local = xtrycalloc (1, sizeof *ctrl->server_local);
  if (!ctrl->server_local)
    {
      log_error (_("can't allocate control structure: %s\n"),
                 gpg_strerror (gpg_error_from_syserror ()));
      xfree (ctrl);
      return;
    }

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error (_("failed to allocate assuan context: %s\n"),
		 gpg_strerror (rc));
      kbxd_exit (2);
    }

  if (fd == GNUPG_INVALID_FD)
    {
      assuan_fd_t filedes[2];

      filedes[0] = assuan_fdopen (0);
      filedes[1] = assuan_fdopen (1);
      rc = assuan_init_pipe_server (ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (ctx, fd, ASSUAN_SOCKET_SERVER_ACCEPTED);
    }

  if (rc)
    {
      assuan_release (ctx);
      log_error (_("failed to initialize the server: %s\n"),
                 gpg_strerror (rc));
      kbxd_exit (2);
    }

  rc = register_commands (ctx);
  if (rc)
    {
      log_error (_("failed to the register commands with Assuan: %s\n"),
                 gpg_strerror(rc));
      kbxd_exit (2);
    }


  if (!hello_line)
    {
      hello_line = xtryasprintf
        ("Home: %s\n"
         "Config: %s\n"
         "%s",
         gnupg_homedir (),
         /*opt.config_filename? opt.config_filename :*/ "[none]",
         hello);
    }

  ctrl->server_local->assuan_ctx = ctx;
  assuan_set_pointer (ctx, ctrl);

  assuan_set_hello_line (ctx, hello_line);
  assuan_register_option_handler (ctx, option_handler);
  assuan_register_reset_notify (ctx, reset_notify);

  ctrl->server_local->session_id = session_id;

  /* The next call enable the use of status_printf.  */
  set_assuan_context_func (get_assuan_ctx_from_ctrl);

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        break;
      if (rc)
        {
          log_info (_("Assuan accept problem: %s\n"), gpg_strerror (rc));
          break;
        }

#ifndef HAVE_W32_SYSTEM
      if (opt.verbose)
        {
	  assuan_peercred_t peercred;

          if (!assuan_get_peercred (ctx, &peercred))
            log_info ("connection from process %ld (%ld:%ld)\n",
                      (long)peercred->pid, (long)peercred->uid,
		      (long)peercred->gid);
        }
#endif

      rc = assuan_process (ctx);
      if (rc)
        {
          log_info (_("Assuan processing failed: %s\n"), gpg_strerror (rc));
          continue;
        }
    }


  set_assuan_context_func (NULL);
  ctrl->server_local->assuan_ctx = NULL;
  assuan_release (ctx);

  if (ctrl->server_local->stopme)
    kbxd_exit (0);

  if (ctrl->refcount)
    log_error ("oops: connection control structure still referenced (%d)\n",
               ctrl->refcount);
  else
    {
      xfree (ctrl->server_local);
      ctrl->server_local = NULL;
    }
}

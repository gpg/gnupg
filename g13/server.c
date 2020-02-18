/* server.c - The G13 Assuan server
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#include "g13.h"
#include <assuan.h>
#include "../common/i18n.h"
#include "keyblob.h"
#include "server.h"
#include "create.h"
#include "mount.h"
#include "suspend.h"
#include "../common/server-help.h"
#include "../common/asshelp.h"
#include "../common/call-gpg.h"


/* The filepointer for status message used in non-server mode */
static FILE *statusfp;

/* Local data for this server module.  A pointer to this is stored in
   the CTRL object of each connection.  */
struct server_local_s
{
  /* The Assuan context we are working on.  */
  assuan_context_t assuan_ctx;

  char *containername;  /* Malloced active containername.  */
};




/* Local prototypes.  */
static int command_has_option (const char *cmd, const char *cmdopt);




/*
   Helper functions.
 */

/* Set an error and a description.  */
#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))


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




/* The handler for Assuan OPTION commands.  */
static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  (void)ctrl;

  if (!strcmp (key, "putenv"))
    {
      /* Change the session's environment to be used for the
         Pinentry.  Valid values are:
          <NAME>            Delete envvar NAME
          <KEY>=            Set envvar NAME to the empty string
          <KEY>=<VALUE>     Set envvar NAME to VALUE
      */
      err = session_env_putenv (opt.session_env, value);
    }
  else if (!strcmp (key, "display"))
    {
      err = session_env_setenv (opt.session_env, "DISPLAY", value);
    }
  else if (!strcmp (key, "ttyname"))
    {
      err = session_env_setenv (opt.session_env, "GPG_TTY", value);
    }
  else if (!strcmp (key, "ttytype"))
    {
      err = session_env_setenv (opt.session_env, "TERM", value);
    }
  else if (!strcmp (key, "lc-ctype"))
    {
      xfree (opt.lc_ctype);
      opt.lc_ctype = xtrystrdup (value);
      if (!opt.lc_ctype)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (key, "lc-messages"))
    {
      xfree (opt.lc_messages);
      opt.lc_messages = xtrystrdup (value);
      if (!opt.lc_messages)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (key, "xauthority"))
    {
      err = session_env_setenv (opt.session_env, "XAUTHORITY", value);
    }
  else if (!strcmp (key, "pinentry-user-data"))
    {
      err = session_env_setenv (opt.session_env, "PINENTRY_USER_DATA", value);
    }
  else if (!strcmp (key, "allow-pinentry-notify"))
    {
      ; /* We always allow it.  */
    }
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}


/* The handler for an Assuan RESET command.  */
static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  xfree (ctrl->server_local->containername);
  ctrl->server_local->containername = NULL;

  FREE_STRLIST (ctrl->recipients);

  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return 0;
}


static const char hlp_open[] =
  "OPEN [<options>] <filename>\n"
  "\n"
  "Open the container FILENAME.  FILENAME must be percent-plus\n"
  "escaped.  A quick check to see whether this is a suitable G13\n"
  "container file is done.  However no cryptographic check or any\n"
  "other check is done.  This command is used to define the target for\n"
  "further commands.  The filename is reset with the RESET command,\n"
  "another OPEN or the CREATE command.";
static gpg_error_t
cmd_open (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  char *p, *pend;
  size_t len;

  /* In any case reset the active container.  */
  xfree (ctrl->server_local->containername);
  ctrl->server_local->containername = NULL;

  /* Parse the line.  */
  line = skip_options (line);
  for (p=line; *p && !spacep (p); p++)
    ;
  pend = p;
  while (spacep(p))
    p++;
  if (*p || pend == line)
    {
      err = gpg_error (GPG_ERR_ASS_SYNTAX);
      goto leave;
    }
  *pend = 0;

  /* Unescape the line and check for embedded Nul bytes.  */
  len = percent_plus_unescape_inplace (line, 0);
  line[len] = 0;
  if (!len || memchr (line, 0, len))
    {
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  /* Do a basic check.  */
  err = g13_is_container (ctrl, line);
  if (err)
    goto leave;

  /* Store the filename.  */
  ctrl->server_local->containername = xtrystrdup (line);
  if (!ctrl->server_local->containername)
    err = gpg_error_from_syserror ();


 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_mount[] =
  "MOUNT [options] [<mountpoint>]\n"
  "\n"
  "Mount the currently open file onto MOUNTPOINT.  If MOUNTPOINT is not\n"
  "given the system picks an unused mountpoint.  MOUNTPOINT must\n"
  "be percent-plus escaped to allow for arbitrary names.";
static gpg_error_t
cmd_mount (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  char *p, *pend;
  size_t len;

  line = skip_options (line);
  for (p=line; *p && !spacep (p); p++)
    ;
  pend = p;
  while (spacep(p))
    p++;
  if (*p)
    {
      err = gpg_error (GPG_ERR_ASS_SYNTAX);
      goto leave;
    }
  *pend = 0;

  /* Unescape the line and check for embedded Nul bytes.  */
  len = percent_plus_unescape_inplace (line, 0);
  line[len] = 0;
  if (memchr (line, 0, len))
    {
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  if (!ctrl->server_local->containername)
    {
      err = gpg_error (GPG_ERR_MISSING_ACTION);
      goto leave;
    }

  /* Perform the mount.  */
  err = g13_mount_container (ctrl, ctrl->server_local->containername,
                             *line? line : NULL);

 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_umount[] =
  "UMOUNT [options] [<mountpoint>]\n"
  "\n"
  "Unmount the currently open file or the one opened at MOUNTPOINT.\n"
  "MOUNTPOINT must be percent-plus escaped.  On success the mountpoint\n"
  "is returned via a \"MOUNTPOINT\" status line.";
static gpg_error_t
cmd_umount (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  char *p, *pend;
  size_t len;

  line = skip_options (line);
  for (p=line; *p && !spacep (p); p++)
    ;
  pend = p;
  while (spacep(p))
    p++;
  if (*p)
    {
      err = gpg_error (GPG_ERR_ASS_SYNTAX);
      goto leave;
    }
  *pend = 0;

  /* Unescape the line and check for embedded Nul bytes.  */
  len = percent_plus_unescape_inplace (line, 0);
  line[len] = 0;
  if (memchr (line, 0, len))
    {
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  /* Perform the unmount.  */
  err = g13_umount_container (ctrl, ctrl->server_local->containername,
                              *line? line : NULL);

 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_suspend[] =
  "SUSPEND\n"
  "\n"
  "Suspend the currently set device.";
static gpg_error_t
cmd_suspend (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  line = skip_options (line);
  if (*line)
    {
      err = gpg_error (GPG_ERR_ASS_SYNTAX);
      goto leave;
    }

  /* Perform the suspend operation.  */
  err = g13_suspend_container (ctrl, ctrl->server_local->containername);

 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_resume[] =
  "RESUME\n"
  "\n"
  "Resume the currently set device.";
static gpg_error_t
cmd_resume (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  line = skip_options (line);
  if (*line)
    {
      err = gpg_error (GPG_ERR_ASS_SYNTAX);
      goto leave;
    }

  /* Perform the suspend operation.  */
  err = g13_resume_container (ctrl, ctrl->server_local->containername);

 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_recipient[] =
  "RECIPIENT <userID>\n"
  "\n"
  "Add USERID to the list of recipients to be used for the next CREATE\n"
  "command.  All recipient commands are cumulative until a RESET or an\n"
  "successful create command.";
static gpg_error_t
cmd_recipient (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  line = skip_options (line);

  if (!add_to_strlist_try (&ctrl->recipients, line))
    err = gpg_error_from_syserror ();

  return leave_cmd (ctx, err);
}


static const char hlp_signer[] =
  "SIGNER <userID>\n"
  "\n"
  "Not yet implemented.";
static gpg_error_t
cmd_signer (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  (void)ctrl;
  (void)line;

  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  return leave_cmd (ctx, err);
}


static const char hlp_create[] =
  "CREATE [options] <filename>\n"
  "\n"
  "Create a new container.  On success the OPEN command is \n"
  "implicitly done for the new container.";
static gpg_error_t
cmd_create (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  char *p, *pend;
  size_t len;

  /* First we close the active container.  */
  xfree (ctrl->server_local->containername);
  ctrl->server_local->containername = NULL;

  /* Parse the line.  */
  line = skip_options (line);
  for (p=line; *p && !spacep (p); p++)
    ;
  pend = p;
  while (spacep(p))
    p++;
  if (*p || pend == line)
    {
      err = gpg_error (GPG_ERR_ASS_SYNTAX);
      goto leave;
    }
  *pend = 0;

  /* Unescape the line and check for embedded Nul bytes.  */
  len = percent_plus_unescape_inplace (line, 0);
  line[len] = 0;
  if (!len || memchr (line, 0, len))
    {
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  /* Create container.  */
  err = g13_create_container (ctrl, line);

  if (!err)
    {
      FREE_STRLIST (ctrl->recipients);

      /* Store the filename.  */
      ctrl->server_local->containername = xtrystrdup (line);
      if (!ctrl->server_local->containername)
        err = gpg_error_from_syserror ();

    }
 leave:
  return leave_cmd (ctx, err);
}


static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multipurpose function to return a variety of information.\n"
  "Supported values for WHAT are:\n"
  "\n"
  "  version     - Return the version of the program.\n"
  "  pid         - Return the process id of the server.\n"
  "  cmd_has_option CMD OPT\n"
  "              - Return OK if the command CMD implements the option OPT.";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  gpg_error_t err = 0;

  if (!strcmp (line, "version"))
    {
      const char *s = PACKAGE_VERSION;
      err = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      err = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strncmp (line, "cmd_has_option", 14)
           && (line[14] == ' ' || line[14] == '\t' || !line[14]))
    {
      char *cmd, *cmdopt;
      line += 14;
      while (*line == ' ' || *line == '\t')
        line++;
      if (!*line)
        err = gpg_error (GPG_ERR_MISSING_VALUE);
      else
        {
          cmd = line;
          while (*line && (*line != ' ' && *line != '\t'))
            line++;
          if (!*line)
            err = gpg_error (GPG_ERR_MISSING_VALUE);
          else
            {
              *line++ = 0;
              while (*line == ' ' || *line == '\t')
                line++;
              if (!*line)
                err = gpg_error (GPG_ERR_MISSING_VALUE);
              else
                {
                  cmdopt = line;
                  if (!command_has_option (cmd, cmdopt))
                    err = gpg_error (GPG_ERR_FALSE);
                }
            }
        }
    }
  else
    err = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");

  return leave_cmd (ctx, err);
}



/* Return true if the command CMD implements the option CMDOPT.  */
static int
command_has_option (const char *cmd, const char *cmdopt)
{
  (void)cmd;
  (void)cmdopt;

  return 0;
}


/* Tell the Assuan library about our commands.  */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] =  {
    { "OPEN",          cmd_open,   hlp_open },
    { "MOUNT",         cmd_mount,  hlp_mount},
    { "UMOUNT",        cmd_umount, hlp_umount },
    { "SUSPEND",       cmd_suspend, hlp_suspend },
    { "RESUME",        cmd_resume,  hlp_resume },
    { "RECIPIENT",     cmd_recipient, hlp_recipient },
    { "SIGNER",        cmd_signer, hlp_signer },
    { "CREATE",        cmd_create, hlp_create },
    { "INPUT",         NULL },
    { "OUTPUT",        NULL },
    { "GETINFO",       cmd_getinfo,hlp_getinfo },
    { NULL }
  };
  gpg_error_t err;
  int i;

  for (i=0; table[i].name; i++)
    {
      err = assuan_register_command (ctx, table[i].name, table[i].handler,
                                     table[i].help);
      if (err)
        return err;
    }
  return 0;
}


/* Startup the server. DEFAULT_RECPLIST is the list of recipients as
   set from the command line or config file.  We only require those
   marked as encrypt-to. */
gpg_error_t
g13_server (ctrl_t ctrl)
{
  gpg_error_t err;
  assuan_fd_t filedes[2];
  assuan_context_t ctx = NULL;
  static const char hello[] = ("GNU Privacy Guard's G13 server "
                               PACKAGE_VERSION " ready");

  /* We use a pipe based server so that we can work from scripts.
     assuan_init_pipe_server will automagically detect when we are
     called with a socketpair and ignore FIELDES in this case. */
  filedes[0] = assuan_fdopen (0);
  filedes[1] = assuan_fdopen (1);
  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("failed to allocate an Assuan context: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  err = assuan_init_pipe_server (ctx, filedes);
  if (err)
    {
      log_error ("failed to initialize the server: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = register_commands (ctx);
  if (err)
    {
      log_error ("failed to the register commands with Assuan: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  assuan_set_pointer (ctx, ctrl);

  if (opt.verbose || opt.debug)
    {
      char *tmp;

      tmp = xtryasprintf ("Home: %s\n"
                          "Config: %s\n"
                          "%s",
                          gnupg_homedir (),
                          opt.config_filename,
                          hello);
      if (tmp)
        {
          assuan_set_hello_line (ctx, tmp);
          xfree (tmp);
        }
    }
  else
    assuan_set_hello_line (ctx, hello);

  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);

  ctrl->server_local = xtrycalloc (1, sizeof *ctrl->server_local);
  if (!ctrl->server_local)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ctrl->server_local->assuan_ctx = ctx;

  while ( !(err = assuan_accept (ctx)) )
    {
      err = assuan_process (ctx);
      if (err)
        log_info ("Assuan processing failed: %s\n", gpg_strerror (err));
    }
  if (err == -1)
    err = 0;
  else
    log_info ("Assuan accept problem: %s\n", gpg_strerror (err));

 leave:
  reset_notify (ctx, NULL);  /* Release all items hold by SERVER_LOCAL.  */
  if (ctrl->server_local)
    {
      xfree (ctrl->server_local);
      ctrl->server_local = NULL;
    }

  assuan_release (ctx);
  return err;
}


/* Send a status line with status ID NO.  The arguments are a list of
   strings terminated by a NULL argument.  */
gpg_error_t
g13_status (ctrl_t ctrl, int no, ...)
{
  gpg_error_t err = 0;
  va_list arg_ptr;
  const char *text;

  va_start (arg_ptr, no);

  if (ctrl->no_server && ctrl->status_fd == -1)
    ; /* No status wanted. */
  else if (ctrl->no_server)
    {
      if (!statusfp)
        {
          if (ctrl->status_fd == 1)
            statusfp = stdout;
          else if (ctrl->status_fd == 2)
            statusfp = stderr;
          else
            statusfp = fdopen (ctrl->status_fd, "w");

          if (!statusfp)
            {
              log_fatal ("can't open fd %d for status output: %s\n",
                         ctrl->status_fd, strerror(errno));
            }
        }

      fputs ("[GNUPG:] ", statusfp);
      fputs (get_status_string (no), statusfp);

      while ( (text = va_arg (arg_ptr, const char*) ))
        {
          putc ( ' ', statusfp );
          for (; *text; text++)
            {
              if (*text == '\n')
                fputs ( "\\n", statusfp );
              else if (*text == '\r')
                fputs ( "\\r", statusfp );
              else
                putc ( *(const byte *)text,  statusfp );
            }
        }
      putc ('\n', statusfp);
      fflush (statusfp);
    }
  else
    {
      err = vprint_assuan_status_strings (ctrl->server_local->assuan_ctx,
                                          get_status_string (no), arg_ptr);
    }

  va_end (arg_ptr);
  return err;
}


/* Helper to notify the client about Pinentry events.  Returns an gpg
   error code. */
gpg_error_t
g13_proxy_pinentry_notify (ctrl_t ctrl, const unsigned char *line)
{
  if (!ctrl || !ctrl->server_local)
    return 0;
  return assuan_inquire (ctrl->server_local->assuan_ctx, line, NULL, NULL, 0);
}


/*
 * Decrypt the keyblob (ENCKEYBLOB,ENCKEYBLOBLEN) and store the result
 * at (R_KEYBLOB, R_KEYBLOBLEN).  Returns 0 on success or an error
 * code.  On error R_KEYBLOB is set to NULL.
 *
 * This actually does not belong here but for that simple wrapper it
 * does not make sense to add another source file.  Note that we do
 * not want to have this in keyblob.c, because that code is also used
 * by the syshelp.
 */
gpg_error_t
g13_keyblob_decrypt (ctrl_t ctrl, const void *enckeyblob, size_t enckeybloblen,
                     void **r_keyblob, size_t *r_keybloblen)
{
  gpg_error_t err;

  /* FIXME:  For now we only implement OpenPGP.  */
  err = gpg_decrypt_blob (ctrl, opt.gpg_program, opt.gpg_arguments,
                          enckeyblob, enckeybloblen,
                          r_keyblob, r_keybloblen);

  return err;
}

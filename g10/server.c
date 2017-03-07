/* server.c - server mode for gpg
 * Copyright (C) 2006, 2008  Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>


#include "gpg.h"
#include <assuan.h>
#include "../common/util.h"
#include "../common/i18n.h"
#include "options.h"
#include "../common/server-help.h"
#include "../common/sysutils.h"
#include "../common/status.h"


#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))


/* Data used to associate an Assuan context with local server data.  */
struct server_local_s
{
  /* Our current Assuan context. */
  assuan_context_t assuan_ctx;
  /* File descriptor as set by the MESSAGE command. */
  gnupg_fd_t message_fd;

  /* List of prepared recipients.  */
  pk_list_t recplist;

  /* Set if pinentry notifications should be passed back to the
     client. */
  int allow_pinentry_notify;
};



/* Helper to close the message fd if it is open. */
static void
close_message_fd (ctrl_t ctrl)
{
  if (ctrl->server_local->message_fd != GNUPG_INVALID_FD)
    {
      assuan_sock_close (ctrl->server_local->message_fd);
      ctrl->server_local->message_fd = GNUPG_INVALID_FD;
    }
}


/* Called by libassuan for Assuan options.  See the Assuan manual for
   details. */
static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)value;

  /* Fixme: Implement the tty and locale args. */
  if (!strcmp (key, "display"))
    {
    }
  else if (!strcmp (key, "ttyname"))
    {
    }
  else if (!strcmp (key, "ttytype"))
    {
    }
  else if (!strcmp (key, "lc-ctype"))
    {
    }
  else if (!strcmp (key, "lc-messages"))
    {
    }
  else if (!strcmp (key, "xauthority"))
    {
    }
  else if (!strcmp (key, "pinentry_user_data"))
    {
    }
  else if (!strcmp (key, "list-mode"))
    {
      /* This is for now a dummy option. */
    }
  else if (!strcmp (key, "allow-pinentry-notify"))
    {
      ctrl->server_local->allow_pinentry_notify = 1;
    }
  else
    return gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return 0;
}


/* Called by libassuan for RESET commands. */
static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  release_pk_list (ctrl->server_local->recplist);
  ctrl->server_local->recplist = NULL;

  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return 0;
}


/* Called by libassuan for INPUT commands. */
static gpg_error_t
input_notify (assuan_context_t ctx, char *line)
{
/*   ctrl_t ctrl = assuan_get_pointer (ctx); */

  (void)ctx;

  if (strstr (line, "--armor"))
    ; /* FIXME */
  else if (strstr (line, "--base64"))
    ; /* FIXME */
  else if (strstr (line, "--binary"))
    ;
  else
    {
      /* FIXME (autodetect encoding) */
    }
  return 0;
}


/* Called by libassuan for OUTPUT commands. */
static gpg_error_t
output_notify (assuan_context_t ctx, char *line)
{
/*   ctrl_t ctrl = assuan_get_pointer (ctx); */

  (void)ctx;

  if (strstr (line, "--armor"))
    ; /* FIXME */
  else if (strstr (line, "--base64"))
    {
      /* FIXME */
    }
  return 0;
}




/*  RECIPIENT [--hidden] <userID>
    RECIPIENT [--hidden] --file <filename>

   Set the recipient for the encryption.  <userID> should be the
   internal representation of the key; the server may accept any other
   way of specification.  If this is a valid and trusted recipient the
   server does respond with OK, otherwise the return is an ERR with
   the reason why the recipient can't be used, the encryption will
   then not be done for this recipient.  If the policy is not to
   encrypt at all if not all recipients are valid, the client has to
   take care of this.  All RECIPIENT commands are cumulative until a
   RESET or an successful ENCRYPT command.  */
static gpg_error_t
cmd_recipient (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int hidden, file;

  hidden = has_option (line,"--hidden");
  file = has_option (line,"--file");
  line = skip_options (line);

  /* FIXME: Expand groups
  if (opt.grouplist)
    remusr = expand_group (rcpts);
  else
    remusr = rcpts;
  */

  err = find_and_check_key (ctrl, line, PUBKEY_USAGE_ENC, hidden, file,
                            &ctrl->server_local->recplist);

  if (err)
    log_error ("command '%s' failed: %s\n", "RECIPIENT", gpg_strerror (err));
  return err;
}



/*  SIGNER <userID>

   Set the signer's keys for the signature creation.  <userID> should
   be the internal representation of the key; the server may accept
   any other way of specification.  If this is a valid and usable
   signing key the server does respond with OK, otherwise it returns
   an ERR with the reason why the key can't be used, the signing will
   then not be done for this key.  If the policy is not to sign at all
   if not all signer keys are valid, the client has to take care of
   this.  All SIGNER commands are cumulative until a RESET but they
   are *not* reset by an SIGN command because it can be expected that
   set of signers are used for more than one sign operation.

   Note that this command returns an INV_RECP status which is a bit
   strange, but they are very similar.  */
static gpg_error_t
cmd_signer (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}



/*  ENCRYPT

   Do the actual encryption process.  Takes the plaintext from the
   INPUT command, writes the ciphertext to the file descriptor set
   with the OUTPUT command, take the recipients from all the
   recipients set so far with RECIPIENTS.

   If this command fails the clients should try to delete all output
   currently done or otherwise mark it as invalid.  GPG does ensure
   that there won't be any security problem with leftover data on the
   output in this case.

   In most cases this command won't fail because most necessary checks
   have been done while setting the recipients.  However some checks
   can only be done right here and thus error may occur anyway (for
   example, no recipients at all).

   The input, output and message pipes are closed after this
   command.  */
static gpg_error_t
cmd_encrypt (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int inp_fd, out_fd;

  (void)line; /* LINE is not used.  */

  if ( !ctrl->server_local->recplist )
    {
      write_status_text (STATUS_NO_RECP, "0");
      err = gpg_error (GPG_ERR_NO_USER_ID);
      goto leave;
    }

  inp_fd = translate_sys2libc_fd (assuan_get_input_fd (ctx), 0);
  if (inp_fd == -1)
    {
      err = set_error (GPG_ERR_ASS_NO_INPUT, NULL);
      goto leave;
    }
  out_fd = translate_sys2libc_fd (assuan_get_output_fd (ctx), 1);
  if (out_fd == -1)
    {
      err = set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);
      goto leave;
    }


  /* FIXME: GPGSM does this here: Add all encrypt-to marked recipients
     from the default list. */

  /* fixme: err = ctrl->audit? 0 : start_audit_session (ctrl);*/

  err = encrypt_crypt (ctrl, inp_fd, NULL, NULL, 0,
                       ctrl->server_local->recplist,
                       out_fd);

 leave:
  /* Release the recipient list on success.  */
  if (!err)
    {
      release_pk_list (ctrl->server_local->recplist);
      ctrl->server_local->recplist = NULL;
    }

  /* Close and reset the fds. */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  if (err)
    log_error ("command '%s' failed: %s\n", "ENCRYPT", gpg_strerror (err));
  return err;
}



/*  DECRYPT

    This performs the decrypt operation.  */
static gpg_error_t
cmd_decrypt (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int inp_fd, out_fd;

  (void)line; /* LINE is not used.  */

  inp_fd = translate_sys2libc_fd (assuan_get_input_fd (ctx), 0);
  if (inp_fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);
  out_fd = translate_sys2libc_fd (assuan_get_output_fd (ctx), 1);
  if (out_fd == -1)
    return set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);

  glo_ctrl.lasterr = 0;
  err = decrypt_message_fd (ctrl, inp_fd, out_fd);
  if (!err)
    err = glo_ctrl.lasterr;

  /* Close and reset the fds. */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  if (err)
    log_error ("command '%s' failed: %s\n", "DECRYPT", gpg_strerror (err));
  return err;
}



/*  VERIFY

   This does a verify operation on the message send to the input-FD.
   The result is written out using status lines.  If an output FD was
   given, the signed text will be written to that.

   If the signature is a detached one, the server will inquire about
   the signed material and the client must provide it.
 */
static gpg_error_t
cmd_verify (assuan_context_t ctx, char *line)
{
  int rc;
#ifdef HAVE_W32_SYSTEM
  (void)ctx;
  (void)line;
  rc = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#else
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gnupg_fd_t fd = assuan_get_input_fd (ctx);
  gnupg_fd_t out_fd = assuan_get_output_fd (ctx);
  estream_t out_fp = NULL;

  /* FIXME: Revamp this code it is nearly to 3 years old and was only
     intended as a quick test.  */

  (void)line;

  if (fd == GNUPG_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);

  if (out_fd != GNUPG_INVALID_FD)
    {
      es_syshd_t syshd;

#ifdef HAVE_W32_SYSTEM
      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = out_fd;
#else
      syshd.type = ES_SYSHD_FD;
      syshd.u.fd = out_fd;
#endif
      out_fp = es_sysopen_nc (&syshd, "w");
      if (!out_fp)
        return set_error (gpg_err_code_from_syserror (), "fdopen() failed");
    }

  log_debug ("WARNING: The server mode is WORK "
             "IN PROGRESS and not ready for use\n");

  rc = gpg_verify (ctrl, fd, ctrl->server_local->message_fd, out_fp);

  es_fclose (out_fp);
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
#endif

  if (rc)
    log_error ("command '%s' failed: %s\n", "VERIFY", gpg_strerror (rc));
  return rc;
}



/*  SIGN [--detached]

   Sign the data set with the INPUT command and write it to the sink
   set by OUTPUT.  With "--detached" specified, a detached signature
   is created.  */
static gpg_error_t
cmd_sign (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}



/*  IMPORT

  Import keys as read from the input-fd, return status message for
  each imported one.  The import checks the validity of the key.  */
static gpg_error_t
cmd_import (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}



/*  EXPORT [--data [--armor|--base64]] [--] pattern

   Similar to the --export command line command, this command exports
   public keys matching PATTERN.  The output is send to the output fd
   unless the --data option has been used in which case the output
   gets send inline using regular data lines.  The options "--armor"
   and "--base" ospecify an output format if "--data" has been used.
   Recall that in general the output format is set with the OUTPUT
   command.
 */
static gpg_error_t
cmd_export (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}



/*  DELKEYS

    Fixme
*/
static gpg_error_t
cmd_delkeys (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}



/*  MESSAGE FD[=<n>]

   Set the file descriptor to read a message which is used with
   detached signatures.  */
static gpg_error_t
cmd_message (assuan_context_t ctx, char *line)
{
  int rc;
  gnupg_fd_t fd;
  ctrl_t ctrl = assuan_get_pointer (ctx);

  rc = assuan_command_parse_fd (ctx, line, &fd);
  if (rc)
    return rc;
  if (fd == GNUPG_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);
  ctrl->server_local->message_fd = fd;
  return 0;
}



/* LISTKEYS [<patterns>]
   LISTSECRETKEYS [<patterns>]

   fixme
*/
static gpg_error_t
do_listkeys (assuan_context_t ctx, char *line, int mode)
{
  (void)ctx;
  (void)line;
  (void)mode;

  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}


static gpg_error_t
cmd_listkeys (assuan_context_t ctx, char *line)
{
  return do_listkeys (ctx, line, 3);
}


static gpg_error_t
cmd_listsecretkeys (assuan_context_t ctx, char *line)
{
  return do_listkeys (ctx, line, 2);
}



/* GENKEY

   Read the parameters in native format from the input fd and create a
   new OpenPGP key.
 */
static gpg_error_t
cmd_genkey (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}


/* GETINFO <what>

   Multipurpose function to return a variety of information.
   Supported values for WHAT are:

     version     - Return the version of the program.
     pid         - Return the process id of the server.

 */
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  int rc;

  if (!strcmp (line, "version"))
    {
      const char *s = VERSION;
      rc = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else
    rc = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");
  return rc;
}

static const char hlp_passwd[] =
  "PASSWD <userID>\n"
  "\n"
  "Change the passphrase of the secret key for USERID.";
static gpg_error_t
cmd_passwd (assuan_context_t ctx, char *line)
{
  /* ctrl_t ctrl = assuan_get_pointer (ctx); */
  gpg_error_t err;

  (void)ctx;
  (void)line;
  /* line = skip_options (line); */

  err = gpg_error (GPG_ERR_NOT_SUPPORTED);

  return err;
}




/* Helper to register our commands with libassuan. */
static int
register_commands (assuan_context_t ctx)
{
  static struct
  {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    { "RECIPIENT",     cmd_recipient },
    { "SIGNER",        cmd_signer    },
    { "ENCRYPT",       cmd_encrypt   },
    { "DECRYPT",       cmd_decrypt   },
    { "VERIFY",        cmd_verify    },
    { "SIGN",          cmd_sign      },
    { "IMPORT",        cmd_import    },
    { "EXPORT",        cmd_export    },
    { "INPUT",         NULL          },
    { "OUTPUT",        NULL          },
    { "MESSAGE",       cmd_message   },
    { "LISTKEYS",      cmd_listkeys  },
    { "LISTSECRETKEYS",cmd_listsecretkeys },
    { "GENKEY",        cmd_genkey    },
    { "DELKEYS",       cmd_delkeys   },
    { "GETINFO",       cmd_getinfo   },
    { "PASSWD",        cmd_passwd,  hlp_passwd},
    { NULL }
  };
  int i, rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name,
                                    table[i].handler, table[i].help);
      if (rc)
        return rc;
    }
  return 0;
}




/* Startup the server.  CTRL must have been allocated by the caller
   and set to the default values. */
int
gpg_server (ctrl_t ctrl)
{
  int rc;
#ifndef HAVE_W32_SYSTEM
  int filedes[2];
#endif
  assuan_context_t ctx = NULL;
  static const char hello[] = ("GNU Privacy Guard's OpenPGP server "
                               VERSION " ready");

  /* We use a pipe based server so that we can work from scripts.
     assuan_init_pipe_server will automagically detect when we are
     called with a socketpair and ignore FILEDES in this case.  */
#ifndef HAVE_W32_SYSTEM
  filedes[0] = assuan_fdopen (0);
  filedes[1] = assuan_fdopen (1);
#endif
  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("failed to allocate the assuan context: %s\n",
		 gpg_strerror (rc));
      goto leave;
    }

#ifdef HAVE_W32_SYSTEM
  rc = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#else
  rc = assuan_init_pipe_server (ctx, filedes);
#endif
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n", gpg_strerror (rc));
      goto leave;
    }

  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to the register commands with Assuan: %s\n",
                 gpg_strerror(rc));
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
                          "fixme: need config filename",
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
  assuan_register_input_notify (ctx, input_notify);
  assuan_register_output_notify (ctx, output_notify);
  assuan_register_option_handler (ctx, option_handler);

  ctrl->server_local = xtrycalloc (1, sizeof *ctrl->server_local);
  if (!ctrl->server_local)
    {
      rc = gpg_error_from_syserror ();
      goto leave;
    }
  ctrl->server_local->assuan_ctx = ctx;
  ctrl->server_local->message_fd = GNUPG_INVALID_FD;

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        {
          rc = 0;
          break;
        }
      else if (rc)
        {
          log_info ("Assuan accept problem: %s\n", gpg_strerror (rc));
          break;
        }

      rc = assuan_process (ctx);
      if (rc)
        {
          log_info ("Assuan processing failed: %s\n", gpg_strerror (rc));
          continue;
        }
    }

 leave:
  if (ctrl->server_local)
    {
      release_pk_list (ctrl->server_local->recplist);

      xfree (ctrl->server_local);
      ctrl->server_local = NULL;
    }
  assuan_release (ctx);
  return rc;
}


/* Helper to notify the client about Pinentry events.  Because that
   might disturb some older clients, this is only done when enabled
   via an option.  If it is not enabled we tell Windows to allow
   setting the foreground window right here.  Returns an gpg error
   code. */
gpg_error_t
gpg_proxy_pinentry_notify (ctrl_t ctrl, const unsigned char *line)
{
  const char *s;

  if (opt.verbose
      && !strncmp (line, "PINENTRY_LAUNCHED", 17)
      && (line[17]==' '||!line[17]))
    {
      for (s = line + 17; *s && spacep (s); s++)
        ;
      log_info (_("pinentry launched (%s)\n"), s);
    }

  if (!ctrl || !ctrl->server_local
      || !ctrl->server_local->allow_pinentry_notify)
    {
      gnupg_allow_set_foregound_window ((pid_t)strtoul (line+17, NULL, 10));
      /* Client might be interested in that event - send as status line.  */
      if (!strncmp (line, "PINENTRY_LAUNCHED", 17)
          && (line[17]==' '||!line[17]))
        {
          for (line += 17; *line && spacep (line); line++)
            ;
          write_status_text (STATUS_PINENTRY_LAUNCHED, line);
        }
      return 0;
    }
  return assuan_inquire (ctrl->server_local->assuan_ctx, line, NULL, NULL, 0);
}

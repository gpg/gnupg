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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#include "util.h"
#include "i18n.h"
#include "options.h"
#include "../common/sysutils.h"


#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))


/* Data used to associate an Assuan context with local server data.  */
struct server_local_s 
{
  /* Our current Assuan context. */
  assuan_context_t assuan_ctx;  
  /* File descriptor as set by the MESSAGE command. */
  gnupg_fd_t message_fd;               
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
/*   ctrl_t ctrl = assuan_get_pointer (ctx); */

  (void)ctx;
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




/*  RECIPIENT <userID>

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
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
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
   are *not* reset by an SIGN command becuase it can be expected that
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
   INPUT command, writes to the ciphertext to the file descriptor set
   with the OUTPUT command, take the recipients form all the
   recipients set so far.  If this command fails the clients should
   try to delete all output currently done or otherwise mark it as
   invalid.  GPG does ensure that there won't be any security problem
   with leftover data on the output in this case.

   This command should in general not fail, as all necessary checks
   have been done while setting the recipients.  The input and output
   pipes are closed.  */
static gpg_error_t
cmd_encrypt (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
}



/*  DECRYPT

   This performs the decrypt operation after doing some checks on the
   internal state (e.g. that only needed data has been set).   */
static gpg_error_t
cmd_decrypt (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
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
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gnupg_fd_t fd = assuan_get_input_fd (ctx);
  gnupg_fd_t out_fd = assuan_get_output_fd (ctx);
  FILE *out_fp = NULL;

  (void)line;

  if (fd == GNUPG_INVALID_FD)
    return gpg_error (GPG_ERR_ASS_NO_INPUT);

  if (out_fd != GNUPG_INVALID_FD)
    {
      out_fp = fdopen ( dup (FD2INT (out_fd)), "w");
      if (!out_fp)
        return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");
    }

  log_debug ("WARNING: The server mode work "
             "in progress and not ready for use\n");

  /* Need to dup it because it might get closed and libassuan won't
     know about it then. */
  rc = gpg_verify (ctrl,
                   dup ( FD2INT (fd)), 
                   dup ( FD2INT (ctrl->server_local->message_fd)),
                   out_fp);

  if (out_fp)
    fclose (out_fp);
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

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



/* Helper to register our commands with libassuan. */
static int
register_commands (assuan_context_t ctx)
{
  static struct 
  {
    const char *name;
    assuan_handler_t handler;
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
    { NULL }
  };
  int i, rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler, NULL);
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
  int filedes[2];
  assuan_context_t ctx = NULL;
  static const char hello[] = ("GNU Privacy Guard's OpenPGP server "
                               VERSION " ready");

  /* We use a pipe based server so that we can work from scripts.
     assuan_init_pipe_server will automagically detect when we are
     called with a socketpair and ignore FILEDES in this case.  */
  filedes[0] = assuan_fdopen (0);
  filedes[1] = assuan_fdopen (1);
  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("failed to allocate the assuan context: %s\n",
		 gpg_strerror (rc));
      goto leave;
    }
  
  rc = assuan_init_pipe_server (ctx, filedes);
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
      char *tmp = NULL;
      const char *s1 = getenv ("GPG_AGENT_INFO");

      if (asprintf (&tmp,
                    "Home: %s\n"
                    "Config: %s\n"
                    "AgentInfo: %s\n"
                    "%s",
                    opt.homedir,
                    "fixme: need config filename",
                    s1?s1:"[not set]",
                    hello) > 0)
        {
          assuan_set_hello_line (ctx, tmp);
          free (tmp);
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

  if (DBG_ASSUAN)
    assuan_set_log_stream (ctx, log_get_stream ());

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
  xfree (ctrl->server_local);
  ctrl->server_local = NULL;
  assuan_release (ctx);
  return rc;
}


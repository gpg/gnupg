/* server.c - Server mode and main entry point 
 * Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>

#include <assuan.h>

#include "gpgsm.h"

#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))


/* The filepointer for status message used in non-server mode */
static FILE *statusfp;

/* Data used to assuciate an Assuan context with local server data */
struct server_local_s {
  assuan_context_t assuan_ctx;
  int message_fd;
  int list_internal;
  int list_external;
  int list_to_output;           /* Write keylistings to the output fd. */
  certlist_t recplist;
  certlist_t signerlist;
  certlist_t default_recplist; /* As set by main() - don't release. */
};



/* Note that it is sufficient to allocate the target string D as
   long as the source string S, i.e.: strlen(s)+1; */
static void
strcpy_escaped_plus (char *d, const char *s)
{
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d++ = xtoi_2 (s);
          s += 2;
        }
      else if (*s == '+')
        *d++ = ' ', s++;
      else
        *d++ = *s++;
    }
  *d = 0; 
}




/* Check whether the option NAME appears in LINE */
static int
has_option (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n)));
}


static void 
close_message_fd (ctrl_t ctrl)
{
  if (ctrl->server_local->message_fd != -1)
    {
      close (ctrl->server_local->message_fd);
      ctrl->server_local->message_fd = -1;
    }
}


static int
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  if (!strcmp (key, "include-certs"))
    {
      int i = *value? atoi (value) : -1;
      if (ctrl->include_certs < -2)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      ctrl->include_certs = i;
    }
  else if (!strcmp (key, "display"))
    {
      if (opt.display)
        free (opt.display);
      opt.display = strdup (value);
      if (!opt.display)
        return out_of_core ();
    }
  else if (!strcmp (key, "ttyname"))
    {
      if (opt.ttyname)
        free (opt.ttyname);
      opt.ttyname = strdup (value);
      if (!opt.ttyname)
        return out_of_core ();
    }
  else if (!strcmp (key, "ttytype"))
    {
      if (opt.ttytype)
        free (opt.ttytype);
      opt.ttytype = strdup (value);
      if (!opt.ttytype)
        return out_of_core ();
    }
  else if (!strcmp (key, "lc-ctype"))
    {
      if (opt.lc_ctype)
        free (opt.lc_ctype);
      opt.lc_ctype = strdup (value);
      if (!opt.lc_ctype)
        return out_of_core ();
    }
  else if (!strcmp (key, "lc-messages"))
    {
      if (opt.lc_messages)
        free (opt.lc_messages);
      opt.lc_messages = strdup (value);
      if (!opt.lc_messages)
        return out_of_core ();
    }
  else if (!strcmp (key, "list-mode"))
    {
      int i = *value? atoi (value) : 0;
      if (!i || i == 1) /* default and mode 1 */
        {
          ctrl->server_local->list_internal = 1;
          ctrl->server_local->list_external = 0;
        }
      else if (i == 2)
        {
          ctrl->server_local->list_internal = 0;
          ctrl->server_local->list_external = 1;
        }
      else if (i == 3)
        {
          ctrl->server_local->list_internal = 1;
          ctrl->server_local->list_external = 1;
        }
      else
        return gpg_error (GPG_ERR_ASS_PARAMETER);
    }
  else if (!strcmp (key, "list-to-output"))
    {
      int i = *value? atoi (value) : 0;
      ctrl->server_local->list_to_output = i;
    }
  else if (!strcmp (key, "with-validation"))
    {
      int i = *value? atoi (value) : 0;
      ctrl->with_validation = i;
    }
  else
    return gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return 0;
}




static void
reset_notify (assuan_context_t ctx)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  gpgsm_release_certlist (ctrl->server_local->recplist);
  gpgsm_release_certlist (ctrl->server_local->signerlist);
  ctrl->server_local->recplist = NULL;
  ctrl->server_local->signerlist = NULL;
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
}


static void
input_notify (assuan_context_t ctx, const char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  ctrl->autodetect_encoding = 0;
  ctrl->is_pem = 0;
  ctrl->is_base64 = 0;
  if (strstr (line, "--armor"))
    ctrl->is_pem = 1;  
  else if (strstr (line, "--base64"))
    ctrl->is_base64 = 1; 
  else if (strstr (line, "--binary"))
    ;
  else
    ctrl->autodetect_encoding = 1;
}

static void
output_notify (assuan_context_t ctx, const char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  ctrl->create_pem = 0;
  ctrl->create_base64 = 0;
  if (strstr (line, "--armor"))
    ctrl->create_pem = 1;  
  else if (strstr (line, "--base64"))
    ctrl->create_base64 = 1; /* just the raw output */
}



/*  RECIPIENT <userID>

  Set the recipient for the encryption.  <userID> should be the
  internal representation of the key; the server may accept any other
  way of specification [we will support this].  If this is a valid and
  trusted recipient the server does respond with OK, otherwise the
  return is an ERR with the reason why the recipient can't be used,
  the encryption will then not be done for this recipient.  If the
  policy is not to encrypt at all if not all recipients are valid, the
  client has to take care of this.  All RECIPIENT commands are
  cumulative until a RESET or an successful ENCRYPT command.  */
static int 
cmd_recipient (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;

  rc = gpgsm_add_to_certlist (ctrl, line, 0, &ctrl->server_local->recplist, 0);
  if (rc)
    {
      gpg_err_code_t r = gpg_err_code (rc);
      gpgsm_status2 (ctrl, STATUS_INV_RECP,
                   r == -1? "1":
                   r == GPG_ERR_NO_PUBKEY?       "1":
                   r == GPG_ERR_AMBIGUOUS_NAME?  "2":
                   r == GPG_ERR_WRONG_KEY_USAGE? "3":
                   r == GPG_ERR_CERT_REVOKED?    "4":
                   r == GPG_ERR_CERT_EXPIRED?    "5":
                   r == GPG_ERR_NO_CRL_KNOWN?    "6":
                   r == GPG_ERR_CRL_TOO_OLD?     "7":
                   r == GPG_ERR_NO_POLICY_MATCH? "8":
                   "0",
                   line, NULL);
    }

  return rc;
}

/*  SIGNER <userID>

  Set the signer's keys for the signature creation.  <userID> should
  be the internal representation of the key; the server may accept any
  other way of specification [we will support this].  If this is a
  valid and usable signing key the server does respond with OK,
  otherwise it returns an ERR with the reason why the key can't be
  used, the signing will then not be done for this key.  If the policy
  is not to sign at all if not all signer keys are valid, the client
  has to take care of this.  All SIGNER commands are cumulative until
  a RESET but they are *not* reset by an SIGN command becuase it can
  be expected that set of signers are used for more than one sign
  operation.  

  Note that this command returns an INV_RECP status which is a bit
  strange, but they are very similar.  */
static int 
cmd_signer (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;

  rc = gpgsm_add_to_certlist (ctrl, line, 1,
                              &ctrl->server_local->signerlist, 0);
  if (rc)
    {
      gpg_err_code_t r = gpg_err_code (rc);
      gpgsm_status2 (ctrl, STATUS_INV_RECP,
                   r == -1?                          "1":
                   r == GPG_ERR_NO_PUBKEY?           "1":
                   r == GPG_ERR_AMBIGUOUS_NAME?      "2":
                   r == GPG_ERR_WRONG_KEY_USAGE?     "3":
                   r == GPG_ERR_CERT_REVOKED?        "4":
                   r == GPG_ERR_CERT_EXPIRED?        "5":
                   r == GPG_ERR_NO_CRL_KNOWN?        "6":
                   r == GPG_ERR_CRL_TOO_OLD?         "7":
                   r == GPG_ERR_NO_POLICY_MATCH?     "8":
                   r == GPG_ERR_NO_SECKEY?           "9":
                   "0",
                  line, NULL);
    }
  return rc;
}


/* ENCRYPT 

  Do the actual encryption process. Takes the plaintext from the INPUT
  command, writes to the ciphertext to the file descriptor set with
  the OUTPUT command, take the recipients form all the recipients set
  so far.  If this command fails the clients should try to delete all
  output currently done or otherwise mark it as invalid.  GPGSM does
  ensure that there won't be any security problem with leftover data
  on the output in this case.

  This command should in general not fail, as all necessary checks
  have been done while setting the recipients.  The input and output
  pipes are closed. */
static int 
cmd_encrypt (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  certlist_t cl;
  int inp_fd, out_fd;
  FILE *out_fp;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");
  
  /* Now add all encrypt-to marked recipients from the default
     list. */
  rc = 0;
  if (!opt.no_encrypt_to)
    {
      for (cl=ctrl->server_local->default_recplist; !rc && cl; cl = cl->next)
        if (cl->is_encrypt_to)
          rc = gpgsm_add_cert_to_certlist (ctrl, cl->cert,
                                           &ctrl->server_local->recplist, 1);
    }
  if (!rc)
    rc = gpgsm_encrypt (assuan_get_pointer (ctx),
                        ctrl->server_local->recplist,
                        inp_fd, out_fp);
  fclose (out_fp);

  gpgsm_release_certlist (ctrl->server_local->recplist);
  ctrl->server_local->recplist = NULL;
  /* Close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return rc;
}

/* DECRYPT

  This performs the decrypt operation after doing some check on the
  internal state. (e.g. that only needed data has been set).  Because
  it utilizes the GPG-Agent for the session key decryption, there is
  no need to ask the client for a protecting passphrase - GpgAgent
  does take care of this by requesting this from the user. */
static int 
cmd_decrypt (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int inp_fd, out_fd;
  FILE *out_fp;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");
  rc = gpgsm_decrypt (ctrl, inp_fd, out_fp); 
  fclose (out_fp);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return rc;
}


/* VERIFY

  This does a verify operation on the message send to the input-FD.
  The result is written out using status lines.  If an output FD was
  given, the signed text will be written to that.
  
  If the signature is a detached one, the server will inquire about
  the signed material and the client must provide it.
  */
static int 
cmd_verify (assuan_context_t ctx, char *line)
{
  int rc;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int fd = assuan_get_input_fd (ctx);
  int out_fd = assuan_get_output_fd (ctx);
  FILE *out_fp = NULL;

  if (fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);

  if (out_fd != -1)
    {
      out_fp = fdopen ( dup(out_fd), "w");
      if (!out_fp)
        return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");
    }

  rc = gpgsm_verify (assuan_get_pointer (ctx), fd,
                     ctrl->server_local->message_fd, out_fp);
  if (out_fp)
    fclose (out_fp);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return rc;
}


/* SIGN [--detached]

  Sign the data set with the INPUT command and write it to the sink
  set by OUTPUT.  With "--detached" specified, a detached signature is
  created (surprise).  */
static int 
cmd_sign (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int inp_fd, out_fd;
  FILE *out_fp;
  int detached;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);

  detached = has_option (line, "--detached"); 

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");

  rc = gpgsm_sign (assuan_get_pointer (ctx), ctrl->server_local->signerlist,
                   inp_fd, detached, out_fp);
  fclose (out_fp);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return rc;
}


/* IMPORT

  Import the certificates read form the input-fd, return status
  message for each imported one.  The import checks the validity of
  the certificate but not of the entire chain.  It is possible to
  import expired certificates.  */
static int 
cmd_import (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  int fd = assuan_get_input_fd (ctx);

  if (fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);

  rc = gpgsm_import (assuan_get_pointer (ctx), fd);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return rc;
}


static int 
cmd_export (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int fd = assuan_get_output_fd (ctx);
  FILE *out_fp;
  char *p;
  STRLIST list, sl;

  if (fd == -1)
    return set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);
  
  /* break the line down into an STRLIST */
  list = NULL;
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              free_strlist (list);
              return out_of_core ();
            }
          sl->flags = 0;
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  out_fp = fdopen ( dup(fd), "w");
  if (!out_fp)
    {
      free_strlist (list);
      return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");
    }

  gpgsm_export (ctrl, list, out_fp);
  fclose (out_fp);
  free_strlist (list);
  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return 0;
}


static int 
cmd_delkeys (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  char *p;
  STRLIST list, sl;
  int rc;

  /* break the line down into an STRLIST */
  list = NULL;
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              free_strlist (list);
              return out_of_core ();
            }
          sl->flags = 0;
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  rc = gpgsm_delete (ctrl, list);
  free_strlist (list);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return rc;
}



/* MESSAGE FD=<n>

   Set the file descriptor to read a message which is used with
   detached signatures */
static int 
cmd_message (assuan_context_t ctx, char *line)
{
  int rc;
  int fd;
  ctrl_t ctrl = assuan_get_pointer (ctx);

  rc = assuan_command_parse_fd (ctx, line, &fd);
  if (rc)
    return rc;
  if (fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);
  ctrl->server_local->message_fd = fd;
  return 0;
}

/* LISTKEYS [<patterns>]
   LISTSECRETKEYS [<patterns>]
*/
static int 
do_listkeys (assuan_context_t ctx, char *line, int mode)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  FILE *fp;
  char *p;
  STRLIST list, sl;
  unsigned int listmode;
  gpg_error_t err;

  /* Break the line down into an STRLIST. */
  list = NULL;
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              free_strlist (list);
              return out_of_core ();
            }
          sl->flags = 0;
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  if (ctrl->server_local->list_to_output)
    {
      if ( assuan_get_output_fd (ctx) == -1 )
        return set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);
      fp = fdopen (assuan_get_output_fd (ctx), "w");
      if (!fp)
        return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");
    }
  else
    {
      fp = assuan_get_data_fp (ctx);
      if (!fp)
        return set_error (GPG_ERR_ASS_GENERAL, "no data stream");
    }
  
  ctrl->with_colons = 1;
  listmode = mode; 
  if (ctrl->server_local->list_internal)
    listmode |= (1<<6);
  if (ctrl->server_local->list_external)
    listmode |= (1<<7);
  err = gpgsm_list_keys (assuan_get_pointer (ctx), list, fp, listmode);
  free_strlist (list);
  if (ctrl->server_local->list_to_output)
    {
      fclose (fp);
      assuan_close_output_fd (ctx);
    }
  return err;
}

static int 
cmd_listkeys (assuan_context_t ctx, char *line)
{
  return do_listkeys (ctx, line, 3);
}

static int 
cmd_listsecretkeys (assuan_context_t ctx, char *line)
{
  return do_listkeys (ctx, line, 2);
}


/* GENKEY

   Read the parameters in native format from the input fd and write a
   certificate request to the output.
 */
static int 
cmd_genkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int inp_fd, out_fd;
  FILE *out_fp;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (GPG_ERR_ASS_NO_INPUT, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (GPG_ERR_ASS_NO_OUTPUT, NULL);

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (GPG_ERR_ASS_GENERAL, "fdopen() failed");
  rc = gpgsm_genkey (ctrl, inp_fd, out_fp);
  fclose (out_fp);

  /* close and reset the fds */
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return rc;
}





/* Tell the assuan library about our commands */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    int (*handler)(assuan_context_t, char *line);
  } table[] = {
    { "RECIPIENT",     cmd_recipient },
    { "SIGNER",        cmd_signer },
    { "ENCRYPT",       cmd_encrypt },
    { "DECRYPT",       cmd_decrypt },
    { "VERIFY",        cmd_verify },
    { "SIGN",          cmd_sign },
    { "IMPORT",        cmd_import },
    { "EXPORT",        cmd_export },
    { "INPUT",         NULL }, 
    { "OUTPUT",        NULL }, 
    { "MESSAGE",       cmd_message },
    { "LISTKEYS",      cmd_listkeys },
    { "LISTSECRETKEYS",cmd_listsecretkeys },
    { "GENKEY",        cmd_genkey },
    { "DELKEYS",       cmd_delkeys },
    { NULL }
  };
  int i, rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler);
      if (rc)
        return rc;
    } 
  return 0;
}

/* Startup the server. DEFAULT_RECPLIST is the list of recipients as
   set from the command line or config file.  We only require those
   marked as encrypt-to. */
void
gpgsm_server (certlist_t default_recplist)
{
  int rc;
  int filedes[2];
  assuan_context_t ctx;
  struct server_control_s ctrl;
  static const char hello[] = ("GNU Privacy Guard's S/M server "
                               VERSION " ready");

  memset (&ctrl, 0, sizeof ctrl);
  gpgsm_init_default_ctrl (&ctrl);

  /* We use a pipe based server so that we can work from scripts.
     assuan_init_pipe_server will automagically detect when we are
     called with a socketpair and ignore FIELDES in this case. */
  filedes[0] = 0;
  filedes[1] = 1;
  rc = assuan_init_pipe_server (&ctx, filedes);
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 gpg_strerror (rc));
      gpgsm_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to the register commands with Assuan: %s\n",
                 gpg_strerror(rc));
      gpgsm_exit (2);
    }
  if (opt.verbose || opt.debug)
    {
      char *tmp = NULL;
      const char *s1 = getenv ("GPG_AGENT_INFO");
      const char *s2 = getenv ("DIRMNGR_INFO");

      if (asprintf (&tmp,
                    "Home: %s\n"
                    "Config: %s\n"
                    "AgentInfo: %s\n"
                    "DirmngrInfo: %s\n"
                    "%s",
                    opt.homedir,
                    opt.config_filename,
                    s1?s1:"[not set]",
                    s2?s2:"[not set]",
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

  assuan_set_pointer (ctx, &ctrl);
  ctrl.server_local = xcalloc (1, sizeof *ctrl.server_local);
  ctrl.server_local->assuan_ctx = ctx;
  ctrl.server_local->message_fd = -1;
  ctrl.server_local->list_internal = 1;
  ctrl.server_local->list_external = 0;
  ctrl.server_local->default_recplist = default_recplist;

  if (DBG_ASSUAN)
    assuan_set_log_stream (ctx, log_get_stream ());

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        {
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

  gpgsm_release_certlist (ctrl.server_local->recplist);
  ctrl.server_local->recplist = NULL;
  gpgsm_release_certlist (ctrl.server_local->signerlist);
  ctrl.server_local->signerlist = NULL;

  assuan_deinit_server (ctx);
}


static const char *
get_status_string ( int no ) 
{
  const char *s;

  switch (no)
    {
    case STATUS_ENTER  : s = "ENTER"; break;
    case STATUS_LEAVE  : s = "LEAVE"; break;
    case STATUS_ABORT  : s = "ABORT"; break;
    case STATUS_NEWSIG : s = "NEWSIG"; break;
    case STATUS_GOODSIG: s = "GOODSIG"; break;
    case STATUS_SIGEXPIRED: s = "SIGEXPIRED"; break;
    case STATUS_KEYREVOKED: s = "KEYREVOKED"; break;
    case STATUS_BADSIG : s = "BADSIG"; break;
    case STATUS_ERRSIG : s = "ERRSIG"; break;
    case STATUS_BADARMOR : s = "BADARMOR"; break;
    case STATUS_RSA_OR_IDEA : s= "RSA_OR_IDEA"; break;
    case STATUS_TRUST_UNDEFINED: s = "TRUST_UNDEFINED"; break;
    case STATUS_TRUST_NEVER	 : s = "TRUST_NEVER"; break;
    case STATUS_TRUST_MARGINAL : s = "TRUST_MARGINAL"; break;
    case STATUS_TRUST_FULLY	 : s = "TRUST_FULLY"; break;
    case STATUS_TRUST_ULTIMATE : s = "TRUST_ULTIMATE"; break;
    case STATUS_GET_BOOL	 : s = "GET_BOOL"; break;
    case STATUS_GET_LINE	 : s = "GET_LINE"; break;
    case STATUS_GET_HIDDEN	 : s = "GET_HIDDEN"; break;
    case STATUS_GOT_IT	 : s = "GOT_IT"; break;
    case STATUS_SHM_INFO	 : s = "SHM_INFO"; break;
    case STATUS_SHM_GET	 : s = "SHM_GET"; break;
    case STATUS_SHM_GET_BOOL	 : s = "SHM_GET_BOOL"; break;
    case STATUS_SHM_GET_HIDDEN : s = "SHM_GET_HIDDEN"; break;
    case STATUS_NEED_PASSPHRASE: s = "NEED_PASSPHRASE"; break;
    case STATUS_VALIDSIG	 : s = "VALIDSIG"; break;
    case STATUS_SIG_ID	 : s = "SIG_ID"; break;
    case STATUS_ENC_TO	 : s = "ENC_TO"; break;
    case STATUS_NODATA	 : s = "NODATA"; break;
    case STATUS_BAD_PASSPHRASE : s = "BAD_PASSPHRASE"; break;
    case STATUS_NO_PUBKEY	 : s = "NO_PUBKEY"; break;
    case STATUS_NO_SECKEY	 : s = "NO_SECKEY"; break;
    case STATUS_NEED_PASSPHRASE_SYM: s = "NEED_PASSPHRASE_SYM"; break;
    case STATUS_DECRYPTION_FAILED: s = "DECRYPTION_FAILED"; break;
    case STATUS_DECRYPTION_OKAY: s = "DECRYPTION_OKAY"; break;
    case STATUS_MISSING_PASSPHRASE: s = "MISSING_PASSPHRASE"; break;
    case STATUS_GOOD_PASSPHRASE : s = "GOOD_PASSPHRASE"; break;
    case STATUS_GOODMDC	 : s = "GOODMDC"; break;
    case STATUS_BADMDC	 : s = "BADMDC"; break;
    case STATUS_ERRMDC	 : s = "ERRMDC"; break;
    case STATUS_IMPORTED	 : s = "IMPORTED"; break;
    case STATUS_IMPORT_OK        : s = "IMPORT_OK"; break;
    case STATUS_IMPORT_RES	 : s = "IMPORT_RES"; break;
    case STATUS_FILE_START	 : s = "FILE_START"; break;
    case STATUS_FILE_DONE	 : s = "FILE_DONE"; break;
    case STATUS_FILE_ERROR	 : s = "FILE_ERROR"; break;
    case STATUS_BEGIN_DECRYPTION:s = "BEGIN_DECRYPTION"; break;
    case STATUS_END_DECRYPTION : s = "END_DECRYPTION"; break;
    case STATUS_BEGIN_ENCRYPTION:s = "BEGIN_ENCRYPTION"; break;
    case STATUS_END_ENCRYPTION : s = "END_ENCRYPTION"; break;
    case STATUS_DELETE_PROBLEM : s = "DELETE_PROBLEM"; break;
    case STATUS_PROGRESS	 : s = "PROGRESS"; break;
    case STATUS_SIG_CREATED	 : s = "SIG_CREATED"; break;
    case STATUS_SESSION_KEY	 : s = "SESSION_KEY"; break;
    case STATUS_NOTATION_NAME  : s = "NOTATION_NAME" ; break;
    case STATUS_NOTATION_DATA  : s = "NOTATION_DATA" ; break;
    case STATUS_POLICY_URL     : s = "POLICY_URL" ; break;
    case STATUS_BEGIN_STREAM   : s = "BEGIN_STREAM"; break;
    case STATUS_END_STREAM     : s = "END_STREAM"; break;
    case STATUS_KEY_CREATED    : s = "KEY_CREATED"; break;
    case STATUS_UNEXPECTED     : s = "UNEXPECTED"; break;
    case STATUS_INV_RECP       : s = "INV_RECP"; break;
    case STATUS_NO_RECP        : s = "NO_RECP"; break;
    case STATUS_ALREADY_SIGNED : s = "ALREADY_SIGNED"; break;
    case STATUS_EXPSIG         : s = "EXPSIG"; break;
    case STATUS_EXPKEYSIG      : s = "EXPKEYSIG"; break;
    case STATUS_TRUNCATED      : s = "TRUNCATED"; break;
    case STATUS_ERROR          : s = "ERROR"; break;
    case STATUS_IMPORT_PROBLEM : s = "IMPORT_PROBLEM"; break;
    default: s = "?"; break;
    }
  return s;
}


gpg_error_t
gpgsm_status2 (ctrl_t ctrl, int no, ...)
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
      assuan_context_t ctx = ctrl->server_local->assuan_ctx;
      char buf[950], *p;
      size_t n;

      p = buf; 
      n = 0;
      while ( (text = va_arg (arg_ptr, const char *)) )
        {
          if (n)
            {
              *p++ = ' ';
              n++;
            }
          for ( ; *text && n < DIM (buf)-2; n++)
            *p++ = *text++;
        }
      *p = 0;
      err = assuan_write_status (ctx, get_status_string (no), buf);
    }

  va_end (arg_ptr);
  return err;
}

gpg_error_t
gpgsm_status (ctrl_t ctrl, int no, const char *text)
{
  return gpgsm_status2 (ctrl, no, text, NULL);
}

gpg_error_t
gpgsm_status_with_err_code (ctrl_t ctrl, int no, const char *text,
                            gpg_err_code_t ec)
{
  char buf[30];

  sprintf (buf, "%u", (unsigned int)ec);
  if (text)
    return gpgsm_status2 (ctrl, no, text, buf, NULL);
  else
    return gpgsm_status2 (ctrl, no, buf, NULL);
}

#if 0
/*
 * Write a status line with a buffer using %XX escapes.  If WRAP is >
 * 0 wrap the line after this length.  If STRING is not NULL it will
 * be prepended to the buffer, no escaping is done for string.
 * A wrap of -1 forces spaces not to be encoded as %20.
 */
void
write_status_text_and_buffer ( int no, const char *string,
                               const char *buffer, size_t len, int wrap )
{
    const char *s, *text;
    int esc, first;
    int lower_limit = ' ';
    size_t n, count, dowrap;

    if( !statusfp )
	return;  /* not enabled */
    
    if (wrap == -1) {
        lower_limit--;
        wrap = 0;
    }

    text = get_status_string (no);
    count = dowrap = first = 1;
    do {
        if (dowrap) {
            fprintf (statusfp, "[GNUPG:] %s ", text );
            count = dowrap = 0;
            if (first && string) {
                fputs (string, statusfp);
                count += strlen (string);
            }
            first = 0;
        }
        for (esc=0, s=buffer, n=len; n && !esc; s++, n-- ) {
            if ( *s == '%' || *(const byte*)s <= lower_limit 
                           || *(const byte*)s == 127 ) 
                esc = 1;
            if ( wrap && ++count > wrap ) {
                dowrap=1;
                break;
            }
        }
        if (esc) {
            s--; n++;
        }
        if (s != buffer) 
            fwrite (buffer, s-buffer, 1, statusfp );
        if ( esc ) {
            fprintf (statusfp, "%%%02X", *(const unsigned char*)s );
            s++; n--;
        }
        buffer = s;
        len = n;
        if ( dowrap && len )
            putc ( '\n', statusfp );
    } while ( len );

    putc ('\n',statusfp);
    fflush (statusfp);
}
#endif

/* server.c - Server mode and main entry point 
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "gpgsm.h"
#include "../assuan/assuan.h"

#define set_error(e,t) assuan_set_error (ctx, ASSUAN_ ## e, (t))


/* The filepointer for status message used in non-server mode */
static FILE *statusfp;

/* Data used to assuciate an Assuan context with local server data */
struct server_local_s {
  ASSUAN_CONTEXT assuan_ctx;
  int message_fd;
  CERTLIST recplist;
};


static void 
close_message_fd (CTRL ctrl)
{
  if (ctrl->server_local->message_fd != -1)
    {
      close (ctrl->server_local->message_fd);
      ctrl->server_local->message_fd = -1;
    }
}


static int
option_handler (ASSUAN_CONTEXT ctx, const char *key, const char *value)
{
  CTRL ctrl = assuan_get_pointer (ctx);

  if (!strcmp (key, "include-certs"))
    {
      int i = *value? atoi (value) : -1;
      if (ctrl->include_certs < -1)
        return ASSUAN_Parameter_Error;
      ctrl->include_certs = i;
    }
  else
    return ASSUAN_Invalid_Option;

  return 0;
}




static void
reset_notify (ASSUAN_CONTEXT ctx)
{
  CTRL ctrl = assuan_get_pointer (ctx);

  gpgsm_release_certlist (ctrl->server_local->recplist);
  ctrl->server_local->recplist = NULL;
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
}


static void
input_notify (ASSUAN_CONTEXT ctx, const char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);

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
output_notify (ASSUAN_CONTEXT ctx, const char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);

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
  the encryption will then not be done for this recipient.  IF the
  policy is not to encrypt at all if not all recipients are valid, the
  client has to take care of this.  All RECIPIENT commands are
  cumulative until a RESET or an successful ENCRYPT command.  */
static int 
cmd_recipient (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;

  rc = gpgsm_add_to_certlist (line, &ctrl->server_local->recplist);

  return map_to_assuan_status (rc);
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
cmd_encrypt (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int inp_fd, out_fd;
  FILE *out_fp;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (No_Input, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (No_Output, NULL);

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (General_Error, "fdopen() failed");
  rc = gpgsm_encrypt (assuan_get_pointer (ctx),
                      ctrl->server_local->recplist,
                      inp_fd, out_fp);
  fclose (out_fp);

  gpgsm_release_certlist (ctrl->server_local->recplist);
  ctrl->server_local->recplist = NULL;
  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return map_to_assuan_status (rc);
}

/* DECRYPT

  This performs the decrypt operation after doing some check on the
  internal state. (e.g. that only needed data has been set).  Because
  it utilizes the GPG-Agent for the session key decryption, there is
  no need to ask the client for a protecting passphrase - GpgAgent
  does take care of this by requesting this from the user. */
static int 
cmd_decrypt (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int inp_fd, out_fd;
  FILE *out_fp;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (No_Input, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (No_Output, NULL);

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (General_Error, "fdopen() failed");
  rc = gpgsm_decrypt (ctrl, inp_fd, out_fp); 
  fclose (out_fp);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return map_to_assuan_status (rc);
}


/* VERIFY

  This does a verify operation on the message send to the input-FD.
  The result is written out using status lines.  If an output FD was
  given, the signed text will be written to that.
  
  If the signature is a detached one, the server will inquire about
  the signed material and the client must provide it.
  */
static int 
cmd_verify (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  CTRL ctrl = assuan_get_pointer (ctx);
  int fd = assuan_get_input_fd (ctx);
  int out_fd = assuan_get_output_fd (ctx);
  FILE *out_fp = NULL;

  if (fd == -1)
    return set_error (No_Input, NULL);

  if (out_fd != -1)
    {
      out_fp = fdopen ( dup(out_fd), "w");
      if (!out_fp)
        return set_error (General_Error, "fdopen() failed");
    }

  rc = gpgsm_verify (assuan_get_pointer (ctx), fd,
                     ctrl->server_local->message_fd, out_fp);
  if (out_fp)
    fclose (out_fp);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return map_to_assuan_status (rc);
}


/* SIGN [--detached]

  Sign the data set with the INPUT command and write it to the sink
  set by OUTPUT.  With "--detached" specified, a detached signature is
  created (surprise).  */
static int 
cmd_sign (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int inp_fd, out_fd;
  FILE *out_fp;
  int detached;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (No_Input, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (No_Output, NULL);

  detached = !!strstr (line, "--detached");  /* fixme: this is ambiguous */

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (General_Error, "fdopen() failed");
  rc = gpgsm_sign (assuan_get_pointer (ctx), inp_fd, detached, out_fp);
  fclose (out_fp);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return map_to_assuan_status (rc);
}


/* IMPORT

  Import the certificates read form the input-fd, return status
  message for each imported one.  The import checks the validity of
  the certificate but not of the path.  It is possible to import
  expired certificates.  */
static int 
cmd_import (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;
  int fd = assuan_get_input_fd (ctx);

  if (fd == -1)
    return set_error (No_Input, NULL);

  rc = gpgsm_import (assuan_get_pointer (ctx), fd);

  /* close and reset the fd */
  close_message_fd (ctrl);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return map_to_assuan_status (rc);
}

/* MESSAGE FD=<n>

   Set the file descriptor to read a message which is used with
   detached signatures */
static int 
cmd_message (ASSUAN_CONTEXT ctx, char *line)
{
  char *endp;
  int fd;
  CTRL ctrl = assuan_get_pointer (ctx);

  if (strncmp (line, "FD=", 3))
    return set_error (Syntax_Error, "FD=<n> expected");
  line += 3;
  if (!digitp (line))
    return set_error (Syntax_Error, "number required");
  fd = strtoul (line, &endp, 10);
  if (*endp)
    return set_error (Syntax_Error, "garbage found");
  if (fd == -1)
    return set_error (No_Input, NULL);

  ctrl->server_local->message_fd = fd;
  return 0;
}

static int 
cmd_listkeys (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);

  ctrl->with_colons = 1;
  /* fixme: check that the returned data_fp is not NULL */
  gpgsm_list_keys (assuan_get_pointer (ctx), NULL,
                        assuan_get_data_fp (ctx), 3);

  return 0;
}

static int 
cmd_listsecretkeys (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);

  ctrl->with_colons = 1;
  /* fixme: check that the returned data_fp is not NULL */
  gpgsm_list_keys (assuan_get_pointer (ctx), NULL,
                        assuan_get_data_fp (ctx), 2);

  return 0;
}


/* GENKEY

   Read the parameters in native format from the input fd and write a
   certificate request to the output.
 */
static int 
cmd_genkey (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int inp_fd, out_fd;
  FILE *out_fp;
  int rc;

  inp_fd = assuan_get_input_fd (ctx);
  if (inp_fd == -1)
    return set_error (No_Input, NULL);
  out_fd = assuan_get_output_fd (ctx);
  if (out_fd == -1)
    return set_error (No_Output, NULL);

  out_fp = fdopen ( dup(out_fd), "w");
  if (!out_fp)
    return set_error (General_Error, "fdopen() failed");
  rc = gpgsm_genkey (ctrl, inp_fd, out_fp);
  fclose (out_fp);

  /* close and reset the fds */
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);

  return map_to_assuan_status (rc);
}





/* Tell the assuan library about our commands */
static int
register_commands (ASSUAN_CONTEXT ctx)
{
  static struct {
    const char *name;
    int cmd_id;
    int (*handler)(ASSUAN_CONTEXT, char *line);
  } table[] = {
    { "RECIPIENT",  0,  cmd_recipient },
    { "ENCRYPT",    0,  cmd_encrypt },
    { "DECRYPT",    0,  cmd_decrypt },
    { "VERIFY",     0,  cmd_verify },
    { "SIGN",       0,  cmd_sign },
    { "IMPORT",     0,  cmd_import },
    { "",     ASSUAN_CMD_INPUT, NULL }, 
    { "",     ASSUAN_CMD_OUTPUT, NULL }, 
    { "MESSAGE",    0,  cmd_message },
    { "LISTKEYS",   0,  cmd_listkeys },
    { "LISTSECRETKEYS",  0,  cmd_listsecretkeys },
    { "GENKEY",     0,  cmd_genkey },
    { NULL }
  };
  int i, j, rc;

  for (i=j=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx,
                                    table[i].cmd_id? table[i].cmd_id
                                                   : (ASSUAN_CMD_USER + j++),
                                    table[i].name, table[i].handler);
      if (rc)
        return rc;
    } 
  return 0;
}

/* Startup the server */
void
gpgsm_server (void)
{
  int rc;
  int filedes[2];
  ASSUAN_CONTEXT ctx;
  struct server_control_s ctrl;

  memset (&ctrl, 0, sizeof ctrl);
  gpgsm_init_default_ctrl (&ctrl);

  /* For now we use a simple pipe based server so that we can work
     from scripts.  We will later add options to run as a daemon and
     wait for requests on a Unix domain socket */
  filedes[0] = 0;
  filedes[1] = 1;
  rc = assuan_init_pipe_server (&ctx, filedes);
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 assuan_strerror(rc));
      gpgsm_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to the register commands with Assuan: %s\n",
                 assuan_strerror(rc));
      gpgsm_exit (2);
    }
  assuan_set_hello_line (ctx, "GNU Privacy Guard's S/M server ready");

  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_input_notify (ctx, input_notify);
  assuan_register_output_notify (ctx, output_notify);
  assuan_register_option_handler (ctx, option_handler);

  assuan_set_pointer (ctx, &ctrl);
  ctrl.server_local = xcalloc (1, sizeof *ctrl.server_local);
  ctrl.server_local->assuan_ctx = ctx;
  ctrl.server_local->message_fd = -1;

  if (DBG_AGENT)
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
          log_info ("Assuan accept problem: %s\n", assuan_strerror (rc));
          break;
        }
      
      rc = assuan_process (ctx);
      if (rc)
        {
          log_info ("Assuan processing failed: %s\n", assuan_strerror (rc));
          continue;
        }
    }

  gpgsm_release_certlist (ctrl.server_local->recplist);
  ctrl.server_local->recplist = NULL;

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
    default: s = "?"; break;
    }
  return s;
}



void
gpgsm_status (CTRL ctrl, int no, const char *text)
{
  if (ctrl->no_server)
    {
      if (ctrl->status_fd == -1)
        return; /* no status wanted */
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
    
      if (text)
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
      ASSUAN_CONTEXT ctx = ctrl->server_local->assuan_ctx;

      assuan_write_status (ctx, get_status_string (no), text);
    }
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
            fprintf (statusfp, "%%%02X", *(const byte*)s );
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








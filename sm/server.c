/* server.c - Server mode and main entry point 
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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


/*  RECIPIENT <userID>

  Set the recipient for the encryption.  <userID> should be the
  internal representation of the key; the server may accept any other
  way of specification [we will support this].  If this is a valid and
  trusted recipient the server does respond with OK, otherwise the
  return is an ERR with the reason why the recipient can't be used,
  the encryption will then not be done for this recipient.  IF the
  policy is not to encrypt at all if not all recipients are valid, the
  client has to take care of this.  All RECIPIENT commands are
  cumulative until a RESET or ENCRYPT command.  */
static int 
cmd_recipient (ASSUAN_CONTEXT ctx, char *line)
{
  

  return set_error (Not_Implemented, "fixme");
}


/* ENCRYPT [armor]

  Do the actual encryption process. Takes the plaintext from the INPUT
  command, writes to the ciphertext to the file descriptor set with
  the OUTPUT command, take the recipients form all the recipients set
  so far.  If this command fails the clients should try to delete all
  output currently done or otherwise mark it as invalid.  GPGSM does
  ensure that there won't be any security problem with leftover data
  on the output in this case.

  This command should in general not fail, as all necessary checks
  have been done while setting the recipients.  The input and output
  pipes are closed.

  The optional armor parameter may be used to request base64 encoded
  output.  */
static int 
cmd_encrypt (ASSUAN_CONTEXT ctx, char *line)
{
  

  return set_error (Not_Implemented, "fixme");
}

/* DECRYPT

  This performs the decrypt operation after doing some check on the
  internal state. (e.g. that only needed data has been set).  Because
  it utilises the GPG-Agent for the session key decryption, there is
  no need to ask the client for a protecting passphrase - GpgAgent
  does take care of this but requesting this from the user. */
static int 
cmd_decrypt (ASSUAN_CONTEXT ctx, char *line)
{
  

  return set_error (Not_Implemented, "fixme");
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
  int fd = assuan_get_input_fd (ctx);

  if (fd == -1)
    return set_error (No_Input, NULL);

  gpgsm_verify (fd);

  return 0;
}


/* SIGN

   FIXME */
static int 
cmd_sign (ASSUAN_CONTEXT ctx, char *line)
{
  

  return set_error (Not_Implemented, "fixme");
}


/* IMPORT

  Import the certificates read form the input-fd, return status
  message for each imported one.  The import checks the validity of
  the certificate but not of the path.  It is possible to import
  expired certificates.  */
static int 
cmd_import (ASSUAN_CONTEXT ctx, char *line)
{
  int fd = assuan_get_input_fd (ctx);

  if (fd == -1)
    return set_error (No_Input, NULL);

  gpgsm_import (fd);

  return 0;
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

  log_info ("Assuan started\n");
  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        {
          log_info ("Assuan terminated\n");
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


  assuan_deinit_pipe_server (ctx);
}








/* command.c - gpg-agent command handler
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

/* FIXME: we should not use the default assuan buffering but setup
   some buffering in secure mempory to protect session keys etc. */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "agent.h"
#include "../assuan/assuan.h"

/* maximum allowed size of the inquired ciphertext */
#define MAXLEN_CIPHERTEXT 4096


#define set_error(e,t) assuan_set_error (ctx, ASSUAN_ ## e, (t))


#if MAX_DIGEST_LEN < 20
#error MAX_DIGEST_LEN shorter than keygrip
#endif

/* Data used to associate an Assuan context with local server data */
struct server_local_s {
  ASSUAN_CONTEXT assuan_ctx;
  int message_fd;
};


/* Map GNUPG_xxx error codes to Assuan status codes
   FIXME: duplicated from ../sm/server.c */
static int
rc_to_assuan_status (int rc)
{
  switch (rc)
    {
    case 0: break;
    case GNUPG_Bad_Certificate:   rc = ASSUAN_Bad_Certificate; break;
    case GNUPG_Bad_Certificate_Path: rc = ASSUAN_Bad_Certificate_Path; break;
    case GNUPG_Missing_Certificate: rc = ASSUAN_Missing_Certificate; break;
    case GNUPG_No_Data:           rc = ASSUAN_No_Data_Available; break;
    case GNUPG_Bad_Signature:     rc = ASSUAN_Bad_Signature; break;
    case GNUPG_Not_Implemented:   rc = ASSUAN_Not_Implemented; break;
    case GNUPG_No_Agent:          rc = ASSUAN_No_Agent; break;
    case GNUPG_Agent_Error:       rc = ASSUAN_Agent_Error; break;
    case GNUPG_No_Public_Key:     rc = ASSUAN_No_Public_Key; break;
    case GNUPG_No_Secret_Key:     rc = ASSUAN_No_Secret_Key; break;
    case GNUPG_Invalid_Data:      rc = ASSUAN_Invalid_Data; break;

    case GNUPG_Bad_PIN:
    case GNUPG_Bad_Passphrase:
      rc = ASSUAN_No_Secret_Key;
      break;

    case GNUPG_Read_Error: 
    case GNUPG_Write_Error:
    case GNUPG_IO_Error: 
      rc = ASSUAN_Server_IO_Error;
      break;
    case GNUPG_Out_Of_Core:    
    case GNUPG_Resource_Limit: 
      rc = ASSUAN_Server_Resource_Problem;
      break;
    case GNUPG_Bug: 
    case GNUPG_Internal_Error:   
      rc = ASSUAN_Server_Bug;
      break;
    default: 
      rc = ASSUAN_Server_Fault;
      break;
    }
  return rc;
}



static void
reset_notify (ASSUAN_CONTEXT ctx)
{
  CTRL ctrl = assuan_get_pointer (ctx);

  memset (ctrl->keygrip, 0, 20);
  ctrl->have_keygrip = 0;
  ctrl->digest.valuelen = 0;
}

/* SIGKEY <hexstring_with_keygrip>
   SETKEY <hexstring_with_keygrip>
  
   Set the  key used for a sign or decrypt operation */
static int
cmd_sigkey (ASSUAN_CONTEXT ctx, char *line)
{
  int n;
  char *p;
  CTRL ctrl = assuan_get_pointer (ctx);
  unsigned char *buf;

  /* parse the hash value */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (*p)
    return set_error (Parameter_Error, "invalid hexstring");
  if ((n&1))
    return set_error (Parameter_Error, "odd number of digits");
  n /= 2;
  if (n != 20)
    return set_error (Parameter_Error, "invalid length of keygrip");

  buf = ctrl->keygrip;
  for (p=line, n=0; n < 20; p += 2, n++)
    buf[n] = xtoi_2 (p);
  ctrl->have_keygrip = 1;
  return 0;
}

/* SETHASH <algonumber> <hexstring> 

  The client can use this command to tell the server about the data
  (which usually is a hash) to be signed. */
static int
cmd_sethash (ASSUAN_CONTEXT ctx, char *line)
{
  int n;
  char *p;
  CTRL ctrl = assuan_get_pointer (ctx);
  unsigned char *buf;
  char *endp;
  int algo;

  /* parse the algo number and check it */
  algo = (int)strtoul (line, &endp, 10);
  for (line = endp; *line == ' ' || *line == '\t'; line++)
    ;
  if (!algo || gcry_md_test_algo (algo))
    return set_error (Unsupported_Algorithm, NULL);
  ctrl->digest.algo = algo;

  /* parse the hash value */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (*p)
    return set_error (Parameter_Error, "invalid hexstring");
  if ((n&1))
    return set_error (Parameter_Error, "odd number of digits");
  n /= 2;
  if (n != 16 && n != 20 && n != 24 && n != 32)
    return set_error (Parameter_Error, "unsupported length of hash");
  if (n > MAX_DIGEST_LEN)
    return set_error (Parameter_Error, "hash value to long");

  buf = ctrl->digest.value;
  ctrl->digest.valuelen = n;
  for (p=line, n=0; n < ctrl->digest.valuelen; p += 2, n++)
    buf[n] = xtoi_2 (p);
  for (; n < ctrl->digest.valuelen; n++)
    buf[n] = 0;
  return 0;
}


/* PKSIGN <options>

   Perform the actual sign operation. Neither input nor output are
   sensitive to eavesdropping */
static int
cmd_pksign (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  CTRL ctrl = assuan_get_pointer (ctx);

  rc = agent_pksign (ctrl, assuan_get_data_fp (ctx));
  return rc_to_assuan_status (rc);
}

/* PKDECRYPT <options>

   Perform the actual decrypt operation.  Input is not 
   sensitive to eavesdropping */
static int
cmd_pkdecrypt (ASSUAN_CONTEXT ctx, char *line)
{
  int rc;
  CTRL ctrl = assuan_get_pointer (ctx);
  char *value;
  size_t valuelen;

  /* First inquire the data to decrypt */
  rc = assuan_inquire (ctx, "CIPHERTEXT",
                       &value, &valuelen, MAXLEN_CIPHERTEXT);
  if (rc)
    return rc;

  rc = agent_pkdecrypt (ctrl, value, valuelen, assuan_get_data_fp (ctx));
  xfree (value);
  return rc_to_assuan_status (rc);
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
    { "SIGKEY",     0,  cmd_sigkey },
    { "SETKEY",     0,  cmd_sigkey },
    { "SETHASH",    0,  cmd_sethash },
    { "PKSIGN",     0,  cmd_pksign },
    { "PKDECRYPT",  0,  cmd_pkdecrypt },
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
  assuan_register_reset_notify (ctx, reset_notify);
  return 0;
}


/* Startup the server */
void
start_command_handler (void)
{
  int rc;
  int filedes[2];
  ASSUAN_CONTEXT ctx;
  struct server_control_s ctrl;

  memset (&ctrl, 0, sizeof ctrl);

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
      agent_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to the register commands with Assuan: %s\n",
                 assuan_strerror(rc));
      agent_exit (2);
    }

  assuan_set_pointer (ctx, &ctrl);
  ctrl.server_local = xcalloc (1, sizeof *ctrl.server_local);
  ctrl.server_local->assuan_ctx = ctx;
  ctrl.server_local->message_fd = -1;

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


  assuan_deinit_pipe_server (ctx);
}


/* command.c - SCdaemon command handler
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
#include <ksba.h>

#include "scdaemon.h"
#include "../assuan/assuan.h"

/* maximum length aloowed as a PIN; used for INQUIRE NEEDPIN */
#define MAXLEN_PIN 100

#define set_error(e,t) assuan_set_error (ctx, ASSUAN_ ## e, (t))

/* Data used to associate an Assuan context with local server data */
struct server_local_s {
  ASSUAN_CONTEXT assuan_ctx;
};


/* Check whether the option NAME appears in LINE */
static int
has_option (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n)));
}




/* Note, that this reset_notify is also used for cleanup purposes. */
static void
reset_notify (ASSUAN_CONTEXT ctx)
{
  CTRL ctrl = assuan_get_pointer (ctx); 

  if (ctrl->card_ctx)
    {
      card_close (ctrl->card_ctx);
      ctrl->card_ctx = NULL;
      xfree (ctrl->in_data.value);
      ctrl->in_data.value = NULL;
    }
}


static int
option_handler (ASSUAN_CONTEXT ctx, const char *key, const char *value)
{
  return 0;
}


/* If the card has not yet been opened, do it.  Note that this
   function returns an Assuan error, so don't map the error a second
   time */
static AssuanError
open_card (CTRL ctrl)
{
  if (!ctrl->card_ctx)
    {
      int rc = card_open (&ctrl->card_ctx);
      if (rc)
        return map_to_assuan_status (rc);
    }
  return 0;
}


/* SERIALNO 

   Return the serial number of the card using a status reponse.  This
   functon should be used to check for the presence of a card.

   This function is special in that it can be used to reset the card.
   Most other functions will return an error when a card change has
   been detected and the use of this function is therefore required.

   Background: We want to keep the client clear of handling card
   changes between operations; i.e. the client can assume that all
   operations are doneon the same card unless he call this function.
 */
static int
cmd_serialno (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  char *serial_and_stamp;
  char *serial;
  time_t stamp;

  if ((rc = open_card (ctrl)))
    return rc;

  rc = card_get_serial_and_stamp (ctrl->card_ctx, &serial, &stamp);
  if (rc)
    return map_to_assuan_status (rc);
  rc = asprintf (&serial_and_stamp, "%s %lu", serial, (unsigned long)stamp);
  xfree (serial);
  if (rc < 0)
    return ASSUAN_Out_Of_Core;
  rc = 0;
  assuan_write_status (ctx, "SERIALNO", serial_and_stamp);
  free (serial_and_stamp);
  return 0;
}




/* LEARN [--force]

   Learn all useful information of the currently inserted card.  When
   used without the force options, the command might do an INQUIRE
   like this:

      INQUIRE KNOWNCARDP <hexstring_with_serialNumber> <timestamp>

   The client should just send an "END" if the processing should go on
   or a "CANCEL" to force the function to terminate with a Cancel
   error message.  The response of this command is a list of status
   lines formatted as this:

     S KEYPAIRINFO <hexstring_with_keygrip> <hexstring_with_id>

   If there is no certificate yet stored on the card a single "X" is
   returned as the keygrip.

*/
static int
cmd_learn (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  int idx;

  if ((rc = open_card (ctrl)))
    return rc;

  /* Unless the force option is used we try a shortcut by identifying
     the card using a serial number and inquiring the client with
     that. The client may choose to cancel the operation if he already
     knows about this card */
  {
    char *serial_and_stamp;
    char *serial;
    time_t stamp;
   
    rc = card_get_serial_and_stamp (ctrl->card_ctx, &serial, &stamp);
    if (rc)
      return map_to_assuan_status (rc);
    rc = asprintf (&serial_and_stamp, "%s %lu", serial, (unsigned long)stamp);
    xfree (serial);
    if (rc < 0)
      return ASSUAN_Out_Of_Core;
    rc = 0;
    assuan_write_status (ctx, "SERIALNO", serial_and_stamp);

    if (!has_option (line, "--force"))
      {
        char *command;

        rc = asprintf (&command, "KNOWNCARDP %s", serial_and_stamp);
        if (rc < 0)
          {
            free (serial_and_stamp);
            return ASSUAN_Out_Of_Core;
          }
        rc = 0;
        rc = assuan_inquire (ctx, command, NULL, NULL, 0); 
        free (command);  /* (must use standard free here) */
        if (rc)
          {
            if (rc != ASSUAN_Canceled)
              log_error ("inquire KNOWNCARDP failed: %s\n",
                         assuan_strerror (rc));
            free (serial_and_stamp);
            return rc; 
          }
        /* not canceled, so we have to proceeed */
      }
    free (serial_and_stamp);
  }

  for (idx=0; !rc; idx++)
    {
      unsigned char keygrip[20];
      char *keyid;
      int no_cert = 0;

      rc = card_enum_keypairs (ctrl->card_ctx, idx, keygrip, &keyid);
      if (rc == GNUPG_Missing_Certificate && keyid)
        {
          /* this does happen with an incomplete personalized
             card; i.e. during the time we have stored the key on the
             card but not stored the certificate; probably becuase it
             has not yet been received back from the CA.  Note that we
             must release KEYID in this case. */
          rc = 0; 
          no_cert = 1;
        }
      if (!rc)
        {
          char *buf, *p;

          buf = p = xtrymalloc (40 + 1 + strlen (keyid) + 1);
          if (!buf)
            rc = GNUPG_Out_Of_Core;
          else
            {
              int i;
              
              if (no_cert)
                *p++ = 'X';
              else
                {
                  for (i=0; i < 20; i++, p += 2)
                    sprintf (p, "%02X", keygrip[i]);
                }
              *p++ = ' ';
              strcpy (p, keyid);
              assuan_write_status (ctx, "KEYPAIRINFO", buf);
              xfree (buf);
            }
        }
      xfree (keyid);
    }
  if (rc == -1)
    rc = 0;


  return map_to_assuan_status (rc);
}



/* READCERT <hexified_certid>

 */
static int
cmd_readcert (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *cert;
  size_t ncert;

  if ((rc = open_card (ctrl)))
    return rc;

  rc = card_read_cert (ctrl->card_ctx, line, &cert, &ncert);
  if (rc)
    {
      log_error ("card_read_cert failed: %s\n", gnupg_strerror (rc));
    }
  if (!rc)
    {
      rc = assuan_send_data (ctx, cert, ncert);
      xfree (cert);
      if (rc)
        return rc;
    }

  return map_to_assuan_status (rc);
}


/* READKEY <hexified_certid>

   Return the public key for the given cert or key ID as an standard
   S-Expression.  */
static int
cmd_readkey (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *cert = NULL;
  size_t ncert, n;
  KsbaCert kc = NULL;
  KsbaSexp p;

  if ((rc = open_card (ctrl)))
    return rc;

  rc = card_read_cert (ctrl->card_ctx, line, &cert, &ncert);
  if (rc)
    {
      log_error ("card_read_cert failed: %s\n", gnupg_strerror (rc));
      goto leave;
    }
      
  kc = ksba_cert_new ();
  if (!kc)
    {
      xfree (cert);
      rc = GNUPG_Out_Of_Core;
      goto leave;
    }
  rc = ksba_cert_init_from_mem (kc, cert, ncert);
  if (rc)
    {
      log_error ("failed to parse the certificate: %s\n", ksba_strerror (rc));
      rc = map_ksba_err (rc);
      goto leave;
    }

  p = ksba_cert_get_public_key (kc);
  if (!p)
    {
      rc = GNUPG_No_Public_Key;
      goto leave;
    }

  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  rc = assuan_send_data (ctx, p, n);
  rc = map_assuan_err (rc);
  xfree (p);


 leave:
  ksba_cert_release (kc);
  xfree (cert);
  return map_to_assuan_status (rc);
}




/* SETDATA <hexstring> 

   The client should use this command to tell us the data he want to
   sign.  */
static int
cmd_setdata (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int n;
  char *p;
  unsigned char *buf;

  /* parse the hexstring */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (*p)
    return set_error (Parameter_Error, "invalid hexstring");
  if ((n&1))
    return set_error (Parameter_Error, "odd number of digits");
  n /= 2;
  buf = xtrymalloc (n);
  if (!buf)
    return ASSUAN_Out_Of_Core;

  ctrl->in_data.value = buf;
  ctrl->in_data.valuelen = n;
  for (p=line, n=0; n < ctrl->in_data.valuelen; p += 2, n++)
    buf[n] = xtoi_2 (p);
  return 0;
}



static int 
pin_cb (void *opaque, const char *info, char **retstr)
{
  ASSUAN_CONTEXT ctx = opaque;
  char *command;
  int rc;
  char *value;
  size_t valuelen;

  *retstr = NULL;
  log_debug ("asking for PIN '%s'\n", info);

  rc = asprintf (&command, "NEEDPIN %s", info);
  if (rc < 0)
    return GNUPG_Out_Of_Core;

  /* FIXME: Write an inquire function which returns the result in
     secure memory */
  rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN); 
  free (command);  
  if (rc)
    return map_assuan_err (rc);

  if (!valuelen || value[valuelen-1])
    {
      /* We require that the returned value is an UTF-8 string */
      xfree (value);
      return GNUPG_Invalid_Response;
    }
  *retstr = value;
  return 0;
}


/* PKSIGN <hexified_id>

 */
static int
cmd_pksign (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;
  void *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ((rc = open_card (ctrl)))
    return rc;

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return ASSUAN_Out_Of_Core;
  rc = card_sign (ctrl->card_ctx,
                  keyidstr, GCRY_MD_SHA1,
                  pin_cb, ctx,
                  ctrl->in_data.value, ctrl->in_data.valuelen,
                  &outdata, &outdatalen);
  xfree (keyidstr);
  if (rc)
    {
      log_error ("card_sign failed: %s\n", gnupg_strerror (rc));
    }
  else
    {
      rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
      if (rc)
        return rc; /* that is already an assuan error code */
    }

  return map_to_assuan_status (rc);
}

/* PKDECRYPT <hexified_id>

 */
static int
cmd_pkdecrypt (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;
  void *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ((rc = open_card (ctrl)))
    return rc;

  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return ASSUAN_Out_Of_Core;
  rc = card_decipher (ctrl->card_ctx,
                      keyidstr, 
                      pin_cb, ctx,
                      ctrl->in_data.value, ctrl->in_data.valuelen,
                      &outdata, &outdatalen);
  xfree (keyidstr);
  if (rc)
    {
      log_error ("card_create_signature failed: %s\n", gnupg_strerror (rc));
    }
  else
    {
      rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
      if (rc)
        return rc; /* that is already an assuan error code */
    }

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
    { "SERIALNO", 0, cmd_serialno },
    { "LEARN", 0, cmd_learn },
    { "READCERT", 0, cmd_readcert },
    { "READKEY", 0,  cmd_readkey },
    { "SETDATA", 0,  cmd_setdata },
    { "PKSIGN", 0,   cmd_pksign },
    { "PKDECRYPT", 0,cmd_pkdecrypt },
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
  assuan_set_hello_line (ctx, "GNU Privacy Guard's Smartcard server ready");

  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);
  return 0;
}


/* Startup the server.  If LISTEN_FD is given as -1, this is simple
   piper server, otherwise it is a regular server */
void
scd_command_handler (int listen_fd)
{
  int rc;
  ASSUAN_CONTEXT ctx;
  struct server_control_s ctrl;

  memset (&ctrl, 0, sizeof ctrl);
  scd_init_default_ctrl (&ctrl);
  
  if (listen_fd == -1)
    {
      int filedes[2];

      filedes[0] = 0;
      filedes[1] = 1;
      rc = assuan_init_pipe_server (&ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (&ctx, listen_fd);
    }
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 assuan_strerror(rc));
      scd_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to register commands with Assuan: %s\n",
                 assuan_strerror(rc));
      scd_exit (2);
    }
  assuan_set_pointer (ctx, &ctrl);
  ctrl.server_local = xcalloc (1, sizeof *ctrl.server_local);
  ctrl.server_local->assuan_ctx = ctx;

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
  reset_notify (ctx); /* used for cleanup */

  assuan_deinit_server (ctx);
}

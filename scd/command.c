/* command.c - SCdaemon command handler
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

#include <assuan.h>

#include "scdaemon.h"
#include "app-common.h"

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
  if (ctrl->app_ctx)
    {
      /* FIXME: close the application. */
      xfree (ctrl->app_ctx);
      ctrl->app_ctx = NULL;
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
  if (ctrl->app_ctx)
    return 0; /* Already initialized for one specific application. */
  if (ctrl->card_ctx)
    return 0; /* Already initialized using a card context. */

  ctrl->app_ctx = select_application ();
  if (!ctrl->app_ctx)
    { /* No application found - fall back to old mode. */
      int rc = card_open (&ctrl->card_ctx);
      if (rc)
        return map_to_assuan_status (rc);
    }
  return 0;
}


/* Do the percent and plus/space unescaping in place and return tghe
   length of the valid buffer. */
static size_t
percent_plus_unescape (unsigned char *string)
{
  unsigned char *p = string;
  size_t n = 0;

  while (*string)
    {
      if (*string == '%' && string[1] && string[2])
        { 
          string++;
          *p++ = xtoi_2 (string);
          n++;
          string+= 2;
        }
      else if (*string == '+')
        {
          *p++ = ' ';
          n++;
          string++;
        }
      else
        {
          *p++ = *string++;
          n++;
        }
    }

  return n;
}



/* SERIALNO 

   Return the serial number of the card using a status reponse.  This
   functon should be used to check for the presence of a card.

   This function is special in that it can be used to reset the card.
   Most other functions will return an error when a card change has
   been detected and the use of this function is therefore required.

   Background: We want to keep the client clear of handling card
   changes between operations; i.e. the client can assume that all
   operations are done on the same card unless he calls this function.
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

  if (ctrl->app_ctx)
    rc = app_get_serial_and_stamp (ctrl->app_ctx, &serial, &stamp);
  else
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

     S APPTYPE <apptype>

   This returns the type of the application, currently the strings:

       P15     = PKCS-15 structure used
       DINSIG  = DIN SIG
       OPENPGP = OpenPGP card
 
   are implemented.  These strings are aliases for the AID

     S KEYPAIRINFO <hexstring_with_keygrip> <hexstring_with_id>

   If there is no certificate yet stored on the card a single "X" is
   returned as the keygrip.  In addition to the keypair info, information
   about all certificates stored on the card is also returned:

     S CERTINFO <certtype> <hexstring_with_id>

   Where CERTTYPE is a number indicating the type of certificate:
      0   := Unknown
      100 := Regular X.509 cert
      101 := Trusted X.509 cert
      102 := Useful X.509 cert

   For certain cards, more information will be returned:

     S KEY-FPR <no> <hexstring>

   For OpenPGP cards this returns the stored fingerprints of the
   keys. This can be used check whether a key is available on the
   card.  NO may be 1, 2 or 3.

     S CA-FPR <no> <hexstring>

   Similar to above, these are the fingerprints of keys assumed to be
   ultimately trusted.

     S DISP-NAME <name_of_card_holder>

   The name of the card holder as stored on the card; percent
   aescaping takes place, spaces are encoded as '+'

     S PUBKEY-URL <url>

   The URL to be used for locating the entire public key.
     
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

    if (ctrl->app_ctx)
      rc = app_get_serial_and_stamp (ctrl->app_ctx, &serial, &stamp);
    else
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

  /* Return information about the certificates. */
  if (ctrl->app_ctx)
    rc = -1; /* This information is not yet available for applications. */
  for (idx=0; !rc; idx++)
    {
      char *certid;
      int certtype;

      rc = card_enum_certs (ctrl->card_ctx, idx, &certid, &certtype);
      if (!rc)
        {
          char *buf;

          buf = xtrymalloc (40 + 1 + strlen (certid) + 1);
          if (!buf)
            rc = out_of_core ();
          else
            {
              sprintf (buf, "%d %s", certtype, certid);
              assuan_write_status (ctx, "CERTINFO", buf);
              xfree (buf);
            }
        }
      xfree (certid);
    }
  if (rc == -1)
    rc = 0;


  /* Return information about the keys. */
  if (ctrl->app_ctx)
    rc = -1; /* This information is not yet available for applications. */
  for (idx=0; !rc; idx++)
    {
      unsigned char keygrip[20];
      char *keyid;
      int no_cert = 0;

      rc = card_enum_keypairs (ctrl->card_ctx, idx, keygrip, &keyid);
      if (gpg_err_code (rc) == GPG_ERR_MISSING_CERT && keyid)
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
            rc = out_of_core ();
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

  if (!rc && ctrl->app_ctx)
    rc = app_write_learn_status (ctrl->app_ctx, ctrl);


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

  if (ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  rc = card_read_cert (ctrl->card_ctx, line, &cert, &ncert);
  if (rc)
    {
      log_error ("card_read_cert failed: %s\n", gpg_strerror (rc));
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

  if (ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  rc = card_read_cert (ctrl->card_ctx, line, &cert, &ncert);
  if (rc)
    {
      log_error ("card_read_cert failed: %s\n", gpg_strerror (rc));
      goto leave;
    }
      
  kc = ksba_cert_new ();
  if (!kc)
    {
      rc = out_of_core ();
      xfree (cert);
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
      rc = gpg_error (GPG_ERR_NO_PUBKEY);
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
    return out_of_core ();

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
      return gpg_error (GPG_ERR_INV_RESPONSE);
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
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ((rc = open_card (ctrl)))
    return rc;

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = strdup (line);
  if (!keyidstr)
    return ASSUAN_Out_Of_Core;
  
  if (ctrl->app_ctx)
    rc = app_sign (ctrl->app_ctx,
                    keyidstr, GCRY_MD_SHA1,
                    pin_cb, ctx,
                    ctrl->in_data.value, ctrl->in_data.valuelen,
                    &outdata, &outdatalen);
  else  
    rc = card_sign (ctrl->card_ctx,
                    keyidstr, GCRY_MD_SHA1,
                    pin_cb, ctx,
                    ctrl->in_data.value, ctrl->in_data.valuelen,
                    &outdata, &outdatalen);
  free (keyidstr);
  if (rc)
    {
      log_error ("card_sign failed: %s\n", gpg_strerror (rc));
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
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ((rc = open_card (ctrl)))
    return rc;

  keyidstr = strdup (line);
  if (!keyidstr)
    return ASSUAN_Out_Of_Core;
  if (ctrl->app_ctx)
    rc = app_decipher (ctrl->app_ctx,
                        keyidstr, 
                        pin_cb, ctx,
                        ctrl->in_data.value, ctrl->in_data.valuelen,
                        &outdata, &outdatalen);
  else
    rc = card_decipher (ctrl->card_ctx,
                        keyidstr, 
                        pin_cb, ctx,
                        ctrl->in_data.value, ctrl->in_data.valuelen,
                        &outdata, &outdatalen);
  free (keyidstr);
  if (rc)
    {
      log_error ("card_create_signature failed: %s\n", gpg_strerror (rc));
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


/* SETATTR <name> <value> 

   This command is used to store data on a a smartcard.  The allowed
   names and values are depend on the currently selected smartcard
   application.  NAME and VALUE must be percent and '+' escaped.

   However, the curent implementation assumes that Name is not escaped;
   this works as long as noone uses arbitrary escaping. 
 
   A PIN will be requested for most NAMEs.  See the corresponding
   setattr function of the actually used application (app-*.c) for
   details.  */
static int
cmd_setattr (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyword;
  int keywordlen;
  size_t nbytes;

  if ((rc = open_card (ctrl)))
    return rc;

  keyword = line;
  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  if (*line)
      *line++ = 0;
  while (spacep (line))
    line++;
  nbytes = percent_plus_unescape (line);

  rc = app_setattr (ctrl->app_ctx, keyword, pin_cb, ctx, line, nbytes);

  return map_to_assuan_status (rc);
}

/* GENKEY [--force] <no>

   Generate a key on-card identified by NO, which is application
   specific.  Return values are application specific.  For OpenPGP
   cards 2 status lines are returned:

     S KEY-FPR  <hexstring>
     S KEY-CREATED-AT <seconds_since_epoch>
     S KEY-DATA [p|n] <hexdata>
     

   --force is required to overwriet an already existing key.  The
   KEY-CREATED-AT is required for further processing because it is
   part of the hashed key material for the fingerprint.

   The public part of the key can also later be retrieved using the
   READKEY command.

 */
static int
cmd_genkey (ASSUAN_CONTEXT ctx, char *line)
{
  CTRL ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyno;
  int force = has_option (line, "--force");

  /* Skip over options. */
  while ( *line == '-' && line[1] == '-' )
    {
      while (!spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  if (!*line)
    return set_error (Parameter_Error, "no key number given");
  keyno = line;
  while (!spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  rc = app_genkey (ctrl->app_ctx, ctrl, keyno, force? 1:0, pin_cb, ctx);

  return map_to_assuan_status (rc);
}





/* Tell the assuan library about our commands */
static int
register_commands (ASSUAN_CONTEXT ctx)
{
  static struct {
    const char *name;
    int (*handler)(ASSUAN_CONTEXT, char *line);
  } table[] = {
    { "SERIALNO",     cmd_serialno },
    { "LEARN",        cmd_learn },
    { "READCERT",     cmd_readcert },
    { "READKEY",      cmd_readkey },
    { "SETDATA",      cmd_setdata },
    { "PKSIGN",       cmd_pksign },
    { "PKDECRYPT",    cmd_pkdecrypt },
    { "INPUT",        NULL }, 
    { "OUTPUT",       NULL }, 
    { "SETATTR",      cmd_setattr },
    { "GENKEY",       cmd_genkey },
    { NULL }
  };
  int i, rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler);
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


/* Send a line with status information via assuan and escape all given
   buffers. The variable elements are pairs of (char *, size_t),
   terminated with a (NULL, 0). */
void
send_status_info (CTRL ctrl, const char *keyword, ...)
{
  va_list arg_ptr;
  const unsigned char *value;
  size_t valuelen;
  char buf[950], *p;
  size_t n;
  ASSUAN_CONTEXT ctx = ctrl->server_local->assuan_ctx;
  
  va_start (arg_ptr, keyword);

  p = buf; 
  n = 0;
  while ( (value = va_arg (arg_ptr, const unsigned char *)) )
    {
      valuelen = va_arg (arg_ptr, size_t);
      if (!valuelen)
        continue; /* empty buffer */
      if (n)
        {
          *p++ = ' ';
          n++;
        }
      for ( ; valuelen && n < DIM (buf)-2; n++, valuelen--, value++)
        {
          if (*value < ' ' || *value == '+')
            {
              sprintf (p, "%%%02X", *value);
              p += 3;
            }
          else if (*value == ' ')
            *p++ = '+';
          else
            *p++ = *value;
        }
    }
  *p = 0;
  assuan_write_status (ctx, keyword, buf);

  va_end (arg_ptr);
}


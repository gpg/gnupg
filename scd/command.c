/* command.c - SCdaemon command handler
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
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
#include <signal.h>
#ifdef USE_GNU_PTH
# include <pth.h>
#endif

#include <assuan.h>

#include "scdaemon.h"
#include <ksba.h>
#include "app-common.h"
#include "apdu.h" /* Required for apdu_*_reader (). */

/* Maximum length allowed as a PIN; used for INQUIRE NEEDPIN */
#define MAXLEN_PIN 100


#define set_error(e,t) assuan_set_error (ctx, ASSUAN_ ## e, (t))


/* Macro to flag a a removed card.  */
#define TEST_CARD_REMOVAL(c,r)                              \
       do {                                                 \
          int _r = (r);                                     \
          if (gpg_err_code (_r) == GPG_ERR_CARD_NOT_PRESENT \
              || gpg_err_code (_r) == GPG_ERR_CARD_REMOVED) \
            update_card_removed ((c)->reader_slot, 1);      \
       } while (0)

#define IS_LOCKED(c)                                                     \
     (locked_session && locked_session != (c)->server_local              \
      && (c)->reader_slot != -1 && locked_session->ctrl_backlink         \
      && (c)->reader_slot == locked_session->ctrl_backlink->reader_slot)


/* Data used to associate an Assuan context with local server data.
   This object describes the local properties of one session.  */
struct server_local_s {
  /* We keep a list of all active sessions with the anchor at
     SESSION_LIST (see below).  This field is used for linking. */
  struct server_local_s *next_session; 

  /* This object is usually assigned to a CTRL object (which is
     globally visible).  While enumeratin all sessions we sometimes
     need to access data of the CTRL object; thus we keep a
     backpointer here. */
  ctrl_t ctrl_backlink;

  /* The Assuan context used by this session/server. */
  assuan_context_t assuan_ctx;

  int event_signal;        /* Or 0 if not used. */

  /* True if the card has been removed and a reset is required to
     continue operation. */
  int card_removed;        
};


/* To keep track of all running sessions, we link all active server
   contexts and the anchor in this variable.  */
static struct server_local_s *session_list;

/* If a session has been locked we store a link to its server object
   in this variable. */
static struct server_local_s *locked_session;




/* Update the CARD_REMOVED element of all sessions using the reader
   given by SLOT to VALUE  */
static void
update_card_removed (int slot, int value)
{
  struct server_local_s *sl;

  for (sl=session_list; sl; sl = sl->next_session)
    if (sl->ctrl_backlink
        && sl->ctrl_backlink->reader_slot == slot)
      sl->card_removed = value;
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


/* Reset the card and free the application context.  With DO_CLOSE set
   to true and this is the last session with a reference to teh
   reader, close the reader and don't do just a reset. */
static void
do_reset (ctrl_t ctrl, int do_close)
{
  int slot = ctrl->reader_slot;

  if (ctrl->card_ctx)
    {
      card_close (ctrl->card_ctx);
      ctrl->card_ctx = NULL;
      xfree (ctrl->in_data.value);
      ctrl->in_data.value = NULL;
    }
  if (ctrl->app_ctx)
    {
      release_application (ctrl->app_ctx);
      ctrl->app_ctx = NULL;
    }
  if (ctrl->reader_slot != -1)
    {
      struct server_local_s *sl;

      /* If we are the only session with the reader open we may close
         it.  If not, do a reset unless the a lock is held on the
         reader.  */
      for (sl=session_list; sl; sl = sl->next_session)
        if (sl != ctrl->server_local
            && sl->ctrl_backlink->reader_slot == ctrl->reader_slot)
          break;
      if (sl) /* There is another session with the reader open. */
        {
          if ( IS_LOCKED (ctrl) ) /* If it is locked, release it. */
            ctrl->reader_slot = -1;
          else
            {
              if (do_close) /* Always mark reader unused. */
                ctrl->reader_slot = -1;
              else if (apdu_reset (ctrl->reader_slot)) /* Reset only if
                                                          not locked */
                {
                  /* The reset failed.  Mark the reader as closed. */
                  ctrl->reader_slot = -1;
                }

              if (locked_session && ctrl->server_local == locked_session)
                {
                  locked_session = NULL;
                  log_debug ("implicitly unlocking due to RESET\n");
                }
            }
        }
      else /* No other session has the reader open.  */
        {
          if (do_close || apdu_reset (ctrl->reader_slot))
            {
              apdu_close_reader (ctrl->reader_slot);
              ctrl->reader_slot = -1;
            }
          if ( IS_LOCKED (ctrl) )
            {
              log_debug ("WARNING: cleaning up stale session lock\n");
              locked_session =  NULL;
            }
        }
    }

  /* Reset card removed flag for the current reader.  */
  update_card_removed (slot, 0);
}


static void
reset_notify (assuan_context_t ctx)
{
  ctrl_t ctrl = assuan_get_pointer (ctx); 

  do_reset (ctrl, 0);
}


static int
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  if (!strcmp (key, "event-signal"))
    {
      /* A value of 0 is allowed to reset the event signal. */
      int i = *value? atoi (value) : -1;
      if (i < 0)
        return ASSUAN_Parameter_Error;
      ctrl->server_local->event_signal = i;
    }

 return 0;
}


/* Return the slot of the current reader or open the reader if no
   other sessions are using a reader.  Note, that we currently support
   only one reader but most of the code (except for this function)
   should be able to cope with several readers.  */
static int
get_reader_slot (void)
{
  struct server_local_s *sl;
  int slot= -1;

  for (sl=session_list; sl; sl = sl->next_session)
    if (sl->ctrl_backlink
        && (slot = sl->ctrl_backlink->reader_slot) != -1)
      break;

  if (slot == -1)
    slot = apdu_open_reader (opt.reader_port);

  return slot;
}

/* If the card has not yet been opened, do it.  Note that this
   function returns an Assuan error, so don't map the error a second
   time */
static assuan_error_t
open_card (ctrl_t ctrl, const char *apptype)
{
  gpg_error_t err;
  int slot;

  /* If we ever got a card not present error code, return that.  Only
     the SERIALNO command and a reset are able to clear from that
     state. */
  if (ctrl->server_local->card_removed)
    return map_to_assuan_status (gpg_error (GPG_ERR_CARD_REMOVED));

  if (ctrl->app_ctx)
    return 0; /* Already initialized for one specific application. */
  if (ctrl->card_ctx)
    return 0; /* Already initialized using a card context. */

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  if (ctrl->reader_slot != -1)
    slot = ctrl->reader_slot;
  else
    slot = get_reader_slot ();
  ctrl->reader_slot = slot;
  if (slot == -1)
    err = gpg_error (GPG_ERR_CARD);
  else
    err = select_application (ctrl, slot, apptype, &ctrl->app_ctx);
  if (!ctrl->app_ctx
      && gpg_err_code (err) != GPG_ERR_CARD_NOT_PRESENT)
    { 
      /* No application found - fall back to old mode. */
      /* Note that we should rework the old code to use the
         application paradigma too. */
      /* If an APPTYPE was requested and it is not pkcs#15, we return
         an error here. */
      if (apptype && !(!strcmp (apptype, "P15") || !strcmp (apptype, "p15")))
        err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      else 
        err = card_open (&ctrl->card_ctx);
    }

  TEST_CARD_REMOVAL (ctrl, err);
  return map_to_assuan_status (err);
}


/* Do the percent and plus/space unescaping in place and return the
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



/* SERIALNO [APPTYPE] 

   Return the serial number of the card using a status reponse.  This
   functon should be used to check for the presence of a card.

   If APPTYPE is given, an application of that type is selected and an
   error is returned if the application is not supported or available.
   The default is to auto-select the application using a hardwired
   preference system.  Note, that a future extension to this function
   may allow to specify a list and order of applications to try.

   This function is special in that it can be used to reset the card.
   Most other functions will return an error when a card change has
   been detected and the use of this function is therefore required.

   Background: We want to keep the client clear of handling card
   changes between operations; i.e. the client can assume that all
   operations are done on the same card unless he calls this function.
 */
static int
cmd_serialno (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  char *serial_and_stamp;
  char *serial;
  time_t stamp;

  /* Clear the remove flag so that the open_card is able to reread it.  */
  if (ctrl->server_local->card_removed)
    {
      if ( IS_LOCKED (ctrl) )
        return gpg_error (GPG_ERR_EBUSY);
      do_reset (ctrl, 0);
    }

  if ((rc = open_card (ctrl, *line? line:NULL)))
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
      110 := Root CA cert (DINSIG)

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
   escaping takes place, spaces are encoded as '+'

     S PUBKEY-URL <url>

   The URL to be used for locating the entire public key.
     
   Note, that this function may be even be used on a locked card.
*/
static int
cmd_learn (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  int idx;

  if ((rc = open_card (ctrl, NULL)))
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

  /* If we are using the modern application paradigma, let the
     application print out its collection of useful status
     information. */
  if (!rc && ctrl->app_ctx)
    rc = app_write_learn_status (ctrl->app_ctx, ctrl);

  /* Return information about the certificates.  FIXME: Move this into
     an app-p15.c*/
  for (idx=0; !rc && !ctrl->app_ctx; idx++)
    {
      char *certid;
      int certtype;

      rc = card_enum_certs (ctrl->card_ctx, idx, &certid, &certtype);
      if (!rc)
        {
          char *buf;

          buf = xtrymalloc (40 + 1 + strlen (certid) + 1);
          if (!buf)
            rc = gpg_error (gpg_err_code_from_errno (errno));
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

  /* Return information about the keys. FIXME: Move this into an
     app-p15.c */
  for (idx=0; !rc && !ctrl->app_ctx; idx++)
    {
      unsigned char keygrip[20];
      char *keyid;
      int no_cert = 0;

      rc = card_enum_keypairs (ctrl->card_ctx, idx, keygrip, &keyid);
      if (gpg_err_code (rc) == GPG_ERR_MISSING_CERT && keyid)
        {
          /* This does happen with an incomplete personalized
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
            rc = gpg_error (gpg_err_code_from_errno (errno));
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

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}



/* READCERT <hexified_certid>

   Note, that this function may be even be used on a locked card.
 */
static int
cmd_readcert (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *cert;
  size_t ncert;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  line = xstrdup (line); /* Need a copy of the line. */
  if (ctrl->app_ctx)
    {
      rc = app_readcert (ctrl->app_ctx, line, &cert, &ncert);
      if (rc)
        log_error ("app_readcert failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      rc = card_read_cert (ctrl->card_ctx, line, &cert, &ncert);
      if (rc)
        log_error ("card_read_cert failed: %s\n", gpg_strerror (rc));
    }
  xfree (line);
  line = NULL;
  if (!rc)
    {
      rc = assuan_send_data (ctx, cert, ncert);
      xfree (cert);
      if (rc)
        return rc;
    }

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}


/* READKEY <hexified_certid>

   Return the public key for the given cert or key ID as an standard
   S-Expression.

   Note, that this function may be even be used on a locked card.
  */
static int
cmd_readkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *cert = NULL;
  size_t ncert, n;
  ksba_cert_t kc = NULL;
  ksba_sexp_t p;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  line = xstrdup (line); /* Need a copy of the line. */
  if (ctrl->app_ctx)
    {
      unsigned char *pk;
      size_t pklen;

      /* If the application supports the READKEY function we use that.
         Otherwise we use the old way by extracting it from the
         certificate.  */
      rc = app_readkey (ctrl->app_ctx, line, &pk, &pklen);
      if (!rc)
        { /* Yeah, got that key - send it back.  */
          rc = assuan_send_data (ctx, pk, pklen);
          xfree (pk);
          rc = map_assuan_err (rc);
          xfree (line);
          line = NULL;
          goto leave;
        }

      if (gpg_err_code (rc) != GPG_ERR_UNSUPPORTED_OPERATION)
        log_error ("app_readkey failed: %s\n", gpg_strerror (rc));
      else  
        {
          rc = app_readcert (ctrl->app_ctx, line, &cert, &ncert);
          if (rc)
            log_error ("app_readcert failed: %s\n", gpg_strerror (rc));
        }
    }
  else
    {
      rc = card_read_cert (ctrl->card_ctx, line, &cert, &ncert);
      if (rc)
        log_error ("card_read_cert failed: %s\n", gpg_strerror (rc));
    }
  xfree (line);
  line = NULL;
  if (rc)
    goto leave;
      
  rc = ksba_cert_new (&kc);
  if (rc)
    {
      xfree (cert);
      goto leave;
    }
  rc = ksba_cert_init_from_mem (kc, cert, ncert);
  if (rc)
    {
      log_error ("failed to parse the certificate: %s\n", gpg_strerror (rc));
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
  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}




/* SETDATA <hexstring> 

   The client should use this command to tell us the data he want to
   sign.  */
static int
cmd_setdata (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int n;
  char *p;
  unsigned char *buf;

  if (locked_session && locked_session != ctrl->server_local)
    return gpg_error (GPG_ERR_EBUSY);

  /* Parse the hexstring. */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (*p)
    return set_error (Parameter_Error, "invalid hexstring");
  if (!n)
    return set_error (Parameter_Error, "no data given");
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
  assuan_context_t ctx = opaque;
  char *command;
  int rc;
  unsigned char *value;
  size_t valuelen;

  *retstr = NULL;
  log_debug ("asking for PIN '%s'\n", info);

  rc = asprintf (&command, "NEEDPIN %s", info);
  if (rc < 0)
    return gpg_error (gpg_err_code_from_errno (errno));

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
cmd_pksign (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
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
  xfree (keyidstr);
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

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}

/* PKAUTH <hexified_id>

 */
static int
cmd_pkauth (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return ASSUAN_Out_Of_Core;
  
  rc = app_auth (ctrl->app_ctx,
                 keyidstr,
                 pin_cb, ctx,
                 ctrl->in_data.value, ctrl->in_data.valuelen,
                 &outdata, &outdatalen);
  xfree (keyidstr);
  if (rc)
    {
      log_error ("app_auth_sign failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
      if (rc)
        return rc; /* that is already an assuan error code */
    }

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}

/* PKDECRYPT <hexified_id>

 */
static int
cmd_pkdecrypt (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  keyidstr = xtrystrdup (line);
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
  xfree (keyidstr);
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

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}


/* GETATTR <name>

   This command is used to retrieve data from a smartcard.  The
   allowed names depend on the currently selected smartcard
   application.  NAME must be percent and '+' escaped.  The value is
   returned through status message, see the LEARN command for details.

   However, the current implementation assumes that Name is not escaped;
   this works as long as noone uses arbitrary escaping. 
 
   Note, that this function may even be used on a locked card.
*/
static int
cmd_getattr (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyword;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  keyword = line;
  for (; *line && !spacep (line); line++)
    ;
  if (*line)
      *line++ = 0;

  /* (We ignore any garbage for now.) */

  /* FIXME: Applications should not return sensistive data if the card
     is locked.  */
  rc = app_getattr (ctrl->app_ctx, ctrl, keyword);

  TEST_CARD_REMOVAL (ctrl, rc);
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
cmd_setattr (assuan_context_t ctx, char *orig_line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyword;
  int keywordlen;
  size_t nbytes;
  char *line, *linebuf;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  /* We need to use a copy of LINE, because PIN_CB uses the same
     context and thus reuses the Assuan provided LINE. */
  line = linebuf = xtrystrdup (orig_line);
  if (!line)
    return ASSUAN_Out_Of_Core;

  keyword = line;
  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  if (*line)
      *line++ = 0;
  while (spacep (line))
    line++;
  nbytes = percent_plus_unescape (line);

  rc = app_setattr (ctrl->app_ctx, keyword, pin_cb, ctx, line, nbytes);
  xfree (linebuf);

  TEST_CARD_REMOVAL (ctrl, rc);
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
cmd_genkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyno;
  int force = has_option (line, "--force");

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  /* Skip over options. */
  while ( *line == '-' && line[1] == '-' )
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  if (!*line)
    return set_error (Parameter_Error, "no key number given");
  keyno = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  keyno = xtrystrdup (keyno);
  if (!keyno)
    return ASSUAN_Out_Of_Core;
  rc = app_genkey (ctrl->app_ctx, ctrl, keyno, force? 1:0, pin_cb, ctx);
  xfree (keyno);

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}


/* RANDOM <nbytes>

   Get NBYTES of random from the card and send them back as data. 

   Note, that this function may be even be used on a locked card.
*/
static int
cmd_random (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  size_t nbytes;
  unsigned char *buffer;

  if (!*line)
    return set_error (Parameter_Error, "number of requested bytes missing");
  nbytes = strtoul (line, NULL, 0);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  buffer = xtrymalloc (nbytes);
  if (!buffer)
    return ASSUAN_Out_Of_Core;

  rc = app_get_challenge (ctrl->app_ctx, nbytes, buffer);
  if (!rc)
    {
      rc = assuan_send_data (ctx, buffer, nbytes);
      xfree (buffer);
      return rc; /* that is already an assuan error code */
    }
  xfree (buffer);

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}


/* PASSWD [--reset] <chvno>
  
   Change the PIN or reset thye retry counter of the card holder
   verfication vector CHVNO. */
static int
cmd_passwd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *chvnostr;
  int reset_mode = has_option (line, "--reset");

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  /* Skip over options. */
  while (*line == '-' && line[1] == '-')
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  if (!*line)
    return set_error (Parameter_Error, "no CHV number given");
  chvnostr = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  
  chvnostr = xtrystrdup (chvnostr);
  if (!chvnostr)
    return ASSUAN_Out_Of_Core;
  rc = app_change_pin (ctrl->app_ctx, ctrl, chvnostr, reset_mode, pin_cb, ctx);
  if (rc)
    log_error ("command passwd failed: %s\n", gpg_strerror (rc));
  xfree (chvnostr);

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}


/* CHECKPIN <hexified_id>

 */
static int
cmd_checkpin (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyidstr;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_EBUSY);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid. */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return ASSUAN_Out_Of_Core;
  
  rc = app_check_pin (ctrl->app_ctx,
                      keyidstr,
                      pin_cb, ctx);
  xfree (keyidstr);
  if (rc)
    log_error ("app_check_pin failed: %s\n", gpg_strerror (rc));

  TEST_CARD_REMOVAL (ctrl, rc);
  return map_to_assuan_status (rc);
}


/* LOCK [--wait]

   Grant exclusive card access to this session.  Note that there is
   no lock counter used and a second lock from the same session will
   get ignore.  A single unlock (or RESET) unlocks the session.
   Return GPG_ERR_EBUSY if another session has locked the reader.

   If the option --wait is given the command will wait until a
   lock has been released.
 */
static int
cmd_lock (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;

 retry:
  if (locked_session)
    {
      if (locked_session != ctrl->server_local)
        rc = gpg_error (GPG_ERR_EBUSY);
    }
  else
    locked_session = ctrl->server_local;

#ifdef USE_GNU_PTH
  if (rc && has_option (line, "--wait"))
    {
      pth_sleep (1); /* Better implement an event mechanism. However,
                        for card operations this should be
                        sufficient. */
      goto retry;
    }
#endif /*USE_GNU_PTH*/
  
  if (rc)
    log_error ("cmd_lock failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}


/* UNLOCK

   Release exclusive card access.
 */
static int
cmd_unlock (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;

  if (locked_session)
    {
      if (locked_session != ctrl->server_local)
        rc = gpg_error (GPG_ERR_EBUSY);
      else
        locked_session = NULL;
    }
  else
    rc = gpg_error (GPG_ERR_NOT_LOCKED);

  if (rc)
    log_error ("cmd_unlock failed: %s\n", gpg_strerror (rc));
  return map_to_assuan_status (rc);
}





/* Tell the assuan library about our commands */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    int (*handler)(assuan_context_t, char *line);
  } table[] = {
    { "SERIALNO",     cmd_serialno },
    { "LEARN",        cmd_learn },
    { "READCERT",     cmd_readcert },
    { "READKEY",      cmd_readkey },
    { "SETDATA",      cmd_setdata },
    { "PKSIGN",       cmd_pksign },
    { "PKAUTH",       cmd_pkauth },
    { "PKDECRYPT",    cmd_pkdecrypt },
    { "INPUT",        NULL }, 
    { "OUTPUT",       NULL }, 
    { "GETATTR",      cmd_getattr },
    { "SETATTR",      cmd_setattr },
    { "GENKEY",       cmd_genkey },
    { "RANDOM",       cmd_random },
    { "PASSWD",       cmd_passwd },
    { "CHECKPIN",     cmd_checkpin },
    { "LOCK",         cmd_lock },
    { "UNLOCK",       cmd_unlock },
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
  assuan_context_t ctx;
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

  /* Allocate and initialize the server object.  Put it into the list
     of active sessions. */
  ctrl.server_local = xcalloc (1, sizeof *ctrl.server_local);
  ctrl.server_local->next_session = session_list;
  session_list = ctrl.server_local;
  ctrl.server_local->ctrl_backlink = &ctrl;
  ctrl.server_local->assuan_ctx = ctx;

  if (DBG_ASSUAN)
    assuan_set_log_stream (ctx, log_get_stream ());

  /* We open the reader right at startup so that the ticker is able to
     update the status file. */
  if (ctrl.reader_slot == -1)
    {
      ctrl.reader_slot = get_reader_slot ();
    }

  /* Command processing loop. */
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

  /* Cleanup.  */
  do_reset (&ctrl, 1); 

  /* Release the server object.  */
  if (session_list == ctrl.server_local)
    session_list = ctrl.server_local->next_session;
  else
    {
      struct server_local_s *sl;
      
      for (sl=session_list; sl->next_session; sl = sl->next_session)
        if (sl->next_session == ctrl.server_local)
          break;
      if (!sl->next_session)
          BUG ();
      sl->next_session = ctrl.server_local->next_session;
    }
  xfree (ctrl.server_local);

  /* Release the Assuan context.  */
  assuan_deinit_server (ctx);
}


/* Send a line with status information via assuan and escape all given
   buffers. The variable elements are pairs of (char *, size_t),
   terminated with a (NULL, 0). */
void
send_status_info (ctrl_t ctrl, const char *keyword, ...)
{
  va_list arg_ptr;
  const unsigned char *value;
  size_t valuelen;
  char buf[950], *p;
  size_t n;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;
  
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


/* This function is called by the ticker thread to check for changes
   of the reader stati.  It updates the reader status files and if
   requested by the caller also send a signal to the caller.  */
void
scd_update_reader_status_file (void)
{
  static struct {
    int any;
    unsigned int status;
    unsigned int changed;
  } last[10];
  int slot;
  int used;
  unsigned int status, changed;

  /* Note, that we only try to get the status, because it does not
     make sense to wait here for a operation to complete.  If we are
     busy working with a card, delays in the status file update should
     be acceptable. */
  for (slot=0; (slot < DIM(last)
                &&!apdu_enum_reader (slot, &used)); slot++)
    if (used && !apdu_get_status (slot, 0, &status, &changed))
      {
        if (!last[slot].any || last[slot].status != status
            || last[slot].changed != changed )
          {
            char *fname;
            char templ[50];
            FILE *fp;
            struct server_local_s *sl;

            log_info ("updating status of slot %d to 0x%04X\n", slot, status);
            
            sprintf (templ, "reader_%d.status", slot);
            fname = make_filename (opt.homedir, templ, NULL );
            fp = fopen (fname, "w");
            if (fp)
              {
                fprintf (fp, "%s\n",
                         (status & 1)? "USABLE":
                         (status & 4)? "ACTIVE":
                         (status & 2)? "PRESENT": "NOCARD");
                fclose (fp);
              }
            xfree (fname);

            /* Set the card removed flag for all current sessions.  We
               will set this on any card change because a reset or
               SERIALNO request must be done in any case.  */
            if (last[slot].any)
              update_card_removed (slot, 1);

            last[slot].any = 1;
            last[slot].status = status;
            last[slot].changed = changed;


            /* Send a signal to all clients who applied for it.  */
            for (sl=session_list; sl; sl = sl->next_session)
              if (sl->event_signal && sl->assuan_ctx)
                {
                  pid_t pid = assuan_get_pid (sl->assuan_ctx);
                  int signo = sl->event_signal;

                  log_info ("client pid is %d, sending signal %d\n",
                            pid, signo);
#ifndef HAVE_W32_SYSTEM
                  if (pid != (pid_t)(-1) && pid && signo > 0)
                    kill (pid, signo);
#endif
                }
          }
      }
}

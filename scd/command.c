/* command.c - SCdaemon command handler
 * Copyright (C) 2001, 2002, 2003, 2004, 2005,
 *               2007, 2008, 2009  Free Software Foundation, Inc.
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
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#ifdef USE_GNU_PTH
# include <pth.h>
#endif

#include "scdaemon.h"
#include <assuan.h>
#include <ksba.h>
#include "app-common.h"
#include "apdu.h" /* Required for apdu_*_reader (). */
#include "exechelp.h"
#ifdef HAVE_LIBUSB
#include "ccid-driver.h"
#endif

/* Maximum length allowed as a PIN; used for INQUIRE NEEDPIN */
#define MAXLEN_PIN 100

/* Maximum allowed size of key data as used in inquiries. */
#define MAXLEN_KEYDATA 4096

/* Maximum allowed size of certificate data as used in inquiries. */
#define MAXLEN_CERTDATA 16384


#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))


/* Macro to flag a removed card.  ENODEV is also tested to catch teh
   case of a removed reader.  */
#define TEST_CARD_REMOVAL(c,r)                              \
       do {                                                 \
          int _r = (r);                                     \
          if (gpg_err_code (_r) == GPG_ERR_CARD_NOT_PRESENT \
              || gpg_err_code (_r) == GPG_ERR_CARD_REMOVED  \
              || gpg_err_code (_r) == GPG_ERR_ENODEV )      \
            update_card_removed ((c)->reader_slot, 1);      \
       } while (0)

#define IS_LOCKED(c)                                                     \
     (locked_session && locked_session != (c)->server_local              \
      && (c)->reader_slot != -1 && locked_session->ctrl_backlink         \
      && (c)->reader_slot == locked_session->ctrl_backlink->reader_slot)


/* Flag indicating that the reader has been disabled.  */
static int reader_disabled;


/* This structure is used to keep track of open readers (slots). */
struct slot_status_s 
{
  int valid;  /* True if the other objects are valid. */
  int slot;   /* Slot number of the reader or -1 if not open. */

  int reset_failed; /* A reset failed. */

  int any;    /* Flag indicating whether any status check has been
                 done.  This is set once to indicate that the status
                 tracking for the slot has been initialized.  */
  unsigned int status;  /* Last status of the slot. */
  unsigned int changed; /* Last change counter of the slot. */
};


/* Data used to associate an Assuan context with local server data.
   This object describes the local properties of one session.  */
struct server_local_s 
{
  /* We keep a list of all active sessions with the anchor at
     SESSION_LIST (see below).  This field is used for linking. */
  struct server_local_s *next_session; 

  /* This object is usually assigned to a CTRL object (which is
     globally visible).  While enumerating all sessions we sometimes
     need to access data of the CTRL object; thus we keep a
     backpointer here. */
  ctrl_t ctrl_backlink;

  /* The Assuan context used by this session/server. */
  assuan_context_t assuan_ctx;

#ifdef HAVE_W32_SYSTEM
  unsigned long event_signal;   /* Or 0 if not used. */
#else
  int event_signal;             /* Or 0 if not used. */
#endif
  
  /* True if the card has been removed and a reset is required to
     continue operation. */
  int card_removed;        

  /* Flag indicating that the application context needs to be released
     at the next opportunity.  */
  int app_ctx_marked_for_release;

  /* A disconnect command has been sent.  */
  int disconnect_allowed;

  /* If set to true we will be terminate ourself at the end of the
     this session.  */
  int stopme;  

};


/* The table with information on all used slots.  FIXME: This is a
   different slot number than the one used by the APDU layer, and
   should be renamed.  */
static struct slot_status_s slot_table[10];


/* To keep track of all running sessions, we link all active server
   contexts and the anchor in this variable.  */
static struct server_local_s *session_list;

/* If a session has been locked we store a link to its server object
   in this variable. */
static struct server_local_s *locked_session;

/* While doing a reset we need to make sure that the ticker does not
   call scd_update_reader_status_file while we are using it. */
static pth_mutex_t status_file_update_lock;


/*-- Local prototypes --*/
static void update_reader_status_file (int set_card_removed_flag);




/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because Pth emulation code might not be able
   to do a static init; in particular, it is not possible for W32. */
void
initialize_module_command (void)
{
  static int initialized;

  if (!initialized)
    {
      if (pth_mutex_init (&status_file_update_lock))
        initialized = 1;
    }
}


/* Update the CARD_REMOVED element of all sessions using the reader
   given by SLOT to VALUE.  */
static void
update_card_removed (int slot, int value)
{
  struct server_local_s *sl;

  for (sl=session_list; sl; sl = sl->next_session)
    if (sl->ctrl_backlink
        && sl->ctrl_backlink->reader_slot == slot)
      {
        sl->card_removed = value;
      }
  /* Let the card application layer know about the removal.  */
  if (value)
    application_notify_card_reset (slot);
}



/* Check whether the option NAME appears in LINE.  Returns 1 or 0. */
static int
has_option (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n)));
}

/* Same as has_option but does only test for the name of the option
   and ignores an argument, i.e. with NAME being "--hash" it would
   return a pointer for "--hash" as well as for "--hash=foo".  If
   there is no such option NULL is returned.  The pointer returned
   points right behind the option name, this may be an equal sign, Nul
   or a space.  */
static const char *
has_option_name (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1))
          && (!s[n] || spacep (s+n) || s[n] == '=')) ? (s+n) : NULL;
}


/* Skip over options.  It is assumed that leading spaces have been
   removed (this is the case for lines passed to a handler from
   assuan).  Blanks after the options are also removed. */
static char *
skip_options (char *line)
{
  while ( *line == '-' && line[1] == '-' )
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  return line;
}



/* Convert the STRING into a newly allocated buffer while translating
   the hex numbers.  Stops at the first invalid character.  Blanks and
   colons are allowed to separate the hex digits.  Returns NULL on
   error or a newly malloced buffer and its length in LENGTH.  */
static unsigned char *
hex_to_buffer (const char *string, size_t *r_length)
{
  unsigned char *buffer;
  const char *s;
  size_t n;

  buffer = xtrymalloc (strlen (string)+1);
  if (!buffer)
    return NULL;
  for (s=string, n=0; *s; s++)
    {
      if (spacep (s) || *s == ':') 
        continue;
      if (hexdigitp (s) && hexdigitp (s+1))
        {
          buffer[n++] = xtoi_2 (s);
          s++;
        }
      else
        break;
    }
  *r_length = n;
  return buffer;
}



/* Reset the card and free the application context.  With SEND_RESET
   set to true actually send a RESET to the reader; this is the normal
   way of calling the function.  */
static void
do_reset (ctrl_t ctrl, int send_reset)
{
  int slot = ctrl->reader_slot;

  if (!(slot == -1 || (slot >= 0 && slot < DIM(slot_table))))
    BUG ();

  /* If there is an active application, release it.  Tell all other
     sessions using the same application to release the
     application.  */
  if (ctrl->app_ctx)
    {
      release_application (ctrl->app_ctx);
      ctrl->app_ctx = NULL;
      if (send_reset)
        {
          struct server_local_s *sl;
          
          for (sl=session_list; sl; sl = sl->next_session)
            if (sl->ctrl_backlink
                && sl->ctrl_backlink->reader_slot == slot)
              {
                sl->app_ctx_marked_for_release = 1;
              }
        }
    }

  /* If we want a real reset for the card, send the reset APDU and
     tell the application layer about it.  */
  if (slot != -1 && send_reset && !IS_LOCKED (ctrl) )
    {
      if (apdu_reset (slot)) 
        {
          slot_table[slot].valid = 0;
        }
      application_notify_card_reset (slot);
    }

  /* If we hold a lock, unlock now. */
  if (locked_session && ctrl->server_local == locked_session)
    {
      locked_session = NULL;
      log_info ("implicitly unlocking due to RESET\n");
    }

  /* Reset the card removed flag for the current reader.  We need to
     take the lock here so that the ticker thread won't concurrently
     try to update the file.  Calling update_reader_status_file is
     required to get hold of the new status of the card in the slot
     table.  */
  if (!pth_mutex_acquire (&status_file_update_lock, 0, NULL))
    {
      log_error ("failed to acquire status_fle_update lock\n");
      ctrl->reader_slot = -1;
      return;
    }
  update_reader_status_file (0);  /* Update slot status table.  */
  update_card_removed (slot, 0);  /* Clear card_removed flag.  */
  if (!pth_mutex_release (&status_file_update_lock))
    log_error ("failed to release status_file_update lock\n");

  /* Do this last, so that the update_card_removed above does its job.  */
  ctrl->reader_slot = -1;
}


static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx); 

  (void) line;

  do_reset (ctrl, 1);
  return 0;
}


static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  if (!strcmp (key, "event-signal"))
    {
      /* A value of 0 is allowed to reset the event signal. */
#ifdef HAVE_W32_SYSTEM
      if (!*value)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      ctrl->server_local->event_signal = strtoul (value, NULL, 16);
#else
      int i = *value? atoi (value) : -1;
      if (i < 0)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      ctrl->server_local->event_signal = i;
#endif
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
  struct slot_status_s *ss;

  ss = &slot_table[0]; /* One reader for now. */

  /* Initialize the item if needed. */
  if (!ss->valid)
    {
      ss->slot = -1;
      ss->valid = 1;
    }

  /* Try to open the reader. */
  if (ss->slot == -1)
    {
      int no_service_flag;
      ss->slot = apdu_open_reader (opt.reader_port, &no_service_flag);

      /* If we still don't have a slot, we have no readers.
	 Invalidate for now until a reader is attached. */
      if(ss->slot == -1)
	{
	  ss->valid = 0;
	}

      if (no_service_flag)
        {
          log_info ("no card services - disabling scdaemon\n");
          reader_disabled = 1;
        }
    }

  /* Return the slot_table index.  */
  return 0;
}

/* If the card has not yet been opened, do it.  Note that this
   function returns an Assuan error, so don't map the error a second
   time.  */
static gpg_error_t
open_card (ctrl_t ctrl, const char *apptype)
{
  gpg_error_t err;
  int slot;

  if (reader_disabled)
    return gpg_error (GPG_ERR_NOT_OPERATIONAL);

  /* If we ever got a card not present error code, return that.  Only
     the SERIALNO command and a reset are able to clear from that
     state. */
  if (ctrl->server_local->card_removed)
    return gpg_error (GPG_ERR_CARD_REMOVED);

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  /* If the application has been marked for release do it now.  We
     can't do it immediately in do_reset because the application may
     still be in use.  */
  if (ctrl->server_local->app_ctx_marked_for_release)
    {
      ctrl->server_local->app_ctx_marked_for_release = 0;
      release_application (ctrl->app_ctx);
      ctrl->app_ctx = NULL;
    }

  /* If we are already initialized for one specific application we
     need to check that the client didn't requested a specific
     application different from the one in use before we continue. */
  if (ctrl->app_ctx)
    return check_application_conflict (ctrl, apptype);

  /* Setup the slot and select the application.  */
  if (ctrl->reader_slot != -1)
    slot = ctrl->reader_slot;
  else
    slot = get_reader_slot ();
  ctrl->reader_slot = slot;
  if (slot == -1)
    err = gpg_error (reader_disabled? GPG_ERR_NOT_OPERATIONAL: GPG_ERR_CARD);
  else
    {
      /* Fixme: We should move the apdu_connect call to
         select_application.  */
      int sw;

      ctrl->server_local->disconnect_allowed = 0;
      sw = apdu_connect (slot);
      if (sw && sw != SW_HOST_ALREADY_CONNECTED)
        {
          if (sw == SW_HOST_NO_CARD)
            err = gpg_error (GPG_ERR_CARD_NOT_PRESENT);
          else
            err = gpg_error (GPG_ERR_CARD);
	}
      else
        err = select_application (ctrl, slot, apptype, &ctrl->app_ctx);
    }

  TEST_CARD_REMOVAL (ctrl, err);
  return err;
}


static const char hlp_serialno[] = 
  "SERIALNO [<apptype>]\n"
  "\n"
  "Return the serial number of the card using a status reponse.  This\n"
  "function should be used to check for the presence of a card.\n"
  "\n"
  "If APPTYPE is given, an application of that type is selected and an\n"
  "error is returned if the application is not supported or available.\n"
  "The default is to auto-select the application using a hardwired\n"
  "preference system.  Note, that a future extension to this function\n"
  "may allow to specify a list and order of applications to try.\n"
  "\n"
  "This function is special in that it can be used to reset the card.\n"
  "Most other functions will return an error when a card change has\n"
  "been detected and the use of this function is therefore required.\n"
  "\n"
  "Background: We want to keep the client clear of handling card\n"
  "changes between operations; i.e. the client can assume that all\n"
  "operations are done on the same card unless he calls this function.";
static gpg_error_t
cmd_serialno (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  char *serial_and_stamp;
  char *serial;
  time_t stamp;

  /* Clear the remove flag so that the open_card is able to reread it.  */
  if (!reader_disabled && ctrl->server_local->card_removed)
    {
      if ( IS_LOCKED (ctrl) )
        return gpg_error (GPG_ERR_LOCKED);
      do_reset (ctrl, 1);
    }

  if ((rc = open_card (ctrl, *line? line:NULL)))
    return rc;

  rc = app_get_serial_and_stamp (ctrl->app_ctx, &serial, &stamp);
  if (rc)
    return rc;

  rc = estream_asprintf (&serial_and_stamp, "%s %lu",
                         serial, (unsigned long)stamp);
  xfree (serial);
  if (rc < 0)
    return out_of_core ();
  rc = 0;
  assuan_write_status (ctx, "SERIALNO", serial_and_stamp);
  xfree (serial_and_stamp);
  return 0;
}


static const char hlp_learn[] = 
  "LEARN [--force] [--keypairinfo]\n"
  "\n"
  "Learn all useful information of the currently inserted card.  When\n"
  "used without the force options, the command might do an INQUIRE\n"
  "like this:\n"
  "\n"
  "   INQUIRE KNOWNCARDP <hexstring_with_serialNumber> <timestamp>\n"
  "\n"
  "The client should just send an \"END\" if the processing should go on\n"
  "or a \"CANCEL\" to force the function to terminate with a Cancel\n"
  "error message.\n"
  "\n"
  "With the option --keypairinfo only KEYPARIINFO lstatus lines are\n"
  "returned.\n"
  "\n"
  "The response of this command is a list of status lines formatted as\n"
  "this:\n"
  "\n"
  "  S APPTYPE <apptype>\n"
  "\n"
  "This returns the type of the application, currently the strings:\n"
  "\n"
  "    P15     = PKCS-15 structure used\n"
  "    DINSIG  = DIN SIG\n"
  "    OPENPGP = OpenPGP card\n"
  "    NKS     = NetKey card\n"
  "\n"
  "are implemented.  These strings are aliases for the AID\n"
  "\n"
  "  S KEYPAIRINFO <hexstring_with_keygrip> <hexstring_with_id>\n"
  "\n"
  "If there is no certificate yet stored on the card a single 'X' is\n"
  "returned as the keygrip.  In addition to the keypair info, information\n"
  "about all certificates stored on the card is also returned:\n"
  "\n"
  "  S CERTINFO <certtype> <hexstring_with_id>\n"
  "\n"
  "Where CERTTYPE is a number indicating the type of certificate:\n"
  "   0   := Unknown\n"
  "   100 := Regular X.509 cert\n"
  "   101 := Trusted X.509 cert\n"
  "   102 := Useful X.509 cert\n"
  "   110 := Root CA cert in a special format (e.g. DINSIG)\n"
  "   111 := Root CA cert as standard X509 cert.\n"
  "\n"
  "For certain cards, more information will be returned:\n"
  "\n"
  "  S KEY-FPR <no> <hexstring>\n"
  "\n"
  "For OpenPGP cards this returns the stored fingerprints of the\n"
  "keys. This can be used check whether a key is available on the\n"
  "card.  NO may be 1, 2 or 3.\n"
  "\n"
  "  S CA-FPR <no> <hexstring>\n"
  "\n"
  "Similar to above, these are the fingerprints of keys assumed to be\n"
  "ultimately trusted.\n"
  "\n"
  "  S DISP-NAME <name_of_card_holder>\n"
  "\n"
  "The name of the card holder as stored on the card; percent\n"
  "escaping takes place, spaces are encoded as '+'\n"
  "\n"
  "  S PUBKEY-URL <url>\n"
  "\n"
  "The URL to be used for locating the entire public key.\n"
  "  \n"
  "Note, that this function may even be used on a locked card.";
static gpg_error_t
cmd_learn (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;
  int only_keypairinfo = has_option (line, "--keypairinfo");

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  /* Unless the force option is used we try a shortcut by identifying
     the card using a serial number and inquiring the client with
     that. The client may choose to cancel the operation if he already
     knows about this card */
  if (!only_keypairinfo)
    {
      char *serial_and_stamp;
      char *serial;
      time_t stamp;
      
      rc = app_get_serial_and_stamp (ctrl->app_ctx, &serial, &stamp);
      if (rc)
        return rc;
      rc = estream_asprintf (&serial_and_stamp, "%s %lu",
                             serial, (unsigned long)stamp);
      xfree (serial);
      if (rc < 0)
        return out_of_core ();
      rc = 0;
      assuan_write_status (ctx, "SERIALNO", serial_and_stamp);
      
      if (!has_option (line, "--force"))
        {
          char *command;
          
          rc = estream_asprintf (&command, "KNOWNCARDP %s", serial_and_stamp);
          if (rc < 0)
            {
              xfree (serial_and_stamp);
              return out_of_core ();
            }
          rc = 0;
          rc = assuan_inquire (ctx, command, NULL, NULL, 0); 
          xfree (command);
          if (rc)
            {
              if (gpg_err_code (rc) != GPG_ERR_ASS_CANCELED)
                log_error ("inquire KNOWNCARDP failed: %s\n",
                           gpg_strerror (rc));
              xfree (serial_and_stamp);
              return rc; 
            }
          /* Not canceled, so we have to proceeed.  */
        }
      xfree (serial_and_stamp);
    }
  
  /* Let the application print out its collection of useful status
     information. */
  if (!rc)
    rc = app_write_learn_status (ctrl->app_ctx, ctrl, only_keypairinfo);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}



static const char hlp_readcert[] =
  "READCERT <hexified_certid>|<keyid>\n"
  "\n"
  "Note, that this function may even be used on a locked card.";
static gpg_error_t
cmd_readcert (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *cert;
  size_t ncert;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  line = xstrdup (line); /* Need a copy of the line. */
  rc = app_readcert (ctrl->app_ctx, line, &cert, &ncert);
  if (rc)
    log_error ("app_readcert failed: %s\n", gpg_strerror (rc));
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
  return rc;
}


static const char hlp_readkey[] = 
  "READKEY <keyid>\n"
  "\n"
  "Return the public key for the given cert or key ID as a standard\n"
  "S-expression.\n"
  "\n"
  "Note, that this function may even be used on a locked card.";
static gpg_error_t
cmd_readkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *cert = NULL;
  size_t ncert, n;
  ksba_cert_t kc = NULL;
  ksba_sexp_t p;
  unsigned char *pk;
  size_t pklen;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  line = xstrdup (line); /* Need a copy of the line. */
  /* If the application supports the READKEY function we use that.
     Otherwise we use the old way by extracting it from the
     certificate.  */
  rc = app_readkey (ctrl->app_ctx, line, &pk, &pklen);
  if (!rc)
    { /* Yeah, got that key - send it back.  */
      rc = assuan_send_data (ctx, pk, pklen);
      xfree (pk);
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
  xfree (p);


 leave:
  ksba_cert_release (kc);
  xfree (cert);
  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}



static const char hlp_setdata[] = 
  "SETDATA <hexstring> \n"
  "\n"
  "The client should use this command to tell us the data he want to sign.";
static gpg_error_t
cmd_setdata (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int n;
  char *p;
  unsigned char *buf;

  if (locked_session && locked_session != ctrl->server_local)
    return gpg_error (GPG_ERR_LOCKED);

  /* Parse the hexstring. */
  for (p=line,n=0; hexdigitp (p); p++, n++)
    ;
  if (*p)
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid hexstring");
  if (!n)
    return set_error (GPG_ERR_ASS_PARAMETER, "no data given");
  if ((n&1))
    return set_error (GPG_ERR_ASS_PARAMETER, "odd number of digits");
  n /= 2;
  buf = xtrymalloc (n);
  if (!buf)
    return out_of_core ();

  ctrl->in_data.value = buf;
  ctrl->in_data.valuelen = n;
  for (p=line, n=0; n < ctrl->in_data.valuelen; p += 2, n++)
    buf[n] = xtoi_2 (p);
  return 0;
}



static gpg_error_t 
pin_cb (void *opaque, const char *info, char **retstr)
{
  assuan_context_t ctx = opaque;
  char *command;
  int rc;
  unsigned char *value;
  size_t valuelen;

  if (!retstr)
    {
      /* We prompt for keypad entry.  To make sure that the popup has
         been show we use an inquire and not just a status message.
         We ignore any value returned.  */
      if (info)
        {
          log_debug ("prompting for keypad entry '%s'\n", info);
          rc = estream_asprintf (&command, "POPUPKEYPADPROMPT %s", info);
          if (rc < 0)
            return gpg_error (gpg_err_code_from_errno (errno));
          rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN); 
          xfree (command);  
        }
      else
        {
          log_debug ("dismiss keypad entry prompt\n");
          rc = assuan_inquire (ctx, "DISMISSKEYPADPROMPT",
                               &value, &valuelen, MAXLEN_PIN); 
        }
      if (!rc)
        xfree (value);
      return rc;
    }

  *retstr = NULL;
  log_debug ("asking for PIN '%s'\n", info);

  rc = estream_asprintf (&command, "NEEDPIN %s", info);
  if (rc < 0)
    return gpg_error (gpg_err_code_from_errno (errno));

  /* Fixme: Write an inquire function which returns the result in
     secure memory and check all further handling of the PIN. */
  rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN); 
  xfree (command);  
  if (rc)
    return rc;

  if (!valuelen || value[valuelen-1])
    {
      /* We require that the returned value is an UTF-8 string */
      xfree (value);
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }
  *retstr = (char*)value;
  return 0;
}


static const char hlp_pksign[] = 
  "PKSIGN [--hash=[rmd160|sha{1,224,256,384,512}|md5]] <hexified_id>\n"
  "\n"
  "The --hash option is optional; the default is SHA1.";
static gpg_error_t
cmd_pksign (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;
  int hash_algo;

  if (has_option (line, "--hash=rmd160"))
    hash_algo = GCRY_MD_RMD160;
  else if (has_option (line, "--hash=sha1"))
    hash_algo = GCRY_MD_SHA1;
  else if (has_option (line, "--hash=sha224"))
    hash_algo = GCRY_MD_SHA224;
  else if (has_option (line, "--hash=sha256"))
    hash_algo = GCRY_MD_SHA256;
  else if (has_option (line, "--hash=sha384"))
    hash_algo = GCRY_MD_SHA384;
  else if (has_option (line, "--hash=sha512"))
    hash_algo = GCRY_MD_SHA512;
  else if (has_option (line, "--hash=md5"))
    hash_algo = GCRY_MD_MD5;
  else if (!strstr (line, "--"))
    hash_algo = GCRY_MD_SHA1; 
  else
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid hash algorithm");

  line = skip_options (line);

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();
  
  rc = app_sign (ctrl->app_ctx,
                 keyidstr, hash_algo,
                 pin_cb, ctx,
                 ctrl->in_data.value, ctrl->in_data.valuelen,
                 &outdata, &outdatalen);

  xfree (keyidstr);
  if (rc)
    {
      log_error ("app_sign failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
      if (rc)
        return rc; /* that is already an assuan error code */
    }

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_pkauth[] = 
  "PKAUTH <hexified_id>";
static gpg_error_t
cmd_pkauth (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

 /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();
  
  rc = app_auth (ctrl->app_ctx,
                 keyidstr,
                 pin_cb, ctx,
                 ctrl->in_data.value, ctrl->in_data.valuelen,
                 &outdata, &outdatalen);
  xfree (keyidstr);
  if (rc)
    {
      log_error ("app_auth failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
      if (rc)
        return rc; /* that is already an assuan error code */
    }

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_pkdecrypt[] = 
  "PKDECRYPT <hexified_id>";
static gpg_error_t
cmd_pkdecrypt (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();
  rc = app_decipher (ctrl->app_ctx,
                     keyidstr, 
                     pin_cb, ctx,
                     ctrl->in_data.value, ctrl->in_data.valuelen,
                     &outdata, &outdatalen);

  xfree (keyidstr);
  if (rc)
    {
      log_error ("app_decipher failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
      if (rc)
        return rc; /* that is already an assuan error code */
    }

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_getattr[] = 
  "GETATTR <name>\n"
  "\n"
  "This command is used to retrieve data from a smartcard.  The\n"
  "allowed names depend on the currently selected smartcard\n"
  "application.  NAME must be percent and '+' escaped.  The value is\n"
  "returned through status message, see the LEARN command for details.\n"
  "\n"
  "However, the current implementation assumes that Name is not escaped;\n"
  "this works as long as noone uses arbitrary escaping. \n"
  "\n"
  "Note, that this function may even be used on a locked card.";
static gpg_error_t
cmd_getattr (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  const char *keyword;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  keyword = line;
  for (; *line && !spacep (line); line++)
    ;
  if (*line)
      *line++ = 0;

  /* (We ignore any garbage for now.) */

  /* FIXME: Applications should not return sensitive data if the card
     is locked.  */
  rc = app_getattr (ctrl->app_ctx, ctrl, keyword);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_setattr[] = 
  "SETATTR <name> <value> \n"
  "\n"
  "This command is used to store data on a a smartcard.  The allowed\n"
  "names and values are depend on the currently selected smartcard\n"
  "application.  NAME and VALUE must be percent and '+' escaped.\n"
  "\n"
  "However, the current implementation assumes that NAME is not\n"
  "escaped; this works as long as noone uses arbitrary escaping.\n"
  "\n"
  "A PIN will be requested for most NAMEs.  See the corresponding\n"
  "setattr function of the actually used application (app-*.c) for\n"
  "details.";
static gpg_error_t
cmd_setattr (assuan_context_t ctx, char *orig_line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyword;
  int keywordlen;
  size_t nbytes;
  char *line, *linebuf;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  /* We need to use a copy of LINE, because PIN_CB uses the same
     context and thus reuses the Assuan provided LINE. */
  line = linebuf = xtrystrdup (orig_line);
  if (!line)
    return out_of_core ();

  keyword = line;
  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  if (*line)
      *line++ = 0;
  while (spacep (line))
    line++;
  nbytes = percent_plus_unescape_inplace (line, 0);

  rc = app_setattr (ctrl->app_ctx, keyword, pin_cb, ctx,
                    (const unsigned char*)line, nbytes);
  xfree (linebuf);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_writecert[] = 
  "WRITECERT <hexified_certid>\n"
  "\n"
  "This command is used to store a certifciate on a smartcard.  The\n"
  "allowed certids depend on the currently selected smartcard\n"
  "application. The actual certifciate is requested using the inquiry\n"
  "\"CERTDATA\" and needs to be provided in its raw (e.g. DER) form.\n"
  "\n"
  "In almost all cases a a PIN will be requested.  See the related\n"
  "writecert function of the actually used application (app-*.c) for\n"
  "details.";
static gpg_error_t
cmd_writecert (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *certid;
  unsigned char *certdata;
  size_t certdatalen;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no certid given");
  certid = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  certid = xtrystrdup (certid);
  if (!certid)
    return out_of_core ();

  /* Now get the actual keydata. */
  rc = assuan_inquire (ctx, "CERTDATA",
                       &certdata, &certdatalen, MAXLEN_CERTDATA);
  if (rc)
    {
      xfree (certid);
      return rc;
    }

  /* Write the certificate to the card. */
  rc = app_writecert (ctrl->app_ctx, ctrl, certid, 
                      pin_cb, ctx, certdata, certdatalen);
  xfree (certid);
  xfree (certdata);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_writekey[] = 
  "WRITEKEY [--force] <keyid> \n"
  "\n"
  "This command is used to store a secret key on a a smartcard.  The\n"
  "allowed keyids depend on the currently selected smartcard\n"
  "application. The actual keydata is requested using the inquiry\n"
  "\"KEYDATA\" and need to be provided without any protection.  With\n"
  "--force set an existing key under this KEYID will get overwritten.\n"
  "The keydata is expected to be the usual canonical encoded\n"
  "S-expression.\n"
  "\n"
  "A PIN will be requested for most NAMEs.  See the corresponding\n"
  "writekey function of the actually used application (app-*.c) for\n"
  "details.";
static gpg_error_t
cmd_writekey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyid;
  int force = has_option (line, "--force");
  unsigned char *keydata;
  size_t keydatalen;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no keyid given");
  keyid = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  keyid = xtrystrdup (keyid);
  if (!keyid)
    return out_of_core ();

  /* Now get the actual keydata. */
  assuan_begin_confidential (ctx);
  rc = assuan_inquire (ctx, "KEYDATA", &keydata, &keydatalen, MAXLEN_KEYDATA);
  assuan_end_confidential (ctx);
  if (rc)
    {
      xfree (keyid);
      return rc;
    }

  /* Write the key to the card. */
  rc = app_writekey (ctrl->app_ctx, ctrl, keyid, force? 1:0,
                     pin_cb, ctx, keydata, keydatalen);
  xfree (keyid);
  xfree (keydata);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_genkey[] = 
  "GENKEY [--force] [--timestamp=<isodate>] <no>\n"
  "\n"
  "Generate a key on-card identified by NO, which is application\n"
  "specific.  Return values are application specific.  For OpenPGP\n"
  "cards 3 status lines are returned:\n"
  "\n"
  "  S KEY-FPR  <hexstring>\n"
  "  S KEY-CREATED-AT <seconds_since_epoch>\n"
  "  S KEY-DATA [-|p|n] <hexdata>\n"
  "\n"
  "  'p' and 'n' are the names of the RSA parameters; '-' is used to\n"
  "  indicate that HEXDATA is the first chunk of a parameter given\n"
  "  by the next KEY-DATA.\n"
  "\n"
  "--force is required to overwrite an already existing key.  The\n"
  "KEY-CREATED-AT is required for further processing because it is\n"
  "part of the hashed key material for the fingerprint.\n"
  "\n"
  "If --timestamp is given an OpenPGP key will be created using this\n"
  "value.  The value needs to be in ISO Format; e.g.\n"
  "\"--timestamp=20030316T120000\" and after 1970-01-01 00:00:00.\n"
  "\n"
  "The public part of the key can also later be retrieved using the\n"
  "READKEY command.";
static gpg_error_t
cmd_genkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *keyno;
  int force;
  const char *s;
  time_t timestamp;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  force = has_option (line, "--force");

  if ((s=has_option_name (line, "--timestamp")))
    {
      if (*s != '=')
        return set_error (GPG_ERR_ASS_PARAMETER, "missing value for option");
      timestamp = isotime2epoch (s+1);
      if (timestamp < 1)
        return set_error (GPG_ERR_ASS_PARAMETER, "invalid time value");
    }
  else
    timestamp = 0;


  line = skip_options (line);
  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no key number given");
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
    return out_of_core ();
  rc = app_genkey (ctrl->app_ctx, ctrl, keyno, force? 1:0,
                   timestamp, pin_cb, ctx);
  xfree (keyno);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_random[] = 
  "RANDOM <nbytes>\n"
  "\n"
  "Get NBYTES of random from the card and send them back as data.\n"
  "This usually involves EEPROM write on the card and thus excessive\n"
  "use of this command may destroy the card.\n"
  "\n"
  "Note, that this function may be even be used on a locked card.";
static gpg_error_t
cmd_random (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  size_t nbytes;
  unsigned char *buffer;

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, 
                      "number of requested bytes missing");
  nbytes = strtoul (line, NULL, 0);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  buffer = xtrymalloc (nbytes);
  if (!buffer)
    return out_of_core ();

  rc = app_get_challenge (ctrl->app_ctx, nbytes, buffer);
  if (!rc)
    {
      rc = assuan_send_data (ctx, buffer, nbytes);
      xfree (buffer);
      return rc; /* that is already an assuan error code */
    }
  xfree (buffer);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}



static const char hlp_passwd[] =
  "PASSWD [--reset] [--nullpin] <chvno>\n"
  "\n"
  "Change the PIN or, if --reset is given, reset the retry counter of\n"
  "the card holder verfication vector CHVNO.  The option --nullpin is\n"
  "used for TCOS cards to set the initial PIN.  The format of CHVNO\n"
  "depends on the card application.";
static gpg_error_t
cmd_passwd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *chvnostr;
  unsigned int flags = 0;

  if (has_option (line, "--reset"))
    flags |= APP_CHANGE_FLAG_RESET;
  if (has_option (line, "--nullpin"))
    flags |= APP_CHANGE_FLAG_NULLPIN;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no CHV number given");
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
    return out_of_core ();
  rc = app_change_pin (ctrl->app_ctx, ctrl, chvnostr, flags, pin_cb, ctx);
  if (rc)
    log_error ("command passwd failed: %s\n", gpg_strerror (rc));
  xfree (chvnostr);

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_checkpin[] = 
  "CHECKPIN <idstr>\n"
  "\n"
  "Perform a VERIFY operation without doing anything else.  This may\n"
  "be used to initialize a the PIN cache earlier to long lasting\n"
  "operations.  Its use is highly application dependent.\n"
  "\n"
  "For OpenPGP:\n"
  "\n"
  "   Perform a simple verify operation for CHV1 and CHV2, so that\n"
  "   further operations won't ask for CHV2 and it is possible to do a\n"
  "   cheap check on the PIN: If there is something wrong with the PIN\n"
  "   entry system, only the regular CHV will get blocked and not the\n"
  "   dangerous CHV3.  IDSTR is the usual card's serial number in hex\n"
  "   notation; an optional fingerprint part will get ignored.  There\n"
  "   is however a special mode if the IDSTR is sffixed with the\n"
  "   literal string \"[CHV3]\": In this case the Admin PIN is checked\n"
  "   if and only if the retry counter is still at 3.\n"
  "\n"
  "For Netkey:\n"
  "\n"
  "   Any of the valid PIN Ids may be used.  These are the strings:\n"
  "\n"
  "     PW1.CH       - Global password 1\n"
  "     PW2.CH       - Global password 2\n"
  "     PW1.CH.SIG   - SigG password 1\n"
  "     PW2.CH.SIG   - SigG password 2\n"
  "\n"
  "   For a definitive list, see the implementation in app-nks.c.\n"
  "   Note that we call a PW2.* PIN a \"PUK\" despite that since TCOS\n"
  "   3.0 they are technically alternative PINs used to mutally\n"
  "   unblock each other.";
static gpg_error_t
cmd_checkpin (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *idstr;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid. */
  idstr = xtrystrdup (line);
  if (!idstr)
    return out_of_core ();
  
  rc = app_check_pin (ctrl->app_ctx, idstr, pin_cb, ctx);
  xfree (idstr);
  if (rc)
    log_error ("app_check_pin failed: %s\n", gpg_strerror (rc));

  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_lock[] = 
  "LOCK [--wait]\n"
  "\n"
  "Grant exclusive card access to this session.  Note that there is\n"
  "no lock counter used and a second lock from the same session will\n"
  "be ignored.  A single unlock (or RESET) unlocks the session.\n"
  "Return GPG_ERR_LOCKED if another session has locked the reader.\n"
  "\n"
  "If the option --wait is given the command will wait until a\n"
  "lock has been released.";
static gpg_error_t
cmd_lock (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;

 retry:
  if (locked_session)
    {
      if (locked_session != ctrl->server_local)
        rc = gpg_error (GPG_ERR_LOCKED);
    }
  else
    locked_session = ctrl->server_local;

#ifdef USE_GNU_PTH
  if (rc && has_option (line, "--wait"))
    {
      rc = 0;
      pth_sleep (1); /* Better implement an event mechanism. However,
                        for card operations this should be
                        sufficient. */
      /* FIXME: Need to check that the connection is still alive.
         This can be done by issuing status messages. */
      goto retry;
    }
#endif /*USE_GNU_PTH*/
  
  if (rc)
    log_error ("cmd_lock failed: %s\n", gpg_strerror (rc));
  return rc;
}


static const char hlp_unlock[] = 
  "UNLOCK\n"
  "\n"
  "Release exclusive card access.";
static gpg_error_t
cmd_unlock (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc = 0;

  (void)line;

  if (locked_session)
    {
      if (locked_session != ctrl->server_local)
        rc = gpg_error (GPG_ERR_LOCKED);
      else
        locked_session = NULL;
    }
  else
    rc = gpg_error (GPG_ERR_NOT_LOCKED);

  if (rc)
    log_error ("cmd_unlock failed: %s\n", gpg_strerror (rc));
  return rc;
}


static const char hlp_getinfo[] = 
  "GETINFO <what>\n"
  "\n"
  "Multi purpose command to return certain information.  \n"
  "Supported values of WHAT are:\n"
  "\n"
  "version     - Return the version of the program.\n"
  "pid         - Return the process id of the server.\n"
  "\n"
  "socket_name - Return the name of the socket.\n"
  "\n"
  "status - Return the status of the current slot (in the future, may\n"
  "also return the status of all slots).  The status is a list of\n"
  "one-character flags.  The following flags are currently defined:\n"
  "  'u'  Usable card present.  This is the normal state during operation.\n"
  "  'r'  Card removed.  A reset is necessary.\n"
  "These flags are exclusive.\n"
  "\n"
  "reader_list - Return a list of detected card readers.  Does\n"
  "              currently only work with the internal CCID driver.\n"
  "\n"
  "deny_admin  - Returns OK if admin commands are not allowed or\n"
  "              GPG_ERR_GENERAL if admin commands are allowed.\n"
  "\n"
  "app_list    - Return a list of supported applications.  One\n"
  "              application per line, fields delimited by colons,\n"
  "              first field is the name.";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  int rc = 0;

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
  else if (!strcmp (line, "socket_name"))
    {
      const char *s = scd_get_socket_name ();

      if (s)
        rc = assuan_send_data (ctx, s, strlen (s));
      else
        rc = gpg_error (GPG_ERR_NO_DATA);
    }
  else if (!strcmp (line, "status"))
    {
      ctrl_t ctrl = assuan_get_pointer (ctx);
      int slot = ctrl->reader_slot;
      char flag = 'r';

      if (!ctrl->server_local->card_removed && slot != -1)
	{
	  struct slot_status_s *ss;
	  
	  if (!(slot >= 0 && slot < DIM(slot_table)))
	    BUG ();

	  ss = &slot_table[slot];

	  if (!ss->valid)
	    BUG ();

	  if (ss->any && (ss->status & 1))
	    flag = 'u';
	}
      rc = assuan_send_data (ctx, &flag, 1);
    }
  else if (!strcmp (line, "reader_list"))
    {
#ifdef HAVE_LIBUSB
      char *s = ccid_get_reader_list ();
#else
      char *s = NULL;
#endif
      
      if (s)
        rc = assuan_send_data (ctx, s, strlen (s));
      else
        rc = gpg_error (GPG_ERR_NO_DATA);
      xfree (s);
    }
  else if (!strcmp (line, "deny_admin"))
    rc = opt.allow_admin? gpg_error (GPG_ERR_GENERAL) : 0;
  else if (!strcmp (line, "app_list"))
    {
      char *s = get_supported_applications ();
      if (s)
        rc = assuan_send_data (ctx, s, strlen (s));
      else
        rc = 0;
      xfree (s);
    }
  else
    rc = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");
  return rc;
}


static const char hlp_restart[] = 
  "RESTART\n"
  "\n"
  "Restart the current connection; this is a kind of warm reset.  It\n"
  "deletes the context used by this connection but does not send a\n"
  "RESET to the card.  Thus the card itself won't get reset. \n"
  "\n"
  "This is used by gpg-agent to reuse a primary pipe connection and\n"
  "may be used by clients to backup from a conflict in the serial\n"
  "command; i.e. to select another application.";
static gpg_error_t
cmd_restart (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  if (ctrl->app_ctx)
    {
      release_application (ctrl->app_ctx);
      ctrl->app_ctx = NULL;
    }
  if (locked_session && ctrl->server_local == locked_session)
    {
      locked_session = NULL;
      log_info ("implicitly unlocking due to RESTART\n");
    }
  return 0;
}


static const char hlp_disconnect[] = 
  "DISCONNECT\n"
  "\n"
  "Disconnect the card if it is not any longer used by other\n"
  "connections and the backend supports a disconnect operation.";
static gpg_error_t
cmd_disconnect (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;
  
  ctrl->server_local->disconnect_allowed = 1;
  return 0;
}



static const char hlp_apdu[] = 
  "APDU [--atr] [--more] [--exlen[=N]] [hexstring]\n"
  "\n"
  "Send an APDU to the current reader.  This command bypasses the high\n"
  "level functions and sends the data directly to the card.  HEXSTRING\n"
  "is expected to be a proper APDU.  If HEXSTRING is not given no\n"
  "commands are set to the card but the command will implictly check\n"
  "whether the card is ready for use. \n"
  "\n"
  "Using the option \"--atr\" returns the ATR of the card as a status\n"
  "message before any data like this:\n"
  "  S CARD-ATR 3BFA1300FF813180450031C173C00100009000B1\n"
  "\n"
  "Using the option --more handles the card status word MORE_DATA\n"
  "(61xx) and concatenates all reponses to one block.\n"
  "\n"
  "Using the option \"--exlen\" the returned APDU may use extended\n"
  "length up to N bytes.  If N is not given a default value is used\n"
  "(currently 4096).";
static gpg_error_t
cmd_apdu (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *apdu;
  size_t apdulen;
  int with_atr;
  int handle_more;
  const char *s;
  size_t exlen;

  with_atr = has_option (line, "--atr");
  handle_more = has_option (line, "--more");

  if ((s=has_option_name (line, "--exlen")))
    {
      if (*s == '=')
        exlen = strtoul (s+1, NULL, 0);
      else
        exlen = 4096;
    }
  else
    exlen = 0;

  line = skip_options (line);

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((rc = open_card (ctrl, NULL)))
    return rc;

  if (with_atr)
    {
      unsigned char *atr;
      size_t atrlen;
      char hexbuf[400];
      
      atr = apdu_get_atr (ctrl->reader_slot, &atrlen);
      if (!atr || atrlen > sizeof hexbuf - 2 )
        {
          rc = gpg_error (GPG_ERR_INV_CARD);
          goto leave;
        }
      bin2hex (atr, atrlen, hexbuf);
      xfree (atr);
      send_status_info (ctrl, "CARD-ATR", hexbuf, strlen (hexbuf), NULL, 0);
    }

  apdu = hex_to_buffer (line, &apdulen);
  if (!apdu)
    {
      rc = gpg_error_from_syserror ();
      goto leave;
    }
  if (apdulen)
    {
      unsigned char *result = NULL;
      size_t resultlen;

      rc = apdu_send_direct (ctrl->reader_slot, exlen,
                             apdu, apdulen, handle_more,
                             &result, &resultlen);
      if (rc)
        log_error ("apdu_send_direct failed: %s\n", gpg_strerror (rc));
      else
        {
          rc = assuan_send_data (ctx, result, resultlen);
          xfree (result);
        }
    }
  xfree (apdu);

 leave:
  TEST_CARD_REMOVAL (ctrl, rc);
  return rc;
}


static const char hlp_killscd[] = 
  "KILLSCD\n"
  "\n"
  "Commit suicide.";
static gpg_error_t
cmd_killscd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  (void)line;

  ctrl->server_local->stopme = 1;
  return gpg_error (GPG_ERR_EOF);
}



/* Tell the assuan library about our commands */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    { "SERIALNO",     cmd_serialno, hlp_serialno },
    { "LEARN",        cmd_learn,    hlp_learn },
    { "READCERT",     cmd_readcert, hlp_readcert },
    { "READKEY",      cmd_readkey,  hlp_readkey },
    { "SETDATA",      cmd_setdata,  hlp_setdata },
    { "PKSIGN",       cmd_pksign,   hlp_pksign },
    { "PKAUTH",       cmd_pkauth,   hlp_pkauth },
    { "PKDECRYPT",    cmd_pkdecrypt,hlp_pkdecrypt },
    { "INPUT",        NULL }, 
    { "OUTPUT",       NULL }, 
    { "GETATTR",      cmd_getattr,  hlp_getattr },
    { "SETATTR",      cmd_setattr,  hlp_setattr },
    { "WRITECERT",    cmd_writecert,hlp_writecert },
    { "WRITEKEY",     cmd_writekey, hlp_writekey },
    { "GENKEY",       cmd_genkey,   hlp_genkey },
    { "RANDOM",       cmd_random,   hlp_random },
    { "PASSWD",       cmd_passwd,   hlp_passwd },
    { "CHECKPIN",     cmd_checkpin, hlp_checkpin },
    { "LOCK",         cmd_lock,     hlp_lock },
    { "UNLOCK",       cmd_unlock,   hlp_unlock },
    { "GETINFO",      cmd_getinfo,  hlp_getinfo },
    { "RESTART",      cmd_restart,  hlp_restart },
    { "DISCONNECT",   cmd_disconnect,hlp_disconnect },
    { "APDU",         cmd_apdu,     hlp_apdu },
    { "KILLSCD",      cmd_killscd,  hlp_killscd },
    { NULL }
  };
  int i, rc;

  for (i=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler,
                                    table[i].help);
      if (rc)
        return rc;
    } 
  assuan_set_hello_line (ctx, "GNU Privacy Guard's Smartcard server ready");

  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);
  return 0;
}


/* Startup the server.  If FD is given as -1 this is simple pipe
   server, otherwise it is a regular server.  Returns true if there
   are no more active asessions.  */
int
scd_command_handler (ctrl_t ctrl, int fd)
{
  int rc;
  assuan_context_t ctx = NULL;
  int stopme;
  
  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("failed to allocate assuan context: %s\n",
                 gpg_strerror (rc));
      scd_exit (2);
    }

  if (fd == -1)
    {
      assuan_fd_t filedes[2];

      filedes[0] = assuan_fdopen (0);
      filedes[1] = assuan_fdopen (1);
      rc = assuan_init_pipe_server (ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (ctx, INT2FD(fd),
				      ASSUAN_SOCKET_SERVER_ACCEPTED);
    }
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 gpg_strerror(rc));
      scd_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to register commands with Assuan: %s\n",
                 gpg_strerror(rc));
      scd_exit (2);
    }
  assuan_set_pointer (ctx, ctrl);

  /* Allocate and initialize the server object.  Put it into the list
     of active sessions. */
  ctrl->server_local = xcalloc (1, sizeof *ctrl->server_local);
  ctrl->server_local->next_session = session_list;
  session_list = ctrl->server_local;
  ctrl->server_local->ctrl_backlink = ctrl;
  ctrl->server_local->assuan_ctx = ctx;

  if (DBG_ASSUAN)
    assuan_set_log_stream (ctx, log_get_stream ());

  /* We open the reader right at startup so that the ticker is able to
     update the status file. */
  if (ctrl->reader_slot == -1)
    {
      ctrl->reader_slot = get_reader_slot ();
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

  /* Cleanup.  We don't send an explicit reset to the card.  */
  do_reset (ctrl, 0); 

  /* Release the server object.  */
  if (session_list == ctrl->server_local)
    session_list = ctrl->server_local->next_session;
  else
    {
      struct server_local_s *sl;
      
      for (sl=session_list; sl->next_session; sl = sl->next_session)
        if (sl->next_session == ctrl->server_local)
          break;
      if (!sl->next_session)
          BUG ();
      sl->next_session = ctrl->server_local->next_session;
    }
  stopme = ctrl->server_local->stopme || reader_disabled;
  xfree (ctrl->server_local);
  ctrl->server_local = NULL;

  /* Release the Assuan context.  */
  assuan_release (ctx);

  if (stopme)
    scd_exit (0);

  /* If there are no more sessions return true.  */
  return !session_list;
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


/* Send a ready formatted status line via assuan.  */
void
send_status_direct (ctrl_t ctrl, const char *keyword, const char *args)
{
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  if (strchr (args, '\n'))
    log_error ("error: LF detected in status line - not sending\n");
  else
    assuan_write_status (ctx, keyword, args);
}


/* Helper to send the clients a status change notification.  */
static void
send_client_notifications (void)
{
  struct {
    pid_t pid; 
#ifdef HAVE_W32_SYSTEM
    HANDLE handle;
#else
    int signo; 
#endif
  } killed[50];
  int killidx = 0;
  int kidx;
  struct server_local_s *sl;
  
  for (sl=session_list; sl; sl = sl->next_session)
    {
      if (sl->event_signal && sl->assuan_ctx)
        {
          pid_t pid = assuan_get_pid (sl->assuan_ctx);
#ifdef HAVE_W32_SYSTEM
          HANDLE handle = (void *)sl->event_signal;
          
          for (kidx=0; kidx < killidx; kidx++)
            if (killed[kidx].pid == pid 
                && killed[kidx].handle == handle)
              break;
          if (kidx < killidx)
            log_info ("event %lx (%p) already triggered for client %d\n",
                      sl->event_signal, handle, (int)pid);
          else
            {
              log_info ("triggering event %lx (%p) for client %d\n",
                        sl->event_signal, handle, (int)pid);
              if (!SetEvent (handle))
                log_error ("SetEvent(%lx) failed: %s\n",
                           sl->event_signal, w32_strerror (-1));
              if (killidx < DIM (killed))
                {
                  killed[killidx].pid = pid;
                  killed[killidx].handle = handle;
                  killidx++;
                }
            }
#else /*!HAVE_W32_SYSTEM*/
          int signo = sl->event_signal;
          
          if (pid != (pid_t)(-1) && pid && signo > 0)
            {
              for (kidx=0; kidx < killidx; kidx++)
                if (killed[kidx].pid == pid 
                    && killed[kidx].signo == signo)
                  break;
              if (kidx < killidx)
                log_info ("signal %d already sent to client %d\n",
                          signo, (int)pid);
              else
                {
                  log_info ("sending signal %d to client %d\n",
                            signo, (int)pid);
                  kill (pid, signo);
                  if (killidx < DIM (killed))
                    {
                      killed[killidx].pid = pid;
                      killed[killidx].signo = signo;
                      killidx++;
                    }
                }
            }
#endif /*!HAVE_W32_SYSTEM*/
        }
    }
}



/* This is the core of scd_update_reader_status_file but the caller
   needs to take care of the locking.  */
static void
update_reader_status_file (int set_card_removed_flag)
{
  int idx;
  unsigned int status, changed;

  /* Make sure that the reader has been opened.  Like get_reader_slot,
     this part of the code assumes that there is only one reader.  */
  if (!slot_table[0].valid)
    (void)get_reader_slot ();

  /* Note, that we only try to get the status, because it does not
     make sense to wait here for a operation to complete.  If we are
     busy working with a card, delays in the status file update should
     be acceptable. */
  for (idx=0; idx < DIM(slot_table); idx++)
    {
      struct slot_status_s *ss = slot_table + idx;
      struct server_local_s *sl;
      int sw_apdu;

      if (!ss->valid || ss->slot == -1)
        continue; /* Not valid or reader not yet open. */
      
      sw_apdu = apdu_get_status (ss->slot, 0, &status, &changed);
      if (sw_apdu == SW_HOST_NO_READER)
        {
          /* Most likely the _reader_ has been unplugged.  */
	  apdu_close_reader (ss->slot);
	  ss->valid = 0;
          status = 0;
          changed = ss->changed;
        }
      else if (sw_apdu)
        {
          /* Get status failed.  Ignore that.  */
          continue; 
        }

      if (!ss->any || ss->status != status || ss->changed != changed )
        {
          char *fname;
          char templ[50];
          FILE *fp;

          log_info ("updating slot %d status: 0x%04X->0x%04X (%u->%u)\n",
                    ss->slot, ss->status, status, ss->changed, changed);
          ss->status = status;
          ss->changed = changed;

	  /* FIXME: Should this be IDX instead of ss->slot?  This
	     depends on how client sessions will associate the reader
	     status with their session.  */
          snprintf (templ, sizeof templ, "reader_%d.status", ss->slot);
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
            
          /* If a status script is executable, run it. */
          {
            const char *args[9], *envs[2];
            char numbuf1[30], numbuf2[30], numbuf3[30];
            char *homestr, *envstr;
            gpg_error_t err;
            
            homestr = make_filename (opt.homedir, NULL);
            if (estream_asprintf (&envstr, "GNUPGHOME=%s", homestr) < 0)
              log_error ("out of core while building environment\n");
            else
              {
                envs[0] = envstr;
                envs[1] = NULL;

                sprintf (numbuf1, "%d", ss->slot);
                sprintf (numbuf2, "0x%04X", ss->status);
                sprintf (numbuf3, "0x%04X", status);
                args[0] = "--reader-port";
                args[1] = numbuf1; 
                args[2] = "--old-code";
                args[3] = numbuf2;  
                args[4] = "--new-code";
                args[5] = numbuf3; 
                args[6] = "--status";
                args[7] = ((status & 1)? "USABLE":
                           (status & 4)? "ACTIVE":
                           (status & 2)? "PRESENT": "NOCARD");
                args[8] = NULL;  

                fname = make_filename (opt.homedir, "scd-event", NULL);
                err = gnupg_spawn_process_detached (fname, args, envs);
                if (err && gpg_err_code (err) != GPG_ERR_ENOENT)
                  log_error ("failed to run event handler `%s': %s\n",
                             fname, gpg_strerror (err));
                xfree (fname);
                xfree (envstr);
              }
            xfree (homestr);
          }

          /* Set the card removed flag for all current sessions.  We
             will set this on any card change because a reset or
             SERIALNO request must be done in any case.  */
          if (ss->any && set_card_removed_flag)
            update_card_removed (idx, 1);
          
          ss->any = 1;

          /* Send a signal to all clients who applied for it.  */
          send_client_notifications ();
        }
      
      /* Check whether a disconnect is pending.  */
      if (opt.card_timeout)
        {
          for (sl=session_list; sl; sl = sl->next_session)
            if (!sl->disconnect_allowed)
              break; 
          if (session_list && !sl)
            {
              /* FIXME: Use a real timeout.  */
              /* At least one connection and all allow a disconnect.  */
              log_info ("disconnecting card in slot %d\n", ss->slot);
              apdu_disconnect (ss->slot);
            }
        }
      
    }
}

/* This function is called by the ticker thread to check for changes
   of the reader stati.  It updates the reader status files and if
   requested by the caller also send a signal to the caller.  */
void
scd_update_reader_status_file (void)
{
  if (!pth_mutex_acquire (&status_file_update_lock, 1, NULL))
    return; /* locked - give up. */
  update_reader_status_file (1);
  if (!pth_mutex_release (&status_file_update_lock))
    log_error ("failed to release status_file_update lock\n");
}

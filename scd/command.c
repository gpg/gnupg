/* command.c - SCdaemon command handler
 * Copyright (C) 2001, 2002, 2003, 2004, 2005,
 *               2007, 2008, 2009, 2011  Free Software Foundation, Inc.
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
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#ifdef USE_NPTH
# include <npth.h>
#endif

#include "scdaemon.h"
#include <assuan.h>
#include <ksba.h>
#include "iso7816.h"
#include "apdu.h" /* Required for apdu_*_reader (). */
#include "atr.h"
#ifdef HAVE_LIBUSB
#include "ccid-driver.h"
#endif
#include "../common/asshelp.h"
#include "../common/server-help.h"
#include "../common/ssh-utils.h"

/* Maximum length allowed as a PIN; used for INQUIRE NEEDPIN.  That
 * length needs to small compared to the maximum Assuan line length.  */
#define MAXLEN_PIN 100

/* Maximum allowed size of key data as used in inquiries. */
#define MAXLEN_KEYDATA 4096

/* Maximum allowed total data size for SETDATA.  */
#define MAXLEN_SETDATA 4096

/* Maximum allowed size of certificate data as used in inquiries. */
#define MAXLEN_CERTDATA 16384

/* Maximum allowed size for "SETATTR --inquire". */
#define MAXLEN_SETATTRDATA 16384


#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))

#define IS_LOCKED(c) (locked_session && locked_session != (c)->server_local)


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
  void *event_signal;           /* Or NULL if not used. */
#else
  int event_signal;             /* Or 0 if not used. */
#endif

  /* True if the card has been removed and a reset is required to
     continue operation. */
  unsigned int card_removed:1;

  /* If set to true we will be terminate ourself at the end of the
     this session.  */
  unsigned int stopme:1;

  /* If set to true, status change will be reported. */
  unsigned int watching_status:1;
};


/* To keep track of all running sessions, we link all active server
   contexts and the anchor in this variable.  */
static struct server_local_s *session_list;

/* If a session has been locked we store a link to its server object
   in this variable. */
static struct server_local_s *locked_session;



/*  Local prototypes.  */
static int command_has_option (const char *cmd, const char *cmdopt);



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
   way of calling the function.  If KEEP_LOCK is set and the session
   is locked that lock wil not be released.  */
static void
do_reset (ctrl_t ctrl, int send_reset, int keep_lock)
{
  card_t card = card_get (ctrl, NULL);

  if (card)
    {
      if (!IS_LOCKED (ctrl) && send_reset)
        card_reset (card);
      else
        {
          ctrl->card_ctx = NULL;
          ctrl->current_apptype = APPTYPE_NONE;
          card_unref_locked (card);
        }
      card_put (card);
    }

  /* If we hold a lock, unlock now. */
  if (!keep_lock && locked_session && ctrl->server_local == locked_session)
    {
      locked_session = NULL;
      log_info ("implicitly unlocking due to RESET\n");
    }
}



static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);

  do_reset (ctrl, 1, has_option (line, "--keep-lock"));
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
#ifdef _WIN64
      ctrl->server_local->event_signal = (void *)strtoull (value, NULL, 16);
#else
      ctrl->server_local->event_signal = (void *)strtoul (value, NULL, 16);
#endif
#else
      int i = *value? atoi (value) : -1;
      if (i < 0)
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      ctrl->server_local->event_signal = i;
#endif
    }

 return 0;
}


/* If the card has not yet been opened, do it.  */
static gpg_error_t
open_card (ctrl_t ctrl)
{
  /* If we ever got a card not present error code, return that.  Only
     the SERIALNO command and a reset are able to clear from that
     state. */
  if (ctrl->server_local->card_removed)
    return gpg_error (GPG_ERR_CARD_REMOVED);

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if (ctrl->card_ctx)
    return 0;

  return select_application (ctrl, NULL, 0, NULL, 0);
}

/* Explicitly open a card for a specific use of APPTYPE or SERIALNO.
 * If OPT_ALL is set also add all possible additional apps. */
static gpg_error_t
open_card_with_request (card_t *card_p, ctrl_t ctrl,
                        const char *apptypestr, const char *serialno,
                        int opt_all)
{
  gpg_error_t err;
  unsigned char *serialno_bin = NULL;
  size_t serialno_bin_len = 0;
  card_t card = card_get (ctrl, NULL);

  if (serialno)
    serialno_bin = hex_to_buffer (serialno, &serialno_bin_len);

  /* If we are already initialized for one specific application we
     need to check that the client didn't requested a specific
     application different from the one in use before we continue. */
  if (apptypestr && card)
    {
      err = check_application_conflict (card, apptypestr,
                                        serialno_bin, serialno_bin_len);
      if (gpg_err_code (err) == GPG_ERR_FALSE)
        {
          /* Different application but switching is supported.  */
          err = select_additional_application (card, ctrl, apptypestr);
        }
      if (err)
	card_put (card);
      goto leave;
    }

  /* Re-scan USB devices.  Release CARD, before the scan.  */
  if (card)
    {
      ctrl->card_ctx = NULL;
      ctrl->current_apptype = APPTYPE_NONE;
      card_unref_locked (card);
      card_put (card);
    }

  err = select_application (ctrl, apptypestr, 1,
                            serialno_bin, serialno_bin_len);
  card = card_get (ctrl, NULL);
  if (!err && opt_all)
    {
      if (card)
        {
          err = select_additional_application (card, ctrl, NULL);
	  if (err)
	    card_put (card);
        }
    }

 leave:
  if (!err)
    *card_p = card;
  xfree (serialno_bin);
  return err;
}


static const char hlp_serialno[] =
  "SERIALNO [--demand=<serialno>] [--all] [<apptype>]\n"
  "\n"
  "Return the serial number of the card using a status response.  This\n"
  "function should be used to check for the presence of a card.\n"
  "\n"
  "If --demand is given, an application on the card with SERIALNO is\n"
  "selected and an error is returned if no such card available.\n"
  "\n"
  "If --all is given, all possible other applications of the card are\n"
  "also selected to prepare for things like \"LEARN --force --multi\".\n"
  "\n"
  "If APPTYPE is given, an application of that type is selected and an\n"
  "error is returned if the application is not supported or available.\n"
  "The default is to auto-select the application using a hardwired\n"
  "preference system.\n"
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
  struct server_local_s *sl;
  gpg_error_t err = 0;
  char *serial;
  const char *demand;
  int opt_all = has_option (line, "--all");
  card_t card = NULL;
  int thisslot;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((demand = has_option_name (line, "--demand")))
    {
      if (*demand != '=')
        return set_error (GPG_ERR_ASS_PARAMETER, "missing value for option");
      line = (char *)++demand;
      while (*line && !spacep (line))
        line++;
      if (*line)
        *line++ = 0;
    }
  else
    demand = NULL;

  line = skip_options (line);

  /* Clear the remove flag so that the open_card is able to reread it.  */
  ctrl->server_local->card_removed = 0;
  err = open_card_with_request (&card, ctrl, *line? line:NULL, demand, opt_all);
  /* Now clear or set the card_removed flag for all sessions using the
   * current slot.  In the error case make sure that the flag is set
   * for the current session. */
  thisslot = card? card->slot : -1;
  for (sl=session_list; sl; sl = sl->next_session)
    {
      ctrl_t c = sl->ctrl_backlink;
      if (c && c->card_ctx && c->card_ctx->slot == thisslot)
        c->server_local->card_removed = err? 1 : 0;
    }
  if (err)
    {
      ctrl->server_local->card_removed = 1;
      return err;
    }

  serial = card_get_serialno (card);
  card_put (card);
  if (!serial)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = assuan_write_status (ctx, "SERIALNO", serial);
  xfree (serial);
  return err;
}



static const char hlp_switchcard[] =
  "SWITCHCARD [<serialno>]\n"
  "\n"
  "Make the card with SERIALNO the current card.\n"
  "The command \"getinfo card_list\" can be used to list\n"
  "the serial numbers of inserted and known cards.  Note\n"
  "that the command \"SERIALNO\" can be used to refresh\n"
  "the list of known cards.  A simple SERIALNO status\n"
  "is printed on success.";
static gpg_error_t
cmd_switchcard (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  unsigned char *sn_bin = NULL;
  size_t sn_bin_len = 0;

  if ((err = open_card (ctrl)))
    return err;

  line = skip_options (line);

  if (*line)
    {
      sn_bin = hex_to_buffer (line, &sn_bin_len);
      if (!sn_bin)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* Note that an SN_BIN of NULL will only print the status.  */
  err = app_switch_current_card (ctrl, sn_bin, sn_bin_len);

 leave:
  xfree (sn_bin);
  return err;
}


static const char hlp_switchapp[] =
  "SWITCHAPP [<appname>]\n"
  "\n"
  "Make APPNAME the active application for the current card.\n"
  "Only some cards support switching between application; the\n"
  "command \"getinfo active_app\" can be used to get a list of\n"
  "applications which can be switched to.  A SERIALNO status\n"
  "including the active appname is printed on success.";
static gpg_error_t
cmd_switchapp (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  card_t card;

  if ((err = open_card (ctrl)))
    return err;

  line = skip_options (line);
  card = card_get (ctrl, NULL);
  if (card)
    {
      err = app_switch_active_app (card, ctrl, line);
      card_put (card);
    }
  else
    err = gpg_error (GPG_ERR_CARD_NOT_PRESENT);

  return err;
}


static const char hlp_learn[] =
  "LEARN [--force] [--keypairinfo] [--reread] [--multi]\n"
  "\n"
  "Learn all useful information of the currently inserted card.  When\n"
  "used without the force options, the command might do an INQUIRE\n"
  "like this:\n"
  "\n"
  "   INQUIRE KNOWNCARDP <hexstring_with_serialNumber>\n"
  "\n"
  "The client should just send an \"END\" if the processing should go on\n"
  "or a \"CANCEL\" to force the function to terminate with a Cancel\n"
  "error message.\n"
  "\n"
  "With the option --keypairinfo only KEYPAIRINFO status lines are\n"
  "returned.  With the option --reread information from the card are\n"
  "read again without the need for a reset (sone some cards).\n"
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
  "    PIV     = PIV card\n"
  "    NKS     = NetKey card\n"
  "\n"
  "are implemented.  These strings are aliases for the AID.  With option\n"
  "--multi information for all switchable apps are returned.\n"
  "\n"
  "  S KEYPAIRINFO <hexgrip> <keyref> [<usage>] [<keytime>] [<algo>]\n"
  "\n"
  "If there is no certificate yet stored on the card a single 'X' is\n"
  "returned as the keygrip.  For more info see doc/DETAILS.  In addition\n"
  "to the keypair info, information about all certificates stored on the\n"
  "card is also returned:\n"
  "\n"
  "  S CERTINFO <certtype> <keyref> [<label>]\n"
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
  "  S KEY-FPR <keyref> <hexstring>\n"
  "\n"
  "For some cards this returns the stored fingerprints of the\n"
  "keys. This can be used check whether a key is available on the\n"
  "card.  KEYREF may be 1, 2 or 3 for OpenPGP or a standard keyref.\n"
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
  int opt_multi = has_option (line, "--multi");
  int opt_reread = has_option (line, "--reread");
  int opt_force = has_option (line, "--force");
  unsigned int flags;
  card_t card;
  const char *keygrip = NULL;

  if ((rc = open_card (ctrl)))
    return rc;

  line = skip_options (line);
  if (strlen (line) == 40)
    keygrip = line;

  card = card_get (ctrl, keygrip);
  if (!card)
    return gpg_error (GPG_ERR_CARD_NOT_PRESENT);

  /* Unless the force option is used we try a shortcut by identifying
     the card using a serial number and inquiring the client with
     that. The client may choose to cancel the operation if he already
     knows about this card */
  if (!only_keypairinfo)
    {
      const char *reader;
      char *serial;

      reader = apdu_get_reader_name (card->slot);
      if (!reader)
        {
          card_put (card);
          return out_of_core ();
        }
      send_status_direct (ctrl, "READER", reader);
      /* No need to free the string of READER.  */

      serial = card_get_serialno (card);
      if (!serial)
        {
          card_put (card);
          return gpg_error (GPG_ERR_INV_VALUE);
        }

      rc = assuan_write_status (ctx, "SERIALNO", serial);
      if (rc < 0)
        {
          xfree (serial);
          card_put (card);
          return out_of_core ();
        }

      if (!opt_force)
        {
          char *command;

          rc = gpgrt_asprintf (&command, "KNOWNCARDP %s", serial);
          if (rc < 0)
            {
              xfree (serial);
              card_put (card);
              return out_of_core ();
            }
          rc = assuan_inquire (ctx, command, NULL, NULL, 0);
          xfree (command);
          if (rc)
            {
              if (gpg_err_code (rc) != GPG_ERR_ASS_CANCELED)
                log_error ("inquire KNOWNCARDP failed: %s\n",
                           gpg_strerror (rc));
              xfree (serial);
              card_put (card);
              return rc;
            }
          /* Not canceled, so we have to proceed.  */
        }
      xfree (serial);
    }

  /* Let the application print out its collection of useful status
     information. */
  flags = 0;
  if (only_keypairinfo)
    flags |= APP_LEARN_FLAG_KEYPAIRINFO;
  if (opt_multi)
    flags |= APP_LEARN_FLAG_MULTI;
  if (opt_reread)
    flags |= APP_LEARN_FLAG_REREAD;

  if (!rc)
    rc = app_write_learn_status (card, ctrl, flags);

  card_put (card);
  return rc;
}



static const char hlp_readcert[] =
  "READCERT <hexified_certid>|<keyid>|<oid>\n"
  "\n"
  "Note, that this function may even be used on a locked card.";
static gpg_error_t
cmd_readcert (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *cert;
  size_t ncert;
  card_t card;
  const char *keygrip = NULL;

  if ((rc = open_card (ctrl)))
    return rc;

  line = xtrystrdup (line); /* Need a copy of the line. */
  if (!line)
    return gpg_error_from_syserror ();

  if (strlen (line) == 40)
    keygrip = line;

  card = card_get (ctrl, keygrip);
  if (!card)
    {
      xfree (line);
      return gpg_error (GPG_ERR_CARD_NOT_PRESENT);
    }

  rc = app_readcert (card, ctrl, line, &cert, &ncert);
  if (rc)
    log_error ("app_readcert failed: %s\n", gpg_strerror (rc));
  card_put (card);
  xfree (line);
  line = NULL;
  if (!rc)
    {
      rc = assuan_send_data (ctx, cert, ncert);
      xfree (cert);
      if (rc)
        return rc;
    }

  return rc;
}


static gpg_error_t
do_readkey (card_t card, ctrl_t ctrl, const char *line,
            int opt_info, unsigned char **pk_p, size_t *pklen_p)
{
  int rc;
  int direct_readkey = 0;

  /* If the application supports the READKEY function we use that.
     Otherwise we use the old way by extracting it from the
     certificate.  */
  rc = app_readkey (card, ctrl, line,
                    opt_info? APP_READKEY_FLAG_INFO : 0,
                    pk_p, pklen_p);
  if (!rc)
    direct_readkey = 1; /* Got the key.  */
  else if (gpg_err_code (rc) == GPG_ERR_UNSUPPORTED_OPERATION
           || gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
    {
      /* Fall back to certificate reading.  */
      unsigned char *cert = NULL;
      size_t ncert;

      rc = app_readcert (card, ctrl, line, &cert, &ncert);
      if (rc)
        log_error ("app_readcert failed: %s\n", gpg_strerror (rc));
      else
        {
          rc = app_help_pubkey_from_cert (cert, ncert, pk_p, pklen_p);
          xfree (cert);
          if (rc)
            log_error ("failed to parse the certificate: %s\n",
                       gpg_strerror (rc));
        }
    }
  else
    log_error ("app_readkey failed: %s\n", gpg_strerror (rc));

  if (!rc && opt_info && !direct_readkey)
    {
      char keygripstr[KEYGRIP_LEN*2+1];
      char *algostr;

      rc = app_help_get_keygrip_string_pk (*pk_p, *pklen_p,
                                           keygripstr, NULL, NULL,
                                           &algostr);
      if (rc)
        {
          log_error ("app_help_get_keygrip_string failed: %s\n",
                     gpg_strerror (rc));
          return rc;
        }

      /* FIXME: Using LINE is not correct because it might be an
       * OID and has not been canonicalized (i.e. uppercased).  */
      send_status_info (ctrl, "KEYPAIRINFO",
                        keygripstr, strlen (keygripstr),
                        line, strlen (line),
                        "-", (size_t)1,
                        "-", (size_t)1,
                        algostr, strlen (algostr),
                        NULL, (size_t)0);
      xfree (algostr);
    }

  return rc;
}

static const char hlp_readkey[] =
  "READKEY [--format=advanced|ssh] [--info[-only]] <keyid>|<oid>|<keygrip>\n"
  "\n"
  "Return the public key for the given cert or key ID as a standard\n"
  "S-expression.  With --format option, it may be returned in advanced\n"
  "S-expression format, or SSH format.  With --info a KEYPAIRINFO\n"
  "status line is also emitted; with --info-only the regular output is\n"
  "suppressed.";
static gpg_error_t
cmd_readkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  int advanced = 0;
  int ssh = 0;
  int opt_info = 0;
  int opt_nokey = 0;
  unsigned char *pk = NULL;
  size_t pklen;
  card_t card;
  const char *keygrip = NULL;

  if ((err = open_card (ctrl)))
    return err;

  if (has_option (line, "--advanced"))
    advanced = 1;
  if (has_option (line, "--format=advanced"))
    advanced = 1;
  if (has_option (line, "--format=ssh"))
    ssh = 1;
  if (has_option (line, "--info"))
    opt_info = 1;
  if (has_option (line, "--info-only"))
    opt_info = opt_nokey = 1;

  line = skip_options (line);

  line = xtrystrdup (line); /* Need a copy of the line. */
  if (!line)
    return gpg_error_from_syserror ();

  if (strlen (line) == 40)
    keygrip = line;

  card = card_get (ctrl, keygrip);
  if (card)
    {
      err = do_readkey (card, ctrl, line, opt_info, &pk, &pklen);
      card_put (card);
    }
  else
    err = gpg_error (GPG_ERR_NO_SECKEY);

  if (err)
    goto leave;

  if (opt_nokey)
    ;
  else if (ssh)
    {
      estream_t stream = NULL;
      gcry_sexp_t s_key;
      void *buf = NULL;
      size_t buflen;

      stream = es_fopenmem (0, "r+b");
      if (!stream)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      err = gcry_sexp_new (&s_key, pk, pklen, 0);
      if (err)
        {
          es_fclose (stream);
          goto leave;
        }

      err = ssh_public_key_in_base64 (s_key, stream, "(none)");
      if (err)
        {
          gcry_sexp_release (s_key);
          es_fclose (stream);
          goto leave;
        }

      err = es_fclose_snatch (stream, &buf, &buflen);
      gcry_sexp_release (s_key);
      if (!err)
        err = assuan_send_data (ctx, buf, buflen);
    }
  else if (advanced)
    {
      gcry_sexp_t s_key;
      unsigned char *pkadv;
      size_t pkadvlen;

      err = gcry_sexp_new (&s_key, pk, pklen, 0);
      if (err)
        goto leave;

      pkadvlen = gcry_sexp_sprint (s_key, GCRYSEXP_FMT_ADVANCED, NULL, 0);
      pkadv = xtrymalloc (pkadvlen);
      if (!pkadv)
        {
          err = gpg_error_from_syserror ();
          gcry_sexp_release (s_key);
          goto leave;
        }
      log_assert (pkadvlen);

      gcry_sexp_sprint (s_key, GCRYSEXP_FMT_ADVANCED, pkadv, pkadvlen);
      gcry_sexp_release (s_key);
      /* (One less to adjust for the trailing '\0') */
      err = assuan_send_data (ctx, pkadv, pkadvlen-1);
      xfree (pkadv);
    }
  else
    err = assuan_send_data (ctx, pk, pklen);

 leave:
  xfree (pk);
  xfree (line);
  return err;
}



static const char hlp_setdata[] =
  "SETDATA [--append] <hexstring>\n"
  "\n"
  "The client should use this command to tell us the data he want to sign.\n"
  "With the option --append, the data is appended to the data set by a\n"
  "previous SETDATA command.";
static gpg_error_t
cmd_setdata (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int append;
  int n, i, off;
  char *p;
  unsigned char *buf;

  append = (ctrl->in_data.value && has_option (line, "--append"));

  line = skip_options (line);

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
  if (append)
    {
      if (ctrl->in_data.valuelen + n > MAXLEN_SETDATA)
        return set_error (GPG_ERR_TOO_LARGE,
                          "limit on total size of data reached");
      buf = xtrymalloc (ctrl->in_data.valuelen + n);
    }
  else
    buf = xtrymalloc (n);
  if (!buf)
    return out_of_core ();

  if (append)
    {
      memcpy (buf, ctrl->in_data.value, ctrl->in_data.valuelen);
      off = ctrl->in_data.valuelen;
    }
  else
    off = 0;
  for (p=line, i=0; i < n; p += 2, i++)
    buf[off+i] = xtoi_2 (p);

  xfree (ctrl->in_data.value);
  ctrl->in_data.value = buf;
  ctrl->in_data.valuelen = off+n;
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
      /* We prompt for pinpad entry.  To make sure that the popup has
         been show we use an inquire and not just a status message.
         We ignore any value returned.  */
      if (info)
        {
          log_debug ("prompting for pinpad entry '%s'\n", info);
          rc = gpgrt_asprintf (&command, "POPUPPINPADPROMPT %s", info);
          if (rc < 0)
            return gpg_error (gpg_err_code_from_errno (errno));
          rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN);
          xfree (command);
        }
      else
        {
          log_debug ("dismiss pinpad entry prompt\n");
          rc = assuan_inquire (ctx, "DISMISSPINPADPROMPT",
                               &value, &valuelen, MAXLEN_PIN);
        }
      if (!rc)
        xfree (value);
      return rc;
    }

  *retstr = NULL;
  log_debug ("asking for PIN '%s'\n", info);

  rc = gpgrt_asprintf (&command, "NEEDPIN %s", info);
  if (rc < 0)
    return gpg_error (gpg_err_code_from_errno (errno));

  /* Fixme: Write an inquire function which returns the result in
     secure memory and check all further handling of the PIN. */
  assuan_begin_confidential (ctx);
  rc = assuan_inquire (ctx, command, &value, &valuelen, MAXLEN_PIN);
  assuan_end_confidential (ctx);
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
  "PKSIGN [--hash=[rmd160|sha{1,224,256,384,512}|md5|none]] <hexified_id>\n"
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
  card_t card;
  const char *keygrip = NULL;

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
  else if (has_option (line, "--hash=none"))  /* For raw RSA.  */
    hash_algo = 0;
  else if (!strstr (line, "--"))
    hash_algo = GCRY_MD_SHA1;
  else
    return set_error (GPG_ERR_ASS_PARAMETER, "invalid hash algorithm");

  line = skip_options (line);

  if ((rc = open_card (ctrl)))
    return rc;

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();

  /* When it's a keygrip, we directly use the card, with no change of
     ctrl->card_ctx. */
  if (strlen (keyidstr) == 40)
    keygrip = keyidstr;

  card = card_get (ctrl, keygrip);
  if (card)
    {
      rc = app_sign (card, ctrl,
                     keyidstr, hash_algo,
                     pin_cb, ctx,
                     ctrl->in_data.value, ctrl->in_data.valuelen,
                     &outdata, &outdatalen);
      card_put (card);
    }
  else
    rc = gpg_error (GPG_ERR_NO_SECKEY);

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

  return rc;
}


static const char hlp_pkauth[] =
  "PKAUTH [--challenge-response] <hexified_id>";
static gpg_error_t
cmd_pkauth (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  unsigned char *outdata;
  size_t outdatalen;
  char *keyidstr;
  card_t card;
  const char *keygrip = NULL;
  int challenge_response = 0;

  if ((rc = open_card (ctrl)))
    return rc;

  if (has_option (line, "--challenge-response"))
    challenge_response = 1;

  line = skip_options (line);

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();

  /* When it's a keygrip, we directly use CARD, with no change of
     ctrl->card_ctx. */
  if (strlen (keyidstr) == 40)
    keygrip = keyidstr;

  if (challenge_response)
    {
      xfree (ctrl->in_data.value);
      ctrl->in_data.value = NULL;
      ctrl->in_data.valuelen = 0;
    }

  card = card_get (ctrl, keygrip);
  if (card)
    {
      rc = app_auth (card, ctrl, keyidstr, pin_cb, ctx,
                     ctrl->in_data.value, ctrl->in_data.valuelen,
                     &outdata, &outdatalen);
      card_put (card);
    }
  else
    rc = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  xfree (keyidstr);
  if (rc)
    {
      log_error ("app_auth failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      if (!challenge_response)
        rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
    }

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
  unsigned int infoflags;
  card_t card;
  const char *keygrip = NULL;

  if ((rc = open_card (ctrl)))
    return rc;

  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();

  /* When it's a keygrip, we directly use CARD, with no change of
     ctrl->card_ctx. */
  if (strlen (keyidstr) == 40)
    keygrip = keyidstr;

  card = card_get (ctrl, keygrip);
  if (card)
    {
      rc = app_decipher (card, ctrl, keyidstr, pin_cb, ctx,
                         ctrl->in_data.value, ctrl->in_data.valuelen,
                         &outdata, &outdatalen, &infoflags);
      card_put (card);
    }
  else
    rc = gpg_error (GPG_ERR_NO_SECKEY);

  xfree (keyidstr);
  if (rc)
    {
      log_error ("app_decipher failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      /* If the card driver told us that there is no padding, send a
         status line.  If there is a padding it is assumed that the
         caller knows what padding is used.  It would have been better
         to always send that information but for backward
         compatibility we can't do that.  */
      if ((infoflags & APP_DECIPHER_INFO_NOPAD))
        send_status_direct (ctrl, "PADDING", "0");
      rc = assuan_send_data (ctx, outdata, outdatalen);
      xfree (outdata);
      if (rc)
        return rc; /* that is already an assuan error code */
    }

  return rc;
}


static const char hlp_getattr[] =
  "GETATTR <name> [<keygrip>]\n"
  "\n"
  "This command is used to retrieve data from a smartcard.  The\n"
  "allowed names depend on the currently selected smartcard\n"
  "application.  NAME must be percent and '+' escaped.  The value is\n"
  "returned through status message, see the LEARN command for details.\n"
  "\n"
  "However, the current implementation assumes that Name is not escaped;\n"
  "this works as long as no one uses arbitrary escaping. \n"
  "\n"
  "Note, that this function may even be used on a locked card.\n"
  "When KEYGRIP is specified, it accesses directly with the KEYGRIP.";
static gpg_error_t
cmd_getattr (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  const char *keyword;
  card_t card;
  const char *keygrip = NULL;

  if ((rc = open_card (ctrl)))
    return rc;

  keyword = line;
  while (*line && !spacep (line))
    line++;
  if (*line)
    *line++ = 0;

  if (strlen (line) == 40)
    keygrip = line;

  card = card_get (ctrl, keygrip);
  if (card)
    {
      /* FIXME: Applications should not return sensitive data if the card
         is locked.  */
      rc = app_getattr (card, ctrl, keyword);
      card_put (card);
    }
  else
    rc = gpg_error (GPG_ERR_NO_SECKEY);

  return rc;
}


static const char hlp_setattr[] =
  "SETATTR [--inquire] <name> <value> \n"
  "\n"
  "This command is used to store data on a smartcard.  The allowed\n"
  "names and values are depend on the currently selected smartcard\n"
  "application.  NAME and VALUE must be percent and '+' escaped.\n"
  "\n"
  "However, the current implementation assumes that NAME is not\n"
  "escaped; this works as long as no one uses arbitrary escaping.\n"
  "\n"
  "If the option --inquire is used, VALUE shall not be given; instead\n"
  "an inquiry using the keyword \"VALUE\" is used to retrieve it.  The\n"
  "value is in this case considered to be confidential and not logged.\n"
  "\n"
  "A PIN will be requested for most NAMEs.  See the corresponding\n"
  "setattr function of the actually used application (app-*.c) for\n"
  "details.";
static gpg_error_t
cmd_setattr (assuan_context_t ctx, char *orig_line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  char *keyword;
  int keywordlen;
  size_t nbytes;
  char *line, *linebuf;
  int opt_inquire;
  card_t card;

  opt_inquire = has_option (orig_line, "--inquire");
  orig_line = skip_options (orig_line);

  if ((err = open_card (ctrl)))
    return err;

  /* We need to use a copy of LINE, because PIN_CB uses the same
     context and thus reuses the Assuan provided LINE. */
  line = linebuf = xtrystrdup (orig_line);
  if (!line)
    return out_of_core ();

  card = card_get (ctrl, NULL);
  if (!card)
    {
      xfree (linebuf);
      return gpg_error (GPG_ERR_CARD_NOT_PRESENT);
    }

  keyword = line;
  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  if (*line)
      *line++ = 0;
  while (spacep (line))
    line++;
  if (opt_inquire)
    {
      unsigned char *value;

      assuan_begin_confidential (ctx);
      err = assuan_inquire (ctx, "VALUE", &value, &nbytes, MAXLEN_SETATTRDATA);
      assuan_end_confidential (ctx);
      if (!err)
        {
          err = app_setattr (card, ctrl, keyword, pin_cb, ctx,
                             value, nbytes);
          wipememory (value, nbytes);
          xfree (value);
        }

   }
  else
    {
      nbytes = percent_plus_unescape_inplace (line, 0);
      err = app_setattr (card, ctrl, keyword, pin_cb, ctx,
                         (const unsigned char*)line, nbytes);
    }

  card_put (card);
  xfree (linebuf);
  return err;
}


static const char hlp_writecert[] =
  "WRITECERT <hexified_certid>\n"
  "\n"
  "This command is used to store a certificate on a smartcard.  The\n"
  "allowed certids depend on the currently selected smartcard\n"
  "application. The actual certifciate is requested using the inquiry\n"
  "\"CERTDATA\" and needs to be provided in its raw (e.g. DER) form.\n"
  "\n"
  "In almost all cases a PIN will be requested.  See the related\n"
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
  card_t card;

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no certid given");
  certid = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl)))
    return rc;

  card = card_get (ctrl, NULL);
  if (!card)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  certid = xtrystrdup (certid);
  if (!certid)
    {
      card_put (card);
      return out_of_core ();
    }

  /* Now get the actual keydata. */
  rc = assuan_inquire (ctx, "CERTDATA",
                       &certdata, &certdatalen, MAXLEN_CERTDATA);
  if (rc)
    {
      card_put (card);
      xfree (certid);
      return rc;
    }

  /* Write the certificate to the card. */
  rc = app_writecert (card, ctrl, certid,
                      pin_cb, ctx, certdata, certdatalen);
  card_put (card);
  xfree (certid);
  xfree (certdata);

  return rc;
}


static const char hlp_writekey[] =
  "WRITEKEY [--force] <keyid> \n"
  "\n"
  "This command is used to store a secret key on a smartcard.  The\n"
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
  card_t card;

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no keyid given");
  keyid = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl)))
    return rc;

  card = card_get (ctrl, NULL);
  if (!card)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  keyid = xtrystrdup (keyid);
  if (!keyid)
    {
      card_put (card);
      return out_of_core ();
    }

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
  rc = app_writekey (card, ctrl, keyid, force? 1:0,
                     pin_cb, ctx, keydata, keydatalen);
  card_put (card);
  xfree (keyid);
  xfree (keydata);

  return rc;
}


static const char hlp_genkey[] =
  "GENKEY [--force] [--timestamp=<isodate>] [--algo=ALGO] <keyref>\n"
  "\n"
  "Generate a key on-card identified by <keyref>, which is application\n"
  "specific.  Return values are also application specific.  For OpenPGP\n"
  "cards 3 status lines are returned:\n"
  "\n"
  "  S KEY-FPR  <hexstring>\n"
  "  S KEY-CREATED-AT <seconds_since_epoch>\n"
  "  S KEY-DATA [-|p|n] <hexdata>\n"
  "\n"
  "  'p' and 'n' are the names of the RSA parameters; '-' is used to\n"
  "  indicate that HEXDATA is the first chunk of a parameter given\n"
  "  by the next KEY-DATA.  Only used by GnuPG version < 2.1.\n"
  "\n"
  "--force is required to overwrite an already existing key.  The\n"
  "KEY-CREATED-AT is required for further processing because it is\n"
  "part of the hashed key material for the fingerprint.\n"
  "\n"
  "If --timestamp is given an OpenPGP key will be created using this\n"
  "value.  The value needs to be in ISO Format; e.g.\n"
  "\"--timestamp=20030316T120000\" and after 1970-01-01 00:00:00.\n"
  "\n"
  "The option --algo can be used to request creation using a specific\n"
  "algorithm.  The possible algorithms are card dependent.\n"
  "\n"
  "The public part of the key can also later be retrieved using the\n"
  "READKEY command.";
static gpg_error_t
cmd_genkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  char *keyref_buffer = NULL;
  char *keyref;
  int force;
  const char *s;
  char *opt_algo = NULL;
  time_t timestamp;
  card_t card;

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

  err = get_option_value (line, "--algo", &opt_algo);
  if (err)
    goto leave;

  line = skip_options (line);
  if (!*line)
    {
      err = set_error (GPG_ERR_ASS_PARAMETER, "no key number given");
      goto leave;
    }
  keyref = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((err = open_card (ctrl)))
    goto leave;

  card = card_get (ctrl, NULL);
  if (!card)
    {
      err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
      goto leave;
    }

  keyref = keyref_buffer = xtrystrdup (keyref);
  if (!keyref)
    {
      err = gpg_error_from_syserror ();
      card_put (card);
      goto leave;
    }
  err = app_genkey (card, ctrl, keyref, opt_algo,
                    force? APP_GENKEY_FLAG_FORCE : 0,
                    timestamp, pin_cb, ctx);
  card_put (card);

 leave:
  xfree (keyref_buffer);
  xfree (opt_algo);
  return err;
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
  card_t card;

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER,
                      "number of requested bytes missing");
  nbytes = strtoul (line, NULL, 0);

  if ((rc = open_card (ctrl)))
    return rc;

  card = card_get (ctrl, NULL);
  if (!card)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  buffer = xtrymalloc (nbytes);
  if (!buffer)
    {
      card_put (card);
      return out_of_core ();
    }

  rc = app_get_challenge (card, ctrl, nbytes, buffer);
  card_put (card);
  if (!rc)
    {
      rc = assuan_send_data (ctx, buffer, nbytes);
      xfree (buffer);
      return rc; /* that is already an assuan error code */
    }
  xfree (buffer);

  return rc;
}



static const char hlp_passwd[] =
  "PASSWD [--reset] [--nullpin] [--clear] <chvno> [<keygrip>]\n"
  "\n"
  "Change the PIN or, if --reset is given, reset the retry counter of\n"
  "the card holder verification vector CHVNO.  The option --nullpin is\n"
  "used for TCOS cards to set the initial PIN.  The option --clear clears\n"
  "the security status associated with the PIN so that the PIN needs to\n"
  "be presented again.  The format of CHVNO depends on the card application.\n"
  "\n"
  "The target card is the currently selected smartcard, when KEYPGIP is not\n"
  "specified.  When it is specified, it accesses directly with the KEYGRIP.";
static gpg_error_t
cmd_passwd (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *chvnostr;
  unsigned int flags = 0;
  card_t card;
  const char *keygrip = NULL;

  if (has_option (line, "--reset"))
    flags |= APP_CHANGE_FLAG_RESET;
  if (has_option (line, "--nullpin"))
    flags |= APP_CHANGE_FLAG_NULLPIN;
  if (has_option (line, "--clear"))
    flags |= APP_CHANGE_FLAG_CLEAR;

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no CHV number given");
  chvnostr = line;
  while (*line && !spacep (line))
    line++;
  if (*line)
    *line++ = 0;

  if (strlen (line) == 40)
    keygrip = line;

  /* Do not allow other flags aside of --clear. */
  if ((flags & APP_CHANGE_FLAG_CLEAR) && (flags & ~APP_CHANGE_FLAG_CLEAR))
    return set_error (GPG_ERR_UNSUPPORTED_OPERATION,
                      "--clear used with other options");

  if ((rc = open_card (ctrl)))
    return rc;

  card = card_get (ctrl, keygrip);
  if (!card)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  chvnostr = xtrystrdup (chvnostr);
  if (!chvnostr)
    {
      card_put (card);
      return out_of_core ();
    }
  rc = app_change_pin (card, ctrl, chvnostr, flags, pin_cb, ctx);
  card_put (card);
  if (rc)
    log_error ("command passwd failed: %s\n", gpg_strerror (rc));
  xfree (chvnostr);

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
  "   is however a special mode if the IDSTR is suffixed with the\n"
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
  "   unblock each other.\n"
  "\n"
  "For PKCS#15:\n"
  "\n"
  "   The key's ID string or the PIN's label may be used.";
static gpg_error_t
cmd_checkpin (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  char *idstr;
  card_t card;

  if ((err = open_card (ctrl)))
    return err;

  card = card_get (ctrl, NULL);
  if (!card)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid. */
  idstr = xtrystrdup (line);
  if (!idstr)
    {
      card_put (card);
      return out_of_core ();
    }

  err = app_check_pin (card, ctrl, idstr, pin_cb, ctx);
  card_put (card);
  xfree (idstr);
  if (err)
    log_error ("app_check_pin failed: %s\n", gpg_strerror (err));

  return err;
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

#ifdef USE_NPTH
  if (rc && has_option (line, "--wait"))
    {
      rc = 0;
      gnupg_sleep (1); /* Better implement an event mechanism. However,
                          for card operations this should be
                          sufficient. */
      /* Send a progress so that we can detect a connection loss.  */
      rc = send_status_printf (ctrl, "PROGRESS", "scd_locked . 0 0");
      if (!rc)
        goto retry;
    }
#endif /*USE_NPTH*/

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
  "  version     - Return the version of the program.\n"
  "  pid         - Return the process id of the server.\n"
  "  socket_name - Return the name of the socket.\n"
  "  connections - Return number of active connections.\n"
  "  status      - Return the status of the current reader (in the future,\n"
  "                may also return the status of all readers).  The status\n"
  "                is a list of one-character flags.  The following flags\n"
  "                are currently defined:\n"
  "                  'u'  Usable card present.\n"
  "                  'r'  Card removed.  A reset is necessary.\n"
  "                These flags are exclusive.\n"
  "  reader_list - Return a list of detected card readers.  Does\n"
  "                currently only work with the internal CCID driver.\n"
  "  deny_admin  - Returns OK if admin commands are not allowed or\n"
  "                GPG_ERR_GENERAL if admin commands are allowed.\n"
  "  app_list    - Return a list of supported applications.  One\n"
  "                application per line, fields delimited by colons,\n"
  "                first field is the name.\n"
  "  card_list   - Return a list of serial numbers of all inserted cards.\n"
  "  active_apps - Return a list of active apps on the current card.\n"
  "  all_active_apps\n"
  "              - Return a list of active apps on all inserted cards.\n"
  "  cmd_has_option CMD OPT\n"
  "              - Returns OK if command CMD has option OPT.\n"
  "  apdu_strerror NUMBER\n"
  "              - Return a string for a status word.\n";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  int rc = 0;
  const char *s;

  if (!strcmp (line, "version"))
    {
      s = VERSION;
      rc = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strncmp (line, "cmd_has_option", 14)
           && (line[14] == ' ' || line[14] == '\t' || !line[14]))
    {
      char *cmd, *cmdopt;
      line += 14;
      while (*line == ' ' || *line == '\t')
        line++;
      if (!*line)
        rc = gpg_error (GPG_ERR_MISSING_VALUE);
      else
        {
          cmd = line;
          while (*line && (*line != ' ' && *line != '\t'))
            line++;
          if (!*line)
            rc = gpg_error (GPG_ERR_MISSING_VALUE);
          else
            {
              *line++ = 0;
              while (*line == ' ' || *line == '\t')
                line++;
              if (!*line)
                rc = gpg_error (GPG_ERR_MISSING_VALUE);
              else
                {
                  cmdopt = line;
                  if (!command_has_option (cmd, cmdopt))
                    rc = gpg_error (GPG_ERR_FALSE);
                }
            }
        }
    }
  else if (!strcmp (line, "socket_name"))
    {
      s = scd_get_socket_name ();
      if (s)
        rc = assuan_send_data (ctx, s, strlen (s));
      else
        rc = gpg_error (GPG_ERR_NO_DATA);
    }
  else if (!strcmp (line, "connections"))
    {
      char numbuf[20];

      snprintf (numbuf, sizeof numbuf, "%d", get_active_connection_count ());
      rc = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "status"))
    {
      ctrl_t ctrl = assuan_get_pointer (ctx);
      char flag;

      if (open_card (ctrl))
        flag = 'r';
      else
        flag = 'u';

      rc = assuan_send_data (ctx, &flag, 1);
    }
  else if (!strcmp (line, "reader_list"))
    {
#ifdef HAVE_LIBUSB
      char *p = ccid_get_reader_list ();
#else
      char *p = NULL;
#endif

      if (p)
        rc = assuan_send_data (ctx, p, strlen (p));
      else
        rc = gpg_error (GPG_ERR_NO_DATA);
      xfree (p);
    }
  else if (!strcmp (line, "deny_admin"))
    rc = opt.allow_admin? gpg_error (GPG_ERR_GENERAL) : 0;
  else if (!strcmp (line, "app_list"))
    {
      char *p = get_supported_applications ();
      if (p)
        rc = assuan_send_data (ctx, p, strlen (p));
      else
        rc = 0;
      xfree (p);
    }
  else if (!strcmp (line, "card_list"))
    {
      ctrl_t ctrl = assuan_get_pointer (ctx);

      rc = app_send_card_list (ctrl);
    }
  else if (!strcmp (line, "active_apps"))
    {
      ctrl_t ctrl = assuan_get_pointer (ctx);
      card_t card = card_get (ctrl, NULL);

      if (!card)
        rc = 0; /* No current card - no active apps.  */
      else
        {
          rc = app_send_active_apps (card, ctrl);
          card_put (card);
        }
    }
  else if (!strcmp (line, "all_active_apps"))
    {
      ctrl_t ctrl = assuan_get_pointer (ctx);
      rc = app_send_active_apps (NULL, ctrl);
    }
  else if ((s=has_leading_keyword (line, "apdu_strerror")))
    {
      unsigned long ul = strtoul (s, NULL, 0);
      s = apdu_strerror (ul);
      rc = assuan_send_data (ctx, s, strlen (s));
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
  card_t card = card_get (ctrl, NULL);

  (void)line;

  if (card)
    {
      ctrl->card_ctx = NULL;
      ctrl->current_apptype = APPTYPE_NONE;
      card_unref_locked (card);
      card_put (card);
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
  "Disconnect the card if the backend supports a disconnect operation.";
static gpg_error_t
cmd_disconnect (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  card_t card;

  (void)line;

  card = card_get (ctrl, NULL);
  if (card)
    {
      apdu_disconnect (card->slot);
      card_put (card);
      return 0;
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
}



static const char hlp_apdu[] =
  "APDU [--[dump-]atr] [--more] [--exlen[=N]] [hexstring]\n"
  "\n"
  "Send an APDU to the current reader.  This command bypasses the high\n"
  "level functions and sends the data directly to the card.  HEXSTRING\n"
  "is expected to be a proper APDU.  If HEXSTRING is not given no\n"
  "commands are set to the card but the command will implicitly check\n"
  "whether the card is ready for use. \n"
  "\n"
  "Using the option \"--atr\" returns the ATR of the card as a status\n"
  "message before any data like this:\n"
  "  S CARD-ATR 3BFA1300FF813180450031C173C00100009000B1\n"
  "\n"
  "Using the option --more handles the card status word MORE_DATA\n"
  "(61xx) and concatenates all responses to one block.\n"
  "\n"
  "Using the option \"--exlen\" the returned APDU may use extended\n"
  "length up to N bytes.  If N is not given a default value is used\n"
  "(currently 4096).";
static gpg_error_t
cmd_apdu (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  card_t card;
  int rc;
  unsigned char *apdu;
  size_t apdulen;
  int with_atr;
  int handle_more;
  const char *s;
  size_t exlen;

  if (has_option (line, "--dump-atr"))
    with_atr = 3;
  else if (has_option (line, "--data-atr"))
    with_atr = 2;
  else
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

  if ((rc = open_card (ctrl)))
    return rc;

  card = card_get (ctrl, NULL);
  if (!card)
    return gpg_error (GPG_ERR_CARD_NOT_PRESENT);

  if (with_atr)
    {
      unsigned char *atr;
      size_t atrlen;
      char hexbuf[400];

      atr = apdu_get_atr (card->slot, &atrlen);
      if (!atr || atrlen > sizeof hexbuf - 2 )
        {
          rc = gpg_error (GPG_ERR_INV_CARD);
          goto leave;
        }
      if (with_atr == 3)
        {
          char *string, *p, *pend;

          string = atr_dump (atr, atrlen);
          if (string)
            {
              for (rc=0, p=string; !rc && (pend = strchr (p, '\n')); p = pend+1)
                {
                  rc = assuan_send_data (ctx, p, pend - p + 1);
                  if (!rc)
                    rc = assuan_send_data (ctx, NULL, 0);
                }
              if (!rc && *p)
                rc = assuan_send_data (ctx, p, strlen (p));
              es_free (string);
              if (rc)
                {
                  xfree (atr);
                  goto leave;
                }
            }
        }
      else if (with_atr == 2)
        {
          rc = assuan_send_data (ctx, atr, atrlen);
          if (rc)
            {
              xfree (atr);
              goto leave;
            }
        }
      else
        {
          bin2hex (atr, atrlen, hexbuf);
          send_status_info (ctrl, "CARD-ATR", hexbuf, strlen (hexbuf), NULL, 0);
        }
      xfree (atr);
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

      card->maybe_check_aid = 1;
      rc = apdu_send_direct (card->slot, exlen,
                             apdu, apdulen, handle_more,
                             NULL, &result, &resultlen);
      if (rc)
        {
          log_error ("apdu_send_direct failed: %s\n", apdu_strerror (rc));
          rc = iso7816_map_sw (rc);
        }
      else
        {
          rc = assuan_send_data (ctx, result, resultlen);
          xfree (result);
        }
    }
  xfree (apdu);

 leave:
  card_put (card);
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
  assuan_set_flag (ctx, ASSUAN_FORCE_CLOSE, 1);
  return 0;
}


static const char hlp_keyinfo[] =
  "KEYINFO [--list[=auth|encr|sign]] [--data] <keygrip>\n"
  "\n"
  "Return information about the key specified by the KEYGRIP.  If the\n"
  "key is not available GPG_ERR_NOT_FOUND is returned.  If the option\n"
  "--list is given the keygrip is ignored and information about all\n"
  "available keys are returned.  Capability may limit the listing.\n"
  "Unless --data is given, the\n"
  "information is returned as a status line using the format:\n"
  "\n"
  "  KEYINFO <keygrip> T <serialno> <idstr> <usage>\n"
  "\n"
  "KEYGRIP is the keygrip.\n"
  "\n"
  "SERIALNO is an ASCII string with the serial number of the\n"
  "         smartcard.  If the serial number is not known a single\n"
  "         dash '-' is used instead.\n"
  "\n"
  "IDSTR is a string used to distinguish keys on a smartcard.  If it\n"
  "      is not known a dash is used instead.\n"
  "\n"
  "USAGE is a string of capabilities of the key, 's' for sign, \n"
  "'e' for encryption, 'a' for auth, and 'c' for cert.  If it is not\n"
  "known a dash is used instead.\n"
  "\n"
  "More information may be added in the future.";
static gpg_error_t
cmd_keyinfo (assuan_context_t ctx, char *line)
{
  int cap;
  int opt_data;
  int action;
  char *keygrip_str;
  ctrl_t ctrl = assuan_get_pointer (ctx);
  card_t card;

  opt_data = has_option (line, "--data");

  cap = 0;
  keygrip_str = NULL;
  if (has_option (line, "--list"))
    cap = 0;
  else if (has_option (line, "--list=sign"))
    cap = GCRY_PK_USAGE_SIGN;
  else if (has_option (line, "--list=encr"))
    cap = GCRY_PK_USAGE_ENCR;
  else if (has_option (line, "--list=auth"))
    cap = GCRY_PK_USAGE_AUTH;
  else
    keygrip_str = skip_options (line);

  if (opt_data)
    action = KEYGRIP_ACTION_SEND_DATA;
  else
    action = KEYGRIP_ACTION_WRITE_STATUS;

  card = app_do_with_keygrip (ctrl, action, keygrip_str, cap);

  if (keygrip_str && !card)
    return gpg_error (GPG_ERR_NOT_FOUND);
  return 0;
}


/* Send a keyinfo string as used by the KEYGRIP_ACTION_SEND_DATA.  If
 * DATA is true the string is emitted as a data line, else as a status
 * line.  */
void
send_keyinfo (ctrl_t ctrl, int data, const char *keygrip_str,
              const char *serialno, const char *idstr, const char *usage)
{
  char *string;
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  string = xtryasprintf ("%s T %s %s %s%s", keygrip_str,
                         serialno? serialno : "-",
                         idstr? idstr : "-",
                         usage? usage : "-",
                         data? "\n" : "");

  if (!string)
    return;

  if (!data)
    assuan_write_status (ctx, "KEYINFO", string);
  else
    assuan_send_data (ctx, string, strlen (string));

  xfree (string);
  return;
}


static const char hlp_devinfo[] =
  "DEVINFO [--watch]\n"
  "\n"
  "Return information about devices.  If the option --watch is given,\n"
  "it keeps reporting status change until it detects no device is\n"
  "available.\n"
  "The information is returned as a status line using the format:\n"
  "\n"
  "  DEVICE <card_type> <serialno> <app_type>\n"
  "\n"
  "CARD_TYPE is the type of the card.\n"
  "\n"
  "SERIALNO is an ASCII string with the serial number of the\n"
  "         smartcard.  If the serial number is not known a single\n"
  "         dash '-' is used instead.\n"
  "\n"
  "APP_TYPE is the type of the application.\n"
  "\n"
  "More information may be added in the future.";
static gpg_error_t
cmd_devinfo (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  int watch = 0;
  card_t card;

  if (has_option (line, "--watch"))
    {
      watch = 1;
      ctrl->server_local->watching_status = 1;
    }

  /* Firstly, send information of available devices.  */
  err = app_send_devinfo (ctrl, 0);

  /* If not watching, that's all.  */
  if (!watch)
    return err;

  if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    return err;

  /* Secondly, try to open device(s) available.  */

  /* Clear the remove flag so that the open_card is able to reread it.  */
  if (ctrl->server_local->card_removed)
    ctrl->server_local->card_removed = 0;

  if ((err = open_card (ctrl))
      && gpg_err_code (err) != GPG_ERR_ENODEV)
    return err;

  err = 0;

  card = card_get (ctrl, NULL);
  if (card)
    {
      /* If any, remove reference to the card in CTRL.  */
      ctrl->card_ctx = NULL;
      ctrl->current_apptype = APPTYPE_NONE;
      card_unref_locked (card);
      card_put (card);
    }

  /* Then, keep watching the status change.  */
  err = app_send_devinfo (ctrl, 1);

  ctrl->server_local->watching_status = 0;
  return err;
}

/* Return true if the command CMD implements the option OPT.  */
static int
command_has_option (const char *cmd, const char *cmdopt)
{
  if (!strcmp (cmd, "SERIALNO"))
    {
      if (!strcmp (cmdopt, "all"))
        return 1;
    }

  return 0;
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
    { "SWITCHCARD",   cmd_switchcard,hlp_switchcard },
    { "SWITCHAPP",    cmd_switchapp,hlp_switchapp },
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
    { "KEYINFO",      cmd_keyinfo,  hlp_keyinfo },
    { "DEVINFO",      cmd_devinfo,  hlp_devinfo },
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
scd_command_handler (ctrl_t ctrl, gnupg_fd_t fd)
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

  if (fd == GNUPG_INVALID_FD)
    {
      assuan_fd_t filedes[2];

      filedes[0] = assuan_fdopen (0);
      filedes[1] = assuan_fdopen (1);
      rc = assuan_init_pipe_server (ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (ctx, fd,
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
  do_reset (ctrl, 0, 0);

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
  stopme = ctrl->server_local->stopme;
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
  while ( (value = va_arg (arg_ptr, const unsigned char *))
           && n < DIM (buf)-2 )
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
          if (*value == '+' || *value == '\"' || *value == '%'
              || *value < ' ')
            {
              sprintf (p, "%%%02X", *value);
              p += 3;
              n += 2;
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
gpg_error_t
send_status_direct (ctrl_t ctrl, const char *keyword, const char *args)
{
  assuan_context_t ctx = ctrl->server_local->assuan_ctx;

  if (strchr (args, '\n'))
    {
      log_error ("error: LF detected in status line - not sending\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }
  return assuan_write_status (ctx, keyword, args);
}


/* This status functions expects a printf style format string.  No
 * filtering of the data is done instead the printf formatted data is
 * send using assuan_send_status. */
gpg_error_t
send_status_printf (ctrl_t ctrl, const char *keyword, const char *format, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx;

  if (!ctrl || !ctrl->server_local || !(ctx = ctrl->server_local->assuan_ctx))
    return 0;

  va_start (arg_ptr, format);
  err = vprint_assuan_status (ctx, keyword, format, arg_ptr);
  va_end (arg_ptr);
  return err;
}


/* Set a gcrypt key for use with the pincache.  The key is a random
 * key unique for this process and is useless after this process has
 * terminated.  This way the cached PINs stored in the gpg-agent are
 * bound to this specific process.  The main purpose of this
 * encryption is to hide the PIN in logs of the IPC.  */
static gpg_error_t
set_key_for_pincache (gcry_cipher_hd_t hd)
{
  static int initialized;
  static unsigned char keybuf[16];

  if (!initialized)
    {
      gcry_randomize (keybuf, sizeof keybuf, GCRY_STRONG_RANDOM);
      initialized = 1;
    }

  return gcry_cipher_setkey (hd, keybuf, sizeof keybuf);
}


/* Store the PIN in the PIN cache. The key to identify the PIN
 * consists of (SLOT,APPNAME,PINREF).  If PIN is NULL the PIN stored
 * under the given key is cleared.  If APPNAME and PINREF are NULL the
 * entire PIN cache for SLOT is cleared.  If SLOT is -1 the entire PIN
 * cache is cleared.  We do no use an scdaemon internal cache but let
 * gpg-agent cache it because it is better suited for this.  */
void
pincache_put (ctrl_t ctrl, int slot, const char *appname, const char *pinref,
              const char *pin, unsigned int pinlen)
{
  gpg_error_t err = 0;
  assuan_context_t ctx;
  char line[950];
  gcry_cipher_hd_t cipherhd = NULL;
  char *pinbuf = NULL;
  unsigned char *wrappedkey = NULL;
  size_t pinbuflen, wrappedkeylen;

  if (!ctrl)
    {
      /* No CTRL object provided.  We could pick an arbitrary
       * connection and send the status to that one.  However, such a
       * connection is inlikley to wait for a respinse from use and
       * thus it would at best be read as a response to the next
       * command send to us.  That is not good because it may clog up
       * our connection.  Thus we better don't do that.  A better will
       * be to queue this up and let the agent poll for general status
       * messages.  */
      /* struct server_local_s *sl; */
      /* for (sl=session_list; sl; sl = sl->next_session) */
      /*   if (sl->ctrl_backlink && sl->ctrl_backlink->server_local */
      /*       && sl->ctrl_backlink->server_local->assuan_ctx) */
      /*     { */
      /*       ctrl = sl->ctrl_backlink; */
      /*       break; */
      /*     } */
    }

  if (!ctrl || !ctrl->server_local || !(ctx=ctrl->server_local->assuan_ctx))
    return;
  if (pin && !pinlen)
    return;  /* Ignore an empty PIN.  */

  snprintf (line, sizeof line, "%d/%s/%s ",
            slot, appname? appname:"", pinref? pinref:"");

  /* Without an APPNAME etc or without a PIN we clear the cache and
   * thus there is no need to send the pin - even if the caller
   * accidentally passed a pin.  */
  if (pin && slot != -1 && appname && pinref)
    {
      /* FIXME: Replace this by OCB mode and use the cache key as
       * additional data.  */
      /* Pad with zeroes (AESWRAP requires multiples of 64 bit but
       * at least 128 bit data).  */
      pinbuflen = pinlen + 8 - (pinlen % 8);
      if (pinbuflen < 16)
        pinbuflen = 16;
      pinbuf = xtrycalloc_secure (1, pinbuflen);
      if (!pinbuf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (pinbuf, pin, pinlen);
      pinlen = pinbuflen;
      pin = pinbuf;

      err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                              GCRY_CIPHER_MODE_AESWRAP, 0);
      if (!err)
        err = set_key_for_pincache (cipherhd);
      if (err)
        goto leave;

      wrappedkeylen = pinlen + 8;
      wrappedkey = xtrymalloc (wrappedkeylen);
      if (!wrappedkey)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      err = gcry_cipher_encrypt (cipherhd, wrappedkey, wrappedkeylen,
                                 pin, pinlen);
      if (err)
        goto leave;
      gcry_cipher_close (cipherhd);
      cipherhd = NULL;
      if (strlen (line) + 2*wrappedkeylen + 1 >= sizeof line)
        {
          log_error ("%s: PIN or pinref string too long - ignored", __func__);
          goto leave;
        }
      bin2hex (wrappedkey, wrappedkeylen, line + strlen (line));
    }

  send_status_direct (ctrl, "PINCACHE_PUT", line);

 leave:
  xfree (pinbuf);
  xfree (wrappedkey);
  gcry_cipher_close (cipherhd);
  if (err)
    log_error ("%s: error caching PIN: %s\n", __func__, gpg_strerror (err));
}


/* Ask the agent for a cached PIN for the tuple (SLOT,APPNAME,PINREF).
 * Returns on success and stores the PIN at R_PIN; the caller needs to
 * wipe(!)  and then free that value.  On error NULL is stored at
 * R_PIN and an error code returned.  Common error codes are:
 *  GPG_ERR_NOT_SUPPORTED - Client does not support the PIN cache
 *  GPG_ERR_NO_DATA       - No PIN cached for the given key tuple
 */
gpg_error_t
pincache_get (ctrl_t ctrl, int slot, const char *appname, const char *pinref,
              char **r_pin)
{
  gpg_error_t err;
  assuan_context_t ctx;
  char command[512];
  unsigned char *value = NULL;
  size_t valuelen;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  gcry_cipher_hd_t cipherhd = NULL;

  if (slot == -1 || !appname || !pinref || !r_pin)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }
  if (!ctrl || !ctrl->server_local || !(ctx = ctrl->server_local->assuan_ctx))
    {
      err = gpg_error (GPG_ERR_USE_CONDITIONS);
      log_error ("%s: called w/o assuan context\n", __func__);
      goto leave;
    }

  snprintf (command, sizeof command, "PINCACHE_GET %d/%s/%s",
            slot, appname? appname:"", pinref? pinref:"");

  /* Limit the inquire to something reasonable.  The 32 extra bytes
   * are a guessed size for padding etc.  */
  err = assuan_inquire (ctx, command, &wrappedkey, &wrappedkeylen,
                        2*MAXLEN_PIN+32);
  if (gpg_err_code (err) == GPG_ERR_ASS_CANCELED)
    {
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      log_info ("caller does not feature a PIN cache");
      goto leave;
    }
  if (err)
    {
      log_error ("%s: sending PINCACHE_GET to caller failed: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }
  if (!wrappedkey || !wrappedkeylen)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  /* Convert to hex to binary and store it in (wrappedkey, wrappedkeylen).  */
  if (!hex2str (wrappedkey, wrappedkey, wrappedkeylen, &wrappedkeylen))
    {
      err = gpg_error_from_syserror ();
      log_error ("%s: caller returned invalid hex string: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }

  if (!wrappedkey || wrappedkeylen < 24)
    {
      err = gpg_error (GPG_ERR_INV_LENGTH); /* too short cryptogram */
      goto leave;
    }

  valuelen = wrappedkeylen - 8;
  value = xtrymalloc_secure (valuelen);
  if (!value)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (!err)
    err = set_key_for_pincache (cipherhd);
  if (err)
    goto leave;

  err = gcry_cipher_decrypt (cipherhd, value, valuelen,
                             wrappedkey, wrappedkeylen);
  if (err)
    {
      log_error ("%s: cached value could not be decrypted: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }

  *r_pin = value;
  value = NULL;

 leave:
  gcry_cipher_close (cipherhd);
  xfree (wrappedkey);
  xfree (value);
  return err;
}


void
popup_prompt (void *opaque, int on)
{
  ctrl_t ctrl = opaque;

  if (ctrl)
    {
      assuan_context_t ctx = ctrl->server_local->assuan_ctx;

      if (ctx)
        {
          const char *cmd;
          gpg_error_t err;
          unsigned char *value;
          size_t valuelen;

          if (on)
            cmd = "POPUPPINPADPROMPT --ack";
          else
            cmd = "DISMISSPINPADPROMPT";
          err = assuan_inquire (ctx, cmd, &value, &valuelen, 100);
          if (!err)
            xfree (value);
        }
    }
}


/*
 * Helper to send the clients a status change notification.
 *
 * When it's removal of card, this function also clean up all
 * references by ctrl->card_ctx of all sessions.
 *
 * Note that this function assumes that all accesses to cards and
 * applications are locked.  By the mrsw-lock, it is guaranteed that
 * no card/app is accessed, when this function is called..
 */
void
send_client_notifications (card_t card, int removal)
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
      if (sl->watching_status)
        {
          if (removal)
            assuan_write_status (sl->assuan_ctx, "DEVINFO_STATUS", "removal");
          else
            assuan_write_status (sl->assuan_ctx, "DEVINFO_STATUS", "new");
        }

      if (sl->ctrl_backlink && sl->ctrl_backlink->card_ctx == card)
        {
          pid_t pid;
#ifdef HAVE_W32_SYSTEM
          HANDLE handle;
#else
          int signo;
#endif

          if (removal)
            {
              sl->ctrl_backlink->card_ctx = NULL;
              sl->ctrl_backlink->current_apptype = APPTYPE_NONE;
              sl->card_removed = 1;
              card_unref_locked (card);
            }

          if (!sl->event_signal || !sl->assuan_ctx)
            continue;

          pid = assuan_get_pid (sl->assuan_ctx);

#ifdef HAVE_W32_SYSTEM
          handle = sl->event_signal;
          for (kidx=0; kidx < killidx; kidx++)
            if (killed[kidx].pid == pid
                && killed[kidx].handle == handle)
              break;
          if (kidx < killidx)
            log_info ("event %p (%p) already triggered for client %d\n",
                      sl->event_signal, handle, (int)pid);
          else
            {
              log_info ("triggering event %p (%p) for client %d\n",
                        sl->event_signal, handle, (int)pid);
              if (!SetEvent (handle))
                log_error ("SetEvent(%p) failed: %s\n",
                           sl->event_signal, w32_strerror (-1));
              if (killidx < DIM (killed))
                {
                  killed[killidx].pid = pid;
                  killed[killidx].handle = handle;
                  killidx++;
                }
            }
#else /*!HAVE_W32_SYSTEM*/
          signo = sl->event_signal;

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

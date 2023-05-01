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
#include "../common/asshelp.h"
#include "../common/server-help.h"

/* Maximum length allowed as a PIN; used for INQUIRE NEEDPIN */
#define MAXLEN_PIN 100

/* Maximum allowed size of key data as used in inquiries. */
#define MAXLEN_KEYDATA 4096

/* Maximum allowed total data size for SETDATA.  */
#define MAXLEN_SETDATA 4096

/* Maximum allowed size of certificate data as used in inquiries. */
#define MAXLEN_CERTDATA 16384


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
  int card_removed;

  /* If set to true we will be terminate ourself at the end of the
     this session.  */
  int stopme;

};


/* To keep track of all running sessions, we link all active server
   contexts and the anchor in this variable.  */
static struct server_local_s *session_list;

/* If a session has been locked we store a link to its server object
   in this variable. */
static struct server_local_s *locked_session;


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
  app_t app = ctrl->app_ctx;

  if (app)
    app_reset (app, ctrl, IS_LOCKED (ctrl)? 0: send_reset);

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

  if (ctrl->app_ctx)
    return 0;

  return select_application (ctrl, NULL, &ctrl->app_ctx, 0, NULL, 0);
}

/* Explicitly open a card for a specific use of APPTYPE or SERIALNO.  */
static gpg_error_t
open_card_with_request (ctrl_t ctrl, const char *apptype, const char *serialno)
{
  gpg_error_t err;
  unsigned char *serialno_bin = NULL;
  size_t serialno_bin_len = 0;
  app_t app = ctrl->app_ctx;

  /* If we are already initialized for one specific application we
     need to check that the client didn't requested a specific
     application different from the one in use before we continue. */
  if (apptype && ctrl->app_ctx)
    return check_application_conflict (apptype, ctrl->app_ctx);

  /* Re-scan USB devices.  Release APP, before the scan.  */
  ctrl->app_ctx = NULL;
  release_application (app, 0);

  if (serialno)
    serialno_bin = hex_to_buffer (serialno, &serialno_bin_len);

  err = select_application (ctrl, apptype, &ctrl->app_ctx, 1,
                            serialno_bin, serialno_bin_len);
  xfree (serialno_bin);

  return err;
}


static const char hlp_serialno[] =
  "SERIALNO [--demand=<serialno>] [<apptype>]\n"
  "\n"
  "Return the serial number of the card using a status response.  This\n"
  "function should be used to check for the presence of a card.\n"
  "\n"
  "If --demand is given, an application on the card with SERIALNO is\n"
  "selected and an error is returned if no such card available.\n"
  "\n"
  "If APPTYPE is given, an application of that type is selected and an\n"
  "error is returned if the application is not supported or available.\n"
  "The default is to auto-select the application using a hardwired\n"
  "preference system.  Note, that a future extension to this function\n"
  "may enable specifying a list and order of applications to try.\n"
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
  int rc = 0;
  char *serial;
  const char *demand;

  if ( IS_LOCKED (ctrl) )
    return gpg_error (GPG_ERR_LOCKED);

  if ((demand = has_option_name (line, "--demand")))
    {
      if (*demand != '=')
        return set_error (GPG_ERR_ASS_PARAMETER, "missing value for option");
      line = (char *)++demand;
      for (; *line && !spacep (line); line++)
        ;
      if (*line)
        *line++ = 0;
    }
  else
    demand = NULL;

  line = skip_options (line);

  /* Clear the remove flag so that the open_card is able to reread it.  */
  if (ctrl->server_local->card_removed)
    ctrl->server_local->card_removed = 0;

  if ((rc = open_card_with_request (ctrl, *line? line:NULL, demand)))
    {
      ctrl->server_local->card_removed = 1;
      return rc;
    }

  /* Success, clear the card_removed flag for all sessions.  */
  for (sl=session_list; sl; sl = sl->next_session)
    {
      ctrl_t c = sl->ctrl_backlink;

      if (c != ctrl)
        c->server_local->card_removed = 0;
    }

  serial = app_get_serialno (ctrl->app_ctx);
  if (!serial)
    return gpg_error (GPG_ERR_INV_VALUE);

  rc = assuan_write_status (ctx, "SERIALNO", serial);
  xfree (serial);
  return rc;
}


static const char hlp_learn[] =
  "LEARN [--force] [--keypairinfo]\n"
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
  "With the option --keypairinfo only KEYPARIINFO status lines are\n"
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
  "    PIV     = PIV card\n"
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

  if ((rc = open_card (ctrl)))
    return rc;

  /* Unless the force option is used we try a shortcut by identifying
     the card using a serial number and inquiring the client with
     that. The client may choose to cancel the operation if he already
     knows about this card */
  if (!only_keypairinfo)
    {
      const char *reader;
      char *serial;
      app_t app = ctrl->app_ctx;

      if (!app)
        return gpg_error (GPG_ERR_CARD_NOT_PRESENT);

      reader = apdu_get_reader_name (app->slot);
      if (!reader)
        return out_of_core ();
      send_status_direct (ctrl, "READER", reader);
      /* No need to free the string of READER.  */

      serial = app_get_serialno (ctrl->app_ctx);
      if (!serial)
	return gpg_error (GPG_ERR_INV_VALUE);

      rc = assuan_write_status (ctx, "SERIALNO", serial);
      if (rc < 0)
        {
          xfree (serial);
          return out_of_core ();
        }

      if (!has_option (line, "--force"))
        {
          char *command;

          rc = gpgrt_asprintf (&command, "KNOWNCARDP %s", serial);
          if (rc < 0)
            {
              xfree (serial);
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
              return rc;
            }
          /* Not canceled, so we have to proceed.  */
        }
      xfree (serial);
    }

  /* Let the application print out its collection of useful status
     information. */
  if (!rc)
    rc = app_write_learn_status (ctrl->app_ctx, ctrl, only_keypairinfo);

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

  if ((rc = open_card (ctrl)))
    return rc;

  line = xstrdup (line); /* Need a copy of the line. */
  rc = app_readcert (ctrl->app_ctx, ctrl, line, &cert, &ncert);
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

  return rc;
}


static const char hlp_readkey[] =
  "READKEY [--advanced] [--info[-only]] <keyid>\n"
  "\n"
  "Return the public key for the given cert or key ID as a standard\n"
  "S-expression.  With --advanced  the S-expression is returned in\n"
  "advanced format.  With --info a KEYPAIRINFO status line is also\n"
  "emitted; with --info-only the regular output is suppressed.";
static gpg_error_t
cmd_readkey (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  int advanced = 0;
  int opt_info = 0;
  int opt_nokey = 0;
  unsigned char *cert = NULL;
  size_t ncert;
  unsigned char *pk;
  size_t pklen;
  int direct_readkey = 0;

  if ((rc = open_card (ctrl)))
    return rc;

  if (has_option (line, "--advanced"))
    advanced = 1;
  if (has_option (line, "--info"))
    opt_info = 1;
  if (has_option (line, "--info-only"))
    opt_info = opt_nokey = 1;

  line = skip_options (line);
  line = xstrdup (line); /* Need a copy of the line. */

  /* If the application supports the READKEY function we use that.
     Otherwise we use the old way by extracting it from the
     certificate.  */
  rc = app_readkey (ctrl->app_ctx, ctrl, advanced, line, &pk, &pklen);
  if (!rc)
    direct_readkey = 1; /* Yeah, got that key - send it back.  */
  else if (gpg_err_code (rc) == GPG_ERR_UNSUPPORTED_OPERATION
           || gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
    {
      /* Fall back to certificate reading.  */
      rc = app_readcert (ctrl->app_ctx, ctrl, line, &cert, &ncert);
      if (rc)
        log_error ("app_readcert failed: %s\n", gpg_strerror (rc));
      else
        {
          rc = app_help_pubkey_from_cert (cert, ncert, &pk, &pklen);
          if (rc)
            log_error ("failed to parse the certificate: %s\n",
                       gpg_strerror (rc));
        }
    }
  else
    log_error ("app_readkey failed: %s\n", gpg_strerror (rc));

  if (!rc && pk && pklen && opt_info && !direct_readkey)
    {
      char keygripstr[KEYGRIP_LEN*2+1];
      char *algostr;

      rc = app_help_get_keygrip_string_pk (pk, pklen,
                                           keygripstr, NULL, NULL,
                                           &algostr);
      if (rc)
        {
          log_error ("app_help_get_keygrip_string failed: %s\n",
                     gpg_strerror (rc));
          goto leave;
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


  if (!rc && pk && pklen && !opt_nokey)
    rc = assuan_send_data (ctx, pk, pklen);

 leave:
  xfree (cert);
  xfree (pk);
  xfree (line);
  return rc;
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

  if ((rc = open_card (ctrl)))
    return rc;

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();

  rc = app_sign (ctrl->app_ctx, ctrl,
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

  if ((rc = open_card (ctrl)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

 /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid */
  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();

  rc = app_auth (ctrl->app_ctx, ctrl, keyidstr, pin_cb, ctx,
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

  if ((rc = open_card (ctrl)))
    return rc;

  keyidstr = xtrystrdup (line);
  if (!keyidstr)
    return out_of_core ();
  rc = app_decipher (ctrl->app_ctx, ctrl, keyidstr, pin_cb, ctx,
                     ctrl->in_data.value, ctrl->in_data.valuelen,
                     &outdata, &outdatalen, &infoflags);

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
  "GETATTR <name>\n"
  "\n"
  "This command is used to retrieve data from a smartcard.  The\n"
  "allowed names depend on the currently selected smartcard\n"
  "application.  NAME must be percent and '+' escaped.  The value is\n"
  "returned through status message, see the LEARN command for details.\n"
  "\n"
  "However, the current implementation assumes that Name is not escaped;\n"
  "this works as long as no one uses arbitrary escaping. \n"
  "\n"
  "Note, that this function may even be used on a locked card.";
static gpg_error_t
cmd_getattr (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  const char *keyword;

  if ((rc = open_card (ctrl)))
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

  return rc;
}


static const char hlp_setattr[] =
  "SETATTR <name> <value> \n"
  "\n"
  "This command is used to store data on a smartcard.  The allowed\n"
  "names and values are depend on the currently selected smartcard\n"
  "application.  NAME and VALUE must be percent and '+' escaped.\n"
  "\n"
  "However, the current implementation assumes that NAME is not\n"
  "escaped; this works as long as no one uses arbitrary escaping.\n"
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

  if ((rc = open_card (ctrl)))
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

  rc = app_setattr (ctrl->app_ctx, ctrl, keyword, pin_cb, ctx,
                    (const unsigned char*)line, nbytes);
  xfree (linebuf);

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

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no certid given");
  certid = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl)))
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

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no keyid given");
  keyid = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((rc = open_card (ctrl)))
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
    return set_error (GPG_ERR_ASS_PARAMETER, "no key number given");
  keyref = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  if ((err = open_card (ctrl)))
    goto leave;

  if (!ctrl->app_ctx)
    {
      err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
      goto leave;
    }

  keyref = keyref_buffer = xtrystrdup (keyref);
  if (!keyref)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = app_genkey (ctrl->app_ctx, ctrl, keyref, opt_algo,
                    force? APP_GENKEY_FLAG_FORCE : 0,
                    timestamp, pin_cb, ctx);

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

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER,
                      "number of requested bytes missing");
  nbytes = strtoul (line, NULL, 0);

  if ((rc = open_card (ctrl)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  buffer = xtrymalloc (nbytes);
  if (!buffer)
    return out_of_core ();

  rc = app_get_challenge (ctrl->app_ctx, ctrl, nbytes, buffer);
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
  "PASSWD [--reset] [--nullpin] [--clear] <chvno>\n"
  "\n"
  "Change the PIN or, if --reset is given, reset the retry counter of\n"
  "the card holder verification vector CHVNO.  The option --nullpin is\n"
  "used for TCOS cards to set the initial PIN.  The option --clear clears\n"
  "the security status associated with the PIN so that the PIN needs to\n"
  "be presented again. The format of CHVNO depends on the card application.";
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
  if (has_option (line, "--clear"))
    flags |= APP_CHANGE_FLAG_CLEAR;

  line = skip_options (line);

  if (!*line)
    return set_error (GPG_ERR_ASS_PARAMETER, "no CHV number given");
  chvnostr = line;
  while (*line && !spacep (line))
    line++;
  *line = 0;

  /* Do not allow other flags aside of --clear. */
  if ((flags & APP_CHANGE_FLAG_CLEAR) && (flags & ~APP_CHANGE_FLAG_CLEAR))
    return set_error (GPG_ERR_UNSUPPORTED_OPERATION,
                      "--clear used with other options");

  if ((rc = open_card (ctrl)))
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
  "   unblock each other.";
static gpg_error_t
cmd_checkpin (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  int rc;
  char *idstr;

  if ((rc = open_card (ctrl)))
    return rc;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We have to use a copy of the key ID because the function may use
     the pin_cb which in turn uses the assuan line buffer and thus
     overwriting the original line with the keyid. */
  idstr = xtrystrdup (line);
  if (!idstr)
    return out_of_core ();

  rc = app_check_pin (ctrl->app_ctx, ctrl, idstr, pin_cb, ctx);
  xfree (idstr);
  if (rc)
    log_error ("app_check_pin failed: %s\n", gpg_strerror (rc));

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

#ifdef USE_NPTH
  if (rc && has_option (line, "--wait"))
    {
      rc = 0;
      npth_sleep (1); /* Better implement an event mechanism. However,
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


/* Ease reading of Assuan data ;ines by sending a physical line after
 * each LF.  */
static gpg_error_t
pretty_assuan_send_data (assuan_context_t ctx,
                         const void *buffer_arg, size_t size)
{
  const char *buffer = buffer_arg;
  const char *p;
  size_t n, nbytes;
  gpg_error_t err;

  nbytes = size;
  do
    {
      p = memchr (buffer, '\n', nbytes);
      n = p ? (p - buffer) + 1 : nbytes;
      err = assuan_send_data (ctx, buffer, n);
      if (err)
        {
          /* We also set ERRNO in case this function is used by a
           * custom estream I/O handler.  */
          gpg_err_set_errno (EIO);
          goto leave;
        }
      buffer += n;
      nbytes -= n;
      if (nbytes && (err=assuan_send_data (ctx, NULL, 0))) /* Flush line. */
        {
          gpg_err_set_errno (EIO);
          goto leave;
        }
    }
  while (nbytes);

 leave:
  return err;
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
  "  reader_list - Return a list of detected card readers.\n"
  "  deny_admin  - Returns OK if admin commands are not allowed or\n"
  "                GPG_ERR_GENERAL if admin commands are allowed.\n"
  "  app_list    - Return a list of supported applications.  One\n"
  "                application per line, fields delimited by colons,\n"
  "                first field is the name.\n"
  "  card_list   - Return a list of serial numbers of active cards,\n"
  "                using a status response.";
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
      char *s = apdu_get_reader_list ();
      if (s)
        rc = pretty_assuan_send_data (ctx, s, strlen (s));
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
  else if (!strcmp (line, "card_list"))
    {
      ctrl_t ctrl = assuan_get_pointer (ctx);

      app_send_card_list (ctrl);
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
  app_t app = ctrl->app_ctx;

  (void)line;

  if (app)
    {
      ctrl->app_ctx = NULL;
      release_application (app, 0);
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

  (void)line;

  if (!ctrl->app_ctx)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  apdu_disconnect (ctrl->app_ctx->slot);
  return 0;
}



static const char hlp_apdu[] =
  "APDU [--[dump-]atr] [--more] [--exlen[=N]] [hexstring]\n"
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
  "(61xx) and concatenates all responses to one block.\n"
  "\n"
  "Using the option \"--exlen\" the returned APDU may use extended\n"
  "length up to N bytes.  If N is not given a default value is used\n"
  "(currently 4096).";
static gpg_error_t
cmd_apdu (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  app_t app;
  int rc;
  unsigned char *apdu;
  size_t apdulen;
  int with_atr;
  int handle_more;
  const char *s;
  size_t exlen;

  if (has_option (line, "--dump-atr"))
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

  app = ctrl->app_ctx;
  if (!app)
    return gpg_error (GPG_ERR_CARD_NOT_PRESENT);

  if (with_atr)
    {
      unsigned char *atr;
      size_t atrlen;
      char hexbuf[400];

      atr = apdu_get_atr (app->slot, &atrlen);
      if (!atr || atrlen > sizeof hexbuf - 2 )
        {
          rc = gpg_error (GPG_ERR_INV_CARD);
          goto leave;
        }
      if (with_atr == 2)
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

      rc = apdu_send_direct (app->slot, exlen,
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



/* Send a keyinfo string.  If DATA is true the string is emitted as a
 * data line, else as a status line.  */
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
 * filtering of the data is done instead the orintf formatted data is
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


/* Helper to send the clients a status change notification.  */
void
send_client_notifications (app_t app, int removal)
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
    if (sl->ctrl_backlink && sl->ctrl_backlink->app_ctx == app)
      {
        pid_t pid;
#ifdef HAVE_W32_SYSTEM
        HANDLE handle;
#else
        int signo;
#endif

        if (removal)
          {
            sl->ctrl_backlink->app_ctx = NULL;
            sl->card_removed = 1;
            release_application (app, 1);
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

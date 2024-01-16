/* card-call-scd.c - IPC calls to scdaemon.
 * Copyright (C) 2019, 2020 g10 Code GmbH
 * Copyright (C) 2001-2003, 2006-2011, 2013 Free Software Foundation, Inc.
 * Copyright (C) 2013-2015  Werner Koch
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "../common/util.h"
#include "../common/membuf.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/sysutils.h"
#include "../common/status.h"
#include "../common/host2net.h"
#include "../common/openpgpdefs.h"
#include "gpg-card.h"

#define CONTROL_D ('D' - 'A' + 1)

#define START_AGENT_NO_STARTUP_CMDS 1
#define START_AGENT_SUPPRESS_ERRORS 2

struct default_inq_parm_s
{
  assuan_context_t ctx;
  struct {
    u32 *keyid;
    u32 *mainkeyid;
    int pubkey_algo;
  } keyinfo;
};

struct cipher_parm_s
{
  struct default_inq_parm_s *dflt;
  assuan_context_t ctx;
  unsigned char *ciphertext;
  size_t ciphertextlen;
};

struct writecert_parm_s
{
  struct default_inq_parm_s *dflt;
  const unsigned char *certdata;
  size_t certdatalen;
};

struct writekey_parm_s
{
  struct default_inq_parm_s *dflt;
  const unsigned char *keydata;
  size_t keydatalen;
};

struct genkey_parm_s
{
  struct default_inq_parm_s *dflt;
  const char *keyparms;
  const char *passphrase;
};

struct card_cardlist_parm_s
{
  gpg_error_t error;
  int with_apps;
  strlist_t list;
};

struct import_key_parm_s
{
  struct default_inq_parm_s *dflt;
  const void *key;
  size_t keylen;
};


struct cache_nonce_parm_s
{
  char **cache_nonce_addr;
  char **passwd_nonce_addr;
};



/*
 * File local variables
 */

/* The established context to the agent.  Note that all calls to
 * scdaemon are routed via the agent and thus we only need to care
 * about the IPC with the agent.  */
static assuan_context_t agent_ctx;



/*
 * Local prototypes
 */
static gpg_error_t learn_status_cb (void *opaque, const char *line);




/* Release the card info structure INFO. */
void
release_card_info (card_info_t info)
{
  int i;


  if (!info)
    return;

  xfree (info->reader); info->reader = NULL;
  xfree (info->cardtype); info->cardtype = NULL;
  xfree (info->manufacturer_name); info->manufacturer_name = NULL;
  xfree (info->serialno); info->serialno = NULL;
  xfree (info->dispserialno); info->dispserialno = NULL;
  xfree (info->apptypestr); info->apptypestr = NULL;
  info->apptype = APP_TYPE_NONE;
  xfree (info->disp_name); info->disp_name = NULL;
  xfree (info->disp_lang); info->disp_lang = NULL;
  xfree (info->pubkey_url); info->pubkey_url = NULL;
  xfree (info->login_data); info->login_data = NULL;
  info->cafpr1len = info->cafpr2len = info->cafpr3len = 0;
  for (i=0; i < DIM(info->private_do); i++)
    {
      xfree (info->private_do[i]);
      info->private_do[i] = NULL;
    }
  while (info->kinfo)
    {
      key_info_t kinfo = info->kinfo->next;
      xfree (info->kinfo->label);
      xfree (info->kinfo);
      info->kinfo = kinfo;
    }
  info->chvusage[0] = info->chvusage[1] = 0;
  xfree (info->chvlabels); info->chvlabels = NULL;
  for (i=0; i < DIM(info->supported_keyalgo); i++)
    {
      free_strlist (info->supported_keyalgo[i]);
      info->supported_keyalgo[i] = NULL;
    }
}


/* Map an application type string to an integer.  */
static app_type_t
map_apptypestr (const char *string)
{
  app_type_t result;

  if (!string)
    result = APP_TYPE_NONE;
  else if (!ascii_strcasecmp (string, "OPENPGP"))
    result = APP_TYPE_OPENPGP;
  else if (!ascii_strcasecmp (string, "NKS"))
    result = APP_TYPE_NKS;
  else if (!ascii_strcasecmp (string, "DINSIG"))
    result = APP_TYPE_DINSIG;
  else if (!ascii_strcasecmp (string, "P15"))
    result = APP_TYPE_P15;
  else if (!ascii_strcasecmp (string, "GELDKARTE"))
    result = APP_TYPE_GELDKARTE;
  else if (!ascii_strcasecmp (string, "SC-HSM"))
    result = APP_TYPE_SC_HSM;
  else if (!ascii_strcasecmp (string, "PIV"))
    result = APP_TYPE_PIV;
  else
    result = APP_TYPE_UNKNOWN;

  return result;
}


/* Return a string representation of the application type.  */
const char *
app_type_string (app_type_t app_type)
{
  const char *result = "?";
  switch (app_type)
    {
    case APP_TYPE_NONE:      result = "None"; break;
    case APP_TYPE_OPENPGP:   result = "OpenPGP"; break;
    case APP_TYPE_NKS:       result = "NetKey"; break;
    case APP_TYPE_DINSIG:    result = "DINSIG"; break;
    case APP_TYPE_P15:       result = "P15"; break;
    case APP_TYPE_GELDKARTE: result = "Geldkarte"; break;
    case APP_TYPE_SC_HSM:    result = "SC-HSM"; break;
    case APP_TYPE_PIV:       result = "PIV"; break;
    case APP_TYPE_UNKNOWN:   result = "Unknown"; break;
    }
  return result;
}



/* If RC is not 0, write an appropriate status message. */
static gpg_error_t
status_sc_op_failure (gpg_error_t err)
{
  switch (gpg_err_code (err))
    {
    case 0:
      break;
    case GPG_ERR_CANCELED:
    case GPG_ERR_FULLY_CANCELED:
      gnupg_status_printf (STATUS_SC_OP_FAILURE, "1");
      break;
    case GPG_ERR_BAD_PIN:
    case GPG_ERR_BAD_RESET_CODE:
      gnupg_status_printf (STATUS_SC_OP_FAILURE, "2");
      break;
    case GPG_ERR_PIN_BLOCKED:
      gnupg_status_printf (STATUS_SC_OP_FAILURE, "3");
      break;
    case GPG_ERR_NO_RESET_CODE:
      gnupg_status_printf (STATUS_SC_OP_FAILURE, "4");
      break;
    default:
      gnupg_status_printf (STATUS_SC_OP_FAILURE, NULL);
      break;
    }
  return err;
}


/* This is the default inquiry callback.  It mainly handles the
   Pinentry notifications.  */
static gpg_error_t
default_inq_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct default_inq_parm_s *parm = opaque;

  (void)parm;

  if (has_leading_keyword (line, "PINENTRY_LAUNCHED"))
    {
      /* err = gpg_proxy_pinentry_notify (parm->ctrl, line); */
      /* if (err) */
      /*   log_error (_("failed to proxy %s inquiry to client\n"), */
      /*              "PINENTRY_LAUNCHED"); */
      /* We do not pass errors to avoid breaking other code.  */
    }
  else
    log_debug ("ignoring gpg-agent inquiry '%s'\n", line);

  return err;
}


/* Print a warning if the server's version number is less than our
   version number.  Returns an error code on a connection problem.  */
static gpg_error_t
warn_version_mismatch (assuan_context_t ctx, const char *servername, int mode)
{
  return warn_server_version_mismatch (ctx, servername, mode,
                                       gnupg_status_strings, NULL,
                                       !opt.quiet);
}


/* Try to connect to the agent via socket or fork it off and work by
 * pipes.  Handle the server's initial greeting.  */
static gpg_error_t
start_agent (unsigned int flags)
{
  gpg_error_t err;
  int started = 0;

  if (agent_ctx)
    err = 0;
  else
    {
      started = 1;
      err = start_new_gpg_agent (&agent_ctx,
                                 GPG_ERR_SOURCE_DEFAULT,
                                 opt.agent_program,
                                 opt.lc_ctype, opt.lc_messages,
                                 opt.session_env,
                                 opt.autostart, opt.verbose, DBG_IPC,
                                 NULL, NULL);
      if (!opt.autostart && gpg_err_code (err) == GPG_ERR_NO_AGENT)
        {
          static int shown;

          if (!shown)
            {
              shown = 1;
              log_info (_("no gpg-agent running in this session\n"));
            }
        }
      else if (!err
               && !(err = warn_version_mismatch (agent_ctx, GPG_AGENT_NAME, 0)))
        {
          /* Tell the agent that we support Pinentry notifications.
             No error checking so that it will work also with older
             agents.  */
          assuan_transact (agent_ctx, "OPTION allow-pinentry-notify",
                           NULL, NULL, NULL, NULL, NULL, NULL);
          /* Tell the agent about what version we are aware.  This is
             here used to indirectly enable GPG_ERR_FULLY_CANCELED.  */
          assuan_transact (agent_ctx, "OPTION agent-awareness=2.1.0",
                           NULL, NULL, NULL, NULL, NULL, NULL);
        }
    }

  if (started && !err && !(flags & START_AGENT_NO_STARTUP_CMDS))
    {
      /* Request the serial number of the card for an early test.  */
      struct card_info_s info;

      memset (&info, 0, sizeof info);

      if (!(flags & START_AGENT_SUPPRESS_ERRORS))
        err = warn_version_mismatch (agent_ctx, SCDAEMON_NAME, 2);

      if (!err)
        err = assuan_transact (agent_ctx, "SCD SERIALNO --all",
                               NULL, NULL, NULL, NULL,
                               learn_status_cb, &info);
      if (err && !(flags & START_AGENT_SUPPRESS_ERRORS))
        {
          switch (gpg_err_code (err))
            {
            case GPG_ERR_NOT_SUPPORTED:
            case GPG_ERR_NO_SCDAEMON:
              gnupg_status_printf (STATUS_CARDCTRL, "6"); /* No card support. */
              break;
            case GPG_ERR_OBJ_TERM_STATE:
              /* Card is in termination state. */
              gnupg_status_printf (STATUS_CARDCTRL, "7");
              break;
            default:
              gnupg_status_printf (STATUS_CARDCTRL, "4");  /* No card.  */
              break;
            }
        }

      if (!err && info.serialno)
        gnupg_status_printf (STATUS_CARDCTRL, "3 %s", info.serialno);

      release_card_info (&info);
    }

  return err;
}


/* Return a new malloced string by unescaping the string S.  Escaping
 * is percent escaping and '+'/space mapping.  A binary nul will
 * silently be replaced by a 0xFF.  Function returns NULL to indicate
 * an out of memory status. */
static char *
unescape_status_string (const unsigned char *s)
{
  return percent_plus_unescape (s, 0xff);
}


/* Take a 20 or 32 byte hexencoded string and put it into the provided
 * FPRLEN byte long buffer FPR in binary format.  Returns the actual
 * used length of the FPR buffer or 0 on error.  */
static unsigned int
unhexify_fpr (const char *hexstr, unsigned char *fpr, unsigned int fprlen)
{
  const char *s;
  int n;

  for (s=hexstr, n=0; hexdigitp (s); s++, n++)
    ;
  if ((*s && *s != ' ') || !(n == 40 || n == 64))
    return 0; /* no fingerprint (invalid or wrong length). */
  for (s=hexstr, n=0; *s && n < fprlen; s += 2, n++)
    fpr[n] = xtoi_2 (s);

  return (n == 20 || n == 32)? n : 0;
}


/* Take the serial number from LINE and return it verbatim in a newly
 * allocated string.  We make sure that only hex characters are
 * returned.  Returns NULL on error. */
static char *
store_serialno (const char *line)
{
  const char *s;
  char *p;

  for (s=line; hexdigitp (s); s++)
    ;
  p = xtrymalloc (s + 1 - line);
  if (p)
    {
      memcpy (p, line, s-line);
      p[s-line] = 0;
    }
  return p;
}



/* Send an APDU to the current card.  On success the status word is
 * stored at R_SW inless R_SW is NULL.  With HEXAPDU being NULL only a
 * RESET command is send to scd.  HEXAPDU may also be one of theseo
 * special strings:
 *
 *   "undefined"       :: Send the command "SCD SERIALNO undefined"
 *   "lock"            :: Send the command "SCD LOCK --wait"
 *   "trylock"         :: Send the command "SCD LOCK"
 *   "unlock"          :: Send the command "SCD UNLOCK"
 *   "reset-keep-lock" :: Send the command "SCD RESET --keep-lock"
 *
 * If R_DATA is not NULL the data without the status code is stored
 * there.  Caller must release it.  If OPTIONS is not NULL, this will
 * be passed verbatim to the SCDaemon's APDU command.  */
gpg_error_t
scd_apdu (const char *hexapdu, const char *options, unsigned int *r_sw,
          unsigned char **r_data, size_t *r_datalen)
{
  gpg_error_t err;

  if (r_data)
    *r_data = NULL;
  if (r_datalen)
    *r_datalen = 0;

  err = start_agent (START_AGENT_NO_STARTUP_CMDS);
  if (err)
    return err;

  if (!hexapdu)
    {
      err = assuan_transact (agent_ctx, "SCD RESET",
                             NULL, NULL, NULL, NULL, NULL, NULL);

    }
  else if (!strcmp (hexapdu, "reset-keep-lock"))
    {
      err = assuan_transact (agent_ctx, "SCD RESET --keep-lock",
                             NULL, NULL, NULL, NULL, NULL, NULL);
    }
  else if (!strcmp (hexapdu, "lock"))
    {
      err = assuan_transact (agent_ctx, "SCD LOCK --wait",
                             NULL, NULL, NULL, NULL, NULL, NULL);
    }
  else if (!strcmp (hexapdu, "trylock"))
    {
      err = assuan_transact (agent_ctx, "SCD LOCK",
                             NULL, NULL, NULL, NULL, NULL, NULL);
    }
  else if (!strcmp (hexapdu, "unlock"))
    {
      err = assuan_transact (agent_ctx, "SCD UNLOCK",
                             NULL, NULL, NULL, NULL, NULL, NULL);
    }
  else if (!strcmp (hexapdu, "undefined"))
    {
      err = assuan_transact (agent_ctx, "SCD SERIALNO undefined",
                             NULL, NULL, NULL, NULL, NULL, NULL);
    }
  else
    {
      char line[ASSUAN_LINELENGTH];
      membuf_t mb;
      unsigned char *data;
      size_t datalen;
      int no_sw;

      init_membuf (&mb, 256);

      no_sw = (options && (strstr (options, "--dump-atr")
                           || strstr (options, "--data-atr")));

      snprintf (line, DIM(line), "SCD APDU %s%s%s",
                options?options:"", options?" -- ":"", hexapdu);
      err = assuan_transact (agent_ctx, line,
                             put_membuf_cb, &mb, NULL, NULL, NULL, NULL);
      if (!err)
        {
          data = get_membuf (&mb, &datalen);
          if (!data)
            err = gpg_error_from_syserror ();
          else if (datalen < (no_sw?1:2)) /* Ooops */
            err = gpg_error (GPG_ERR_CARD);
          else
            {
              if (r_sw)
                *r_sw = no_sw? 0 : buf16_to_uint (data+datalen-2);
              if (r_data && r_datalen)
                {
                  *r_data = data;
                  *r_datalen = datalen - (no_sw?0:2);
                  data = NULL;
                }
            }
          xfree (data);
        }
    }

  return err;
}


/* This is a dummy data line callback.  */
static gpg_error_t
dummy_data_cb (void *opaque, const void *buffer, size_t length)
{
  (void)opaque;
  (void)buffer;
  (void)length;
  return 0;
}

/* A simple callback used to return the serialnumber of a card.  */
static gpg_error_t
get_serialno_cb (void *opaque, const char *line)
{
  char **serialno = opaque;
  const char *keyword = line;
  const char *s;
  int keywordlen, n;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  /* FIXME: Should we use has_leading_keyword? */
  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      if (*serialno)
        return gpg_error (GPG_ERR_CONFLICT); /* Unexpected status line. */
      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;
      if (!n || (n&1)|| !(spacep (s) || !*s) )
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      *serialno = xtrymalloc (n+1);
      if (!*serialno)
        return out_of_core ();
      memcpy (*serialno, line, n);
      (*serialno)[n] = 0;
    }

  return 0;
}


/* Make the card with SERIALNO the current one.  */
gpg_error_t
scd_switchcard (const char *serialno)
{
  int err;
  char line[ASSUAN_LINELENGTH];

  err = start_agent (START_AGENT_SUPPRESS_ERRORS);
  if (err)
    return err;

  snprintf (line, DIM(line), "SCD SWITCHCARD -- %s", serialno);
  return assuan_transact (agent_ctx, line,
                          NULL, NULL, NULL, NULL,
                          NULL, NULL);
}


/* Make the app APPNAME the one on the card.  */
gpg_error_t
scd_switchapp (const char *appname)
{
  int err;
  char line[ASSUAN_LINELENGTH];

  if (appname && !*appname)
    appname = NULL;

  err = start_agent (START_AGENT_SUPPRESS_ERRORS);
  if (err)
    return err;

  snprintf (line, DIM(line), "SCD SWITCHAPP --%s%s",
            appname? " ":"", appname? appname:"");
  return assuan_transact (agent_ctx, line,
                          NULL, NULL, NULL, NULL,
                          NULL, NULL);
}


/* For historical reasons OpenPGP cards simply use the numbers 1 to 3
 * for the <keyref>.  Other cards and future versions of
 * scd/app-openpgp.c may print the full keyref; i.e. "OpenPGP.1"
 * instead of "1".  This is a helper to cope with that. */
static const char *
parse_keyref_helper (const char *string)
{
  if (*string == '1' && spacep (string+1))
    return "OPENPGP.1";
  else if (*string == '2' && spacep (string+1))
    return "OPENPGP.2";
  else if (*string == '3' && spacep (string+1))
    return "OPENPGP.3";
  else
    return string;
}


/* Create a new key info object with KEYREF.  All fields but the
 * keyref are zeroed out.  Never returns NULL.  The created object is
 * appended to the list at INFO. */
static key_info_t
create_kinfo (card_info_t info, const char *keyref)
{
  key_info_t kinfo, ki;

  kinfo = xcalloc (1, sizeof *kinfo + strlen (keyref));
  strcpy (kinfo->keyref, keyref);

  if (!info->kinfo)
    info->kinfo = kinfo;
  else
    {
      for (ki=info->kinfo; ki->next; ki = ki->next)
        ;
      ki->next = kinfo;
    }
  return kinfo;
}


/* The status callback to handle the LEARN and GETATTR commands.  */
static gpg_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct card_info_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  char *line_buffer = NULL; /* In case we need a copy.  */
  char *pline, *endp;
  key_info_t kinfo;
  const char *keyref;
  int i;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  switch (keywordlen)
    {
    case 3:
      if (!memcmp (keyword, "KDF", 3))
        {
          parm->kdf_do_enabled = 1;
        }
      break;

    case 5:
      if (!memcmp (keyword, "UIF-", 4)
          && strchr("123", keyword[4]))
        {
          unsigned char *data;
          int no = keyword[4] - '1';

          log_assert (no >= 0 && no <= 2);
          data = unescape_status_string (line);
          /* I am not sure why we test for 0xff but we better keep
           * that in case of bogus card versions which did not
           * initialize that DO correctly.  */
          parm->uif[no] = (data[0] == 0xff)? 0 : data[0];
          xfree (data);
        }
      break;

    case 6:
      if (!memcmp (keyword, "READER", keywordlen))
        {
          xfree (parm->reader);
          parm->reader = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "EXTCAP", keywordlen))
        {
          char *p, *p2, *buf;
          int abool;
          unsigned long number;

          buf = p = unescape_status_string (line);
          if (buf)
            {
              for (p = strtok (buf, " "); p; p = strtok (NULL, " "))
                {
                  p2 = strchr (p, '=');
                  if (p2)
                    {
                      *p2++ = 0;
                      abool = (*p2 == '1');
                      if (!strcmp (p, "ki"))
                        parm->extcap.ki = abool;
                      else if (!strcmp (p, "aac"))
                        parm->extcap.aac = abool;
                      else if (!strcmp (p, "bt"))
                        parm->extcap.bt = abool;
                      else if (!strcmp (p, "kdf"))
                        parm->extcap.kdf = abool;
                      else if (!strcmp (p, "si"))
                        parm->status_indicator = strtoul (p2, NULL, 10);
                      else if (!strcmp (p, "pd"))
                        parm->extcap.private_dos = abool;
                      else if (!strcmp (p, "mcl3"))
                        parm->extcap.mcl3 = strtoul (p2, NULL, 10);
                      else if (!strcmp (p, "sm"))
                        {
                          /* Unfortunately this uses OpenPGP algorithm
                           * ids so that we need to map them to Gcrypt
                           * ids.  The mapping is limited to what
                           * OpenPGP cards support.  Other cards
                           * should use a different tag than "sm". */
                          parm->extcap.sm = 1;
                          number = strtoul (p2, NULL, 10);
                          switch (number)
                            {
                            case CIPHER_ALGO_3DES:
                              parm->extcap.smalgo = GCRY_CIPHER_3DES;
                              break;
                            case CIPHER_ALGO_AES:
                              parm->extcap.smalgo = GCRY_CIPHER_AES;
                              break;
                            case CIPHER_ALGO_AES192:
                              parm->extcap.smalgo = GCRY_CIPHER_AES192;
                              break;
                            case CIPHER_ALGO_AES256:
                              parm->extcap.smalgo = GCRY_CIPHER_AES256;
                              break;
                            default:
                              /* Unknown algorithm; dont claim SM support.  */
                              parm->extcap.sm = 0;
                              break;
                            }
                        }
                    }
                }
              xfree (buf);
            }
        }
      else if (!memcmp (keyword, "CA-FPR", keywordlen))
        {
          int no = atoi (line);
          while (*line && !spacep (line))
            line++;
          while (spacep (line))
            line++;
          if (no == 1)
            parm->cafpr1len = unhexify_fpr (line, parm->cafpr1,
                                            sizeof parm->cafpr1);
          else if (no == 2)
            parm->cafpr2len = unhexify_fpr (line, parm->cafpr2,
                                            sizeof parm->cafpr2);
          else if (no == 3)
            parm->cafpr3len = unhexify_fpr (line, parm->cafpr3,
                                            sizeof parm->cafpr3);
        }
      break;

    case 7:
      if (!memcmp (keyword, "APPTYPE", keywordlen))
        {
          xfree (parm->apptypestr);
          parm->apptypestr = unescape_status_string (line);
          parm->apptype = map_apptypestr (parm->apptypestr);
        }
      else if (!memcmp (keyword, "KEY-FPR", keywordlen))
        {
          /* The format of such a line is:
           *   KEY-FPR <keyref> <fingerprintinhex>
           */
          const char *fpr;

          line_buffer = pline = xstrdup (line);

          keyref = parse_keyref_helper (pline);
          while (*pline && !spacep (pline))
            pline++;
          if (*pline)
            *pline++ = 0; /* Terminate keyref.  */
          while (spacep (pline)) /* Skip to the fingerprint.  */
            pline++;
          fpr = pline;

          /* Check whether we already have an item for the keyref.  */
          kinfo = find_kinfo (parm, keyref);
          if (!kinfo)  /* No: new entry.  */
            kinfo = create_kinfo (parm, keyref);
          else /* Existing entry - clear the fpr.  */
            memset (kinfo->fpr, 0, sizeof kinfo->fpr);

          /* Set or update or the fingerprint.  */
          kinfo->fprlen = unhexify_fpr (fpr, kinfo->fpr, sizeof kinfo->fpr);
        }
      break;

    case 8:
      if (!memcmp (keyword, "SERIALNO", keywordlen))
        {
          xfree (parm->serialno);
          parm->serialno = store_serialno (line);
          parm->is_v2 = (strlen (parm->serialno) >= 16
                         && (xtoi_2 (parm->serialno+12) == 0 /* Yubikey */
                             || xtoi_2 (parm->serialno+12) >= 2));
        }
      else if (!memcmp (keyword, "CARDTYPE", keywordlen))
        {
          xfree (parm->cardtype);
          parm->cardtype = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "DISP-SEX", keywordlen))
        {
          parm->disp_sex = *line == '1'? 1 : *line == '2' ? 2: 0;
        }
      else if (!memcmp (keyword, "KEY-ATTR", keywordlen))
        {
          char keyrefbuf[20];
          int keyno, algo, n;
          const char *curve;
          unsigned int nbits;

          /* To prepare for future changes we allow for a full OpenPGP
           * keyref here.  */
          if (!ascii_strncasecmp (line, "OPENPGP.", 8))
            line += 8;

          /* Note that KEY-ATTR returns OpenPGP algorithm numbers but
           * we want to use the Gcrypt numbers here.  A compatible
           * change would be to add another parameter along with a
           * magic algo number to indicate that.  */
          algo = PUBKEY_ALGO_RSA;
          keyno = n = 0;
          sscanf (line, "%d %d %n", &keyno, &algo, &n);
          algo = map_openpgp_pk_to_gcry (algo);
          if (keyno < 1 || keyno > 3)
            ; /* Out of range - ignore.  */
          else
            {
              snprintf (keyrefbuf, sizeof keyrefbuf, "OPENPGP.%d", keyno);
              keyref = keyrefbuf;

              kinfo = find_kinfo (parm, keyref);
              if (!kinfo)  /* No: new entry.  */
                kinfo = create_kinfo (parm, keyref);

              /* Although we could use the the value at %n directly as
               * keyalgo string, we want to use the standard
               * keyalgo_string function and thus we reconstruct it
               * here to make sure the displayed form of the curve
               * names is used.  */
              nbits = 0;
              curve = NULL;
              if (algo == GCRY_PK_ECDH || algo == GCRY_PK_ECDSA
                  || algo == GCRY_PK_EDDSA || algo == GCRY_PK_ECC)
                {
                  curve = openpgp_is_curve_supported (line + n, NULL, NULL);
                }
              else /* For rsa we see here for example "rsa2048".  */
                {
                  if (line[n] && line[n+1] && line[n+2])
                    nbits = strtoul (line+n+3, NULL, 10);
                }
              kinfo->keyalgo = get_keyalgo_string (algo, nbits, curve);
              kinfo->keyalgo_id = algo;
            }
        }
      break;

    case 9:
      if (!memcmp (keyword, "DISP-NAME", keywordlen))
        {
          xfree (parm->disp_name);
          parm->disp_name = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "DISP-LANG", keywordlen))
        {
          xfree (parm->disp_lang);
          parm->disp_lang = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "CHV-USAGE", keywordlen))
        {
          unsigned int byte1, byte2;

          byte1 = byte2 = 0;
          sscanf (line, "%x %x", &byte1, &byte2);
          parm->chvusage[0] = byte1;
          parm->chvusage[1] = byte2;
        }
      else if (!memcmp (keyword, "CHV-LABEL", keywordlen))
        {
          xfree (parm->chvlabels);
          parm->chvlabels = xstrdup (line);
        }
      else if (!memcmp (keyword, "KEY-LABEL", keywordlen))
        {
          /* The format of such a line is:
           *   KEY-LABEL <keyref> [label|"-"]           */
          const char *fields[2];
          int nfields;
          char *label;

          line_buffer = pline = xstrdup (line);

          if ((nfields = split_fields (line_buffer, fields, DIM (fields))) < 2)
            goto leave;  /* not enough args - ignore.  */

          keyref = fields[0];
          /* We don't remove the percent escaping because that is only
           * used in case of strange characters in the label; we
           * should not print them.  Note that this info is only for
           * human consumption, anyway.  */
          label = xtrystrdup (fields[1]);
          if (!label)
            goto leave; /* We ignore malloc failures here.  */

          /* Check whether we already have an item for the keyref.  */
          kinfo = find_kinfo (parm, keyref);
          if (!kinfo)  /* New entry.  */
            kinfo = create_kinfo (parm, keyref);

          xfree (kinfo->label);
          kinfo->label = label;
        }
      break;

    case 10:
      if (!memcmp (keyword, "PUBKEY-URL", keywordlen))
        {
          xfree (parm->pubkey_url);
          parm->pubkey_url = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "LOGIN-DATA", keywordlen))
        {
          xfree (parm->login_data);
          parm->login_data = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "CHV-STATUS", keywordlen))
        {
          char *p, *buf;

          buf = p = unescape_status_string (line);
          if (buf)
            while (spacep (p))
              p++;

          if (!buf)
            ;
          else if (parm->apptype == APP_TYPE_OPENPGP)
            {
              parm->chv1_cached = atoi (p);
              while (*p && !spacep (p))
                p++;
              while (spacep (p))
                p++;
              for (i=0; *p && i < 3; i++)
                {
                  parm->chvmaxlen[i] = atoi (p);
                  while (*p && !spacep (p))
                    p++;
                  while (spacep (p))
                    p++;
                }
              parm->nchvmaxlen = 3;
              for (i=0; *p && i < 3; i++)
                {
                  parm->chvinfo[i] = atoi (p);
                  while (*p && !spacep (p))
                    p++;
                  while (spacep (p))
                    p++;
                }
              parm->nchvinfo = 3;
            }
          else
            {
              for (i=0; *p && i < DIM (parm->chvinfo); i++)
                {
                  parm->chvinfo[i] = atoi (p);
                  while (*p && !spacep (p))
                    p++;
                  while (spacep (p))
                    p++;
                }
              parm->nchvinfo = i;
            }

          xfree (buf);
        }
      else if (!memcmp (keyword, "APPVERSION", keywordlen))
        {
          unsigned int val = 0;

          sscanf (line, "%x", &val);
          parm->appversion = val;
        }
      break;

    case 11:
      if (!memcmp (keyword, "SIG-COUNTER", keywordlen))
        {
          parm->sig_counter = strtoul (line, NULL, 0);
        }
      else if (!memcmp (keyword, "KEYPAIRINFO", keywordlen))
        {
          /* The format of such a line is:
           *   KEYPAIRINFO <hexgrip> <keyref> [usage] [keytime]
           */
          const char *fields[4];
          int nfields;
          const char *hexgrp, *usage;
          time_t keytime;

          line_buffer = pline = xstrdup (line);

          if ((nfields = split_fields (line_buffer, fields, DIM (fields))) < 2)
            goto leave;  /* not enough args - invalid status line.  */

          hexgrp = fields[0];
          keyref = fields[1];
          if (nfields > 2)
            usage = fields[2];
          else
            usage = "";
          if (nfields > 3)
            keytime = parse_timestamp (fields[3], NULL);
          else
            keytime = 0;

          /* Check whether we already have an item for the keyref.  */
          kinfo = find_kinfo (parm, keyref);
          if (!kinfo)  /* New entry.  */
            kinfo = create_kinfo (parm, keyref);
          else /* Existing entry - clear grip and usage  */
            {
              memset (kinfo->grip, 0, sizeof kinfo->grip);
              kinfo->usage = 0;
            }

          /* Set or update the grip.  Note that due to the
           * calloc/memset an erroneous too short grip will be nul
           * padded on the right. */
          unhexify_fpr (hexgrp, kinfo->grip, sizeof kinfo->grip);
          /* Parse and set the usage.  */
          for (; *usage; usage++)
            {
              switch (*usage)
                {
                case 's': kinfo->usage |= GCRY_PK_USAGE_SIGN; break;
                case 'c': kinfo->usage |= GCRY_PK_USAGE_CERT; break;
                case 'a': kinfo->usage |= GCRY_PK_USAGE_AUTH; break;
                case 'e': kinfo->usage |= GCRY_PK_USAGE_ENCR; break;
                }
            }
          /* Store the keytime.  */
          kinfo->created = keytime == (time_t)(-1)? 0 : (u32)keytime;
        }
      else if (!memcmp (keyword, "CARDVERSION", keywordlen))
        {
          unsigned int val = 0;

          sscanf (line, "%x", &val);
          parm->cardversion = val;
        }
      break;

    case 12:
      if (!memcmp (keyword, "PRIVATE-DO-", 11)
          && strchr("1234", keyword[11]))
        {
          int no = keyword[11] - '1';
          log_assert (no >= 0 && no <= 3);
          xfree (parm->private_do[no]);
          parm->private_do[no] = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "MANUFACTURER", 12))
        {
          xfree (parm->manufacturer_name);
          parm->manufacturer_name = NULL;
          parm->manufacturer_id = strtoul (line, &endp, 0);
          while (endp && spacep (endp))
            endp++;
          if (endp && *endp)
            parm->manufacturer_name = xstrdup (endp);
        }
      break;

    case 13:
      if (!memcmp (keyword, "$DISPSERIALNO", keywordlen))
        {
          xfree (parm->dispserialno);
          parm->dispserialno = unescape_status_string (line);
        }
      else if (!memcmp (keyword, "KEY-ATTR-INFO", keywordlen))
        {
          if (!strncmp (line, "OPENPGP.", 8))
            {
              int no;

              line += 8;
              no = atoi (line);
              if (no >= 1 && no <= 3)
                {
                  no--;
                  line++;
                  while (spacep (line))
                    line++;
                  append_to_strlist (&parm->supported_keyalgo[no],
                                     xstrdup (line));
                }
            }
          /* Skip when it's not "OPENPGP.[123]".  */
        }
      break;

    default:
      /* Unknown.  */
      break;
    }

 leave:
  xfree (line_buffer);
  return 0;
}


/* Call the scdaemon to learn about a smartcard.  This fills INFO
 * with data from the card. */
gpg_error_t
scd_learn (card_info_t info, int reread)
{
  gpg_error_t err;
  struct default_inq_parm_s parm;
  struct card_info_s dummyinfo;

  if (!info)
    info = &dummyinfo;

  memset (info, 0, sizeof *info);
  memset (&parm, 0, sizeof parm);

  err = start_agent (0);
  if (err)
    return err;

  parm.ctx = agent_ctx;
  err = assuan_transact (agent_ctx,
                         reread? "SCD LEARN --force --reread"
                         /*  */: "SCD LEARN --force",
                         dummy_data_cb, NULL, default_inq_cb, &parm,
                         learn_status_cb, info);
  /* Also try to get some other key attributes.  */
  if (!err)
    {
      info->initialized = 1;

      err = scd_getattr ("KEY-ATTR", info);
      if (gpg_err_code (err) == GPG_ERR_INV_NAME
          || gpg_err_code (err) == GPG_ERR_UNSUPPORTED_OPERATION)
        err = 0; /* Not implemented or GETATTR not supported.  */
      err = scd_getattr ("$DISPSERIALNO", info);
      if (gpg_err_code (err) == GPG_ERR_INV_NAME
          || gpg_err_code (err) == GPG_ERR_UNSUPPORTED_OPERATION)
        err = 0; /* Not implemented or GETATTR not supported.  */
      err = scd_getattr ("KEY-LABEL", info);
      if (gpg_err_code (err) == GPG_ERR_INV_NAME
          || gpg_err_code (err) == GPG_ERR_UNSUPPORTED_OPERATION)
        err = 0; /* Not implemented or GETATTR not supported.  */
    }

  if (info == &dummyinfo)
    release_card_info (info);

  return err;
}


/* Call the agent to retrieve a data object.  This function returns
 * the data in the same structure as used by the learn command.  It is
 * allowed to update such a structure using this command. */
gpg_error_t
scd_getattr (const char *name, struct card_info_s *info)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s parm;

  memset (&parm, 0, sizeof parm);

  if (!*name)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* We assume that NAME does not need escaping. */
  if (12 + strlen (name) > DIM(line)-1)
    return gpg_error (GPG_ERR_TOO_LARGE);
  stpcpy (stpcpy (line, "SCD GETATTR "), name);

  err = start_agent (0);
  if (err)
    return err;

  parm.ctx = agent_ctx;
  err = assuan_transact (agent_ctx, line, NULL, NULL, default_inq_cb, &parm,
                        learn_status_cb, info);

  return err;
}


/* Send an setattr command to the SCdaemon.  */
gpg_error_t
scd_setattr (const char *name,
             const unsigned char *value, size_t valuelen)
{
  gpg_error_t err;
  char *tmp;
  char *line = NULL;
  struct default_inq_parm_s parm;


  if (!*name || !valuelen)
    return gpg_error (GPG_ERR_INV_VALUE);

  tmp = strconcat ("SCD SETATTR ", name, " ", NULL);
  if (!tmp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  line = percent_data_escape (1, tmp, value, valuelen);
  xfree (tmp);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (strlen (line) + 10 > ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  err = start_agent (0);
  if (err )
    goto leave;

  memset (&parm, 0, sizeof parm);
  parm.ctx = agent_ctx;
  err = assuan_transact (agent_ctx, line, NULL, NULL,
                         default_inq_cb, &parm, NULL, NULL);

 leave:
  xfree (line);
  return status_sc_op_failure (err);
}



/* Handle a CERTDATA inquiry.  Note, we only send the data,
 * assuan_transact takes care of flushing and writing the END
 * command. */
static gpg_error_t
inq_writecert_parms (void *opaque, const char *line)
{
  gpg_error_t err;
  struct writecert_parm_s *parm = opaque;

  if (has_leading_keyword (line, "CERTDATA"))
    {
      err = assuan_send_data (parm->dflt->ctx,
                              parm->certdata, parm->certdatalen);
    }
  else
    err = default_inq_cb (parm->dflt, line);

  return err;
}


/* Send a WRITECERT command to the SCdaemon. */
gpg_error_t
scd_writecert (const char *certidstr,
               const unsigned char *certdata, size_t certdatalen)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct writecert_parm_s parms;
  struct default_inq_parm_s dfltparm;

  memset (&dfltparm, 0, sizeof dfltparm);

  err = start_agent (0);
  if (err)
    return err;

  memset (&parms, 0, sizeof parms);

  snprintf (line, sizeof line, "SCD WRITECERT %s", certidstr);
  dfltparm.ctx = agent_ctx;
  parms.dflt = &dfltparm;
  parms.certdata = certdata;
  parms.certdatalen = certdatalen;

  err = assuan_transact (agent_ctx, line, NULL, NULL,
                         inq_writecert_parms, &parms, NULL, NULL);

  return status_sc_op_failure (err);
}



/* Send a WRITEKEY command to the agent (so that the agent can fetch
 * the key to write).  KEYGRIP is the hexified keygrip of the source
 * key which will be written to the slot KEYREF.  FORCE must be true
 * to overwrite an existing key.  */
gpg_error_t
scd_writekey (const char *keyref, int force, const char *keygrip)
{
  gpg_error_t err;
  struct default_inq_parm_s parm;
  char line[ASSUAN_LINELENGTH];

  memset (&parm, 0, sizeof parm);

  err = start_agent (0);
  if (err)
    return err;

  /* Note: We don't send the s/n but "-" because gpg-agent has
   * currently no use for it. */
  /* FIXME: For OpenPGP we should provide the creation time.  */
  snprintf (line, sizeof line, "KEYTOCARD%s %s - %s",
            force? " --force":"", keygrip, keyref);
  err = assuan_transact (agent_ctx, line, NULL, NULL,
                         default_inq_cb, &parm, NULL, NULL);

  return status_sc_op_failure (err);
}



/* Status callback for the SCD GENKEY command. */
static gpg_error_t
scd_genkey_cb (void *opaque, const char *line)
{
  u32 *createtime = opaque;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

 if (keywordlen == 14 && !memcmp (keyword,"KEY-CREATED-AT", keywordlen))
    {
      if (createtime)
        *createtime = (u32)strtoul (line, NULL, 10);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "PROGRESS", keywordlen))
    {
      gnupg_status_printf (STATUS_PROGRESS, "%s", line);
    }

  return 0;
}


/* Send a GENKEY command to the SCdaemon.  If *CREATETIME is not 0,
 * the value will be passed to SCDAEMON with --timestamp option so that
 * the key is created with this.  Otherwise, timestamp was generated by
 * SCDAEMON.  On success, creation time is stored back to CREATETIME.  */
gpg_error_t
scd_genkey (const char *keyref, int force, const char *algo, u32 *createtime)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  gnupg_isotime_t tbuf;
  struct default_inq_parm_s dfltparm;

  memset (&dfltparm, 0, sizeof dfltparm);

  err = start_agent (0);
  if (err)
    return err;

  if (createtime && *createtime)
    epoch2isotime (tbuf, *createtime);
  else
    *tbuf = 0;

  snprintf (line, sizeof line, "SCD GENKEY %s%s %s %s%s -- %s",
            *tbuf? "--timestamp=":"", tbuf,
            force? "--force":"",
            algo? "--algo=":"",
            algo? algo:"",
            keyref);

  dfltparm.ctx = agent_ctx;
  err = assuan_transact (agent_ctx, line,
                         NULL, NULL, default_inq_cb, &dfltparm,
                         scd_genkey_cb, createtime);

  return status_sc_op_failure (err);
}



/* Return the serial number of the card or an appropriate error.  The
 * serial number is returned as a hexstring.  If DEMAND is not NULL
 * the reader with the a card of the serial number DEMAND is
 * requested.  */
gpg_error_t
scd_serialno (char **r_serialno, const char *demand)
{
  int err;
  char *serialno = NULL;
  char line[ASSUAN_LINELENGTH];

  err = start_agent (START_AGENT_SUPPRESS_ERRORS);
  if (err)
    return err;

  if (!demand)
    strcpy (line, "SCD SERIALNO --all");
  else
    snprintf (line, DIM(line), "SCD SERIALNO --demand=%s --all", demand);

  err = assuan_transact (agent_ctx, line,
                         NULL, NULL, NULL, NULL,
                         get_serialno_cb, &serialno);
  if (err)
    {
      xfree (serialno);
      return err;
    }

  if (r_serialno)
    *r_serialno = serialno;
  else
    xfree (serialno);
  return 0;
}



/* Send a READCERT command to the SCdaemon. */
gpg_error_t
scd_readcert (const char *certidstr, void **r_buf, size_t *r_buflen)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;
  struct default_inq_parm_s dfltparm;

  memset (&dfltparm, 0, sizeof dfltparm);

  *r_buf = NULL;
  err = start_agent (0);
  if (err)
    return err;

  dfltparm.ctx = agent_ctx;

  init_membuf (&data, 2048);

  snprintf (line, sizeof line, "SCD READCERT %s", certidstr);
  err = assuan_transact (agent_ctx, line,
                         put_membuf_cb, &data,
                         default_inq_cb, &dfltparm,
                         NULL, NULL);
  if (err)
    {
      xfree (get_membuf (&data, &len));
      return err;
    }

  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return gpg_error_from_syserror ();

  return 0;
}



/* Send a READKEY command to the SCdaemon.  On success a new
 * s-expression is stored at R_RESULT.  If CREATE_SHADOW is set stub
 * keys will be created if they do not exist. */
gpg_error_t
scd_readkey (const char *keyrefstr, int create_shadow, gcry_sexp_t *r_result)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  unsigned char *buf;
  size_t len, buflen;

  if (r_result)
    *r_result = NULL;
  err = start_agent (0);
  if (err)
    return err;

  init_membuf (&data, 1024);
  if (create_shadow)
    snprintf (line, DIM(line), "READKEY %s--card -- %s",
              r_result? "" : "--no-data ", keyrefstr);
  else
    snprintf (line, DIM(line), "SCD READKEY %s", keyrefstr);
  err = assuan_transact (agent_ctx, line,
                         put_membuf_cb, &data,
                         NULL, NULL,
                         NULL, NULL);
  if (err)
    {
      xfree (get_membuf (&data, &len));
      return err;
    }
  buf = get_membuf (&data, &buflen);
  if (!buf)
    return gpg_error_from_syserror ();

  err = r_result ? gcry_sexp_new (r_result, buf, buflen, 0) : 0;
  xfree (buf);

  return err;
}



/* Callback function for card_cardlist.  */
static gpg_error_t
card_cardlist_cb (void *opaque, const char *line)
{
  struct card_cardlist_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      const char *s;
      int n;

      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;

      if (!n || (n&1))
        parm->error = gpg_error (GPG_ERR_ASS_PARAMETER);
      if (parm->with_apps)
        {
          /* Format of the stored string is the S/N, a space, and a
           * space separated list of appnames.  */
          if (*s && (*s != ' ' || spacep (s+1) || !s[1]))
            parm->error = gpg_error (GPG_ERR_ASS_PARAMETER);
          else /* We assume the rest of the line is well formatted.  */
            add_to_strlist (&parm->list, line);
        }
      else
        {
          if (*s)
            parm->error = gpg_error (GPG_ERR_ASS_PARAMETER);
          else
            add_to_strlist (&parm->list, line);
        }
    }

  return 0;
}


/* Return the serial numbers of all cards currently inserted.  */
gpg_error_t
scd_cardlist (strlist_t *result)
{
  gpg_error_t err;
  struct card_cardlist_parm_s parm;

  memset (&parm, 0, sizeof parm);
  *result = NULL;

  err = start_agent (START_AGENT_SUPPRESS_ERRORS);
  if (err)
    return err;

  err = assuan_transact (agent_ctx, "SCD GETINFO card_list",
                         NULL, NULL, NULL, NULL,
                         card_cardlist_cb, &parm);
  if (!err && parm.error)
    err = parm.error;

  if (!err)
    *result = parm.list;
  else
    free_strlist (parm.list);

  return err;
}


/* Return the serial numbers and appnames of the current card or, with
 * ALL given has true, of all cards currently inserted.  */
gpg_error_t
scd_applist (strlist_t *result, int all)
{
  gpg_error_t err;
  struct card_cardlist_parm_s parm;

  memset (&parm, 0, sizeof parm);
  *result = NULL;

  err = start_agent (START_AGENT_SUPPRESS_ERRORS);
  if (err)
    return err;

  parm.with_apps = 1;
  err = assuan_transact (agent_ctx,
                         all ? "SCD GETINFO all_active_apps"
                         /**/: "SCD GETINFO active_apps",
                         NULL, NULL, NULL, NULL,
                         card_cardlist_cb, &parm);
  if (!err && parm.error)
    err = parm.error;

  if (!err)
    *result = parm.list;
  else
    free_strlist (parm.list);

  return err;
}



/* Change the PIN of a card or reset the retry counter.  If NULLPIN is
 * set the TCOS specific NullPIN is changed.  */
gpg_error_t
scd_change_pin (const char *pinref, int reset_mode, int nullpin)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset (&dfltparm, 0, sizeof dfltparm);

  err = start_agent (0);
  if (err)
    return err;
  dfltparm.ctx = agent_ctx;

  snprintf (line, sizeof line, "SCD PASSWD%s %s",
            nullpin? " --nullpin": reset_mode? " --reset":"", pinref);
  err = assuan_transact (agent_ctx, line,
                         NULL, NULL,
                         default_inq_cb, &dfltparm,
                         NULL, NULL);

  return status_sc_op_failure (err);
}


/* Perform a CHECKPIN operation.  SERIALNO should be the serial
 * number of the card - optionally followed by the fingerprint;
 * however the fingerprint is ignored here. */
gpg_error_t
scd_checkpin (const char *serialno)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm;

  memset (&dfltparm, 0, sizeof dfltparm);

  err = start_agent (0);
  if (err)
    return err;
  dfltparm.ctx = agent_ctx;

  snprintf (line, sizeof line, "SCD CHECKPIN %s", serialno);
  err = assuan_transact (agent_ctx, line,
                         NULL, NULL,
                         default_inq_cb, &dfltparm,
                         NULL, NULL);
  return status_sc_op_failure (err);
}


/* Return the S2K iteration count as computed by gpg-agent.  On error
 * print a warning and return a default value. */
unsigned long
agent_get_s2k_count (void)
{
  gpg_error_t err;
  membuf_t data;
  char *buf;
  unsigned long count = 0;

  err = start_agent (0);
  if (err)
    goto leave;

  init_membuf (&data, 32);
  err = assuan_transact (agent_ctx, "GETINFO s2k_count",
                        put_membuf_cb, &data,
                        NULL, NULL, NULL, NULL);
  if (err)
    xfree (get_membuf (&data, NULL));
  else
    {
      put_membuf (&data, "", 1);
      buf = get_membuf (&data, NULL);
      if (!buf)
        err = gpg_error_from_syserror ();
      else
        {
          count = strtoul (buf, NULL, 10);
          xfree (buf);
        }
    }

 leave:
  if (err || count < 65536)
    {
      /* Don't print an error if an older agent is used.  */
      if (err && gpg_err_code (err) != GPG_ERR_ASS_PARAMETER)
        log_error (_("problem with the agent: %s\n"), gpg_strerror (err));

      /* Default to 65536 which was used up to 2.0.13.  */
      count = 65536;
    }

  return count;
}



struct havekey_status_parm_s
{
  char *string;
};

static gpg_error_t
havekey_status_cb (void *opaque, const char *line)
{
  struct havekey_status_parm_s *parm = opaque;
  const char *s;
  char *p;

  if ((s = has_leading_keyword (line, "KEYFILEINFO")))
    {
      xfree (parm->string);
      parm->string = xtrystrdup (s);
      if (!parm->string)
        return gpg_error_from_syserror ();
      p = strchr (parm->string, ' ');
      if (p)
        *p = 0;
    }

  return 0;
}


/* Run the HAVEKEY --info command and stores the retrieved string at
 * R_RESULT.  Caller must free that string.  If an error is returned
 * R_RESULT is set to NULL.  */
gpg_error_t
scd_havekey_info (const unsigned char *grip, char **r_result)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct havekey_status_parm_s parm = {NULL};

  *r_result = NULL;

  err = start_agent (0);
  if (err)
    return err;

  snprintf (line, sizeof line, "HAVEKEY --info ");
  log_assert (ASSUAN_LINELENGTH > strlen(line) + 2*KEYGRIP_LEN + 10);
  bin2hex (grip, KEYGRIP_LEN, line+strlen(line));

  err = assuan_transact (agent_ctx, line,
                         NULL, NULL, NULL, NULL,
                         havekey_status_cb, &parm);
  if (err)
    xfree (parm.string);
  else
    *r_result = parm.string;
  return err;
}


/* Run the DELETE_KEY command.  If FORCE is given the user will not be
 * asked for confirmation.  */
gpg_error_t
scd_delete_key (const unsigned char *grip, int force)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct default_inq_parm_s dfltparm = {NULL};

  err = start_agent (0);
  if (err)
    return err;
  dfltparm.ctx = agent_ctx;

  snprintf (line, sizeof line, "DELETE_KEY%s ", force?" --force":"");
  log_assert (ASSUAN_LINELENGTH > strlen(line) + 2*KEYGRIP_LEN + 10);
  bin2hex (grip, KEYGRIP_LEN, line+strlen(line));

  err = assuan_transact (agent_ctx, line,
                         NULL, NULL, default_inq_cb, &dfltparm, NULL, NULL);
  return err;
}



/* Return a malloced string describing the statusword SW.  On error
 * NULL is returned.  */
char *
scd_apdu_strerror (unsigned int sw)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  char *buf;

  err = start_agent (0);
  if (err)
    return NULL;

  init_membuf (&data, 64);
  snprintf (line, sizeof line, "SCD GETINFO apdu_strerror 0x%x", sw);
  err = assuan_transact (agent_ctx, line, put_membuf_cb, &data,
                         NULL, NULL, NULL, NULL);
  if (err)
    {
      xfree (get_membuf (&data, NULL));
      return NULL;
    }

  put_membuf (&data, "", 1);
  buf = get_membuf (&data, NULL);
  return buf;
}

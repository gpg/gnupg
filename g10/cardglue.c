/* cardglue.c - mainly dispatcher for card related functions.
 * Copyright (C) 2003 Free Software Foundation, Inc.
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
#ifdef ENABLE_CARD_SUPPORT
/* 
   Note, that most card related code has been taken from 1.9.x branch
   and is maintained over there if at all possible.  Thus, if you make
   changes here, please check that a similar change has been commited
   to the 1.9.x branch.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "status.h"
#include "i18n.h"

#include "cardglue.h"
#include "apdu.h"
#include "app-common.h"

struct ctrl_ctx_s {
  int (*status_cb)(void *opaque, const char *line);
  void *status_cb_arg;
};


static char *default_reader_port;
static APP current_app;




/* Create a serialno/fpr string from the serial number and the secret
   key.  caller must free the returned string.  There is no error
   return. [Taken from 1.9's keyid.c]*/
char *
serialno_and_fpr_from_sk (const unsigned char *sn, size_t snlen,
                          PKT_secret_key *sk)
{
  unsigned char fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  char *buffer, *p;
  int i;
  
  fingerprint_from_sk (sk, fpr, &fprlen);
  buffer = p = xmalloc (snlen*2 + 1 + fprlen*2 + 1);
  for (i=0; i < snlen; i++, p+=2)
    sprintf (p, "%02X", sn[i]);
  *p++ = '/';
  for (i=0; i < fprlen; i++, p+=2)
    sprintf (p, "%02X", fpr[i]);
  *p = 0;
  return buffer;
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
  
  va_start (arg_ptr, keyword);

  p = buf; 
  n = 0;
  valuelen = strlen (keyword);
  for ( ; valuelen && n < DIM (buf)-2; n++, valuelen--, keyword++)
    *p++ = *keyword;

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
  ctrl->status_cb (ctrl->status_cb_arg, buf);

  va_end (arg_ptr);
}


void gcry_md_hash_buffer (int algo, void *digest,
			  const void *buffer, size_t length)
{
  MD_HANDLE h = md_open (algo, 0);
  if (!h)
    BUG();
  md_write (h, (byte *) buffer, length);
  md_final (h);
  memcpy (digest, md_read (h, algo), md_digest_length (algo));
  md_close (h);
}


/* This is a limited version of the one in 1.9 but it should be
   sufficient here. */
void
log_printf (const char *fmt, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, fmt);
  vfprintf (log_stream (), fmt, arg_ptr);
  va_end (arg_ptr);
}



/* Print a hexdump of BUFFER.  With TEXT of NULL print just the raw
   dump, with TEXT just an empty string, print a trailing linefeed,
   otherwise print an entire debug line. */
void
log_printhex (const char *text, const void *buffer, size_t length)
{
  if (text && *text)
    log_debug ("%s ", text);
  if (length)
    {
      const unsigned char *p = buffer;
      log_printf ("%02X", *p);
      for (length--, p++; length--; p++)
        log_printf (" %02X", *p);
    }
  if (text)
    log_printf ("\n");
}



void
app_set_default_reader_port (const char *portstr)
{
  xfree (default_reader_port);
  default_reader_port = portstr? xstrdup (portstr): NULL;
}


/* Retrieve the serial number and the time of the last update of the
   card.  The serial number is returned as a malloced string (hex
   encoded) in SERIAL and the time of update is returned in STAMP.  If
   no update time is available the returned value is 0.  Caller must
   free SERIAL unless the function returns an error. */
int 
app_get_serial_and_stamp (APP app, char **serial, time_t *stamp)
{
  unsigned char *buf, *p;
  int i;

  if (!app || !serial || !stamp)
    return gpg_error (GPG_ERR_INV_VALUE);

  *serial = NULL;
  *stamp = 0; /* not available */

  buf = xtrymalloc (app->serialnolen * 2 + 1);
  if (!buf)
    return gpg_error_from_errno (errno);
  for (p=buf, i=0; i < app->serialnolen; p +=2, i++)
    sprintf (p, "%02X", app->serialno[i]);
  *p = 0;
  *serial = buf;
  return 0;
}






/* Release the card info structure. */
void 
agent_release_card_info (struct agent_card_info_s *info)
{
  if (!info)
    return;

  xfree (info->serialno); info->serialno = NULL;
  xfree (info->disp_name); info->disp_name = NULL;
  xfree (info->disp_lang); info->disp_lang = NULL;
  xfree (info->pubkey_url); info->pubkey_url = NULL;
  xfree (info->login_data); info->login_data = NULL;
  info->fpr1valid = info->fpr2valid = info->fpr3valid = 0;
}


/* Open the current card and select the openpgp application.  Return
   an APP context handle to be used for further procesing or NULL on
   error or if no OpenPGP application exists.*/
static APP
open_card (void)
{
  int slot;
  int rc;
  APP app;

  current_app = NULL;/* FIXME: Release it first.*/
  slot = apdu_open_reader (default_reader_port);
  if (slot == -1)
    {
      log_error ("card reader not available\n");
      return NULL;
    }

  app = xcalloc (1, sizeof *app);
  app->slot = slot;
  rc = app_select_openpgp (app, &app->serialno, &app->serialnolen);
  if (rc)
    {
/*        apdu_close_reader (slot); */
      log_info ("selecting openpgp failed: %s\n", gpg_strerror (rc));
      xfree (app);
      return NULL;
    }

  app->initialized = 1;
  current_app = app;
  return app;
}



/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status. */
static char *
unescape_status_string (const unsigned char *s)
{
  char *buffer, *d;

  buffer = d = xmalloc (strlen (s)+1);
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d = xtoi_2 (s);
          if (!*d)
            *d = '\xff';
          d++;
          s += 2;
        }
      else if (*s == '+')
        {
          *d++ = ' ';
          s++;
        }
      else
        *d++ = *s++;
    }
  *d = 0; 
  return buffer;
}

/* Take a 20 byte hexencoded string and put it into the the provided
   20 byte buffer FPR in binary format. */
static int
unhexify_fpr (const char *hexstr, unsigned char *fpr)
{
  const char *s;
  int n;

  for (s=hexstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (*s || (n != 40))
    return 0; /* no fingerprint (invalid or wrong length). */
  n /= 2;
  for (s=hexstr, n=0; *s; s += 2, n++)
    fpr[n] = xtoi_2 (s);
  return 1; /* okay */
}

/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned. */
static char *
store_serialno (const char *line)
{
  const char *s;
  char *p;

  for (s=line; hexdigitp (s); s++)
    ;
  p = xmalloc (s + 1 - line);
  memcpy (p, line, s-line);
  p[s-line] = 0;
  return p;
}



static int
learn_status_cb (void *opaque, const char *line)
{
  struct agent_card_info_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  int i;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      parm->serialno = store_serialno (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-NAME", keywordlen))
    {
      parm->disp_name = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-LANG", keywordlen))
    {
      parm->disp_lang = unescape_status_string (line);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "DISP-SEX", keywordlen))
    {
      parm->disp_sex = *line == '1'? 1 : *line == '2' ? 2: 0;
    }
  else if (keywordlen == 10 && !memcmp (keyword, "PUBKEY-URL", keywordlen))
    {
      parm->pubkey_url = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "LOGIN-DATA", keywordlen))
    {
      parm->login_data = unescape_status_string (line);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "SIG-COUNTER", keywordlen))
    {
      parm->sig_counter = strtoul (line, NULL, 0);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "CHV-STATUS", keywordlen))
    {
      char *p, *buf;

      buf = p = unescape_status_string (line);
      if (buf)
        {
          while (spacep (p))
            p++;
          parm->chv1_cached = atoi (p);
          while (!spacep (p))
            p++;
          while (spacep (p))
            p++;
          for (i=0; *p && i < 3; i++)
            {
              parm->chvmaxlen[i] = atoi (p);
              while (!spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          for (i=0; *p && i < 3; i++)
            {
              parm->chvretry[i] = atoi (p);
              while (!spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          xfree (buf);
        }
    }
  else if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      int no = atoi (line);
      while (!spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1valid = unhexify_fpr (line, parm->fpr1);
      else if (no == 2)
        parm->fpr2valid = unhexify_fpr (line, parm->fpr2);
      else if (no == 3)
        parm->fpr3valid = unhexify_fpr (line, parm->fpr3);
    }
  
  return 0;
}


/* Return card info. */
int 
agent_learn (struct agent_card_info_s *info)
{
  APP app;
  int rc;
  struct ctrl_ctx_s ctrl;
  time_t stamp;
  char *serial;
  
  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  memset (&ctrl, 0, sizeof ctrl);
  ctrl.status_cb = learn_status_cb;
  ctrl.status_cb_arg = info;

  rc = app_get_serial_and_stamp (app, &serial, &stamp);
  if (!rc)
    {
      send_status_info (&ctrl, "SERIALNO", serial, strlen(serial), NULL, 0);
      xfree (serial);
      rc = app->fnc.learn_status (app, &ctrl);
    }

  return rc;
}

static int 
pin_cb (void *opaque, const char *info, char **retstr)
{
  char *value;
  int canceled;

  *retstr = NULL;
  log_debug ("asking for PIN '%s'\n", info);

  value = ask_passphrase (info, "Enter PIN: ", &canceled);
  if (!value && canceled)
    return -1;
  else if (!value)
    return G10ERR_GENERAL;

  *retstr = value;
  return 0;
}



/* Send a SETATTR command to the SCdaemon. */
int 
agent_scd_setattr (const char *name,
                   const unsigned char *value, size_t valuelen)
{
  APP app;

  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  return app->fnc.setattr (app, name, pin_cb, NULL, value, valuelen);
}

/* Send a GENKEY command to the SCdaemon. */
int 
agent_scd_genkey (struct agent_card_genkey_s *info, int keyno, int force)
{

  return gpg_error (GPG_ERR_CARD);
}

/* Send a PKSIGN command to the SCdaemon. */
int 
agent_scd_pksign (const char *serialno, int hashalgo,
                  const unsigned char *indata, size_t indatalen,
                  char **r_buf, size_t *r_buflen)
{
  APP app;

  *r_buf = NULL;
  *r_buflen = 0;
  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  /* Check that the card's serialnumber is as required.*/

  return app->fnc.sign (app, serialno, hashalgo,
                        pin_cb, NULL,
                        indata, indatalen,
                        r_buf, r_buflen);
}


/* Send a PKDECRYPT command to the SCdaemon. */
int 
agent_scd_pkdecrypt (const char *serialno,
                     const unsigned char *indata, size_t indatalen,
                     char **r_buf, size_t *r_buflen)
{

  return gpg_error (GPG_ERR_CARD);
}

/* Change the PIN of an OpenPGP card or reset the retry counter. */
int 
agent_scd_change_pin (int chvno)
{

  return gpg_error (GPG_ERR_CARD);
}




#endif /*ENABLE_CARD_SUPPORT*/


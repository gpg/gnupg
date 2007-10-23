/* cardglue.c - mainly dispatcher for card related functions.
 * Copyright (C) 2003, 2004, 2005, 2006 Free Software Foundation, Inc.
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
#ifndef ENABLE_CARD_SUPPORT
#error  not configured for card support.
#endif
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
#include "ttyio.h"
#include "i18n.h"

#include "cardglue.h"
#include "apdu.h"
#include "app-common.h"



struct ctrl_ctx_s 
{
  assuan_error_t (*status_cb)(void *opaque, const char *line);
  void *status_cb_arg;
};


struct pincb_parm_s
{
  const char *sn;
};


struct writekey_parm_s
{
  assuan_context_t ctx;
  const unsigned char *keydata;
  size_t keydatalen;
};



static char *default_reader_port;
static app_t current_app;


/* Local prototypes. */
static assuan_error_t learn_status_cb (void *opaque, const char *line);


/* To avoid cluttering the code with bunches of ifdefs we use a few
   dummy functions instead and defines. */
#ifndef ENABLE_AGENT_SUPPORT

#define ASSUAN_LINELENGTH 100

static assuan_context_t 
agent_open (int try, const char *orig_codeset)
{
  return NULL;
}

void 
agent_close (assuan_context_t ctx)
{
}

const char *
assuan_strerror (assuan_error_t err)
{
  return "no Assuan support";
}

assuan_error_t 
assuan_transact (assuan_context_t ctx,
                 const char *command,
                 assuan_error_t (*data_cb)(void *, const void *, size_t),
                 void *data_cb_arg,
                 assuan_error_t (*inquire_cb)(void*, const char *),
                 void *inquire_cb_arg,
                 assuan_error_t (*status_cb)(void*, const char *),
                 void *status_cb_arg)
{
  return 100; /* ASSUAN_NOT_IMPLEMENTED */
}
assuan_error_t 
assuan_send_data (assuan_context_t ctx, const void *buffer, size_t length)
{
  return 100; /* ASSUAN_NOT_IMPLEMENTED */
}  
#endif /*!ENABLE_AGENT_SUPPORT*/


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
send_status_info (ctrl_t ctrl, const char *keyword, ...)
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
  if (ctrl && ctrl->status_cb)
    ctrl->status_cb (ctrl->status_cb_arg, buf);

  va_end (arg_ptr);
}


/* Replacement function of the Libgcrypt onewhich is used in gnupg
   1.9.  Thus function computes the digest of ALGO from the data in
   BUFFER of LENGTH.  ALGO must be supported. */
void 
gcry_md_hash_buffer (int algo, void *digest,
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


void
card_set_reader_port (const char *portstr)
{
  app_set_default_reader_port (portstr);
}


/* Retrieve the serial number and the time of the last update of the
   card.  The serial number is returned as a malloced string (hex
   encoded) in SERIAL and the time of update is returned in STAMP.  If
   no update time is available the returned value is 0.  Caller must
   free SERIAL unless the function returns an error. */
int 
app_get_serial_and_stamp (app_t app, char **serial, time_t *stamp)
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
  int i;

  if (!info)
    return;

  xfree (info->serialno); info->serialno = NULL;
  xfree (info->disp_name); info->disp_name = NULL;
  xfree (info->disp_lang); info->disp_lang = NULL;
  xfree (info->pubkey_url); info->pubkey_url = NULL;
  xfree (info->login_data); info->login_data = NULL;
  info->fpr1valid = info->fpr2valid = info->fpr3valid = 0;
  info->cafpr1valid = info->cafpr2valid = info->cafpr3valid = 0;
  for (i=0; i < 4; i++)
    {
      xfree (info->private_do[i]);
      info->private_do[i] = NULL;
    }
}


/* Print an error message for a failed assuan_transact and return a
   gpg error code. No error is printed if RC is 0. */
static gpg_error_t
test_transact (int rc, const char *command)
{
  if (!rc)
    return 0;
  log_error ("sending command `%s' to agent failed: %s\n",
             command, assuan_strerror (rc));
  return gpg_error (GPG_ERR_CARD);
}


/* Try to open a card using an already running agent.  Prepare a
   proper application context and return it. */
static app_t
open_card_via_agent (int *scd_available)
{
  assuan_context_t ctx;
  app_t app;
  struct agent_card_info_s info;
  int rc;

  *scd_available = 0;
  ctx = agent_open (1, NULL);
  if (!ctx)
    return NULL;

  /* Request the serialbnumber of the card.  If we get
     NOT_SUPPORTED or NO_SCDAEMON back, the gpg-agent either has
     disabled scdaemon or it can't be used.  We close the connection
     in this case and use our own code.  This may happen if just the
     gpg-agent has been installed for the sake of passphrase
     caching. */
  memset (&info, 0, sizeof info);
  rc = assuan_transact (ctx, "SCD SERIALNO openpgp",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, &info);
  if (rc)
    {
      if ((rc & 0xffff) == 60 || (rc & 0xffff) == 119)
        ;  /* No scdaemon available to gpg-agent. */
      else
        {
          write_status_text (STATUS_CARDCTRL, "4");
          log_info ("selecting openpgp failed: %s\n", assuan_strerror (rc));
          *scd_available = 1;
        }
      agent_release_card_info (&info);
      agent_close (ctx);
      return NULL;
    }
  
  app = xcalloc (1, sizeof *app);
  app->assuan_ctx = ctx;

  return app;
}



/* Open the current card and select the openpgp application.  Return
   an APP context handle to be used for further procesing or NULL on
   error or if no OpenPGP application exists.*/
static app_t
open_card (void)
{
  int slot = -1;
  int rc;
  app_t app;
  int did_shutdown = 0;
  int retry_count = 0;

  /* First check whether we can contact a gpg-agent and divert all
     operation to it. This is required because gpg as well as the
     agent require exclusive access to the reader. */
  if (opt.use_agent)
    {
      int scd_available;

      app = open_card_via_agent (&scd_available);
      if (app)
        goto ready; /* Yes, there is a agent with a usable card, go that way. */
      if (scd_available)
        return NULL; /* agent avilabale but card problem. */
    }


  /* No agent or usable agent, thus we do it on our own. */
  card_close ();
  
 retry:
  if (did_shutdown)
    apdu_reset (slot);
  else
    {
      slot = apdu_open_reader (default_reader_port);
      if (slot == -1)
        {
          write_status_text (STATUS_CARDCTRL, "5");
          log_error (_("card reader not available\n"));
          return NULL;
        }
    }

  app = xcalloc (1, sizeof *app);
  app->slot = slot;
  rc = app_select_openpgp (app);
  if (opt.limit_card_insert_tries 
      && ++retry_count >= opt.limit_card_insert_tries)
    ;
  else if (rc && !opt.batch)
    {
      write_status_text (STATUS_CARDCTRL, "1");
      
      did_shutdown = !!apdu_shutdown_reader (slot);

      if ( cpr_get_answer_okay_cancel ("cardctrl.insert_card.okay",
           _("Please insert the card and hit return or enter 'c' to cancel: "),
                                       1) )
        {
          if (!did_shutdown)
            apdu_close_reader (slot);
          xfree (app);
          goto retry;
        }
    }
  if (rc)
    {
      write_status_text (STATUS_CARDCTRL, "4");
      log_info (_("selecting openpgp failed: %s\n"), gpg_strerror (rc));
      apdu_close_reader (slot);
      xfree (app);
      return NULL;
    }

 ready:
  app->initialized = 1;
  current_app = app;
  if (is_status_enabled () )
    {
      int i;
      char *p, *buf;

      buf = xmalloc (5 + app->serialnolen * 2 + 1);
      p = stpcpy (buf, "3 ");
      for (i=0; i < app->serialnolen; p +=2, i++)
        sprintf (p, "%02X", app->serialno[i]);
      write_status_text (STATUS_CARDCTRL, buf);
      xfree (buf);
    }

  return app;
}


void
card_close (void)
{
  if (current_app)
    {
      app_t app = current_app;
      current_app = NULL;

      if (app->assuan_ctx)
        agent_close (app->assuan_ctx);
      else
        apdu_close_reader (app->slot);
      xfree (app);
    }
}


/* Format a cache ID from the serialnumber in SN and return it as an
   allocated string.  In case of an error NULL is returned. */
static char *
format_cacheid (const char *sn)
{
  const char *s;
  size_t snlen;
  char *cacheid = NULL;

  /* The serialnumber we use for a card is "CARDSN:serialno".  Where
     serialno is the BCD string (i.e. hex string) with the full
     number.  The serial number expect here constsis of hexdigits
     followed by other characters, we cut off these other
     characters. */
  if (sn)
    {
      for (s=sn,snlen=0; hexdigitp (s); s++, snlen++)
        ;
      if (snlen == 32)
        {
          /* Yes, this looks indeed like an OpenPGP card S/N. */
          cacheid = xtrymalloc (7+snlen+1);
          if (cacheid)
            {
              memcpy (cacheid, "CARDSN:", 7);
              memcpy (cacheid+7, sn, snlen);
              cacheid[7+snlen] = 0;
            }
        }
    }
  return cacheid;
}


/* If RC is not 0, write an appropriate status message. */
static void
status_sc_op_failure (int rc)
{
  if (rc == G10ERR_CANCELED)
    write_status_text (STATUS_SC_OP_FAILURE, "1");
  else if (rc == G10ERR_BAD_PASS)
    write_status_text (STATUS_SC_OP_FAILURE, "2");
  else if (rc)
    write_status (STATUS_SC_OP_FAILURE);
}  


/* Check that the serial number of the current card (as described by
   APP) matches SERIALNO.  If there is no match and we are not in
   batch mode, present a prompt to insert the desired card.  The
   function returnd 0 if the present card is okay, -1 if the user
   selected to insert a new card or an error value.  Note that the
   card context will be closed in all cases except for 0 as return
   value and if it was possible to merely shutdown the reader. */
static int
check_card_serialno (app_t app, const char *serialno)
{
  const char *s;
  int ask = 0;
  int n;

  for (s = serialno, n=0; *s != '/' && hexdigitp (s); s++, n++)
    ;
  if (n != 32)
    {
      log_error ("invalid serial number in keyring detected\n");
      return gpg_error (GPG_ERR_INV_ID);
    }
  if (app->serialnolen != 16)
    ask = 1;
  for (s = serialno, n=0; !ask && n < 16; s += 2, n++)
    if (app->serialno[n] != xtoi_2 (s))
      ask = 1;
  if (ask)
    {
      char buf[5+32+1];
      int did_shutdown = 0;

      if (current_app && !apdu_shutdown_reader (current_app->slot))
        did_shutdown = 1;
      else
        card_close ();

      if (!opt.batch)
        tty_printf (_("Please remove the current card and "
                      "insert the one with serial number:\n"
                      "   %.*s\n"), 32, serialno);

      sprintf (buf, "1 %.32s", serialno);
      write_status_text (STATUS_CARDCTRL, buf);

      if ( !opt.batch
           && cpr_get_answer_okay_cancel ("cardctrl.change_card.okay",
                                          _("Hit return when ready "
                                            "or enter 'c' to cancel: "),
                                          1) )
        {
          card_close ();
          return -1;
        }
      if (did_shutdown)
        apdu_reset (current_app->slot);
      else
        card_close ();
      return gpg_error (GPG_ERR_INV_ID);
    }
  return 0;
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



static assuan_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct agent_card_info_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  int i;

/*   log_debug ("got status line `%s'\n", line); */
  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      xfree (parm->serialno);
      parm->serialno = store_serialno (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-NAME", keywordlen))
    {
      xfree (parm->disp_name);
      parm->disp_name = unescape_percent_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-LANG", keywordlen))
    {
      xfree (parm->disp_lang);
      parm->disp_lang = unescape_percent_string (line);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "DISP-SEX", keywordlen))
    {
      parm->disp_sex = *line == '1'? 1 : *line == '2' ? 2: 0;
    }
  else if (keywordlen == 10 && !memcmp (keyword, "PUBKEY-URL", keywordlen))
    {
      xfree (parm->pubkey_url);
      parm->pubkey_url = unescape_percent_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "LOGIN-DATA", keywordlen))
    {
      xfree (parm->login_data);
      parm->login_data = unescape_percent_string (line);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "SIG-COUNTER", keywordlen))
    {
      parm->sig_counter = strtoul (line, NULL, 0);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "CHV-STATUS", keywordlen))
    {
      char *p, *buf;

      buf = p = unescape_percent_string (line);
      if (buf)
        {
          while (spacep (p))
            p++;
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
          for (i=0; *p && i < 3; i++)
            {
              parm->chvretry[i] = atoi (p);
              while (*p && !spacep (p))
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
      while (* line && !spacep (line))
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
  else if (keywordlen == 8 && !memcmp (keyword, "KEY-TIME", keywordlen))
    {
      int no = atoi (line);
      while (* line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1time = strtoul (line, NULL, 10);
      else if (no == 2)
        parm->fpr2time = strtoul (line, NULL, 10);
      else if (no == 3)
        parm->fpr3time = strtoul (line, NULL, 10);
    }
  else if (keywordlen == 6 && !memcmp (keyword, "CA-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->cafpr1valid = unhexify_fpr (line, parm->cafpr1);
      else if (no == 2)
        parm->cafpr2valid = unhexify_fpr (line, parm->cafpr2);
      else if (no == 3)
        parm->cafpr3valid = unhexify_fpr (line, parm->cafpr3);
    }
  else if (keywordlen == 12 && !memcmp (keyword, "PRIVATE-DO-", 11)
           && strchr ("1234", keyword[11]))
    {
      int no = keyword[11] - '1';
      assert (no >= 0 && no <= 3);
      xfree (parm->private_do[no]);
      parm->private_do[no] = unescape_percent_string (line);
    }
 
  return 0;
}


/* Return card info. */
int 
agent_learn (struct agent_card_info_s *info)
{
  app_t app;
  int rc;
  struct ctrl_ctx_s ctrl;
  time_t stamp;
  char *serial;
  
  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  memset (info, 0, sizeof *info);

  if (app->assuan_ctx)
    {
      rc = assuan_transact (app->assuan_ctx, "SCD LEARN --force",
                            NULL, NULL, NULL, NULL,
                            learn_status_cb, info);
      rc = test_transact (rc, "SCD LEARN");
    }
  else
    {
      memset (&ctrl, 0, sizeof ctrl);
      ctrl.status_cb = learn_status_cb;
      ctrl.status_cb_arg = info;

      rc = app_get_serial_and_stamp (app, &serial, &stamp);
      if (!rc)
        {
          send_status_info (&ctrl, "SERIALNO",
                            serial, strlen(serial), NULL, 0);
          xfree (serial);
          rc = app->fnc.learn_status (app, &ctrl);
        }
    }

  return rc;
}


/* Get an attribute from the card. Make sure info is initialized. */
int 
agent_scd_getattr (const char *name, struct agent_card_info_s *info)
{
  int rc;
  app_t app;
  struct ctrl_ctx_s ctrl;

  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  if (app->assuan_ctx)
    {
      char line[ASSUAN_LINELENGTH];

      /* We assume that NAME does not need escaping. */
      if (12 + strlen (name) > DIM(line)-1)
        return gpg_error (GPG_ERR_CARD);
      stpcpy (stpcpy (line, "SCD GETATTR "), name); 

      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL, NULL, NULL,
                                           learn_status_cb, info),
                          "SCD GETATTR");
    }
  else
    {
      ctrl.status_cb = learn_status_cb;
      ctrl.status_cb_arg = info;
      rc = app->fnc.getattr (app, &ctrl, name);
    }

  return rc;
}



static int 
pin_cb (void *opaque, const char *info, char **retstr)
{
  struct pincb_parm_s *parm = opaque;
  char *value;
  int canceled;
  int isadmin = 0;
  int newpin = 0;
  const char *again_text = NULL;
  const char *ends, *s;
  char *cacheid = NULL;

  *retstr = NULL;
  /*   log_debug ("asking for PIN '%s'\n", info); */

  /* We use a special prefix to check whether the Admin PIN has been
     requested. */
  if (info && *info =='|' && (ends=strchr (info+1, '|')))
    {
      for (s=info+1; s < ends; s++)
        {
          if (*s == 'A')
            isadmin = 1;
          else if (*s == 'N')
            newpin = 1;
        }
      info = ends+1;
    }
  else if (info && *info == '|')
    log_debug ("pin_cb called without proper PIN info hack\n");

  /* If we are not requesting a new PIN and we are not requesting an
     AdminPIN, compute a string to be used as the cacheID for
     gpg-agent. */
  if (!newpin && !isadmin && parm)
    {
      cacheid = format_cacheid (parm->sn);
    }
  else if (newpin && parm)
    {
      /* Make really sure that it is not cached anymore. */
      agent_clear_pin_cache (parm->sn);
    }


 again:
  if (is_status_enabled())
    {
      if (parm && parm->sn && *parm->sn)
        {
          char *buf = xmalloc ( 10 + strlen (parm->sn) + 1);
          strcpy (stpcpy (buf, isadmin? "OPENPGP 3 ":"OPENPGP 1 "), parm->sn);
          write_status_text (STATUS_NEED_PASSPHRASE_PIN, buf);
          xfree (buf);
        }
      else  
        write_status_text (STATUS_NEED_PASSPHRASE_PIN,
                           isadmin? "OPENPGP 3" : "OPENPGP 1");
    }

  value = ask_passphrase (info, again_text,
                          newpin && isadmin? "passphrase.adminpin.new.ask" :
                          newpin?  "passphrase.pin.new.ask" :
                          isadmin? "passphrase.adminpin.ask" :
                                   "passphrase.pin.ask", 
                          newpin && isadmin? _("Enter New Admin PIN: ") :
                          newpin?  _("Enter New PIN: ") :
                          isadmin? _("Enter Admin PIN: ")
                                 : _("Enter PIN: "),
                          cacheid,
                          &canceled);
  xfree (cacheid);
  cacheid = NULL;
  again_text = NULL;
  if (!value && canceled)
    return G10ERR_CANCELED;
  else if (!value)
    return G10ERR_GENERAL;

  if (newpin)
    {
      char *value2;

      value2 = ask_passphrase (info, NULL,
                               "passphrase.pin.repeat", 
                               _("Repeat this PIN: "),
                               NULL,
                               &canceled);
      if (!value2 && canceled)
        {
          xfree (value);
          return G10ERR_CANCELED;
        }
      else if (!value2)
        {
          xfree (value);
          return G10ERR_GENERAL;
        }
      if (strcmp (value, value2))
        {
          again_text = N_("PIN not correctly repeated; try again");
          xfree (value2);
          xfree (value);
          value = NULL;
          goto again;
        }
      xfree (value2);
    }

  *retstr = value;
  return 0;
}



/* Send a SETATTR command to the SCdaemon. */
int 
agent_scd_setattr (const char *name,
                   const unsigned char *value, size_t valuelen,
                   const char *serialno)
{
  app_t app;
  int rc;
  struct pincb_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.sn = serialno;

  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  if (app->assuan_ctx)
    {
      char line[ASSUAN_LINELENGTH];
      char *p;

      /* We assume that NAME does not need escaping. */
      if (12 + strlen (name) > DIM(line)-1)
        return gpg_error (GPG_ERR_CARD);
      p = stpcpy (stpcpy (line, "SCD SETATTR "), name); 
      *p++ = ' ';
      for (; valuelen; value++, valuelen--)
        {
          if (p >= line + DIM(line)-5 )
            return gpg_error (GPG_ERR_CARD);
          if (*value < ' ' || *value == '+' || *value == '%')
            {
              sprintf (p, "%%%02X", *value);
              p += 3;
            }
          else if (*value == ' ')
            *p++ = '+';
          else
            *p++ = *value;
        }
      *p = 0;

      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL, NULL, NULL, NULL, NULL),
                          "SCD SETATTR");
    }
  else
    {
      rc = app->fnc.setattr (app, name, pin_cb, &parm, value, valuelen);
    }

  status_sc_op_failure (rc);
  return rc;
}


/* Handle a KEYDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static assuan_error_t
inq_writekey_parms (void *opaque, const char *keyword)
{
  struct writekey_parm_s *parm = opaque; 

  return assuan_send_data (parm->ctx, parm->keydata, parm->keydatalen);
}


/* Send a WRITEKEY command to the SCdaemon. */
int 
agent_scd_writekey (int keyno, const char *serialno,
                    const unsigned char *keydata, size_t keydatalen)
{
  app_t app;
  int rc;
  char line[ASSUAN_LINELENGTH];
  struct pincb_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.sn = serialno;

  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  if (app->assuan_ctx)
    {
      struct writekey_parm_s parms;

      snprintf (line, DIM(line)-1, "SCD WRITEKEY --force OPENPGP.%d", keyno);
      line[DIM(line)-1] = 0;
      parms.ctx = app->assuan_ctx;
      parms.keydata = keydata;
      parms.keydatalen = keydatalen;
      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL,
                                           inq_writekey_parms, &parms,
                                           NULL, NULL),
                          "SCD WRITEKEY");
    }
  else
    {
      snprintf (line, DIM(line)-1, "OPENPGP.%d", keyno);
      line[DIM(line)-1] = 0;
      rc = app->fnc.writekey (app, NULL, line, 0x0001,
                              pin_cb, &parm,
                              keydata, keydatalen);
    }

  status_sc_op_failure (rc);
  return rc;
}



static assuan_error_t
genkey_status_cb (void *opaque, const char *line)
{
  struct agent_card_genkey_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;

/*   log_debug ("got status line `%s'\n", line); */
  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      parm->fprvalid = unhexify_fpr (line, parm->fpr);
    }
  if (keywordlen == 8 && !memcmp (keyword, "KEY-DATA", keywordlen))
    {
      MPI a;
      const char *name = line;
      char *buf;

      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;

      buf = xmalloc ( 2 + strlen (line) + 1);
      strcpy (stpcpy (buf, "0x"), line);
      a = mpi_alloc (300);
      if( mpi_fromstr (a, buf) )
        log_error ("error parsing received key data\n");
      else if (*name == 'n' && spacep (name+1))
        parm->n = a;
      else if (*name == 'e' && spacep (name+1))
        parm->e = a;
      else
        {
          log_info ("unknown parameter name in received key data\n");
          mpi_free (a);
        }
      xfree (buf);
    }
  else if (keywordlen == 14 && !memcmp (keyword,"KEY-CREATED-AT", keywordlen))
    {
      parm->created_at = (u32)strtoul (line, NULL, 10);
    }

  return 0;
}

/* Send a GENKEY command to the SCdaemon. */
int 
agent_scd_genkey (struct agent_card_genkey_s *info, int keyno, int force,
                  const char *serialno)
{
  app_t app;
  char line[ASSUAN_LINELENGTH];
  struct ctrl_ctx_s ctrl;
  int rc;
  struct pincb_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.sn = serialno;

  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  memset (info, 0, sizeof *info);

  if (app->assuan_ctx)
    {
      snprintf (line, DIM(line)-1, "SCD GENKEY %s%d",
                force? "--force ":"", keyno);
      line[DIM(line)-1] = 0;
      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL, NULL, NULL,
                                           genkey_status_cb, info),
                          "SCD GENKEY");
    }
  else
    {
      snprintf (line, DIM(line)-1, "%d", keyno);
      ctrl.status_cb = genkey_status_cb;
      ctrl.status_cb_arg = info;
      rc = app->fnc.genkey (app, &ctrl, line,
                            force? 1:0,
                            pin_cb, &parm);
    }

  status_sc_op_failure (rc);
  return rc;
}


static assuan_error_t
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
}
  

/* Send a PKSIGN command to the SCdaemon. */
int 
agent_scd_pksign (const char *serialno, int hashalgo,
                  const unsigned char *indata, size_t indatalen,
                  unsigned char **r_buf, size_t *r_buflen)
{
  struct pincb_parm_s parm;
  app_t app;
  int rc;

  *r_buf = NULL;
  *r_buflen = 0;
  memset (&parm, 0, sizeof parm);
  parm.sn = serialno;
 retry:
  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  if (app->assuan_ctx)
    {
      char *p, line[ASSUAN_LINELENGTH];
      membuf_t data;
      size_t len;
      int i;

      if (indatalen*2 + 50 > DIM(line))
        return gpg_error (GPG_ERR_GENERAL);

      p = stpcpy (line, "SCD SETDATA ");
      for (i=0; i < indatalen ; i++, p += 2 )
        sprintf (p, "%02X", indata[i]);
      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL, NULL, NULL, NULL, NULL),
                          "SCD SETDATA");
      if (!rc)
        {
          init_membuf (&data, 1024);
          snprintf (line, DIM(line)-1, "SCD PKSIGN %s%s",
                    hashalgo == GCRY_MD_RMD160? "--hash=rmd160 ": "",
                    serialno);
          line[DIM(line)-1] = 0;
          rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                               membuf_data_cb, &data,
                                               NULL, NULL, NULL, NULL),
                              "SCD PKSIGN");
          if (rc)
            xfree (get_membuf (&data, &len));
          else
            *r_buf = get_membuf (&data, r_buflen);
        }
    }
  else
    {
      /* Check that the card's serialnumber is as required.*/
      rc = check_card_serialno (app, serialno);
      if (rc == -1)
        goto retry;

      if (!rc)
        rc = app->fnc.sign (app, serialno, hashalgo,
                            pin_cb, &parm,
                            indata, indatalen,
                            r_buf, r_buflen);
    }

  if (rc)
    {
      status_sc_op_failure (rc);
      if (!app->assuan_ctx)
        agent_clear_pin_cache (serialno);
    }
  return rc;
}


/* Send a PKDECRYPT command to the SCdaemon. */
int 
agent_scd_pkdecrypt (const char *serialno,
                     const unsigned char *indata, size_t indatalen,
                     unsigned char **r_buf, size_t *r_buflen)
{
  struct pincb_parm_s parm;
  app_t app;
  int rc;

  *r_buf = NULL;
  *r_buflen = 0;
  memset (&parm, 0, sizeof parm);
  parm.sn = serialno;
 retry:
  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  if (app->assuan_ctx)
    {
      char *p, line[ASSUAN_LINELENGTH];
      membuf_t data;
      size_t len;
      int i;

      if (indatalen*2 + 50 > DIM(line))
        return gpg_error (GPG_ERR_GENERAL);

      p = stpcpy (line, "SCD SETDATA ");
      for (i=0; i < indatalen ; i++, p += 2 )
        sprintf (p, "%02X", indata[i]);
      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL, NULL, NULL, NULL, NULL),
                          "SCD SETDATA");
      if (!rc)
        {
          init_membuf (&data, 1024);
          snprintf (line, DIM(line)-1, "SCD PKDECRYPT %s", serialno);
          line[DIM(line)-1] = 0;
          rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                               membuf_data_cb, &data,
                                               NULL, NULL, NULL, NULL),
                              "SCD PKDECRYPT");
          if (rc)
            xfree (get_membuf (&data, &len));
          else
            *r_buf = get_membuf (&data, r_buflen);
        }
    }
  else
    {
      /* Check that the card's serialnumber is as required.*/
      rc = check_card_serialno (app, serialno);
      if (rc == -1)
        goto retry;
      
      if (!rc)
        rc = app->fnc.decipher (app, serialno, 
                                pin_cb, &parm,
                                indata, indatalen,
                                r_buf, r_buflen);
    }

  if (rc)
    {
      status_sc_op_failure (rc);
      if (!app->assuan_ctx)
        agent_clear_pin_cache (serialno);
    }
  return rc;
}

/* Change the PIN of an OpenPGP card or reset the retry
   counter. SERIALNO may be NULL or a hex string finally passed to the
   passphrase callback. */
int 
agent_scd_change_pin (int chvno, const char *serialno)
{
  app_t app;
  int reset = 0;
  int rc;
  struct pincb_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.sn = serialno;

  reset = (chvno >= 100);
  chvno %= 100;

  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  if (app->assuan_ctx)
    {
      char line[ASSUAN_LINELENGTH];

      snprintf (line, DIM(line)-1, "SCD PASSWD%s %d",
                reset? " --reset":"", chvno);
      line[DIM(line)-1] = 0;
      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL, NULL, NULL, NULL, NULL),
                          "SCD PASSWD");
    }
  else
    {
      char chvnostr[50];

      sprintf (chvnostr, "%d", chvno);
      rc = app->fnc.change_pin (app, NULL, chvnostr, reset,
                                pin_cb, &parm);
    }

  status_sc_op_failure (rc);
  return rc;
}

/* Perform a CHECKPIN operation.  SERIALNO should be the serial
   number of the card - optionally followed by the fingerprint;
   however the fingerprint is ignored here. */
int
agent_scd_checkpin (const char *serialnobuf)
{
  app_t app;
  int rc;
  struct pincb_parm_s parm;

  memset (&parm, 0, sizeof parm);
  parm.sn = serialnobuf;

  app = current_app? current_app : open_card ();
  if (!app)
    return gpg_error (GPG_ERR_CARD);

  if (app->assuan_ctx)
    {
      char line[ASSUAN_LINELENGTH];

      if (15 + strlen (serialnobuf) > DIM(line)-1)
        return gpg_error (GPG_ERR_CARD);
      stpcpy (stpcpy (line, "SCD CHECKPIN "), serialnobuf); 
      rc = test_transact (assuan_transact (app->assuan_ctx, line,
                                           NULL, NULL, NULL, NULL, NULL, NULL),
                          "SCD CHECKPIN");
    }
  else
    {
      rc = app->fnc.check_pin (app, serialnobuf, pin_cb, &parm);
    }

  status_sc_op_failure (rc);
  return rc;
}



void
agent_clear_pin_cache (const char *sn)
{
  char *cacheid = format_cacheid (sn);
  if (cacheid)
    {
      passphrase_clear_cache (NULL, cacheid, 0);
      xfree (cacheid);
    }
}

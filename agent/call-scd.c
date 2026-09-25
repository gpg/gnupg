/* call-scd.c - fork of the scdaemon to do SC operations
 * Copyright (C) 2001, 2002, 2005, 2007, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 Werner Koch
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif
#include <npth.h>

#include "agent.h"
#include <assuan.h>
#include "../common/strlist.h"
#include "../common/i18n.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

/* Callback parameter for learn card */
struct learn_parm_s
{
  void (*kpinfo_cb)(void*, const char *);
  void *kpinfo_cb_arg;
  void (*certinfo_cb)(void*, const char *);
  void *certinfo_cb_arg;
  void (*sinfo_cb)(void*, const char *, size_t, const char *);
  void *sinfo_cb_arg;
};


/* Callback parameter used by inq_getpin and inq_writekey_parms.  */
struct inq_needpin_parm_s
{
  assuan_context_t ctx;
  ctrl_t ctrl;
  assuan_context_t passthru;  /* If not NULL, pass unknown inquiries
                                 up to the caller.  */

  /* The next fields are used by inq_writekey_parm.  */
  const unsigned char *keydata;
  size_t keydatalen;
};




static int
start_scd (ctrl_t ctrl)
{
  return daemon_start (DAEMON_SCD, ctrl, 0);
}


static gpg_error_t
unlock_scd (ctrl_t ctrl, gpg_error_t err)
{
  return daemon_unlock (DAEMON_SCD, ctrl, err);
}


static assuan_context_t
daemon_ctx (ctrl_t ctrl)
{
  return daemon_type_ctx (DAEMON_SCD, ctrl);
}



/* This handler is a helper for pincache_put_cb but may also be called
 * directly for that status code with ARGS being the arguments after
 * the status keyword (and with white space removed).  */
static gpg_error_t
handle_pincache_put (const char *args)
{
  gpg_error_t err;
  const char *s, *key, *pin;
  char *keybuf = NULL;
  size_t keylen;

  key = s = args;
  while (*s && !spacep (s))
    s++;
  keylen = s - key;
  if (keylen < 3)
    {
      /* At least we need 2 slashes and slot number.  */
      log_error ("%s: ignoring invalid key\n", __func__);
      err = 0;
      goto leave;
    }

  keybuf = xtrymalloc (keylen+1);
  if (!keybuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  memcpy (keybuf, key, keylen);
  keybuf[keylen] = 0;
  key = keybuf;

  while (spacep (s))
    s++;
  pin = s;
  if (!*pin)
    {
      /* No value - flush the cache.  The cache module knows about
       * the structure of the key to flush only parts.  */
      if (DBG_CACHE)
        log_debug ("%s: flushing cache '%s'\n", __func__, key);
      agent_put_cache (NULL, key, CACHE_MODE_PIN, NULL, -1);
      err = 0;
      goto leave;
    }

  if (DBG_CACHE)
    log_debug ("%s: caching '%s'->'%s'\n", __func__, key, "[hidden]");
  agent_put_cache (NULL, key, CACHE_MODE_PIN, pin, -1);
  err = 0;

 leave:
  xfree (keybuf);
  return err;
}


/* This status callback is to intercept the PINCACHE_PUT status
 * messages.  OPAQUE is not used.  */
static gpg_error_t
pincache_put_cb (void *opaque, const char *line)
{
  const char *s;

  (void)opaque;

  s = has_leading_keyword (line, "PINCACHE_PUT");
  if (s)
    return handle_pincache_put (s);
  else
    return 0;
}


/* Handle a PINCACHE_GET inquiry.  ARGS are the arguments of the
 * inquiry which should be a single string with the key for the cached
 * value.  CTX is the Assuan handle.  */
static gpg_error_t
handle_pincache_get (const char *args, assuan_context_t ctx)
{
  gpg_error_t err;
  const char *key;
  char *pin = NULL;

  if (DBG_CACHE)
    log_debug ("%s: enter '%s'\n", __func__, args);
  key = args;
  if (strlen (key) < 5)
    {
      /* We need at least 2 slashes, one slot number and two 1 byte strings.*/
      err = gpg_error (GPG_ERR_INV_REQUEST);
      log_debug ("%s: key too short\n", __func__);
      goto leave;
    }

  pin = agent_get_cache (NULL, key, CACHE_MODE_PIN);
  if (!pin || !*pin)
    {
      xfree (pin);
      pin = NULL;
      err = 0;  /* Not found is indicated by sending no data back.  */
      if (DBG_CACHE)
        log_debug ("%s: not cached\n", __func__);
      goto leave;
    }
  if (DBG_CACHE)
    log_debug ("%s: cache returned '%s'\n", __func__, "[hidden]"/*pin*/);
  err = assuan_send_data (ctx, pin, strlen (pin));

 leave:
  xfree (pin);
  return err;
}



static gpg_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct learn_parm_s *parm = opaque;
  gpg_error_t err = 0;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;
  if (keywordlen == 8 && !memcmp (keyword, "CERTINFO", keywordlen))
    {
      parm->certinfo_cb (parm->certinfo_cb_arg, line);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "KEYPAIRINFO", keywordlen))
    {
      parm->kpinfo_cb (parm->kpinfo_cb_arg, line);
    }
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);
  else if (keywordlen && *line)
    {
      parm->sinfo_cb (parm->sinfo_cb_arg, keyword, keywordlen, line);
    }

  return err;
}


/* Perform the LEARN command and return a list of all private keys
 * stored on the card.  If DEMAND_SN is given the info is returned for
 * the card with that S/N instead of the current card.  This may then
 * switch the current card.  */
int
agent_card_learn (ctrl_t ctrl,
                  const char *demand_sn,
                  void (*kpinfo_cb)(void*, const char *),
                  void *kpinfo_cb_arg,
                  void (*certinfo_cb)(void*, const char *),
                  void *certinfo_cb_arg,
                  void (*sinfo_cb)(void*, const char *, size_t, const char *),
                  void *sinfo_cb_arg)
{
  int rc;
  struct learn_parm_s parm;
  char line[ASSUAN_LINELENGTH];

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  memset (&parm, 0, sizeof parm);
  parm.kpinfo_cb = kpinfo_cb;
  parm.kpinfo_cb_arg = kpinfo_cb_arg;
  parm.certinfo_cb = certinfo_cb;
  parm.certinfo_cb_arg = certinfo_cb_arg;
  parm.sinfo_cb = sinfo_cb;
  parm.sinfo_cb_arg = sinfo_cb_arg;

  if (demand_sn && *demand_sn)
    snprintf (line, sizeof line, "LEARN --demand=%s --force", demand_sn);
  else
    snprintf (line, sizeof line, "LEARN --force");

  rc = assuan_transact (daemon_ctx (ctrl), line,
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, &parm);
  if (rc)
    return unlock_scd (ctrl, rc);

  return unlock_scd (ctrl, 0);
}



static gpg_error_t
get_serialno_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  char **serialno = opaque;
  const char *keyword = line;
  const char *s;
  int keywordlen, n;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

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
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);

  return err;
}


/* Return the serial number of the card or an appropriate error.  The
 * serial number is returned as a hexstring.  If the serial number is
 * not required by the caller R_SERIALNO can be NULL; this might be
 * useful to test whether a card is available. */
int
agent_card_serialno (ctrl_t ctrl, char **r_serialno, const char *demand)
{
  int rc;
  char *serialno = NULL;
  char line[ASSUAN_LINELENGTH];

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  if (!demand)
    strcpy (line, "SERIALNO --all");
  else
    snprintf (line, DIM(line), "SERIALNO --demand=%s", demand);

  rc = assuan_transact (daemon_ctx (ctrl), line,
                        NULL, NULL, NULL, NULL,
                        get_serialno_cb, &serialno);
  if (rc)
    {
      xfree (serialno);
      return unlock_scd (ctrl, rc);
    }
  if (r_serialno)
    *r_serialno = serialno;
  else
    xfree (serialno);
  return unlock_scd (ctrl, 0);
}




#define MAXPIN 90

#define ASKPIN_NONE  0
#define ASKPIN_END   1
#define ASKPIN_START 2
#define ASKPIN_NEXT  3

static gpg_error_t
scd_check_cb (struct pin_entry_info_s *pi)
{
  gpg_error_t err;
  ctrl_t ctrl = pi->check_cb_arg;
  assuan_context_t scd_ctx;
  int done = 0;

  scd_ctx = daemon_ctx (ctrl);

  assuan_begin_confidential (scd_ctx);
  err = assuan_send_data (scd_ctx, pi->pin, strlen (pi->pin));
  assuan_end_confidential (scd_ctx);

  ctrl->askpin_err = 0;
  ctrl->askpin_arg = NULL;
  npth_cond_signal (&ctrl->askpin_cond);
  npth_mutex_unlock (&ctrl->askpin_lock);

  npth_mutex_lock (&ctrl->askpin_lock);
  while (ctrl->askpin_req == ASKPIN_NONE)
    npth_cond_wait (&ctrl->askpin_cond, &ctrl->askpin_lock);

  if (ctrl->askpin_req == ASKPIN_END)
    {
      ctrl->askpin_req = ASKPIN_NONE;
      ctrl->askpin_err = 0;
      err = 0;
      done = 1;
    }
  else if (ctrl->askpin_req == ASKPIN_NEXT)
    {
      ctrl->askpin_req = ASKPIN_NONE;
      err = ctrl->askpin_err;
      ctrl->askpin_err = 0;
    }
  else
    log_debug ("askpin: invalid request\n");

  if (!done)
    {
      ctrl->askpin_arg = NULL;
      npth_cond_signal (&ctrl->askpin_cond);
      npth_mutex_unlock (&ctrl->askpin_lock);
    }
  return err;
}

static void
select_prompt (ctrl_t ctrl, const char **r_prompt, int *r_newpin,
               int *r_any_flags)
{
  const char *info = ctrl->askpin_arg;
  const char *ends;
  const char *prompt = "PIN";

  /* Parse the flags. */
  if (info && *info =='|' && (ends=strchr (info+1, '|')))
    {
      const char *s;

      for (s=info+1; s < ends; s++)
        {
          if (*s == 'A')
            prompt = L_("Admin PIN");
          else if (*s == 'P')
            /* TRANSLATORS: A PUK is the Personal Unblocking Code
               used to unblock a PIN. */
            prompt = L_("PUK");
          else if (*s == 'N')
            *r_newpin = 1;
          else if (*s == 'R')
            prompt = L_("Reset Code");
        }
      ctrl->askpin_arg = ends+1;
      *r_any_flags = 1;
    }
  else if (info && *info == '|')
    log_debug ("pin_cb called without proper PIN info hack\n");

  *r_prompt = prompt;
}


static void *
askpin_thread (void *arg)
{
  ctrl_t ctrl = arg;

  npth_mutex_lock (&ctrl->askpin_lock);
  while (ctrl->askpin_req == ASKPIN_NONE)
    npth_cond_wait (&ctrl->askpin_cond, &ctrl->askpin_lock);

  if (ctrl->askpin_req == ASKPIN_END)
    {
      ctrl->askpin_req = ASKPIN_NONE;
      ctrl->askpin_err = 0;
      ctrl->askpin_arg = NULL;
    }
  else if (ctrl->askpin_req == ASKPIN_START)
    {
      gpg_error_t err;
      struct pin_entry_info_s *pi;

      ctrl->askpin_req = ASKPIN_NONE;
      pi = gcry_calloc_secure (1, sizeof (*pi) + MAXPIN);
      if (!pi)
        err = gpg_error_from_syserror ();
      else
        {
          const char *prompt;
          int newpin = 0;
          int any_flags = 0;
          char *desc = NULL;

          pi->max_length = MAXPIN - 1;
          pi->min_digits = 0; // ??? 1 ???
          pi->max_digits = 16;
          pi->max_tries = 1;
          pi->check_cb = scd_check_cb;
          pi->check_cb_arg = ctrl;

          select_prompt (ctrl, &prompt, &newpin, &any_flags);
          if (*ctrl->askpin_arg)
            {
              const char *info = ctrl->askpin_arg;
              if (!any_flags)
                asprintf (&desc,
                          L_("Please enter the PIN%s%s%s to unlock the card"),
                          " (",
                          info,
                          ")");
              else
                asprintf (&desc, "%s", info);
            }
          else
            {
              asprintf (&desc,
                        L_("Please enter the PIN%s%s%s to unlock the card"),
                        "", "", "");
            }
          if (newpin)
            pi->with_repeat = 1;
          if (desc)
            {
              npth_mutex_unlock (&ctrl->askpin_lock);
              err = agent_askpin (ctrl, desc, prompt, NULL, pi, NULL, 0);
              npth_mutex_lock (&ctrl->askpin_lock);
            }
          else
            err = gpg_error_from_syserror ();
          xfree (desc);
        }

      ctrl->askpin_err = err;
      xfree (pi);
    }
  else
    {
      /* NOTE: ASKPIN_NEXT is handled in the callback.  */
      log_debug ("askpin: unknown request\n");
      ctrl->askpin_err = GPG_ERR_UNSUPPORTED_PROTOCOL;
    }

  ctrl->askpin_arg = NULL;
  npth_cond_signal (&ctrl->askpin_cond);
  npth_mutex_unlock (&ctrl->askpin_lock);
  return NULL;
}

static gpg_error_t
start_askpin_thread (ctrl_t ctrl)
{
  npth_attr_t tattr;
  npth_t tid;
  int rc;

  rc = npth_mutex_init (&ctrl->askpin_lock, NULL);
  if (rc)
    return gpg_error_from_errno (rc);

  rc = npth_cond_init (&ctrl->askpin_cond, NULL);
  if (rc)
    {
      npth_mutex_destroy (&ctrl->askpin_lock);
      return gpg_error_from_errno (rc);
    }

  rc = npth_attr_init (&tattr);
  if (rc)
    {
      npth_mutex_destroy (&ctrl->askpin_lock);
      npth_cond_destroy (&ctrl->askpin_cond);
      return gpg_error_from_errno (rc);
    }
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  rc = npth_create (&tid, &tattr, askpin_thread, ctrl);
  npth_attr_destroy (&tattr);
  if (rc)
    {
      npth_mutex_destroy (&ctrl->askpin_lock);
      npth_cond_destroy (&ctrl->askpin_cond);
      return gpg_error_from_errno (rc);
    }

  ctrl->inq_askpin_tid = tid;
  return 0;
}

static gpg_error_t
finish_askpin_thread (ctrl_t ctrl)
{
  int rc;

  if (!ctrl->inq_askpin_tid)
    return 0;

  npth_mutex_lock (&ctrl->askpin_lock);
  ctrl->askpin_req = ASKPIN_END;
  npth_cond_signal (&ctrl->askpin_cond);
  npth_mutex_unlock (&ctrl->askpin_lock);

  rc = npth_join (ctrl->inq_askpin_tid, NULL);

  ctrl->inq_askpin_tid = 0;
  npth_mutex_destroy (&ctrl->askpin_lock);
  npth_cond_destroy (&ctrl->askpin_cond);
  return gpg_error_from_errno (rc);
}

static gpg_error_t
scd_pin_request_start (ctrl_t ctrl, const char *info)
{
  gpg_error_t err;

  err = start_askpin_thread (ctrl);
  if (err)
    return err;

  npth_mutex_lock (&ctrl->askpin_lock);
  ctrl->askpin_req = ASKPIN_START;
  ctrl->askpin_arg = info;
  ctrl->askpin_err = 0;
  npth_cond_signal (&ctrl->askpin_cond);
  while (ctrl->askpin_arg)
    npth_cond_wait (&ctrl->askpin_cond, &ctrl->askpin_lock);
  err = ctrl->askpin_err;
  npth_mutex_unlock (&ctrl->askpin_lock);

  if (err)
    finish_askpin_thread (ctrl);

  return err;
}

static gpg_error_t
scd_pin_request_next (ctrl_t ctrl, const char *info)
{
  gpg_error_t err;

  npth_mutex_lock (&ctrl->askpin_lock);
  ctrl->askpin_req = ASKPIN_NEXT;
  ctrl->askpin_arg = info;
  ctrl->askpin_err = GPG_ERR_BAD_PIN;
  npth_cond_signal (&ctrl->askpin_cond);
  while (ctrl->askpin_arg)
    npth_cond_wait (&ctrl->askpin_cond, &ctrl->askpin_lock);
  err = ctrl->askpin_err;
  npth_mutex_unlock (&ctrl->askpin_lock);

  if (err)
    finish_askpin_thread (ctrl);

  return err;
}

static gpg_error_t
scd_pin_request_finish (ctrl_t ctrl, const char *info)
{
  gpg_error_t err;

  npth_mutex_lock (&ctrl->askpin_lock);
  ctrl->askpin_req = ASKPIN_END;
  ctrl->askpin_arg = info;
  ctrl->askpin_err = 0;
  npth_cond_signal (&ctrl->askpin_cond);
  while (ctrl->askpin_arg)
    npth_cond_wait (&ctrl->askpin_cond, &ctrl->askpin_lock);
  err = ctrl->askpin_err;
  npth_mutex_unlock (&ctrl->askpin_lock);

  err = finish_askpin_thread (ctrl);
  return err;
}


/* Callback used to ask for the PIN which should be set into BUF.  The
   buf has been allocated by the caller and is of size MAXBUF which
   includes the terminating null.  The function should return an UTF-8
   string with the passphrase, the buffer may optionally be padded
   with arbitrary characters.

   INFO gets displayed as part of a generic string.  However if the
   first character of INFO is a vertical bar all up to the next
   vertical bar are considered flags and only everything after the
   second vertical bar gets displayed as the full prompt.

   Flags:

      'N' = New PIN, this requests a second prompt to repeat the
            PIN.  If the PIN is not correctly repeated it starts from
            all over.
      'A' = The PIN is an Admin PIN, SO-PIN or alike.
      'P' = The PIN is a PUK (Personal Unblocking Key).
      'R' = The PIN is a Reset Code.

   Example:

     "|AN|Please enter the new security officer's PIN"

   The text "Please ..." will get displayed and the flags 'A' and 'N'
   are considered.
 */
static int
scd_getpin (ctrl_t ctrl, const char *info, char *buf, size_t maxbuf)
{
  struct pin_entry_info_s *pi;
  int rc;
  const char *ends, *s;
  int any_flags = 0;
  int newpin = 0;
  int resetcode = 0;
  int is_puk = 0;
  const char *again_text = NULL;
  const char *prompt = "PIN";

  if (buf && maxbuf < 2)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Parse the flags. */
  if (info && *info =='|' && (ends=strchr (info+1, '|')))
    {
      for (s=info+1; s < ends; s++)
        {
          if (*s == 'A')
            prompt = L_("Admin PIN");
          else if (*s == 'P')
            {
              /* TRANSLATORS: A PUK is the Personal Unblocking Code
                 used to unblock a PIN. */
              prompt = L_("PUK");
              is_puk = 1;
            }
          else if (*s == 'N')
            newpin = 1;
          else if (*s == 'R')
            {
              prompt = L_("Reset Code");
              resetcode = 1;
            }
        }
      info = ends+1;
      any_flags = 1;
    }
  else if (info && *info == '|')
    log_debug ("pin_cb called without proper PIN info hack\n");

  /* If BUF has been passed as NULL, we are in pinpad mode: The
     callback opens the popup and immediately returns. */
  if (!buf)
    {
      if (maxbuf == 0) /* Close the pinentry. */
        {
          agent_popup_message_stop (ctrl);
          rc = 0;
        }
      else if (maxbuf == 1)  /* Open the pinentry. */
        {
          if (info)
            {
              char *desc;
              const char *desc2;

              if (!strcmp (info, "--ack"))
                {
                  desc2 = L_("Push ACK button on card/token.");
                  desc = NULL;
                }
              else
                {
                  desc2 = NULL;
                  desc = strconcat (info, "%0A%0A",
                                    L_("Use the reader's pinpad for input."),
                                    NULL);
                }

              if (!desc2 && !desc)
                rc = gpg_error_from_syserror ();
              else
                {
                  rc = agent_popup_message_start (ctrl,
                                                  desc2? desc2:desc, NULL);
                  xfree (desc);
                }
            }
          else
            rc = agent_popup_message_start (ctrl, NULL, NULL);
        }
      else
        rc = gpg_error (GPG_ERR_INV_VALUE);
      return rc;
    }

  /* FIXME: keep PI and TRIES in OPAQUE.  Frankly this is a whole
     mess because we should call the card's verify function from the
     pinentry check pin CB. */
 again:
  pi = gcry_calloc_secure (1, sizeof (*pi) + maxbuf + 10);
  if (!pi)
    return gpg_error_from_syserror ();
  pi->max_length = maxbuf-1;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 16;
  pi->max_tries = 3;

  if (any_flags)
    {
      rc = agent_askpin (ctrl, info, prompt, again_text, pi, NULL, 0);
      again_text = NULL;
      if (!rc && newpin)
        {
          struct pin_entry_info_s *pi2;
          pi2 = gcry_calloc_secure (1, sizeof (*pi) + maxbuf + 10);
          if (!pi2)
            {
              rc = gpg_error_from_syserror ();
              xfree (pi);
              return rc;
            }
          pi2->max_length = maxbuf-1;
          pi2->min_digits = 0;
          pi2->max_digits = 16;
          pi2->max_tries = 1;
          rc = agent_askpin (ctrl,
                             (resetcode?
                              L_("Repeat this Reset Code"):
                              is_puk?
                              L_("Repeat this PUK"):
                              L_("Repeat this PIN")),
                             prompt, NULL, pi2, NULL, 0);
          if (!rc && strcmp (pi->pin, pi2->pin))
            {
              again_text = (resetcode?
                            L_("Reset Code not correctly repeated; try again"):
                            is_puk?
                            L_("PUK not correctly repeated; try again"):
                            L_("PIN not correctly repeated; try again"));
              xfree (pi2);
              xfree (pi);
              goto again;
            }
          xfree (pi2);
        }
    }
  else
    {
      char *desc;

      if ( asprintf (&desc,
                     L_("Please enter the PIN%s%s%s to unlock the card"),
                     info? " (":"",
                     info? info:"",
                     info? ")":"") < 0)
        desc = NULL;
      rc = agent_askpin (ctrl, desc? desc : info, prompt, NULL, pi, NULL, 0);
      xfree (desc);
    }

  if (!rc)
    {
      strncpy (buf, pi->pin, maxbuf-1);
      buf[maxbuf-1] = 0;
    }
  xfree (pi);
  return rc;
}

/* Handle the NEEDPIN inquiry. */
static gpg_error_t
inq_needpin (void *opaque, const char *line)
{
  struct inq_needpin_parm_s *parm = opaque;
  const char *s;
  char *pin;
  size_t pinlen;
  int rc;

  if ((s = has_leading_keyword (line, "NEEDPIN")))
    {
      line = s;
      pinlen = 90;
      pin = gcry_malloc_secure (pinlen);
      if (!pin)
        return out_of_core ();

      rc = scd_getpin (parm->ctrl, line, pin, pinlen);
      if (!rc)
        {
          assuan_begin_confidential (parm->ctx);
          rc = assuan_send_data (parm->ctx, pin, pinlen);
          assuan_end_confidential (parm->ctx);
        }
      wipememory (pin, pinlen);
      xfree (pin);
    }
  else if ((s = has_leading_keyword (line, "POPUPPINPADPROMPT")))
    {
      rc = scd_getpin (parm->ctrl, s, NULL, 1);
    }
  else if ((s = has_leading_keyword (line, "DISMISSPINPADPROMPT")))
    {
      rc = scd_getpin (parm->ctrl, "", NULL, 0);
    }
  else if ((s = has_leading_keyword (line, "PINCACHE_GET")))
    {
      rc = handle_pincache_get (s, parm->ctx);
    }
  else if ((s = has_leading_keyword (line, "ASKPIN")))
    {
      rc = scd_pin_request_start (parm->ctrl, line);
    }
  else if ((s = has_leading_keyword (line, "NEXTPIN")))
    {
      rc = scd_pin_request_next (parm->ctrl, line);
    }
  else if ((s = has_leading_keyword (line, "FINISHPIN")))
    {
      rc = scd_pin_request_finish (parm->ctrl, line);
    }
  else if (parm->passthru)
    {
      unsigned char *value;
      size_t valuelen;
      int rest;
      int needrest = !strncmp (line, "KEYDATA", 8);

      /* Pass the inquiry up to our caller.  We limit the maximum
         amount to an arbitrary value.  As we know that the KEYDATA
         enquiry is pretty sensitive we disable logging then */
      if ((rest = (needrest
                   && !assuan_get_flag (parm->passthru, ASSUAN_CONFIDENTIAL))))
        assuan_begin_confidential (parm->passthru);
      rc = assuan_inquire (parm->passthru, line, &value, &valuelen, 8096);
      if (rest)
        assuan_end_confidential (parm->passthru);
      if (!rc)
        {
          if ((rest = (needrest
                       && !assuan_get_flag (parm->ctx, ASSUAN_CONFIDENTIAL))))
            assuan_begin_confidential (parm->ctx);
          rc = assuan_send_data (parm->ctx, value, valuelen);
          if (rest)
            assuan_end_confidential (parm->ctx);
          xfree (value);
        }
      else
        log_error ("error forwarding inquiry '%s': %s\n",
                   line, gpg_strerror (rc));
    }
  else
    {
      log_error ("unsupported inquiry '%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return rc;
}


/* Helper returning a command option to describe the used hash
   algorithm.  See scd/command.c:cmd_pksign.  */
static const char *
hash_algo_option (int algo)
{
  switch (algo)
    {
    case GCRY_MD_MD5   : return "--hash=md5";
    case GCRY_MD_RMD160: return "--hash=rmd160";
    case GCRY_MD_SHA1  : return "--hash=sha1";
    case GCRY_MD_SHA224: return "--hash=sha224";
    case GCRY_MD_SHA256: return "--hash=sha256";
    case GCRY_MD_SHA384: return "--hash=sha384";
    case GCRY_MD_SHA512: return "--hash=sha512";
    default:             return "";
    }
}


static int
prepare_setdata (ctrl_t ctrl, const unsigned char *indata, size_t indatalen)
{
  int rc;
  char *p, line[ASSUAN_LINELENGTH];
  size_t len;
  int i;

  for (len = 0; len < indatalen;)
    {
      p = stpcpy (line, "SETDATA ");
      if (len)
        p = stpcpy (p, "--append ");
      for (i=0; len < indatalen && (i*2 < DIM(line)-50); i++, len++)
        {
          sprintf (p, "%02X", indata[len]);
          p += 2;
        }
      rc = assuan_transact (daemon_ctx (ctrl), line,
                            NULL, NULL, NULL, NULL, NULL, NULL);
      if (rc)
        return rc;
    }

  return 0;
}

/* Create a signature using the current card.  MDALGO is either 0 or
 * gives the digest algorithm.  DESC_TEXT is an additional parameter
 * passed to GETPIN_CB. */
int
agent_card_pksign (ctrl_t ctrl,
                   const char *keyid,
                   int mdalgo,
                   const unsigned char *indata, size_t indatalen,
                   unsigned char **r_buf, size_t *r_buflen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_needpin_parm_s inqparm;

  *r_buf = NULL;
  rc = start_scd (ctrl);
  if (rc)
    return rc;

  /* FIXME: In the mdalgo case (INDATA,INDATALEN) might be long and
   * thus we can't convey it on a single Assuan line.  */
  if (!mdalgo)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  rc = prepare_setdata (ctrl, indata, indatalen);
  if (rc)
    return unlock_scd (ctrl, rc);

  init_membuf (&data, 1024);
  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.ctrl = ctrl;
  inqparm.passthru = 0;
  inqparm.keydata = NULL;
  inqparm.keydatalen = 0;

  if (ctrl->use_auth_call)
    snprintf (line, sizeof line, "PKAUTH %s", keyid);
  else
    snprintf (line, sizeof line, "PKSIGN %s %s",
              hash_algo_option (mdalgo), keyid);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        inq_needpin, &inqparm,
                        pincache_put_cb, NULL);

  if (rc)
    {
      size_t len;

      xfree (get_membuf (&data, &len));
      return unlock_scd (ctrl, rc);
    }

  *r_buf = get_membuf (&data, r_buflen);
  return unlock_scd (ctrl, 0);
}




/* Check whether there is any padding info from scdaemon.  */
static gpg_error_t
padding_info_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  int *r_padding = opaque;
  const char *s;

  if ((s=has_leading_keyword (line, "PADDING")))
    {
      if (r_padding)
        *r_padding = atoi (s);
    }
  else if ((s=has_leading_keyword (line, "PINCACHE_PUT")))
    err = handle_pincache_put (s);

  return err;
}


/* Decipher INDATA using the current card.  Note that the returned
 * value is not an s-expression but the raw data as returned by
 * scdaemon.  The padding information is stored at R_PADDING with -1
 * for not known, when it's not NULL.  DESC_TEXT is an additional
 * parameter passed to GETPIN_CB.  */
int
agent_card_pkdecrypt (ctrl_t ctrl,
                      const char *keyid,
                      const unsigned char *indata, size_t indatalen,
                      unsigned char **r_buf, size_t *r_buflen, int *r_padding)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_needpin_parm_s inqparm;
  size_t len;

  *r_buf = NULL;
  if (r_padding)
    *r_padding = -1; /* Unknown.  */
  rc = start_scd (ctrl);
  if (rc)
    return rc;

  /* FIXME: use secure memory where appropriate */

  rc = prepare_setdata (ctrl, indata, indatalen);
  if (rc)
    return unlock_scd (ctrl, rc);

  init_membuf (&data, 1024);
  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.ctrl = ctrl;
  inqparm.passthru = 0;
  inqparm.keydata = NULL;
  inqparm.keydatalen = 0;
  snprintf (line, DIM(line), "PKDECRYPT %s", keyid);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        inq_needpin, &inqparm,
                        padding_info_cb, r_padding);

  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (ctrl, rc);
    }
  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return unlock_scd (ctrl, gpg_error (GPG_ERR_ENOMEM));

  return unlock_scd (ctrl, 0);
}



/* Read a certificate with ID into R_BUF and R_BUFLEN. */
int
agent_card_readcert (ctrl_t ctrl,
                     const char *id, char **r_buf, size_t *r_buflen)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len;

  *r_buf = NULL;
  rc = start_scd (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line), "READCERT %s", id);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        NULL, NULL,
                        pincache_put_cb, NULL);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return unlock_scd (ctrl, rc);
    }
  *r_buf = get_membuf (&data, r_buflen);
  if (!*r_buf)
    return unlock_scd (ctrl, gpg_error (GPG_ERR_ENOMEM));

  return unlock_scd (ctrl, 0);
}



struct readkey_status_parm_s
{
  char *keyref;
};

static gpg_error_t
readkey_status_cb (void *opaque, const char *line)
{
  struct readkey_status_parm_s *parm = opaque;
  gpg_error_t err = 0;
  char *line_buffer = NULL;
  const char *s;

  if ((s = has_leading_keyword (line, "KEYPAIRINFO"))
      && !parm->keyref)
    {
      /* The format of such a line is:
       *   KEYPAIRINFO <hexgrip> <keyref> [usage] [keytime] [algostr]
       *
       * Here we only need the keyref.  We use only the first received
       * KEYPAIRINFO; it is possible to receive several if there are
       * two or more active cards with the same key.  */
      const char *fields[2];
      int nfields;

      line_buffer = xtrystrdup (line);
      if (!line_buffer)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      if ((nfields = split_fields (line_buffer, fields, DIM (fields))) < 2)
        goto leave;  /* Not enough args; invalid status line - skip.  */

      parm->keyref = xtrystrdup (fields[1]);
      if (!parm->keyref)
        err = gpg_error_from_syserror ();
    }
  else
    err = pincache_put_cb (NULL, line);

 leave:
  xfree (line_buffer);
  return err;
}


/* Read a key with ID (keyref or keygrip) and return it in a malloced
 * buffer pointed to by R_BUF as a valid S-expression.  If R_KEYREF is
 * not NULL the keyref is stored there. */
int
agent_card_readkey (ctrl_t ctrl, const char *id,
                    unsigned char **r_buf, char **r_keyref)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t len, buflen;
  struct readkey_status_parm_s parm;

  memset (&parm, 0, sizeof parm);

  *r_buf = NULL;
  if (r_keyref)
    *r_keyref = NULL;

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  snprintf (line, DIM(line), "READKEY%s -- %s",
            r_keyref? " --info":"", id);
  rc = assuan_transact (daemon_ctx (ctrl), line,
                        put_membuf_cb, &data,
                        NULL, NULL,
                        readkey_status_cb, &parm);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      xfree (parm.keyref);
      return unlock_scd (ctrl, rc);
    }
  *r_buf = get_membuf (&data, &buflen);
  if (!*r_buf)
    {
      xfree (parm.keyref);
      return unlock_scd (ctrl, gpg_error (GPG_ERR_ENOMEM));
    }

  if (!gcry_sexp_canon_len (*r_buf, buflen, NULL, NULL))
    {
      xfree (parm.keyref);
      xfree (*r_buf); *r_buf = NULL;
      return unlock_scd (ctrl, gpg_error (GPG_ERR_INV_VALUE));
    }
  if (r_keyref)
    *r_keyref = parm.keyref;
  else
    xfree (parm.keyref);

  return unlock_scd (ctrl, 0);
}


/* Handle a KEYDATA inquiry.  Note, we only send the data,
   assuan_transact takes care of flushing and writing the end */
static gpg_error_t
inq_writekey_parms (void *opaque, const char *line)
{
  struct inq_needpin_parm_s *parm = opaque;

  if (has_leading_keyword (line, "KEYDATA"))
    return assuan_send_data (parm->ctx, parm->keydata, parm->keydatalen);
  else
    return inq_needpin (opaque, line);
}


/* Call scd to write a key to a card under the id KEYREF.  */
gpg_error_t
agent_card_writekey (ctrl_t ctrl,  int force, const char *serialno,
                     const char *keyref,
                     const char *keydata, size_t keydatalen)
{
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct inq_needpin_parm_s parms;

  (void)serialno; /* NULL or a number to check for the correct card.
                   * But is is not implemented.  */

  err = start_scd (ctrl);
  if (err)
    return err;

  snprintf (line, DIM(line), "WRITEKEY %s%s", force ? "--force " : "", keyref);
  parms.ctx = daemon_ctx (ctrl);
  parms.ctrl = ctrl;
  parms.passthru = 0;
  parms.keydata = keydata;
  parms.keydatalen = keydatalen;

  err = assuan_transact (daemon_ctx (ctrl), line, NULL, NULL,
                         inq_writekey_parms, &parms,
                         pincache_put_cb, NULL);
  return unlock_scd (ctrl, err);
}



/* Type used with the card_getattr_cb.  */
struct card_getattr_parm_s {
  const char *keyword;  /* Keyword to look for.  */
  size_t keywordlen;    /* strlen of KEYWORD.  */
  char *data;           /* Malloced and unescaped data.  */
  int error;            /* ERRNO value or 0 on success. */
};

/* Callback function for agent_card_getattr.  */
static gpg_error_t
card_getattr_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct card_getattr_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;

  if (parm->data)
    return 0; /* We want only the first occurrence.  */

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == parm->keywordlen
      && !memcmp (keyword, parm->keyword, keywordlen))
    {
      parm->data = percent_plus_unescape ((const unsigned char*)line, 0xff);
      if (!parm->data)
        parm->error = errno;
    }
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);

  return err;
}


/* Call the agent to retrieve a single line data object. On success
   the object is malloced and stored at RESULT; it is guaranteed that
   NULL is never stored in this case.  On error an error code is
   returned and NULL stored at RESULT. */
gpg_error_t
agent_card_getattr (ctrl_t ctrl, const char *name, char **result,
                    const char *keygrip)
{
  int err;
  struct card_getattr_parm_s parm;
  char line[ASSUAN_LINELENGTH];

  *result = NULL;

  if (!*name)
    return gpg_error (GPG_ERR_INV_VALUE);

  memset (&parm, 0, sizeof parm);
  parm.keyword = name;
  parm.keywordlen = strlen (name);

  /* We assume that NAME does not need escaping. */
  if (8 + strlen (name) > DIM(line)-1)
    return gpg_error (GPG_ERR_TOO_LARGE);
  if (keygrip == NULL)
    stpcpy (stpcpy (line, "GETATTR "), name);
  else
    snprintf (line, sizeof line, "GETATTR %s %s", name, keygrip);

  err = start_scd (ctrl);
  if (err)
    return err;

  err = assuan_transact (daemon_ctx (ctrl), line,
                         NULL, NULL, NULL, NULL,
                         card_getattr_cb, &parm);
  if (!err && parm.error)
    err = gpg_error_from_errno (parm.error);

  if (!err && !parm.data)
    err = gpg_error (GPG_ERR_NO_DATA);

  if (!err)
    *result = parm.data;
  else
    xfree (parm.data);

  return unlock_scd (ctrl, err);
}



struct card_keyinfo_parm_s {
  int error;
  struct card_key_info_s *list;
};

/* Callback function for agent_card_keylist.  */
static gpg_error_t
card_keyinfo_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct card_keyinfo_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  struct card_key_info_s *keyinfo = NULL;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 7 && !memcmp (keyword, "KEYINFO", keywordlen))
    {
      const char *s;
      int n;
      struct card_key_info_s **l_p = &parm->list;

      /* It's going to append the information at the end.  */
      while ((*l_p))
        l_p = &(*l_p)->next;

      keyinfo = xtrycalloc (1, sizeof *keyinfo);
      if (!keyinfo)
        goto alloc_error;

      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;

      if (n != 40)
        goto parm_error;

      memcpy (keyinfo->keygrip, line, 40);
      keyinfo->keygrip[40] = 0;

      line = s;

      if (!*line)
        goto parm_error;

      while (spacep (line))
        line++;

      if (*line++ != 'T')
        goto parm_error;

      if (!*line)
        goto parm_error;

      while (spacep (line))
        line++;

      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;

      if (!n)
        goto skip;

      keyinfo->serialno = xtrymalloc (n+1);
      if (!keyinfo->serialno)
        goto alloc_error;

      memcpy (keyinfo->serialno, line, n);
      keyinfo->serialno[n] = 0;

      line = s;

      if (!*line)
        goto skip;

      while (spacep (line))
        line++;

      if (!*line)
        goto skip;

      for (s = line; *s && !spacep (s); s++)
        ;

      keyinfo->idstr = xtrymalloc (s - line + 1);
      if (!keyinfo->idstr)
        goto alloc_error;
      memcpy (keyinfo->idstr, line, s - line);
      keyinfo->idstr[s - line] = 0;

      while (spacep (s))
        s++;

      if (!*s)
        goto skip;

      keyinfo->usage = xtrystrdup (s);
      if (!keyinfo->usage)
        goto alloc_error;

    skip:
      *l_p = keyinfo;
    }
  else if (keywordlen == 12 && !memcmp (keyword, "PINCACHE_PUT", keywordlen))
    err = handle_pincache_put (line);

  return err;

 alloc_error:
  xfree (keyinfo->serialno);
  xfree (keyinfo->idstr);
  xfree (keyinfo);
  if (!parm->error)
    parm->error = gpg_error_from_syserror ();
  return 0;

 parm_error:
  xfree (keyinfo);
  if (!parm->error)
    parm->error = gpg_error (GPG_ERR_ASS_PARAMETER);
  return 0;
}


void
agent_card_free_keyinfo (struct card_key_info_s *l)
{
  struct card_key_info_s *l_next;

  for (; l; l = l_next)
    {
      l_next = l->next;
      xfree (l->serialno);
      xfree (l->idstr);
      xfree (l->usage);
      xfree (l);
    }
}

/* Call the scdaemon to check if a key of KEYGRIP is available, or
   retrieve list of available keys on cards.  With CAP, we can limit
   keys with specified capability.  On success, the allocated
   structure is stored at RESULT.  On error, an error code is returned
   and NULL is stored at RESULT.  */
gpg_error_t
agent_card_keyinfo (ctrl_t ctrl, const char *keygrip, int cap,
                    struct card_key_info_s **result)
{
  int err;
  struct card_keyinfo_parm_s parm;
  char line[ASSUAN_LINELENGTH];
  char *list_option;

  *result = NULL;

  switch (cap)
    {
    case                  0: list_option = "--list";      break;
    case GCRY_PK_USAGE_SIGN: list_option = "--list=sign"; break;
    case GCRY_PK_USAGE_ENCR: list_option = "--list=encr"; break;
    case GCRY_PK_USAGE_AUTH: list_option = "--list=auth"; break;
    default:                 return gpg_error (GPG_ERR_INV_VALUE);
    }

  memset (&parm, 0, sizeof parm);
  snprintf (line, sizeof line, "KEYINFO %s", keygrip ? keygrip : list_option);

  err = start_scd (ctrl);
  if (err)
    return err;

  err = assuan_transact (daemon_ctx (ctrl), line,
                         NULL, NULL, NULL, NULL,
                         card_keyinfo_cb, &parm);
  if (!err && parm.error)
    err = parm.error;

  if (!err)
    *result = parm.list;
  else
    agent_card_free_keyinfo (parm.list);

  return unlock_scd (ctrl, err);
}

static gpg_error_t
pass_status_thru (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  assuan_context_t ctx = opaque;
  char keyword[200];
  int i;

  if (line[0] == '#' && (!line[1] || spacep (line+1)))
    {
      /* We are called in convey comments mode.  Now, if we see a
         comment marker as keyword we forward the line verbatim to the
         the caller.  This way the comment lines from scdaemon won't
         appear as status lines with keyword '#'.  */
      assuan_write_line (ctx, line);
    }
  else
    {
      for (i=0; *line && !spacep (line) && i < DIM(keyword)-1; line++, i++)
        keyword[i] = *line;
      keyword[i] = 0;

      /* Truncate any remaining keyword stuff.  */
      for (; *line && !spacep (line); line++)
        ;
      while (spacep (line))
        line++;

      /* We do not want to pass PINCACHE_PUT through.  */
      if (!strcmp (keyword, "PINCACHE_PUT"))
        err = handle_pincache_put (line);
      else
        assuan_write_status (ctx, keyword, line);
    }
  return err;
}

static gpg_error_t
pass_data_thru (void *opaque, const void *buffer, size_t length)
{
  assuan_context_t ctx = opaque;

  assuan_send_data (ctx, buffer, length);
  return 0;
}

#define DEVINFO_WATCH_COMMAND "DEVINFO --watch"

struct devinfo_watch_thread {
  ctrl_t ctrl;
  void *assuan_context;
};

static void *
devinfo_watch_thread (void *arg)
{
  struct devinfo_watch_thread *d = arg;

  assuan_set_flag (daemon_ctx (d->ctrl), ASSUAN_CONVEY_COMMENTS, 1);
  assuan_transact (daemon_ctx (d->ctrl), DEVINFO_WATCH_COMMAND,
                   pass_data_thru, d->assuan_context,
                   NULL, NULL,
                   pass_status_thru, d->assuan_context);
  return NULL;
}

static int
agent_card_devinfo (ctrl_t ctrl, void *assuan_context)
{
  npth_t thread;
  struct devinfo_watch_thread dwt;
  gpg_error_t err = 0;
  npth_attr_t tattr;
  assuan_context_t scd_ctx;
  gnupg_fd_t scd_fds[2];
  gnupg_fd_t client_input;
  gnupg_fd_t scd_sock;
  int rc;
  gnupg_fd_t client_fds[2];

  if (ctrl->thread_startup.fd == GNUPG_INVALID_FD)
    return GPG_ERR_INV_HANDLE;

  rc = daemon_start (DAEMON_SCD, ctrl, 1);
  if (rc)
    return rc;

  dwt.ctrl = ctrl;
  dwt.assuan_context = assuan_context;
  scd_ctx = daemon_ctx (ctrl);

  err = npth_attr_init (&tattr);
  if (err)
    return err;

  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);
  err = npth_create (&thread, &tattr, devinfo_watch_thread, &dwt);
  npth_attr_destroy (&tattr);
  if (err)
    {
      log_error ("error spawning devinfo_watch_thread: %s\n", strerror (err));
      return err;
    }

  assuan_get_active_fds (assuan_context, 0, client_fds, 2);
  client_input = client_fds[0];

  assuan_get_active_fds (scd_ctx, 0, scd_fds, 2);
  scd_sock = scd_fds[0];

  while (1)
    {
      fd_set fdset;
      int nfd;
      int ret;

      FD_ZERO (&fdset);
      FD_SET (FD2INT (client_input), &fdset);
      nfd = FD2NUM (client_input);

      ret = npth_select (nfd+1, &fdset, NULL, NULL, NULL);
      if (ret == 1)
        break;
    }

  /* Forcibly close the socket connection to scdaemon.  */
#ifdef HAVE_W32_SYSTEM
# if _WIN64
  shutdown ((uintptr_t)scd_sock, SD_BOTH);
# else
  shutdown ((unsigned int)scd_sock, SD_BOTH);
# endif
#else
  shutdown (scd_sock, SHUT_RDWR);
#endif
  /* Then, join the thread.  */
  npth_join (thread, NULL);

  return unlock_scd (ctrl, rc);
}

/* Send the line CMDLINE with command for the SCDdaemon to it and send
   all status messages back.  This command is used as a general quoting
   mechanism to pass everything verbatim to SCDAEMON.  The PIN
   inquiry is handled inside gpg-agent.  */
int
agent_card_scd (ctrl_t ctrl, const char *cmdline, void *assuan_context)
{
  int rc;
  struct inq_needpin_parm_s inqparm;
  int saveflag;

  /* This is a layer violation, but it's needed that because DEVINFO
     --watch is so special.  */
  if (!strcmp (cmdline, DEVINFO_WATCH_COMMAND))
    return agent_card_devinfo (ctrl, assuan_context);

  rc = start_scd (ctrl);
  if (rc)
    return rc;

  inqparm.ctx = daemon_ctx (ctrl);
  inqparm.ctrl = ctrl;
  inqparm.passthru = assuan_context;
  inqparm.keydata = NULL;
  inqparm.keydatalen = 0;

  saveflag = assuan_get_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS);
  assuan_set_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS, 1);
  rc = assuan_transact (daemon_ctx (ctrl), cmdline,
                        pass_data_thru, assuan_context,
                        inq_needpin, &inqparm,
                        pass_status_thru, assuan_context);

  assuan_set_flag (daemon_ctx (ctrl), ASSUAN_CONVEY_COMMENTS, saveflag);
  if (rc)
    {
      return unlock_scd (ctrl, rc);
    }

  return unlock_scd (ctrl, 0);
}

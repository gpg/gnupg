/* app.c - Application selection.
 * Copyright (C) 2003, 2004, 2005 Free Software Foundation, Inc.
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
#include <npth.h>

#include "scdaemon.h"
#include "../common/exechelp.h"
#include "iso7816.h"
#include "apdu.h"
#include "../common/tlv.h"
#include "../common/membuf.h"


/* Forward declaration of internal function.  */
static gpg_error_t
select_additional_application_internal (card_t card, apptype_t req_apptype);
static gpg_error_t
send_serialno_and_app_status (card_t card, int with_apps, ctrl_t ctrl);

/* Lock to protect the list of cards and its associated
 * applications.  */
static npth_mutex_t card_list_lock;

/* A list of card contexts.  A card is a collection of applications
 * (described by app_t) on the same physical token. */
static card_t card_top;


/* The list of application names and their select function.  If no
 * specific application is selected the first available application on
 * a card is selected.  */
struct app_priority_list_s
{
  apptype_t apptype;
  char const *name;
  gpg_error_t (*select_func)(app_t);
};

static struct app_priority_list_s app_priority_list[] =
  {{ APPTYPE_OPENPGP  , "openpgp",   app_select_openpgp   },
   { APPTYPE_PIV      , "piv",       app_select_piv       },
   { APPTYPE_NKS      , "nks",       app_select_nks       },
   { APPTYPE_P15      , "p15",       app_select_p15       },
   { APPTYPE_GELDKARTE, "geldkarte", app_select_geldkarte },
   { APPTYPE_DINSIG   , "dinsig",    app_select_dinsig    },
   { APPTYPE_SC_HSM   , "sc-hsm",    app_select_sc_hsm    },
   { APPTYPE_NONE     , NULL,        NULL                 }
   /* APPTYPE_UNDEFINED is special and not listed here.  */
  };





/* Map a cardtype to a string.  Never returns NULL.  */
const char *
strcardtype (cardtype_t t)
{
  switch (t)
    {
    case CARDTYPE_GENERIC: return "generic";
    case CARDTYPE_YUBIKEY: return "yubikey";
    }
  return "?";
}


/* Map an application type to a string.  Never returns NULL.  */
const char *
strapptype (apptype_t t)
{
  int i;

  for (i=0; app_priority_list[i].apptype; i++)
    if (app_priority_list[i].apptype == t)
      return app_priority_list[i].name;
  return t == APPTYPE_UNDEFINED? "undefined" : t? "?" : "none";
}


const char *
xstrapptype (app_t app)
{
  return app? strapptype (app->apptype) : "[no_app]";
}


/* Return the apptype for NAME.  */
static apptype_t
apptype_from_name (const char *name)
{
  int i;

  if (!name)
    return APPTYPE_NONE;

  for (i=0; app_priority_list[i].apptype; i++)
    if (!ascii_strcasecmp (app_priority_list[i].name, name))
      return app_priority_list[i].apptype;
  if (!ascii_strcasecmp ("undefined", name))
    return APPTYPE_UNDEFINED;
  return APPTYPE_NONE;
}


/* Return the apptype for KEYREF.  This is the first part of the
 * KEYREF up to the dot.  */
static apptype_t
apptype_from_keyref (const char *keyref)
{
  int i;
  unsigned int n;
  const char *s;

  if (!keyref)
    return APPTYPE_NONE;
  s = strchr (keyref, '.');
  if (!s || s == keyref || !s[1])
    return APPTYPE_NONE; /* Not a valid keyref.  */
  n = s - keyref;

  for (i=0; app_priority_list[i].apptype; i++)
    if (strlen (app_priority_list[i].name) == n
        && !ascii_strncasecmp (app_priority_list[i].name, keyref, n))
      return app_priority_list[i].apptype;

  return APPTYPE_NONE;
}


/* Initialization function to change the default app_priority_list.
 * LIST is a list of comma or space separated strings with application
 * names.  Unknown names will only result in warning message.
 * Application not mentioned in LIST are used in their original order
 * after the given once.  */
void
app_update_priority_list (const char *arg)
{
  struct app_priority_list_s save;
  char **names;
  int i, j, idx;

  names = strtokenize (arg, ", ");
  if (!names)
    log_fatal ("strtokenize failed: %s\n",
               gpg_strerror (gpg_error_from_syserror ()));

  idx = 0;
  for (i=0; names[i]; i++)
    {
      ascii_strlwr (names[i]);
      for (j=0; j < i; j++)
        if (!strcmp (names[j], names[i]))
          break;
      if (j < i)
        {
          log_info ("warning: duplicate application '%s' in priority list\n",
                    names[i]);
          continue;
        }

      for (j=idx; app_priority_list[j].name; j++)
        if (!strcmp (names[i], app_priority_list[j].name))
          break;
      if (!app_priority_list[j].name)
        {
          log_info ("warning: unknown application '%s' in priority list\n",
                    names[i]);
          continue;
        }
      save = app_priority_list[idx];
      app_priority_list[idx] = app_priority_list[j];
      app_priority_list[j] = save;
      idx++;
    }
  log_assert (idx < DIM (app_priority_list));

  xfree (names);
  for (i=0; app_priority_list[i].name; i++)
    log_info ("app priority %d: %s\n", i, app_priority_list[i].name);
}


static void
print_progress_line (void *opaque, const char *what, int pc, int cur, int tot)
{
  ctrl_t ctrl = opaque;
  char line[100];

  if (ctrl)
    {
      snprintf (line, sizeof line, "%s %c %d %d", what, pc, cur, tot);
      send_status_direct (ctrl, "PROGRESS", line);
    }
}


/* Lock the CARD.  This function shall be used right before calling
 * any of the actual application functions to serialize access to the
 * reader.  We do this always even if the card is not actually used.
 * This allows an actual connection to assume that it never shares a
 * card (while performing one command).  Returns 0 on success; only
 * then the unlock_reader function must be called after returning from
 * the handler.  Right now we assume a that a reader has just one
 * card; this may eventually need refinement. */
static gpg_error_t
lock_card (card_t card, ctrl_t ctrl)
{
  if (npth_mutex_lock (&card->lock))
    {
      gpg_error_t err = gpg_error_from_syserror ();
      log_error ("failed to acquire CARD lock for %p: %s\n",
                 card, gpg_strerror (err));
      return err;
    }

  apdu_set_progress_cb (card->slot, print_progress_line, ctrl);
  apdu_set_prompt_cb (card->slot, popup_prompt, ctrl);

  return 0;
}


/* Release a lock on a card.  See lock_reader(). */
static void
unlock_card (card_t card)
{
  apdu_set_progress_cb (card->slot, NULL, NULL);
  apdu_set_prompt_cb (card->slot, NULL, NULL);

  if (npth_mutex_unlock (&card->lock))
    {
      gpg_error_t err = gpg_error_from_syserror ();
      log_error ("failed to release CARD lock for %p: %s\n",
                 card, gpg_strerror (err));
    }
}


/* This function may be called to print information pertaining to the
 * current state of this module to the log. */
void
app_dump_state (void)
{
  card_t c;
  app_t a;

  npth_mutex_lock (&card_list_lock);
  for (c = card_top; c; c = c->next)
    {
      log_info ("app_dump_state: card=%p slot=%d type=%s\n",
                c, c->slot, strcardtype (c->cardtype));
      /* FIXME The use of log_info risks a race!  */
      for (a=c->app; a; a = a->next)
        log_info ("app_dump_state:   app=%p type='%s'\n",
                  a, strapptype (a->apptype));
    }
  npth_mutex_unlock (&card_list_lock);
}


/* Check whether the application NAME is allowed.  This does not mean
   we have support for it though.  */
static int
is_app_allowed (const char *name)
{
  strlist_t l;

  for (l=opt.disabled_applications; l; l = l->next)
    if (!strcmp (l->d, name))
      return 0; /* no */
  return 1; /* yes */
}


/* This function is mainly used by the serialno command to check for
 * an application conflict which may appear if the serialno command is
 * used to request a specific application and the connection has
 * already done a select_application.   Return values are:
 *   0              - No conflict
 *   GPG_ERR_FALSE  - Another application is in use but it is possible
 *                    to switch to the requested application.
 *   Other code     - Switching is not possible.
 *
 * If SERIALNO_BIN is not NULL a conflict is only asserted if the
 * serialno of the card matches.
 */
gpg_error_t
check_application_conflict (card_t card, const char *name,
                            const unsigned char *serialno_bin,
                            size_t serialno_bin_len)
{
  apptype_t apptype;

  if (!card || !name)
    return 0;
  if (!card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED); /* Should not happen.  */

  if (serialno_bin && card->serialno)
    {
      if (serialno_bin_len != card->serialnolen
          || memcmp (serialno_bin, card->serialno, card->serialnolen))
        return 0; /* The card does not match the requested S/N.  */
    }

  apptype = apptype_from_name (name);
  if (card->app->apptype == apptype)
    return 0;

  if (card->app->apptype == APPTYPE_UNDEFINED)
    return 0;

  if (card->cardtype == CARDTYPE_YUBIKEY)
    {
      if (card->app->apptype == APPTYPE_OPENPGP)
        {
          /* Current app is OpenPGP.  */
          if (!ascii_strcasecmp (name, "piv"))
            return gpg_error (GPG_ERR_FALSE);  /* Switching allowed.  */
        }
      else if (card->app->apptype == APPTYPE_PIV)
        {
          /* Current app is PIV.  */
          if (!ascii_strcasecmp (name, "openpgp"))
            return gpg_error (GPG_ERR_FALSE);  /* Switching allowed.  */
        }
    }

  log_info ("application '%s' in use - can't switch\n",
            strapptype (card->app->apptype));

  return gpg_error (GPG_ERR_CONFLICT);
}


gpg_error_t
card_reset (card_t card, ctrl_t ctrl, int send_reset)
{
  gpg_error_t err = 0;

  if (send_reset)
    {
      int sw;

      lock_card (card, ctrl);
      sw = apdu_reset (card->slot);
      if (sw)
        err = gpg_error (GPG_ERR_CARD_RESET);

      card->reset_requested = 1;
      unlock_card (card);

      scd_kick_the_loop ();
      gnupg_sleep (1);
    }
  else
    {
      ctrl->card_ctx = NULL;
      ctrl->current_apptype = APPTYPE_NONE;
      card_unref (card);
    }

  return err;
}

static gpg_error_t
app_new_register (int slot, ctrl_t ctrl, const char *name,
                  int periodical_check_needed)
{
  gpg_error_t err = 0;
  card_t card = NULL;
  app_t app = NULL;
  unsigned char *result = NULL;
  size_t resultlen;
  int want_undefined;
  int i;

  /* Need to allocate a new card object  */
  card = xtrycalloc (1, sizeof *card);
  if (!card)
    {
      err = gpg_error_from_syserror ();
      log_info ("error allocating context: %s\n", gpg_strerror (err));
      return err;
    }

  card->slot = slot;
  card->card_status = (unsigned int)-1;

  if (npth_mutex_init (&card->lock, NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("error initializing mutex: %s\n", gpg_strerror (err));
      xfree (card);
      return err;
    }

  err = lock_card (card, ctrl);
  if (err)
    {
      xfree (card);
      return err;
    }

  want_undefined = (name && !strcmp (name, "undefined"));

  /* Try to read the GDO file first to get a default serial number.
     We skip this if the undefined application has been requested. */
  if (!want_undefined)
    {
      err = iso7816_select_file (slot, 0x3F00, 1);
      if (gpg_err_code (err) == GPG_ERR_CARD)
        {
          /* Might be SW==0x7D00.  Let's test whether it is a Yubikey
           * by selecting its manager application and then reading the
           * config.  */
          static char const yk_aid[] =
            { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17 }; /*MGR*/
          static char const otp_aid[] =
            { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01 }; /*OTP*/
          unsigned char *buf;
          size_t buflen;
          const unsigned char *s0;
          unsigned char formfactor;
          size_t n;

          if (!iso7816_select_application (slot, yk_aid, sizeof yk_aid,
                                           0x0001)
              && !iso7816_apdu_direct (slot, "\x00\x1d\x00\x00\x00", 5, 0,
                                       NULL, &buf, &buflen))
            {
              card->cardtype = CARDTYPE_YUBIKEY;
              if (opt.verbose)
                {
                  log_info ("Yubico: config=");
                  log_printhex (buf, buflen, "");
                }

              /* We skip the first byte which seems to be the total
               * length of the config data.  */
              if (buflen > 1)
                {
                  s0 = find_tlv (buf+1, buflen-1, 0x04, &n);  /* Form factor */
                  formfactor = (s0 && n == 1)? *s0 : 0;

                  s0 = find_tlv (buf+1, buflen-1, 0x02, &n);  /* Serial */
                  if (s0 && n >= 4)
                    {
                      card->serialno = xtrymalloc (3 + 1 + n);
                      if (card->serialno)
                        {
                          card->serialnolen = 3 + 1 + n;
                          card->serialno[0] = 0xff;
                          card->serialno[1] = 0x02;
                          card->serialno[2] = 0x0;
                          card->serialno[3] = formfactor;
                          memcpy (card->serialno + 4, s0, n);
                          /* Note that we do not clear the error
                           * so that no further serial number
                           * testing is done.  After all we just
                           * set the serial number.  */
                        }
                    }

                  s0 = find_tlv (buf+1, buflen-1, 0x05, &n);  /* version */
                  if (s0 && n == 3)
                    card->cardversion = ((s0[0]<<16)|(s0[1]<<8)|s0[2]);
                  else if (!s0)
                    {
                      /* No version - this is not a Yubikey 5.  We now
                       * switch to the OTP app and take the first
                       * three bytes of the reponse as version
                       * number.  */
                      xfree (buf);
                      buf = NULL;
                      if (!iso7816_select_application_ext (slot,
                                                       otp_aid, sizeof otp_aid,
                                                       1, &buf, &buflen)
                          && buflen > 3)
                        card->cardversion = ((buf[0]<<16)|(buf[1]<<8)|buf[2]);
                    }
                }
              xfree (buf);
            }
        }

      if (!err)
        err = iso7816_select_file (slot, 0x2F02, 0);
      if (!err)
        err = iso7816_read_binary (slot, 0, 0, &result, &resultlen);
      if (!err)
        {
          size_t n;
          const unsigned char *p;

          p = find_tlv_unchecked (result, resultlen, 0x5A, &n);
          if (p)
            resultlen -= (p-result);
          if (p && n > resultlen && n == 0x0d && resultlen+1 == n)
            {
              /* The object does not fit into the buffer.  This is an
                 invalid encoding (or the buffer is too short.  However, I
                 have some test cards with such an invalid encoding and
                 therefore I use this ugly workaround to return something
                 I can further experiment with. */
              log_info ("enabling BMI testcard workaround\n");
              n--;
            }

          if (p && n <= resultlen)
            {
              /* The GDO file is pretty short, thus we simply reuse it for
                 storing the serial number. */
              memmove (result, p, n);
              card->serialno = result;
              card->serialnolen = n;
              err = app_munge_serialno (card);
              if (err)
                goto leave;
            }
          else
            xfree (result);
          result = NULL;
        }
    }

  /* Allocate a new app object.  */
  app = xtrycalloc (1, sizeof *app);
  if (!app)
    {
      err = gpg_error_from_syserror ();
      log_info ("error allocating app context: %s\n", gpg_strerror (err));
      goto leave;
    }
  card->app = app;
  app->card = card;

  /* Figure out the application to use.  */
  if (want_undefined)
    {
      /* We switch to the "undefined" application only if explicitly
         requested.  */
      app->apptype = APPTYPE_UNDEFINED;
      /* Clear the error so that we don't run through the application
       * selection chain.  */
      err = 0;
    }
  else
    {
      /* For certain error codes, there is no need to try more.  */
      if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT
          || gpg_err_code (err) == GPG_ERR_ENODEV)
        goto leave;

      /* Set a default error so that we run through the application
       * selection chain.  */
      err = gpg_error (GPG_ERR_NOT_FOUND);
    }

  /* Find the first available app if NAME is NULL or the matching
   * NAME but only if that application is also enabled.  */
  for (i=0; err && app_priority_list[i].name; i++)
    {
      if (is_app_allowed (app_priority_list[i].name)
          && (!name || !strcmp (name, app_priority_list[i].name)))
        err = app_priority_list[i].select_func (app);
    }
  if (err && name && gpg_err_code (err) != GPG_ERR_OBJ_TERM_STATE)
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);

 leave:
  if (err)
    {
      if (name)
        log_info ("can't select application '%s': %s\n",
                  name, gpg_strerror (err));
      else
        log_info ("no supported card application found: %s\n",
                  gpg_strerror (err));
      unlock_card (card);
      xfree (app);
      xfree (card);
      return err;
    }

  card->periodical_check_needed = periodical_check_needed;
  card->next = card_top;
  card_top = card;

  unlock_card (card);
  return 0;
}


/* If called with NAME as NULL, select the best fitting application
 * and return its card context; otherwise select the application with
 * NAME and return its card context.  Returns an error code and stores
 * NULL at R_CARD if no application was found or no card is present.  */
gpg_error_t
select_application (ctrl_t ctrl, const char *name, card_t *r_card,
                    int scan, const unsigned char *serialno_bin,
                    size_t serialno_bin_len)
{
  gpg_error_t err = 0;
  card_t card, card_prev = NULL;

  *r_card = NULL;

  npth_mutex_lock (&card_list_lock);

  if (scan || !card_top)
    {
      struct dev_list *l;
      int new_card = 0;

      /* Scan the devices to find new device(s).  */
      err = apdu_dev_list_start (opt.reader_port, &l);
      if (err)
        {
          npth_mutex_unlock (&card_list_lock);
          return err;
        }

      while (1)
        {
          int slot;
          int periodical_check_needed_this;

          slot = apdu_open_reader (l);
          if (slot < 0)
            break;

          periodical_check_needed_this = apdu_connect (slot);
          if (periodical_check_needed_this < 0)
            {
              /* We close a reader with no card.  */
              err = gpg_error (GPG_ERR_ENODEV);
            }
          else
            {
              err = app_new_register (slot, ctrl, name,
                                      periodical_check_needed_this);
              new_card++;
            }

          if (err)
            {
              pincache_put (ctrl, slot, NULL, NULL, NULL, 0);
              apdu_close_reader (slot);
            }
        }

      apdu_dev_list_finish (l);

      /* If new device(s), kick the scdaemon loop.  */
      if (new_card)
        scd_kick_the_loop ();
    }

  for (card = card_top; card; card = card->next)
    {
      lock_card (card, ctrl);
      if (serialno_bin == NULL)
        break;
      if (card->serialnolen == serialno_bin_len
          && !memcmp (card->serialno, serialno_bin, card->serialnolen))
        break;
      unlock_card (card);
      card_prev = card;
    }

  if (card)
    {
      err = check_application_conflict (card, name, NULL, 0);
      if (!err)
        ctrl->current_apptype = card->app ? card->app->apptype : APPTYPE_NONE;
      else if (gpg_err_code (err) == GPG_ERR_FALSE)
        {
          apptype_t req_apptype = apptype_from_name (name);

          if (!req_apptype)
            err = gpg_error (GPG_ERR_NOT_FOUND);
          else
            {
              err = select_additional_application_internal (card, req_apptype);
              if (!err)
                ctrl->current_apptype = req_apptype;
            }
        }

      if (!err)
        {
          /* Note: We do not use card_ref as we are already locked.  */
          card->ref_count++;
          *r_card = card;
          if (card_prev)
            {
              card_prev->next = card->next;
              card->next = card_top;
              card_top = card;
            }
        }
      unlock_card (card);
    }
  else
    err = gpg_error (GPG_ERR_ENODEV);

  npth_mutex_unlock (&card_list_lock);

  return err;
}


/* Switch the current card for the session CTRL and print a SERIALNO
 * status line on success.  (SERIALNO, SERIALNOLEN) is the binary s/n
 * of the card to switch to.  */
gpg_error_t
app_switch_current_card (ctrl_t ctrl,
                         const unsigned char *serialno, size_t serialnolen)
{
  gpg_error_t err;
  card_t card, cardtmp;

  npth_mutex_lock (&card_list_lock);

  if (!ctrl->card_ctx)
    {
      err = gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
      goto leave;
    }

  if (serialno && serialnolen)
    {
      for (card = card_top; card; card = card->next)
        {
          if (card->serialnolen == serialnolen
              && !memcmp (card->serialno, serialno, card->serialnolen))
            break;
        }
      if (!card)
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }

      /* Note: We do not use card_ref here because we only swap the
       * context of the current session and there is no chance of a
       * context switch.  This also works if the card stays the same. */
      cardtmp = ctrl->card_ctx;
      ctrl->card_ctx = card;
      card->ref_count++;
      card_unref_locked (cardtmp);
    }

  /* Print the status line.  */
  err = send_serialno_and_app_status (ctrl->card_ctx, 0, ctrl);

 leave:
  npth_mutex_unlock (&card_list_lock);
  return err;
}


static gpg_error_t
select_additional_application_internal (card_t card, apptype_t req_apptype)
{
  gpg_error_t err = 0;
  app_t app;
  int i;

  /* Check that the requested app has not yet been put onto the list.  */
  for (app = card->app; app; app = app->next)
    if (app->apptype == req_apptype)
      {
        /* We already got this one.  Note that in this case we don't
         * make it the current one but it doesn't matter because
         * maybe_switch_app will do that anyway.  */
        err = 0;
        app = NULL;
        goto leave;
      }

  /* Allocate a new app object.  */
  app = xtrycalloc (1, sizeof *app);
  if (!app)
    {
      err = gpg_error_from_syserror ();
      log_info ("error allocating app context: %s\n", gpg_strerror (err));
      goto leave;
    }
  app->card = card;

  /* Find the app and run the select.  */
  for (i=0; app_priority_list[i].apptype; i++)
    {
      if (app_priority_list[i].apptype == req_apptype
          && is_app_allowed (app_priority_list[i].name))
        {
          err = app_priority_list[i].select_func (app);
          break;
        }
    }
  if (!app_priority_list[i].apptype
      || (err && gpg_err_code (err) != GPG_ERR_OBJ_TERM_STATE))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);

  if (err)
    goto leave;

  /* Add this app.  We make it the current one to avoid an extra
   * reselect by maybe_switch_app after the select we just did.  */
  app->next = card->app;
  card->app = app;
  log_info ("added app '%s' to the card context and switched\n",
            strapptype (app->apptype));

 leave:
  if (err)
    xfree (app);
  return err;
}


/* Add all possible additional applications to the card context but do
 * not change the current one.  This currently works only for Yubikeys. */
static gpg_error_t
select_all_additional_applications_internal (card_t card)
{
  gpg_error_t err = 0;
  apptype_t candidates[3];
  int i, j;

  if (card->cardtype == CARDTYPE_YUBIKEY)
    {
      candidates[0] = APPTYPE_OPENPGP;
      candidates[1] = APPTYPE_PIV;
      candidates[2] = APPTYPE_NONE;
    }
  else
    {
      candidates[0] = APPTYPE_NONE;
    }

  /* Find the app and run the select.  */
  for (i=0; app_priority_list[i].apptype; i++)
    {
      app_t app, app_r, app_prev;

      for (j=0; candidates[j]; j++)
        if (candidates[j] == app_priority_list[i].apptype
            && is_app_allowed (app_priority_list[i].name))
          break;
      if (!candidates[j])
        continue;

      for (app = card->app; app; app = app->next)
        if (app->apptype == candidates[j])
          break;
      if (app)
        continue; /* Already on the list of apps.  */

      app = xtrycalloc (1, sizeof *app);
      if (!app)
        {
          err = gpg_error_from_syserror ();
          log_info ("error allocating app context: %s\n", gpg_strerror (err));
          goto leave;
        }
      app->card = card;
      err = app_priority_list[i].select_func (app);
      if (err)
        {
          log_error ("error selecting additional app '%s': %s - skipped\n",
                     strapptype (candidates[j]), gpg_strerror (err));
          err = 0;
          xfree (app);
        }
      else
        {
          /* Append to the list of apps.  */
          app_prev = card->app;
          for (app_r=app_prev->next; app_r; app_prev=app_r, app_r=app_r->next)
            ;
          app_prev->next = app;
          log_info ("added app '%s' to the card context\n",
                    strapptype (app->apptype));
        }
    }

 leave:
  return err;
}


/* This function needs to be called with the NAME of the new
 * application to be selected on CARD.  On success the application is
 * added to the list of the card's active applications as currently
 * active application.  On error no new application is allocated.
 * Selecting an already selected application has no effect. */
gpg_error_t
select_additional_application (ctrl_t ctrl, const char *name)
{
  gpg_error_t err = 0;
  apptype_t req_apptype;
  card_t card;

  if (!name)
    req_apptype = 0;
  else
    {
      req_apptype = apptype_from_name (name);
      if (!req_apptype)
        return gpg_error (GPG_ERR_NOT_FOUND);
    }

  card = ctrl->card_ctx;
  if (!card)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);

  err = lock_card (card, ctrl);
  if (err)
    return err;

  if (req_apptype)
    {
      err = select_additional_application_internal (card, req_apptype);
      if (!err)
        {
          ctrl->current_apptype = req_apptype;
          log_debug ("current_apptype is set to %s\n", name);
        }
    }
  else
    {
      err = select_all_additional_applications_internal (card);
    }

  unlock_card (card);
  return err;
}


char *
get_supported_applications (void)
{
  int idx;
  size_t nbytes;
  char *buffer, *p;
  const char *s;

  for (nbytes=1, idx=0; (s=app_priority_list[idx].name); idx++)
    nbytes += strlen (s) + 1 + 1;

  buffer = xtrymalloc (nbytes);
  if (!buffer)
    return NULL;

  for (p=buffer, idx=0; (s=app_priority_list[idx].name); idx++)
    if (is_app_allowed (s))
      p = stpcpy (stpcpy (p, s), ":\n");
  *p = 0;

  return buffer;
}


/* Deallocate the application.  */
static void
deallocate_card (card_t card)
{
  card_t c, c_prev = NULL;
  app_t a, anext;

  for (c = card_top; c; c = c->next)
    if (c == card)
      {
        if (c_prev == NULL)
          card_top = c->next;
        else
          c_prev->next = c->next;
        break;
      }
    else
      c_prev = c;

  if (card->ref_count)
    log_error ("releasing still used card context (%d)\n", card->ref_count);

  for (a = card->app; a; a = anext)
    {
      if (a->fnc.deinit)
        {
          a->fnc.deinit (a);
          a->fnc.deinit = NULL;
        }
      anext = a->next;
      xfree (a);
    }

  xfree (card->serialno);
  unlock_card (card);
  xfree (card);
}


/* Increment the reference counter of CARD.  Returns CARD.  */
card_t
card_ref (card_t card)
{
  lock_card (card, NULL);
  ++card->ref_count;
  unlock_card (card);
  return card;
}


/* Decrement the reference counter for CARD.  Note that we are using
 * reference counting to track the users of the card's application and
 * are deferring the actual deallocation to allow for a later reuse by
 * a new connection.  Using NULL for CARD is a no-op. */
void
card_unref (card_t card)
{
  if (!card)
    return;

  /* We don't deallocate CARD here.  Instead, we keep it.  This is
     useful so that a card does not get reset even if only one session
     is using the card - this way the PIN cache and other cached data
     are preserved.  */

  lock_card (card, NULL);
  card_unref_locked (card);
  unlock_card (card);
}


/* This is the same as card_unref but assumes that CARD is already
 * locked.  */
void
card_unref_locked (card_t card)
{
  if (!card)
    return;

  if (!card->ref_count)
    log_bug ("tried to release an already released card context\n");

  --card->ref_count;
}



/* The serial number may need some cosmetics.  Do it here.  This
   function shall only be called once after a new serial number has
   been put into APP->serialno.

   Prefixes we use:

     FF 00 00 = For serial numbers starting with an FF
     FF 01 00 = Some german p15 cards return an empty serial number so the
                serial number from the EF(TokenInfo) is used instead.
     FF 02 00 = Serial number from Yubikey config
     FF 7F 00 = No serialno.

     All other serial numbers not starting with FF are used as they are.
*/
gpg_error_t
app_munge_serialno (card_t card)
{
  if (card->serialnolen && card->serialno[0] == 0xff)
    {
      /* The serial number starts with our special prefix.  This
         requires that we put our default prefix "FF0000" in front. */
      unsigned char *p = xtrymalloc (card->serialnolen + 3);
      if (!p)
        return gpg_error_from_syserror ();
      memcpy (p, "\xff\0", 3);
      memcpy (p+3, card->serialno, card->serialnolen);
      card->serialnolen += 3;
      xfree (card->serialno);
      card->serialno = p;
    }
  else if (!card->serialnolen)
    {
      unsigned char *p = xtrymalloc (3);
      if (!p)
        return gpg_error_from_syserror ();
      memcpy (p, "\xff\x7f", 3);
      card->serialnolen = 3;
      xfree (card->serialno);
      card->serialno = p;
    }
  return 0;
}



/* Retrieve the serial number of the card.  The serial number is
   returned as a malloced string (hex encoded) in SERIAL.  Caller must
   free SERIAL unless the function returns an error.  */
char *
card_get_serialno (card_t card)
{
  char *serial;

  if (!card)
    return NULL;

  if (!card->serialnolen)
    serial = xtrystrdup ("FF7F00");
  else
    serial = bin2hex (card->serialno, card->serialnolen, NULL);

  return serial;
}

/* Same as card_get_serialno but takes an APP object.  */
char *
app_get_serialno (app_t app)
{
  if (!app || !app->card)
    return NULL;
  return card_get_serialno (app->card);
}


/* Helper to run the reselect function.  */
static gpg_error_t
run_reselect (ctrl_t ctrl, card_t c, app_t a, app_t a_prev)
{
  gpg_error_t err;

  if (!a->fnc.reselect)
    {
      log_info ("slot %d, app %s: re-select not implemented\n",
                c->slot, xstrapptype (a));
      return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
    }

  /* Give the current app a chance to save some state before another
   * app is selected.  We ignore errors here because that state saving
   * (e.g. putting PINs into a cache) is a convenience feature and not
   * required to always work. */
  if (a_prev && a_prev->fnc.prep_reselect)
    {
      err = a_prev->fnc.prep_reselect (a_prev, ctrl);
      if (err)
        log_error ("slot %d, app %s: preparing re-select from %s failed: %s\n",
                   c->slot, xstrapptype (a),
                   xstrapptype (a_prev), gpg_strerror (err));
    }

  err = a->fnc.reselect (a, ctrl);
  if (err)
    {
      log_error ("slot %d, app %s: error re-selecting: %s\n",
                     c->slot, xstrapptype (a), gpg_strerror (err));
      return err;
    }
  if (DBG_APP)
    log_debug ("slot %d, app %s: re-selected\n", c->slot, xstrapptype (a));

  return 0;
}


/* Check that the card has been initialized and whether we need to
 * switch to another application on the same card.  Switching means
 * that the new active app will be moved to the head of the list at
 * CARD->app.  This function must be called with the card lock held. */
static gpg_error_t
maybe_switch_app (ctrl_t ctrl, card_t card, const char *keyref)
{
  gpg_error_t err;
  app_t app;
  app_t app_prev = NULL;
  apptype_t apptype;

  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!ctrl->current_apptype)
    {
      /* For whatever reasons the current apptype has not been set -
       * fix that and use the current app.  */
      ctrl->current_apptype = card->app->apptype;
      return 0;
    }
  if (DBG_APP)
    log_debug ("slot %d: have=%s want=%s keyref=%s\n",
               card->slot, strapptype (card->app->apptype),
               strapptype (ctrl->current_apptype),
               keyref? keyref:"[none]");

  app = NULL;
  if (keyref)
    {
      /* Switch based on the requested KEYREF.  */
      apptype = apptype_from_keyref (keyref);
      if (apptype)
        {
          for (app = card->app; app; app_prev = app, app = app->next)
            if (app->apptype == apptype)
              break;
          if (!app_prev && ctrl->current_apptype == card->app->apptype)
            return 0;  /* Already the first app - no need to switch.  */
        }
      else if (strlen (keyref) == 40)
        {
          /* This looks like a keygrip.  Iterate over all apps to find
           * the corresponding app.  */
          for (app = card->app; app; app_prev = app, app = app->next)
            if (app->fnc.with_keygrip
                && !app->fnc.with_keygrip (app, ctrl,
                                           KEYGRIP_ACTION_LOOKUP, keyref, 0))
              break;
          if (!app_prev && ctrl->current_apptype == card->app->apptype)
            return 0;   /* Already the first app - no need to switch.  */
        }
    }

  if (!app)
    {
      /* Switch based on the current application of this connection or
       * if a keyref based switch didn't worked.  */
      if (ctrl->current_apptype == card->app->apptype)
        return 0; /* No need to switch.  */
      app_prev = card->app;
      for (app = app_prev->next; app; app_prev = app, app = app->next)
        if (app->apptype == ctrl->current_apptype)
          break;
    }
  if (!app)
    return gpg_error (GPG_ERR_WRONG_CARD);

  err = run_reselect (ctrl, card, app, app_prev);
  if (err)
    return err;

  /* Swap APP with the head of the app list if needed.  Note that APP
   * is not the head of the list. */
  if (app_prev)
    {
      app_prev->next = app->next;
      app->next = card->app;
      card->app = app;
    }

  if (opt.verbose)
    log_info ("slot %d, app %s: %s\n",
              card->slot, xstrapptype (app),
              app_prev? "switched":"re-selected");

  ctrl->current_apptype = app->apptype;

  return 0;
}


/* Helper for app_write_learn_status.  */
static gpg_error_t
write_learn_status_core (card_t card, app_t app, ctrl_t ctrl,
                         unsigned int flags)
{
  /* We do not send CARD and APPTYPE if only keypairinfo is requested.  */
  if (!(flags & APP_LEARN_FLAG_KEYPAIRINFO))
    {
      if (card && card->cardtype)
        send_status_direct (ctrl, "CARDTYPE", strcardtype (card->cardtype));
      if (card && card->cardversion)
        send_status_printf (ctrl, "CARDVERSION", "%X", card->cardversion);
      if (app->apptype)
        send_status_direct (ctrl, "APPTYPE", strapptype (app->apptype));
      if (app->appversion)
        send_status_printf (ctrl, "APPVERSION", "%X", app->appversion);
    }

  return app->fnc.learn_status (app, ctrl, flags);
}


/* Write out the application specific status lines for the LEARN
   command. */
gpg_error_t
app_write_learn_status (card_t card, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err, err2, tmperr;
  app_t app, last_app;
  int any_reselect = 0;

  if (!card)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = lock_card (card, ctrl);
  if (err)
    return err;

  /* Always make sure that the current app for this connection has
   * been selected and is at the top of the list.  */
  if ((err = maybe_switch_app (ctrl, card, NULL)))
    ;
  else if (!card->app->fnc.learn_status)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      err = write_learn_status_core (card, card->app, ctrl, flags);
      if (!err && card->app->fnc.reselect && (flags & APP_LEARN_FLAG_MULTI))
        {
          /* The current app has the reselect feature so that we can
           * loop over all other apps which are capable of a reselect
           * and finally reselect the first app again.  Note that we
           * did the learn for the currently selected card above.  */
          app = last_app = card->app;
          for (app = app->next; app && !err; app = app->next)
            if (app->fnc.reselect)
              {
                if (last_app && last_app->fnc.prep_reselect)
                  {
                    tmperr = last_app->fnc.prep_reselect (last_app, ctrl);
                    if (tmperr)
                      log_info ("slot %d, app %s:"
                                " preparing re-select from %s failed: %s\n",
                                card->slot, xstrapptype (app),
                                xstrapptype (last_app),
                                gpg_strerror (tmperr));
                  }
                any_reselect = 1;
                err = app->fnc.reselect (app, ctrl);
                if (!err)
                  {
                    last_app = app;
                    err = write_learn_status_core (NULL, app, ctrl, flags);
                  }
              }
          app = card->app;
          if (any_reselect)
            {
              if (last_app && last_app->fnc.prep_reselect)
                {
                  tmperr = last_app->fnc.prep_reselect (last_app, ctrl);
                  if (tmperr)
                    log_info ("slot %d, app %s:"
                              " preparing re-select from %s failed: %s\n",
                              card->slot, xstrapptype (app),
                              xstrapptype (last_app), gpg_strerror (tmperr));
                }
              err2 = app->fnc.reselect (app, ctrl);
              if (err2)
                {
                  log_error ("error re-selecting '%s': %s\n",
                             strapptype(app->apptype), gpg_strerror (err2));
                  if (!err)
                    err = err2;
                }
            }
        }
    }

  unlock_card (card);
  return err;
}


/* Read the certificate with id CERTID (as returned by learn_status in
   the CERTINFO status lines) and return it in the freshly allocated
   buffer put into CERT and the length of the certificate put into
   CERTLEN. */
gpg_error_t
app_readcert (card_t card, ctrl_t ctrl, const char *certid,
              unsigned char **cert, size_t *certlen)
{
  gpg_error_t err;

  if (!card)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, certid)))
    ;
  else if (!card->app->fnc.readcert)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling readcert(%s)\n",
                   card->slot, xstrapptype (card->app), certid);
      err = card->app->fnc.readcert (card->app, certid, cert, certlen);
    }

  unlock_card (card);
  return err;
}


/* Read the key with ID KEYID.  On success a canonical encoded
 * S-expression with the public key will get stored at PK and its
 * length (for assertions) at PKLEN; the caller must release that
 * buffer. On error NULL will be stored at PK and PKLEN and an error
 * code returned.  If the key is not required NULL may be passed for
 * PK; this makse send if the APP_READKEY_FLAG_INFO has also been set.
 *
 * This function might not be supported by all applications.  */
gpg_error_t
app_readkey (card_t card, ctrl_t ctrl, const char *keyid, unsigned int flags,
             unsigned char **pk, size_t *pklen)
{
  gpg_error_t err;

  if (pk)
    *pk = NULL;
  if (pklen)
    *pklen = 0;

  if (!card || !keyid)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, keyid)))
    ;
  else if (!card->app->fnc.readkey)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling readkey(%s)\n",
                   card->slot, xstrapptype (card->app), keyid);
      err = card->app->fnc.readkey (card->app, ctrl, keyid, flags, pk, pklen);
    }

  unlock_card (card);
  return err;
}


/* Perform a GETATTR operation.  */
gpg_error_t
app_getattr (card_t card, ctrl_t ctrl, const char *name)
{
  gpg_error_t err;

  if (!card || !name || !*name)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, NULL)))
    ;
  else if (name && !strcmp (name, "CARDTYPE"))
    {
      send_status_direct (ctrl, "CARDTYPE", strcardtype (card->cardtype));
    }
  else if (name && !strcmp (name, "APPTYPE"))
    {
      send_status_direct (ctrl, "APPTYPE", strapptype (card->app->apptype));
    }
  else if (name && !strcmp (name, "SERIALNO"))
    {
      char *serial;

      serial = card_get_serialno (card);
      if (!serial)
        err = gpg_error (GPG_ERR_INV_VALUE);
      else
        {
          send_status_direct (ctrl, "SERIALNO", serial);
          xfree (serial);
        }
    }
  else if (!card->app->fnc.getattr)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling getattr(%s)\n",
                   card->slot, xstrapptype (card->app), name);
      err = card->app->fnc.getattr (card->app, ctrl, name);
    }

  unlock_card (card);
  return err;
}


/* Perform a SETATTR operation.  */
gpg_error_t
app_setattr (card_t card, ctrl_t ctrl, const char *name,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const unsigned char *value, size_t valuelen)
{
  gpg_error_t err;

  if (!card || !name || !*name || !value)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, NULL)))
    ;
  else if (!card->app->fnc.setattr)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling setattr(%s)\n",
                   card->slot, xstrapptype (card->app), name);
      err = card->app->fnc.setattr (card->app, ctrl, name, pincb, pincb_arg,
                                    value, valuelen);
    }

  unlock_card (card);
  return err;
}


/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
gpg_error_t
app_sign (card_t card, ctrl_t ctrl, const char *keyidstr, int hashalgo,
          gpg_error_t (*pincb)(void*, const char *, char **),
          void *pincb_arg,
          const void *indata, size_t indatalen,
          unsigned char **outdata, size_t *outdatalen )
{
  gpg_error_t err;

  if (!card || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, keyidstr)))
    ;
  else if (!card->app->fnc.sign)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling sign(%s)\n",
                   card->slot, xstrapptype (card->app), keyidstr);
      err = card->app->fnc.sign (card->app, ctrl, keyidstr, hashalgo,
                                 pincb, pincb_arg,
                                 indata, indatalen,
                                 outdata, outdatalen);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation sign result: %s\n", gpg_strerror (err));
  return err;
}


/* Create the signature using the INTERNAL AUTHENTICATE command and
   return the allocated result in OUTDATA.  If a PIN is required the
   PINCB will be used to ask for the PIN; it should return the PIN in
   an allocated buffer and put it into PIN.  */
gpg_error_t
app_auth (card_t card, ctrl_t ctrl, const char *keyidstr,
          gpg_error_t (*pincb)(void*, const char *, char **),
          void *pincb_arg,
          const void *indata, size_t indatalen,
          unsigned char **outdata, size_t *outdatalen )
{
  gpg_error_t err;

  if (!card || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, keyidstr)))
    ;
  else if (!card->app->fnc.auth)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling auth(%s)\n",
                   card->slot, xstrapptype (card->app), keyidstr);
      err = card->app->fnc.auth (card->app, ctrl, keyidstr,
                                 pincb, pincb_arg,
                                 indata, indatalen,
                                 outdata, outdatalen);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation auth result: %s\n", gpg_strerror (err));
  return err;
}


/* Decrypt the data in INDATA and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
gpg_error_t
app_decipher (card_t card, ctrl_t ctrl, const char *keyidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              unsigned char **outdata, size_t *outdatalen,
              unsigned int *r_info)
{
  gpg_error_t err;

  *r_info = 0;

  if (!card || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, keyidstr)))
    ;
  else if (!card->app->fnc.decipher)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling decipher(%s)\n",
                   card->slot, xstrapptype (card->app), keyidstr);
      err = card->app->fnc.decipher (card->app, ctrl, keyidstr,
                                     pincb, pincb_arg,
                                     indata, indatalen,
                                     outdata, outdatalen,
                                     r_info);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation decipher result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform the WRITECERT operation.  */
gpg_error_t
app_writecert (card_t card, ctrl_t ctrl,
               const char *certidstr,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg,
               const unsigned char *data, size_t datalen)
{
  gpg_error_t err;

  if (!card || !certidstr || !*certidstr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, certidstr)))
    ;
  else if (!card->app->fnc.writecert)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling writecert(%s)\n",
                   card->slot, xstrapptype (card->app), certidstr);
      err = card->app->fnc.writecert (card->app, ctrl, certidstr,
                                      pincb, pincb_arg, data, datalen);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation writecert result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform the WRITEKEY operation.  */
gpg_error_t
app_writekey (card_t card, ctrl_t ctrl,
              const char *keyidstr, unsigned int flags,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const unsigned char *keydata, size_t keydatalen)
{
  gpg_error_t err;

  if (!card || !keyidstr || !*keyidstr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, keyidstr)))
    ;
  else if (!card->app->fnc.writekey)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling writekey(%s)\n",
                   card->slot, xstrapptype (card->app), keyidstr);
      err = card->app->fnc.writekey (card->app, ctrl, keyidstr, flags,
                                     pincb, pincb_arg, keydata, keydatalen);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation writekey result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a GENKEY operation.  */
gpg_error_t
app_genkey (card_t card, ctrl_t ctrl, const char *keynostr,
            const char *keytype, unsigned int flags, time_t createtime,
            gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg)
{
  gpg_error_t err;

  if (!card || !keynostr || !*keynostr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, keynostr)))
    ;
  else if (!card->app->fnc.genkey)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling genkey(%s)\n",
                   card->slot, xstrapptype (card->app), keynostr);
      err = card->app->fnc.genkey (card->app, ctrl, keynostr, keytype, flags,
                                   createtime, pincb, pincb_arg);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation genkey result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a GET CHALLENGE operation.  This function is special as it
   directly accesses the card without any application specific
   wrapper. */
gpg_error_t
app_get_challenge (card_t card, ctrl_t ctrl,
                   size_t nbytes, unsigned char *buffer)
{
  gpg_error_t err;

  if (!card || !nbytes || !buffer)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if (!card->ref_count)
    err = gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  else
    err = iso7816_get_challenge (card->slot, nbytes, buffer);

  unlock_card (card);
  return err;
}


/* Perform a CHANGE REFERENCE DATA or RESET RETRY COUNTER operation.  */
gpg_error_t
app_change_pin (card_t card, ctrl_t ctrl, const char *chvnostr,
                unsigned int flags,
                gpg_error_t (*pincb)(void*, const char *, char **),
                void *pincb_arg)
{
  gpg_error_t err;

  if (!card || !chvnostr || !*chvnostr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, NULL)))
    ;
  else if (!card->app->fnc.change_pin)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling change_pin(%s)\n",
                   card->slot, xstrapptype (card->app), chvnostr);
      err = card->app->fnc.change_pin (card->app, ctrl,
                                       chvnostr, flags, pincb, pincb_arg);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation change_pin result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a VERIFY operation without doing anything else.  This may
   be used to initialize a the PIN cache for long lasting other
   operations.  Its use is highly application dependent. */
gpg_error_t
app_check_pin (card_t card, ctrl_t ctrl, const char *keyidstr,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  gpg_error_t err;

  if (!card || !keyidstr || !*keyidstr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  if ((err = maybe_switch_app (ctrl, card, NULL)))
    ;
  else if (!card->app->fnc.check_pin)
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  else
    {
      if (DBG_APP)
        log_debug ("slot %d app %s: calling check_pin(%s)\n",
                   card->slot, xstrapptype (card->app), keyidstr);
      err = card->app->fnc.check_pin (card->app, ctrl, keyidstr,
                                      pincb, pincb_arg);
    }

  unlock_card (card);
  if (opt.verbose)
    log_info ("operation check_pin result: %s\n", gpg_strerror (err));
  return err;
}


static void
report_change (int slot, int old_status, int cur_status)
{
  char *homestr, *envstr;
  char *fname;
  char templ[50];
  FILE *fp;

  snprintf (templ, sizeof templ, "reader_%d.status", slot);
  fname = make_filename (gnupg_homedir (), templ, NULL );
  fp = fopen (fname, "w");
  if (fp)
    {
      fprintf (fp, "%s\n",
               (cur_status & 1)? "USABLE":
               (cur_status & 4)? "ACTIVE":
               (cur_status & 2)? "PRESENT": "NOCARD");
      fclose (fp);
    }
  xfree (fname);

  homestr = make_filename (gnupg_homedir (), NULL);
  if (gpgrt_asprintf (&envstr, "GNUPGHOME=%s", homestr) < 0)
    log_error ("out of core while building environment\n");
  else
    {
      gpg_error_t err;
      const char *args[9], *envs[2];
      char numbuf1[30], numbuf2[30], numbuf3[30];

      envs[0] = envstr;
      envs[1] = NULL;

      sprintf (numbuf1, "%d", slot);
      sprintf (numbuf2, "0x%04X", old_status);
      sprintf (numbuf3, "0x%04X", cur_status);
      args[0] = "--reader-port";
      args[1] = numbuf1;
      args[2] = "--old-code";
      args[3] = numbuf2;
      args[4] = "--new-code";
      args[5] = numbuf3;
      args[6] = "--status";
      args[7] = ((cur_status & 1)? "USABLE":
                 (cur_status & 4)? "ACTIVE":
                 (cur_status & 2)? "PRESENT": "NOCARD");
      args[8] = NULL;

      fname = make_filename (gnupg_homedir (), "scd-event", NULL);
      err = gnupg_spawn_process_detached (fname, args, envs);
      if (err && gpg_err_code (err) != GPG_ERR_ENOENT)
        log_error ("failed to run event handler '%s': %s\n",
                   fname, gpg_strerror (err));
      xfree (fname);
      xfree (envstr);
    }
  xfree (homestr);
}


int
scd_update_reader_status_file (void)
{
  card_t card, card_next;
  int periodical_check_needed = 0;

  npth_mutex_lock (&card_list_lock);
  for (card = card_top; card; card = card_next)
    {
      int sw;
      unsigned int status;

      lock_card (card, NULL);
      card_next = card->next;

      if (card->reset_requested)
        status = 0;
      else
        {
          sw = apdu_get_status (card->slot, 0, &status);
          if (sw == SW_HOST_NO_READER)
            {
              /* Most likely the _reader_ has been unplugged.  */
              status = 0;
            }
          else if (sw)
            {
              /* Get status failed.  Ignore that.  */
              if (card->periodical_check_needed)
                periodical_check_needed = 1;
              unlock_card (card);
              continue;
            }
        }

      if (card->card_status != status)
        {
          report_change (card->slot, card->card_status, status);
          send_client_notifications (card, status == 0);

          if (status == 0)
            {
              log_debug ("Removal of a card: %d\n", card->slot);
              pincache_put (NULL, card->slot, NULL, NULL, NULL, 0);
              apdu_close_reader (card->slot);
              deallocate_card (card);
            }
          else
            {
              card->card_status = status;
              if (card->periodical_check_needed)
                periodical_check_needed = 1;
              unlock_card (card);
            }
        }
      else
        {
          if (card->periodical_check_needed)
            periodical_check_needed = 1;
          unlock_card (card);
        }
    }

  npth_mutex_unlock (&card_list_lock);

  return periodical_check_needed;
}

/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because Pth emulation code might not be able
   to do a static init; in particular, it is not possible for W32. */
gpg_error_t
initialize_module_command (void)
{
  gpg_error_t err;

  if (npth_mutex_init (&card_list_lock, NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("app: error initializing mutex: %s\n", gpg_strerror (err));
      return err;
    }

  return apdu_init ();
}


/* Sort helper for app_send_card_list.  */
static int
compare_card_list_items (const void *arg_a, const void *arg_b)
{
  const card_t a = *(const card_t *)arg_a;
  const card_t b = *(const card_t *)arg_b;

  return a->slot - b->slot;
}


/* Helper for send_card_and_app_list and app_switch_active_app.  */
static gpg_error_t
send_serialno_and_app_status (card_t card, int with_apps, ctrl_t ctrl)
{
  gpg_error_t err;
  app_t a;
  char buf[65];
  char *p;
  membuf_t mb;

  if (DIM (buf) < 2 * card->serialnolen + 1)
    return 0; /* Oops.  */

  bin2hex (card->serialno, card->serialnolen, buf);
  if (with_apps)
    {
      /* Note that in case the additional applications have not yet been
       * added to the card context (which is commonly done by means of
       * "SERIALNO --all", we do that here.  */
      err = select_all_additional_applications_internal (card);
      if (err)
        return err;

      init_membuf (&mb, 256);
      put_membuf_str (&mb, buf);
      for (a = card->app; a; a = a->next)
        {
          if (!a->fnc.with_keygrip)
            continue;
          put_membuf (&mb, " ", 1);
          put_membuf_str (&mb, xstrapptype (a));
        }
      put_membuf (&mb, "", 1);
      p = get_membuf (&mb, NULL);
      if (!p)
        return gpg_error_from_syserror ();
      send_status_direct (ctrl, "SERIALNO", p);
      xfree (p);
    }
  else
    send_status_direct (ctrl, "SERIALNO", buf);

  return 0;
}


/* Common code for app_send_card_list and app_send_active_apps.  */
static gpg_error_t
send_card_and_app_list (ctrl_t ctrl, card_t wantcard, int with_apps)
{
  gpg_error_t err;
  card_t c;
  card_t *cardlist = NULL;
  int n, ncardlist;

  npth_mutex_lock (&card_list_lock);
  for (n=0, c = card_top; c; c = c->next)
    n++;
  cardlist = xtrycalloc (n, sizeof *cardlist);
  if (!cardlist)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  for (ncardlist=0, c = card_top; c; c = c->next)
    cardlist[ncardlist++] = c;
  qsort (cardlist, ncardlist, sizeof *cardlist, compare_card_list_items);

  for (n=0; n < ncardlist; n++)
    {
      if (wantcard && wantcard != cardlist[n])
        continue;
      err = send_serialno_and_app_status (cardlist[n], with_apps, ctrl);
      if (err)
        goto leave;
    }

  err = 0;

 leave:
  npth_mutex_unlock (&card_list_lock);
  xfree (cardlist);
  return err;
}


/* Send status lines with the serialno of all inserted cards.  */
gpg_error_t
app_send_card_list (ctrl_t ctrl)
{
  return send_card_and_app_list (ctrl, NULL, 0);
}


/* Send status lines with the serialno and appname of the current card
 * or of all cards if CARD is NULL.  */
gpg_error_t
app_send_active_apps (card_t card, ctrl_t ctrl)
{
  return send_card_and_app_list (ctrl, card, 1);
}


/* Switch to APPNAME and print a respective status line with that app
 * listed first.  If APPNAME is NULL or the empty string no switching
 * is done but the status line is printed anyway.  */
gpg_error_t
app_switch_active_app (card_t card, ctrl_t ctrl, const char *appname)
{
  gpg_error_t err;
  apptype_t apptype;

  if (!card)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = lock_card (card, ctrl);
  if (err)
    return err;

  /* Note that in case the additional applications have not yet been
   * added to the card context (which is commonly done by means of
   * "SERIALNO --all", we do that here.  */
  err = select_all_additional_applications_internal (card);
  if (err)
    goto leave;

  if (appname && *appname)
    {
      apptype = apptype_from_name (appname);
      if (!apptype)
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }

      ctrl->current_apptype = apptype;
      err = maybe_switch_app (ctrl, card, NULL);
      if (err)
        goto leave;
    }

  /* Print the status line.  */
  err = send_serialno_and_app_status (card, 1, ctrl);

 leave:
  unlock_card (card);
  return err;
}


/* Execute an action for each app.  ACTION can be one of:
 *
 * - KEYGRIP_ACTION_SEND_DATA
 *
 *     If KEYGRIP_STR matches a public key of any active application
 *     send information as LF terminated data lines about the public
 *     key.  The format of these lines is
 *         <keygrip> T <serialno> <idstr>
 *     If a match was found a pointer to the matching application is
 *     returned.  With the KEYGRIP_STR given as NULL, lines for all
 *     keys (with CAPABILITY) will be send and the return value is
 *     GPG_ERR_TRUE.
 *
 * - KEYGRIP_ACTION_WRITE_STATUS
 *
 *     Same as KEYGRIP_ACTION_SEND_DATA but uses status lines instead
 *     of data lines.
 *
 * - KEYGRIP_ACTION_LOOKUP
 *
 *     Returns a pointer to the application matching KEYGRIP_STR but
 *     does not emit any status or data lines.  If no key with that
 *     keygrip is available or KEYGRIP_STR is NULL, GPG_ERR_NOT_FOUND
 *     is returned.
 */
card_t
app_do_with_keygrip (ctrl_t ctrl, int action, const char *keygrip_str,
                     int capability)
{
  int locked = 0;
  card_t c;
  app_t a, a_prev;

  npth_mutex_lock (&card_list_lock);

  for (c = card_top; c; c = c->next)
    {
      if (lock_card (c, ctrl))
        {
          c = NULL;
          goto leave_the_loop;
        }
      locked = 1;
      a_prev = NULL;
      for (a = c->app; a; a = a->next)
        {
          if (!a->fnc.with_keygrip)
            continue;

          /* Note that we need to do a re-select even for the current
           * app because the last selected application (e.g. after
           * init) might be a different one and we do not run
           * maybe_switch_app here.  Of course we we do this only iff
           * we have an additional app. */
          if (c->app->next)
            {
              if (run_reselect (ctrl, c, a, a_prev))
                continue;
            }
          a_prev = a;

          if (DBG_APP)
            log_debug ("slot %d, app %s: calling with_keygrip(%s)\n",
                       c->slot, xstrapptype (a),
                       action == KEYGRIP_ACTION_SEND_DATA? "send_data":
                       action == KEYGRIP_ACTION_WRITE_STATUS? "write_data":
                       action == KEYGRIP_ACTION_LOOKUP? "lookup":"?");
          if (!a->fnc.with_keygrip (a, ctrl, action, keygrip_str, capability))
            goto leave_the_loop; /* ACTION_LOOKUP succeeded.  */
        }

      /* Select the first app again.  */
      if (c->app->next)
        run_reselect (ctrl, c, c->app, a_prev);

      unlock_card (c);
      locked = 0;
    }

 leave_the_loop:
  /* Force switching of the app if the selected one is not the current
   * one.  Changing the current apptype is sufficient to do this.  */
  if (c && c->app && c->app->apptype != a->apptype)
    ctrl->current_apptype = a->apptype;

  if (locked && c)
    {
      unlock_card (c);
      locked = 0;
    }
  npth_mutex_unlock (&card_list_lock);
  return c;
}

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
#include "app-common.h"
#include "iso7816.h"
#include "apdu.h"
#include "../common/tlv.h"

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


static gpg_error_t
check_conflict (card_t card, const char *name)
{
  if (!card || !name)
    return 0;
  if (!card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED); /* Should not happen.  */

  /* FIXME:  Needs changes for app switching.  */
  if (!card->app->apptype
      || !ascii_strcasecmp (strapptype (card->app->apptype), name))
    return 0;

  if (card->app->apptype == APPTYPE_UNDEFINED)
    return 0;

  log_info ("application '%s' in use - can't switch\n",
            strapptype (card->app->apptype));

  return gpg_error (GPG_ERR_CONFLICT);
}


/* This function is used by the serialno command to check for an
   application conflict which may appear if the serialno command is
   used to request a specific application and the connection has
   already done a select_application. */
gpg_error_t
check_application_conflict (const char *name, card_t card)
{
  return check_conflict (card, name);
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

          slot = apdu_open_reader (l, !card_top);
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
            apdu_close_reader (slot);
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
      err = check_conflict (card, name);
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

     All other serial number not starting with FF are used as they are.
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


/* Write out the application specific status lines for the LEARN
   command. */
gpg_error_t
app_write_learn_status (card_t card, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;
  app_t app;

  if (!card)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  app = card->app;
  if (!app->fnc.learn_status)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We do not send CARD and APPTYPE if only keypairinfo is requested.  */
  if (!(flags &1))
    {
      if (card->cardtype)
        send_status_direct (ctrl, "CARDTYPE", strcardtype (card->cardtype));
      if (card->cardversion)
        send_status_printf (ctrl, "CARDVERSION", "%X", card->cardversion);
      if (app->apptype)
        send_status_direct (ctrl, "APPTYPE", strapptype (app->apptype));
      if (app->appversion)
        send_status_printf (ctrl, "APPVERSION", "%X", app->appversion);
      /* FIXME: Send info for the other active apps of the card?  */
    }

  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = app->fnc.learn_status (card->app, ctrl, flags);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.readcert)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.readcert (card->app, certid, cert, certlen);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.readkey)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.readkey (card->app, ctrl, keyid, flags, pk, pklen);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);

  if (name && !strcmp (name, "CARDTYPE"))
    {
      send_status_direct (ctrl, "CARDTYPE", strcardtype (card->cardtype));
      return 0;
    }
  if (name && !strcmp (name, "APPTYPE"))
    {
      send_status_direct (ctrl, "APPTYPE", strapptype (card->app->apptype));
      return 0;
    }
  if (name && !strcmp (name, "SERIALNO"))
    {
      char *serial;

      serial = card_get_serialno (card);
      if (!serial)
        return gpg_error (GPG_ERR_INV_VALUE);

      send_status_direct (ctrl, "SERIALNO", serial);
      xfree (serial);
      return 0;
    }

  if (!card->app->fnc.getattr)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.getattr (card->app, ctrl, name);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.setattr)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.setattr (card->app, name, pincb, pincb_arg,
                                value, valuelen);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.sign)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.sign (card->app, keyidstr, hashalgo,
                             pincb, pincb_arg,
                             indata, indatalen,
                             outdata, outdatalen);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.auth)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.auth (card->app, keyidstr,
                             pincb, pincb_arg,
                             indata, indatalen,
                             outdata, outdatalen);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.decipher)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.decipher (card->app, keyidstr,
                                 pincb, pincb_arg,
                                 indata, indatalen,
                                 outdata, outdatalen,
                                 r_info);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.writecert)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.writecert (card->app, ctrl, certidstr,
                                  pincb, pincb_arg, data, datalen);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.writekey)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.writekey (card->app, ctrl, keyidstr, flags,
                                 pincb, pincb_arg, keydata, keydatalen);
  unlock_card (card);
  if (opt.verbose)
    log_info ("operation writekey result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a SETATTR operation.  */
gpg_error_t
app_genkey (card_t card, ctrl_t ctrl, const char *keynostr,
            const char *keytype, unsigned int flags, time_t createtime,
            gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg)
{
  gpg_error_t err;

  if (!card || !keynostr || !*keynostr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.genkey)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.genkey (card->app, ctrl, keynostr, keytype, flags,
                               createtime, pincb, pincb_arg);
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
  if (!card->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  err = lock_card (card, ctrl);
  if (err)
    return err;
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.change_pin)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.change_pin (card->app, ctrl,
                                   chvnostr, flags, pincb, pincb_arg);
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
  if (!card->ref_count || !card->app)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->app->fnc.check_pin)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_card (card, ctrl);
  if (err)
    return err;
  err = card->app->fnc.check_pin (card->app, keyidstr, pincb, pincb_arg);
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


void
app_send_card_list (ctrl_t ctrl)
{
  card_t c;
  char buf[65];

  npth_mutex_lock (&card_list_lock);
  for (c = card_top; c; c = c->next)
    {
      if (DIM (buf) < 2 * c->serialnolen + 1)
        continue;

      bin2hex (c->serialno, c->serialnolen, buf);
      send_status_direct (ctrl, "SERIALNO", buf);
    }
  npth_mutex_unlock (&card_list_lock);
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
 *     keys will be send and the return value is NULL.
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
 *     keygrip is available or KEYGRIP_STR is NULL, NULL is returned.
 */
card_t
app_do_with_keygrip (ctrl_t ctrl, int action, const char *keygrip_str)
{
  card_t c;
  app_t a;

  npth_mutex_lock (&card_list_lock);

  for (c = card_top; c; c = c->next)
    for (a = c->app; a; a = a->next)
      if (a->fnc.with_keygrip
          && !a->fnc.with_keygrip (a, ctrl, action, keygrip_str))
        break;
  /* FIXME: Add app switching logic.  The above code assumes that the
   * actions can be performend without switching.  This needs to be
   * checked.  For a lookup we also need to reorder the apps so that
   * the selected one will be used. */

  npth_mutex_unlock (&card_list_lock);
  return c;
}

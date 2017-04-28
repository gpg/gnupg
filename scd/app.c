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

static npth_mutex_t app_list_lock;
static app_t app_top;

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


/* Lock the reader SLOT.  This function shall be used right before
   calling any of the actual application functions to serialize access
   to the reader.  We do this always even if the reader is not
   actually used.  This allows an actual connection to assume that it
   never shares a reader (while performing one command).  Returns 0 on
   success; only then the unlock_reader function must be called after
   returning from the handler. */
static gpg_error_t
lock_app (app_t app, ctrl_t ctrl)
{
  if (npth_mutex_lock (&app->lock))
    {
      gpg_error_t err = gpg_error_from_syserror ();
      log_error ("failed to acquire APP lock for %p: %s\n",
                 app, gpg_strerror (err));
      return err;
    }

  apdu_set_progress_cb (app->slot, print_progress_line, ctrl);

  return 0;
}

/* Release a lock on the reader.  See lock_reader(). */
static void
unlock_app (app_t app)
{
  apdu_set_progress_cb (app->slot, NULL, NULL);

  if (npth_mutex_unlock (&app->lock))
    {
      gpg_error_t err = gpg_error_from_syserror ();
      log_error ("failed to release APP lock for %p: %s\n",
                 app, gpg_strerror (err));
    }
}


/* This function may be called to print information pertaining to the
   current state of this module to the log. */
void
app_dump_state (void)
{
  app_t a;

  npth_mutex_lock (&app_list_lock);
  for (a = app_top; a; a = a->next)
    log_info ("app_dump_state: app=%p type='%s'\n", a, a->apptype);
  npth_mutex_unlock (&app_list_lock);
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
check_conflict (app_t app, const char *name)
{
  if (!app || !name || (app->apptype && !ascii_strcasecmp (app->apptype, name)))
    return 0;

  log_info ("application '%s' in use - can't switch\n",
            app->apptype? app->apptype : "<null>");

  return gpg_error (GPG_ERR_CONFLICT);
}

/* This function is used by the serialno command to check for an
   application conflict which may appear if the serialno command is
   used to request a specific application and the connection has
   already done a select_application. */
gpg_error_t
check_application_conflict (const char *name, app_t app)
{
  return check_conflict (app, name);
}


gpg_error_t
app_reset (app_t app, ctrl_t ctrl, int send_reset)
{
  gpg_error_t err = 0;

  if (send_reset)
    {
      int sw;

      lock_app (app, ctrl);
      sw = apdu_reset (app->slot);
      if (sw)
        err = gpg_error (GPG_ERR_CARD_RESET);

      app->reset_requested = 1;
      unlock_app (app);

      scd_kick_the_loop ();
      gnupg_sleep (1);
    }
  else
    {
      ctrl->app_ctx = NULL;
      release_application (app, 0);
    }

  return err;
}

static gpg_error_t
app_new_register (int slot, ctrl_t ctrl, const char *name,
                  int periodical_check_needed)
{
  gpg_error_t err = 0;
  app_t app = NULL;
  unsigned char *result = NULL;
  size_t resultlen;
  int want_undefined;

  /* Need to allocate a new one.  */
  app = xtrycalloc (1, sizeof *app);
  if (!app)
    {
      err = gpg_error_from_syserror ();
      log_info ("error allocating context: %s\n", gpg_strerror (err));
      return err;
    }

  app->slot = slot;
  app->card_status = (unsigned int)-1;

  if (npth_mutex_init (&app->lock, NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("error initializing mutex: %s\n", gpg_strerror (err));
      xfree (app);
      return err;
    }

  err = lock_app (app, ctrl);
  if (err)
    {
      xfree (app);
      return err;
    }

  want_undefined = (name && !strcmp (name, "undefined"));

  /* Try to read the GDO file first to get a default serial number.
     We skip this if the undefined application has been requested. */
  if (!want_undefined)
    {
      err = iso7816_select_file (slot, 0x3F00, 1);
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
              /* The object it does not fit into the buffer.  This is an
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
              app->serialno = result;
              app->serialnolen = n;
              err = app_munge_serialno (app);
              if (err)
                goto leave;
            }
          else
            xfree (result);
          result = NULL;
        }
    }

  /* For certain error codes, there is no need to try more.  */
  if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT
      || gpg_err_code (err) == GPG_ERR_ENODEV)
    goto leave;

  /* Figure out the application to use.  */
  if (want_undefined)
    {
      /* We switch to the "undefined" application only if explicitly
         requested.  */
      app->apptype = "UNDEFINED";
      err = 0;
    }
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);

  if (err && is_app_allowed ("openpgp")
          && (!name || !strcmp (name, "openpgp")))
    err = app_select_openpgp (app);
  if (err && is_app_allowed ("nks") && (!name || !strcmp (name, "nks")))
    err = app_select_nks (app);
  if (err && is_app_allowed ("p15") && (!name || !strcmp (name, "p15")))
    err = app_select_p15 (app);
  if (err && is_app_allowed ("geldkarte")
      && (!name || !strcmp (name, "geldkarte")))
    err = app_select_geldkarte (app);
  if (err && is_app_allowed ("dinsig") && (!name || !strcmp (name, "dinsig")))
    err = app_select_dinsig (app);
  if (err && is_app_allowed ("sc-hsm") && (!name || !strcmp (name, "sc-hsm")))
    err = app_select_sc_hsm (app);
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
      unlock_app (app);
      xfree (app);
      return err;
    }

  app->periodical_check_needed = periodical_check_needed;

  npth_mutex_lock (&app_list_lock);
  app->next = app_top;
  app_top = app;
  npth_mutex_unlock (&app_list_lock);
  unlock_app (app);
  return 0;
}

/* If called with NAME as NULL, select the best fitting application
   and return a context; otherwise select the application with NAME
   and return a context.  Returns an error code and stores NULL at
   R_APP if no application was found or no card is present. */
gpg_error_t
select_application (ctrl_t ctrl, const char *name, app_t *r_app,
                    int scan, const unsigned char *serialno_bin,
                    size_t serialno_bin_len)
{
  gpg_error_t err = 0;
  app_t a, a_prev = NULL;

  *r_app = NULL;

  if (scan || !app_top)
    {
      struct dev_list *l;
      int periodical_check_needed = 0;

      /* Scan the devices to find new device(s).  */
      err = apdu_dev_list_start (opt.reader_port, &l);
      if (err)
        return err;

      while (1)
        {
          int slot;
          int periodical_check_needed_this;

          slot = apdu_open_reader (l, !app_top);
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
              if (periodical_check_needed_this)
                periodical_check_needed = 1;
            }

          if (err)
            apdu_close_reader (slot);
        }

      apdu_dev_list_finish (l);

      /* If periodical check is needed for new device(s), kick the
       scdaemon loop.  */
      if (periodical_check_needed)
        scd_kick_the_loop ();
    }

  npth_mutex_lock (&app_list_lock);
  for (a = app_top; a; a = a->next)
    {
      lock_app (a, ctrl);
      if (serialno_bin == NULL)
        break;
      if (a->serialnolen == serialno_bin_len
          && !memcmp (a->serialno, serialno_bin, a->serialnolen))
        break;
      unlock_app (a);
      a_prev = a;
    }

  if (a)
    {
      err = check_conflict (a, name);
      if (!err)
        {
          a->ref_count++;
          *r_app = a;
          if (a_prev)
            {
              a_prev->next = a->next;
              a->next = app_top;
              app_top = a;
            }
      }
      unlock_app (a);
    }
  else
    err = gpg_error (GPG_ERR_ENODEV);

  npth_mutex_unlock (&app_list_lock);

  return err;
}


char *
get_supported_applications (void)
{
  const char *list[] = {
    "openpgp",
    "nks",
    "p15",
    "geldkarte",
    "dinsig",
    "sc-hsm",
    /* Note: "undefined" is not listed here because it needs special
       treatment by the client.  */
    NULL
  };
  int idx;
  size_t nbytes;
  char *buffer, *p;

  for (nbytes=1, idx=0; list[idx]; idx++)
    nbytes += strlen (list[idx]) + 1 + 1;

  buffer = xtrymalloc (nbytes);
  if (!buffer)
    return NULL;

  for (p=buffer, idx=0; list[idx]; idx++)
    if (is_app_allowed (list[idx]))
      p = stpcpy (stpcpy (p, list[idx]), ":\n");
  *p = 0;

  return buffer;
}


/* Deallocate the application.  */
static void
deallocate_app (app_t app)
{
  app_t a, a_prev = NULL;

  for (a = app_top; a; a = a->next)
    if (a == app)
      {
        if (a_prev == NULL)
          app_top = a->next;
        else
          a_prev->next = a->next;
        break;
      }
    else
      a_prev = a;

  if (app->ref_count)
    log_error ("trying to release context used yet (%d)\n", app->ref_count);

  if (app->fnc.deinit)
    {
      app->fnc.deinit (app);
      app->fnc.deinit = NULL;
    }

  xfree (app->serialno);

  unlock_app (app);
  xfree (app);
}

/* Free the resources associated with the application APP.  APP is
   allowed to be NULL in which case this is a no-op.  Note that we are
   using reference counting to track the users of the application and
   actually deferring the deallocation to allow for a later reuse by
   a new connection. */
void
release_application (app_t app, int locked_already)
{
  if (!app)
    return;

  /* We don't deallocate app here.  Instead, we keep it.  This is
     useful so that a card does not get reset even if only one session
     is using the card - this way the PIN cache and other cached data
     are preserved.  */

  if (!locked_already)
    lock_app (app, NULL);

  if (!app->ref_count)
    log_bug ("trying to release an already released context\n");

  --app->ref_count;
  if (!locked_already)
    unlock_app (app);
}



/* The serial number may need some cosmetics.  Do it here.  This
   function shall only be called once after a new serial number has
   been put into APP->serialno.

   Prefixes we use:

     FF 00 00 = For serial numbers starting with an FF
     FF 01 00 = Some german p15 cards return an empty serial number so the
                serial number from the EF(TokenInfo) is used instead.
     FF 7F 00 = No serialno.

     All other serial number not starting with FF are used as they are.
*/
gpg_error_t
app_munge_serialno (app_t app)
{
  if (app->serialnolen && app->serialno[0] == 0xff)
    {
      /* The serial number starts with our special prefix.  This
         requires that we put our default prefix "FF0000" in front. */
      unsigned char *p = xtrymalloc (app->serialnolen + 3);
      if (!p)
        return gpg_error_from_syserror ();
      memcpy (p, "\xff\0", 3);
      memcpy (p+3, app->serialno, app->serialnolen);
      app->serialnolen += 3;
      xfree (app->serialno);
      app->serialno = p;
    }
  else if (!app->serialnolen)
    {
      unsigned char *p = xtrymalloc (3);
      if (!p)
        return gpg_error_from_syserror ();
      memcpy (p, "\xff\x7f", 3);
      app->serialnolen = 3;
      xfree (app->serialno);
      app->serialno = p;
    }
  return 0;
}



/* Retrieve the serial number of the card.  The serial number is
   returned as a malloced string (hex encoded) in SERIAL.  Caller must
   free SERIAL unless the function returns an error.  */
char *
app_get_serialno (app_t app)
{
  char *serial;

  if (!app)
    return NULL;

  if (!app->serialnolen)
    serial = xtrystrdup ("FF7F00");
  else
    serial = bin2hex (app->serialno, app->serialnolen, NULL);

  return serial;
}


/* Write out the application specifig status lines for the LEARN
   command. */
gpg_error_t
app_write_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;

  if (!app)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->fnc.learn_status)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We do not send APPTYPE if only keypairinfo is requested.  */
  if (app->apptype && !(flags & 1))
    send_status_direct (ctrl, "APPTYPE", app->apptype);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.learn_status (app, ctrl, flags);
  unlock_app (app);
  return err;
}


/* Read the certificate with id CERTID (as returned by learn_status in
   the CERTINFO status lines) and return it in the freshly allocated
   buffer put into CERT and the length of the certificate put into
   CERTLEN. */
gpg_error_t
app_readcert (app_t app, ctrl_t ctrl, const char *certid,
              unsigned char **cert, size_t *certlen)
{
  gpg_error_t err;

  if (!app)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.readcert)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.readcert (app, certid, cert, certlen);
  unlock_app (app);
  return err;
}


/* Read the key with ID KEYID.  On success a canonical encoded
   S-expression with the public key will get stored at PK and its
   length (for assertions) at PKLEN; the caller must release that
   buffer. On error NULL will be stored at PK and PKLEN and an error
   code returned.

   This function might not be supported by all applications.  */
gpg_error_t
app_readkey (app_t app, ctrl_t ctrl, int advanced, const char *keyid,
             unsigned char **pk, size_t *pklen)
{
  gpg_error_t err;

  if (pk)
    *pk = NULL;
  if (pklen)
    *pklen = 0;

  if (!app || !keyid || !pk || !pklen)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.readkey)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err= app->fnc.readkey (app, advanced, keyid, pk, pklen);
  unlock_app (app);
  return err;
}


/* Perform a GETATTR operation.  */
gpg_error_t
app_getattr (app_t app, ctrl_t ctrl, const char *name)
{
  gpg_error_t err;

  if (!app || !name || !*name)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);

  if (app->apptype && name && !strcmp (name, "APPTYPE"))
    {
      send_status_direct (ctrl, "APPTYPE", app->apptype);
      return 0;
    }
  if (name && !strcmp (name, "SERIALNO"))
    {
      char *serial;

      serial = app_get_serialno (app);
      if (!serial)
        return gpg_error (GPG_ERR_INV_VALUE);

      send_status_direct (ctrl, "SERIALNO", serial);
      xfree (serial);
      return 0;
    }

  if (!app->fnc.getattr)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err =  app->fnc.getattr (app, ctrl, name);
  unlock_app (app);
  return err;
}

/* Perform a SETATTR operation.  */
gpg_error_t
app_setattr (app_t app, ctrl_t ctrl, const char *name,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const unsigned char *value, size_t valuelen)
{
  gpg_error_t err;

  if (!app || !name || !*name || !value)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.setattr)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.setattr (app, name, pincb, pincb_arg, value, valuelen);
  unlock_app (app);
  return err;
}

/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
gpg_error_t
app_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
          gpg_error_t (*pincb)(void*, const char *, char **),
          void *pincb_arg,
          const void *indata, size_t indatalen,
          unsigned char **outdata, size_t *outdatalen )
{
  gpg_error_t err;

  if (!app || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.sign)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.sign (app, keyidstr, hashalgo,
                       pincb, pincb_arg,
                       indata, indatalen,
                       outdata, outdatalen);
  unlock_app (app);
  if (opt.verbose)
    log_info ("operation sign result: %s\n", gpg_strerror (err));
  return err;
}

/* Create the signature using the INTERNAL AUTHENTICATE command and
   return the allocated result in OUTDATA.  If a PIN is required the
   PINCB will be used to ask for the PIN; it should return the PIN in
   an allocated buffer and put it into PIN.  */
gpg_error_t
app_auth (app_t app, ctrl_t ctrl, const char *keyidstr,
          gpg_error_t (*pincb)(void*, const char *, char **),
          void *pincb_arg,
          const void *indata, size_t indatalen,
          unsigned char **outdata, size_t *outdatalen )
{
  gpg_error_t err;

  if (!app || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.auth)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.auth (app, keyidstr,
                       pincb, pincb_arg,
                       indata, indatalen,
                       outdata, outdatalen);
  unlock_app (app);
  if (opt.verbose)
    log_info ("operation auth result: %s\n", gpg_strerror (err));
  return err;
}


/* Decrypt the data in INDATA and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
gpg_error_t
app_decipher (app_t app, ctrl_t ctrl, const char *keyidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              unsigned char **outdata, size_t *outdatalen,
              unsigned int *r_info)
{
  gpg_error_t err;

  *r_info = 0;

  if (!app || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.decipher)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.decipher (app, keyidstr,
                           pincb, pincb_arg,
                           indata, indatalen,
                           outdata, outdatalen,
                           r_info);
  unlock_app (app);
  if (opt.verbose)
    log_info ("operation decipher result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform the WRITECERT operation.  */
gpg_error_t
app_writecert (app_t app, ctrl_t ctrl,
              const char *certidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const unsigned char *data, size_t datalen)
{
  gpg_error_t err;

  if (!app || !certidstr || !*certidstr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.writecert)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.writecert (app, ctrl, certidstr,
                            pincb, pincb_arg, data, datalen);
  unlock_app (app);
  if (opt.verbose)
    log_info ("operation writecert result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform the WRITEKEY operation.  */
gpg_error_t
app_writekey (app_t app, ctrl_t ctrl,
              const char *keyidstr, unsigned int flags,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const unsigned char *keydata, size_t keydatalen)
{
  gpg_error_t err;

  if (!app || !keyidstr || !*keyidstr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.writekey)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.writekey (app, ctrl, keyidstr, flags,
                           pincb, pincb_arg, keydata, keydatalen);
  unlock_app (app);
  if (opt.verbose)
    log_info ("operation writekey result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a SETATTR operation.  */
gpg_error_t
app_genkey (app_t app, ctrl_t ctrl, const char *keynostr, unsigned int flags,
            time_t createtime,
            gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg)
{
  gpg_error_t err;

  if (!app || !keynostr || !*keynostr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.genkey)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.genkey (app, ctrl, keynostr, flags,
                         createtime, pincb, pincb_arg);
  unlock_app (app);
  if (opt.verbose)
    log_info ("operation genkey result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a GET CHALLENGE operation.  This function is special as it
   directly accesses the card without any application specific
   wrapper. */
gpg_error_t
app_get_challenge (app_t app, ctrl_t ctrl, size_t nbytes, unsigned char *buffer)
{
  gpg_error_t err;

  if (!app || !nbytes || !buffer)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = iso7816_get_challenge (app->slot, nbytes, buffer);
  unlock_app (app);
  return err;
}



/* Perform a CHANGE REFERENCE DATA or RESET RETRY COUNTER operation.  */
gpg_error_t
app_change_pin (app_t app, ctrl_t ctrl, const char *chvnostr, int reset_mode,
                gpg_error_t (*pincb)(void*, const char *, char **),
                void *pincb_arg)
{
  gpg_error_t err;

  if (!app || !chvnostr || !*chvnostr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.change_pin)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.change_pin (app, ctrl, chvnostr, reset_mode,
                             pincb, pincb_arg);
  unlock_app (app);
  if (opt.verbose)
    log_info ("operation change_pin result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a VERIFY operation without doing anything lese.  This may
   be used to initialize a the PIN cache for long lasting other
   operations.  Its use is highly application dependent. */
gpg_error_t
app_check_pin (app_t app, ctrl_t ctrl, const char *keyidstr,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  gpg_error_t err;

  if (!app || !keyidstr || !*keyidstr || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.check_pin)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_app (app, ctrl);
  if (err)
    return err;
  err = app->fnc.check_pin (app, keyidstr, pincb, pincb_arg);
  unlock_app (app);
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
  app_t a, app_next;
  int periodical_check_needed = 0;

  npth_mutex_lock (&app_list_lock);
  for (a = app_top; a; a = app_next)
    {
      int sw;
      unsigned int status;

      lock_app (a, NULL);
      app_next = a->next;

      if (a->reset_requested)
        status = 0;
      else
        {
          sw = apdu_get_status (a->slot, 0, &status);
          if (sw == SW_HOST_NO_READER)
            {
              /* Most likely the _reader_ has been unplugged.  */
              status = 0;
            }
          else if (sw)
            {
              /* Get status failed.  Ignore that.  */
              if (a->periodical_check_needed)
                periodical_check_needed = 1;
              unlock_app (a);
              continue;
            }
        }

      if (a->card_status != status)
        {
          report_change (a->slot, a->card_status, status);
          send_client_notifications (a, status == 0);

          if (status == 0)
            {
              log_debug ("Removal of a card: %d\n", a->slot);
              apdu_close_reader (a->slot);
              deallocate_app (a);
            }
          else
            {
              a->card_status = status;
              if (a->periodical_check_needed)
                periodical_check_needed = 1;
              unlock_app (a);
            }
        }
      else
        {
          if (a->periodical_check_needed)
            periodical_check_needed = 1;
          unlock_app (a);
        }
    }
  npth_mutex_unlock (&app_list_lock);

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

  if (npth_mutex_init (&app_list_lock, NULL))
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
  app_t a;
  char buf[65];

  npth_mutex_lock (&app_list_lock);
  for (a = app_top; a; a = a->next)
    {
      if (DIM (buf) < 2 * a->serialnolen + 1)
        continue;

      bin2hex (a->serialno, a->serialnolen, buf);
      send_status_direct (ctrl, "SERIALNO", buf);
    }
  npth_mutex_unlock (&app_list_lock);
}

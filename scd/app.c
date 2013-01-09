/* app.c - Application selection.
 *	Copyright (C) 2003, 2004, 2005 Free Software Foundation, Inc.
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
#include <pth.h>

#include "scdaemon.h"
#include "app-common.h"
#include "iso7816.h"
#include "apdu.h"
#include "tlv.h"

/* This table is used to keep track of locks on a per reader base.
   The index into the table is the slot number of the reader.  The
   mutex will be initialized on demand (one of the advantages of a
   userland threading system). */
static struct
{
  int initialized;
  pth_mutex_t lock;
  app_t app;        /* Application context in use or NULL. */
  app_t last_app;   /* Last application object used as this slot or NULL. */
} lock_table[10];



static void deallocate_app (app_t app);



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
lock_reader (int slot, ctrl_t ctrl)
{
  gpg_error_t err;

  if (slot < 0 || slot >= DIM (lock_table))
    return gpg_error (slot<0? GPG_ERR_INV_VALUE : GPG_ERR_RESOURCE_LIMIT);

  if (!lock_table[slot].initialized)
    {
      if (!pth_mutex_init (&lock_table[slot].lock))
        {
          err = gpg_error_from_syserror ();
          log_error ("error initializing mutex: %s\n", strerror (errno));
          return err;
        }
      lock_table[slot].initialized = 1;
      lock_table[slot].app = NULL;
      lock_table[slot].last_app = NULL;
    }
  
  if (!pth_mutex_acquire (&lock_table[slot].lock, 0, NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("failed to acquire APP lock for slot %d: %s\n",
                 slot, strerror (errno));
      return err;
    }

  apdu_set_progress_cb (slot, print_progress_line, ctrl);

  return 0;
}

/* Release a lock on the reader.  See lock_reader(). */
static void
unlock_reader (int slot)
{
  if (slot < 0 || slot >= DIM (lock_table)
      || !lock_table[slot].initialized)
    log_bug ("unlock_reader called for invalid slot %d\n", slot);

  apdu_set_progress_cb (slot, NULL, NULL);

  if (!pth_mutex_release (&lock_table[slot].lock))
    log_error ("failed to release APP lock for slot %d: %s\n",
               slot, strerror (errno));
}


static void
dump_mutex_state (pth_mutex_t *m)
{
#ifdef _W32_PTH_H
  (void)m;
  log_printf ("unknown under W32");
#else
  if (!(m->mx_state & PTH_MUTEX_INITIALIZED))
    log_printf ("not_initialized");
  else if (!(m->mx_state & PTH_MUTEX_LOCKED))
    log_printf ("not_locked");
  else
    log_printf ("locked tid=0x%lx count=%lu", (long)m->mx_owner, m->mx_count);
#endif
}


/* This function may be called to print information pertaining to the
   current state of this module to the log. */
void
app_dump_state (void)
{
  int slot;

  for (slot=0; slot < DIM (lock_table); slot++)
    if (lock_table[slot].initialized)
      {
        log_info ("app_dump_state: slot=%d lock=", slot);
        dump_mutex_state (&lock_table[slot].lock);
        if (lock_table[slot].app)
          {
            log_printf (" app=%p", lock_table[slot].app);
            if (lock_table[slot].app->apptype)
              log_printf (" type=`%s'", lock_table[slot].app->apptype);
          }
        if (lock_table[slot].last_app)
          {
            log_printf (" lastapp=%p", lock_table[slot].last_app);
            if (lock_table[slot].last_app->apptype)
              log_printf (" type=`%s'", lock_table[slot].last_app->apptype);
          }
        log_printf ("\n");
      }
}

/* Check wether the application NAME is allowed.  This does not mean
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


/* This may be called to tell this module about a removed or resetted card. */
void
application_notify_card_reset (int slot)
{
  app_t app;

  if (slot < 0 || slot >= DIM (lock_table))
    return;

  /* FIXME: We are ignoring any error value here.  */
  lock_reader (slot, NULL); 

  /* Mark application as non-reusable.  */
  if (lock_table[slot].app)
    lock_table[slot].app->no_reuse = 1;

  /* Deallocate a saved application for that slot, so that we won't
     try to reuse it.  If there is no saved application, set a flag so
     that we won't save the current state. */
  app = lock_table[slot].last_app;

  if (app)
    {
      lock_table[slot].last_app = NULL;
      deallocate_app (app);
    }
  unlock_reader (slot); 
}

 
/* This function is used by the serialno command to check for an
   application conflict which may appear if the serialno command is
   used to request a specific application and the connection has
   already done a select_application. */
gpg_error_t
check_application_conflict (ctrl_t ctrl, const char *name)
{
  int slot = ctrl->reader_slot;
  app_t app;

  if (slot < 0 || slot >= DIM (lock_table))
    return gpg_error (GPG_ERR_INV_VALUE);

  app = lock_table[slot].initialized ? lock_table[slot].app : NULL;
  if (app && app->apptype && name)
    if ( ascii_strcasecmp (app->apptype, name))
        return gpg_error (GPG_ERR_CONFLICT);
  return 0;
}


/* If called with NAME as NULL, select the best fitting application
   and return a context; otherwise select the application with NAME
   and return a context.  SLOT identifies the reader device. Returns
   an error code and stores NULL at R_APP if no application was found
   or no card is present. */
gpg_error_t
select_application (ctrl_t ctrl, int slot, const char *name, app_t *r_app)
{
  gpg_error_t err;
  app_t app = NULL;
  unsigned char *result = NULL;
  size_t resultlen;

  (void)ctrl;

  *r_app = NULL;

  err = lock_reader (slot, ctrl);
  if (err)
    return err;

  /* First check whether we already have an application to share. */
  app = lock_table[slot].initialized ? lock_table[slot].app : NULL;
  if (app && name)
    if (!app->apptype || ascii_strcasecmp (app->apptype, name))
      {
        unlock_reader (slot);
        if (app->apptype)
          log_info ("application `%s' in use by reader %d - can't switch\n",
                    app->apptype, slot);
        return gpg_error (GPG_ERR_CONFLICT);
      }

  /* Don't use a non-reusable marked application.  */
  if (app && app->no_reuse)
    {
      unlock_reader (slot);
      log_info ("lingering application `%s' in use by reader %d"
                " - can't switch\n",
                app->apptype? app->apptype:"?", slot);
      return gpg_error (GPG_ERR_CONFLICT);
    }

  /* If we don't have an app, check whether we have a saved
     application for that slot.  This is useful so that a card does
     not get reset even if only one session is using the card - this
     way the PIN cache and other cached data are preserved.  */
  if (!app && lock_table[slot].initialized && lock_table[slot].last_app)
    {
      app = lock_table[slot].last_app;
      if (!name || (app->apptype && !ascii_strcasecmp (app->apptype, name)) )
        {
          /* Yes, we can reuse this application - either the caller
             requested an unspecific one or the requested one matches
             the saved one. */
          lock_table[slot].app = app;
          lock_table[slot].last_app = NULL;
        }
      else 
        {
          /* No, this saved application can't be used - deallocate it. */
          lock_table[slot].last_app = NULL;
          deallocate_app (app);
          app = NULL;
        }
    }

  /* If we can reuse an application, bump the reference count and
     return it.  */
  if (app)
    {
      if (app->slot != slot)
        log_bug ("slot mismatch %d/%d\n", app->slot, slot);
      app->slot = slot;

      app->ref_count++;
      *r_app = app;
      unlock_reader (slot);
      return 0; /* Okay: We share that one. */
    }
  
  /* Need to allocate a new one.  */
  app = xtrycalloc (1, sizeof *app);
  if (!app)
    {
      err = gpg_error_from_syserror ();
      log_info ("error allocating context: %s\n", gpg_strerror (err));
      unlock_reader (slot);
      return err;
    }
  app->slot = slot;


  /* Fixme: We should now first check whether a card is at all
     present. */

  /* Try to read the GDO file first to get a default serial number. */
  err = iso7816_select_file (slot, 0x3F00, 1, NULL, NULL);
  if (!err)
    err = iso7816_select_file (slot, 0x2F02, 0, NULL, NULL);
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

  /* For certain error codes, there is no need to try more.  */
  if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT
      || gpg_err_code (err) == GPG_ERR_ENODEV)
    goto leave;
  
  /* Figure out the application to use.  */
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
  if (err && name)
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);

 leave:
  if (err)
    {
      if (name)
        log_info ("can't select application `%s': %s\n",
                  name, gpg_strerror (err));
      else
        log_info ("no supported card application found: %s\n",
                  gpg_strerror (err));
      xfree (app);
      unlock_reader (slot);
      return err;
    }

  app->ref_count = 1;

  lock_table[slot].app = app;
  *r_app = app;
  unlock_reader (slot);
  return 0;
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


/* Deallocate the application. */
static void
deallocate_app (app_t app)
{
  if (app->fnc.deinit)
    {
      app->fnc.deinit (app);
      app->fnc.deinit = NULL;
    }

  xfree (app->serialno);
  xfree (app);
}

/* Free the resources associated with the application APP.  APP is
   allowed to be NULL in which case this is a no-op.  Note that we are
   using reference counting to track the users of the application and
   actually deferring the deallocation to allow for a later reuse by
   a new connection. */
void
release_application (app_t app)
{
  int slot;

  if (!app)
    return;

  if (!app->ref_count)
    log_bug ("trying to release an already released context\n");
  if (--app->ref_count)
    return;

  /* Move the reference to the application in the lock table. */
  slot = app->slot;
  /* FIXME: We are ignoring any error value.  */
  lock_reader (slot, NULL);
  if (lock_table[slot].app != app)
    {
      unlock_reader (slot);
      log_bug ("app mismatch %p/%p\n", app, lock_table[slot].app);
      deallocate_app (app);
      return;
    }

  if (lock_table[slot].last_app)
    deallocate_app (lock_table[slot].last_app);
  if (app->no_reuse)
    {
      /* If we shall not re-use the application we can't save it for
         later use. */
      deallocate_app (app);
      lock_table[slot].last_app = NULL;
    }
  else
    lock_table[slot].last_app = lock_table[slot].app;
  lock_table[slot].app = NULL;
  unlock_reader (slot);
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



/* Retrieve the serial number and the time of the last update of the
   card.  The serial number is returned as a malloced string (hex
   encoded) in SERIAL and the time of update is returned in STAMP.  If
   no update time is available the returned value is 0.  Caller must
   free SERIAL unless the function returns an error.  If STAMP is not
   of interest, NULL may be passed. */
gpg_error_t 
app_get_serial_and_stamp (app_t app, char **serial, time_t *stamp)
{
  char *buf;

  if (!app || !serial)
    return gpg_error (GPG_ERR_INV_VALUE);

  *serial = NULL;
  if (stamp)
    *stamp = 0; /* not available */

  if (!app->serialnolen)
    buf = xtrystrdup ("FF7F00");
  else
    buf = bin2hex (app->serialno, app->serialnolen, NULL);
  if (!buf)
    return gpg_error_from_syserror ();

  *serial = buf;
  return 0;
}


/* Write out the application specifig status lines for the LEARN
   command. */
gpg_error_t
app_write_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;

  if (!app)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.learn_status)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* We do not send APPTYPE if only keypairinfo is requested.  */
  if (app->apptype && !(flags & 1))
    send_status_info (ctrl, "APPTYPE",
                      app->apptype, strlen (app->apptype), NULL, 0);
  err = lock_reader (app->slot, ctrl);
  if (err)
    return err;
  err = app->fnc.learn_status (app, ctrl, flags);
  unlock_reader (app->slot);
  return err;
}


/* Read the certificate with id CERTID (as returned by learn_status in
   the CERTINFO status lines) and return it in the freshly allocated
   buffer put into CERT and the length of the certificate put into
   CERTLEN. */
gpg_error_t
app_readcert (app_t app, const char *certid,
              unsigned char **cert, size_t *certlen)
{
  gpg_error_t err;

  if (!app)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!app->fnc.readcert)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_reader (app->slot, NULL/* FIXME*/);
  if (err)
    return err;
  err = app->fnc.readcert (app, certid, cert, certlen);
  unlock_reader (app->slot);
  return err;
}


/* Read the key with ID KEYID.  On success a canonical encoded
   S-expression with the public key will get stored at PK and its
   length (for assertions) at PKLEN; the caller must release that
   buffer. On error NULL will be stored at PK and PKLEN and an error
   code returned.

   This function might not be supported by all applications.  */
gpg_error_t 
app_readkey (app_t app, const char *keyid, unsigned char **pk, size_t *pklen)
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
  err = lock_reader (app->slot, NULL /*FIXME*/);
  if (err)
    return err;
  err= app->fnc.readkey (app, keyid, pk, pklen);
  unlock_reader (app->slot);
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
      send_status_info (ctrl, "APPTYPE",
                        app->apptype, strlen (app->apptype), NULL, 0);
      return 0;
    }
  if (name && !strcmp (name, "SERIALNO"))
    {
      char *serial;
      time_t stamp;
      int rc;
      
      rc = app_get_serial_and_stamp (app, &serial, &stamp);
      if (rc)
        return rc;
      send_status_info (ctrl, "SERIALNO", serial, strlen (serial), NULL, 0);
      xfree (serial);
      return 0;
    }

  if (!app->fnc.getattr)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_reader (app->slot, ctrl);
  if (err)
    return err;
  err =  app->fnc.getattr (app, ctrl, name);
  unlock_reader (app->slot);
  return err;
}

/* Perform a SETATTR operation.  */
gpg_error_t 
app_setattr (app_t app, const char *name,
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
  err = lock_reader (app->slot, NULL /*FIXME*/);
  if (err)
    return err;
  err = app->fnc.setattr (app, name, pincb, pincb_arg, value, valuelen);
  unlock_reader (app->slot);
  return err;
}

/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
gpg_error_t 
app_sign (app_t app, const char *keyidstr, int hashalgo,
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
  err = lock_reader (app->slot, NULL /*FIXME*/);
  if (err)
    return err;
  err = app->fnc.sign (app, keyidstr, hashalgo,
                       pincb, pincb_arg,
                       indata, indatalen,
                       outdata, outdatalen);
  unlock_reader (app->slot);
  if (opt.verbose)
    log_info ("operation sign result: %s\n", gpg_strerror (err));
  return err;
}

/* Create the signature using the INTERNAL AUTHENTICATE command and
   return the allocated result in OUTDATA.  If a PIN is required the
   PINCB will be used to ask for the PIN; it should return the PIN in
   an allocated buffer and put it into PIN.  */
gpg_error_t 
app_auth (app_t app, const char *keyidstr,
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
  err = lock_reader (app->slot, NULL /*FIXME*/);
  if (err)
    return err;
  err = app->fnc.auth (app, keyidstr,
                       pincb, pincb_arg,
                       indata, indatalen,
                       outdata, outdatalen);
  unlock_reader (app->slot);
  if (opt.verbose)
    log_info ("operation auth result: %s\n", gpg_strerror (err));
  return err;
}


/* Decrypt the data in INDATA and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
gpg_error_t 
app_decipher (app_t app, const char *keyidstr,
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
  if (!app->fnc.decipher)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  err = lock_reader (app->slot, NULL /*FIXME*/);
  if (err)
    return err;
  err = app->fnc.decipher (app, keyidstr,
                           pincb, pincb_arg,
                           indata, indatalen,
                           outdata, outdatalen);
  unlock_reader (app->slot);
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
  err = lock_reader (app->slot, ctrl);
  if (err)
    return err;
  err = app->fnc.writecert (app, ctrl, certidstr,
                            pincb, pincb_arg, data, datalen);
  unlock_reader (app->slot);
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
  err = lock_reader (app->slot, ctrl);
  if (err)
    return err;
  err = app->fnc.writekey (app, ctrl, keyidstr, flags,
                           pincb, pincb_arg, keydata, keydatalen);
  unlock_reader (app->slot);
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
  err = lock_reader (app->slot, ctrl);
  if (err)
    return err;
  err = app->fnc.genkey (app, ctrl, keynostr, flags, 
                         createtime, pincb, pincb_arg);
  unlock_reader (app->slot);
  if (opt.verbose)
    log_info ("operation genkey result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a GET CHALLENGE operation.  This fucntion is special as it
   directly accesses the card without any application specific
   wrapper. */
gpg_error_t
app_get_challenge (app_t app, size_t nbytes, unsigned char *buffer)
{
  gpg_error_t err;

  if (!app || !nbytes || !buffer)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!app->ref_count)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  err = lock_reader (app->slot, NULL /*FIXME*/);
  if (err)
    return err;
  err = iso7816_get_challenge (app->slot, nbytes, buffer);
  unlock_reader (app->slot);
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
  err = lock_reader (app->slot, ctrl);
  if (err)
    return err;
  err = app->fnc.change_pin (app, ctrl, chvnostr, reset_mode,
                             pincb, pincb_arg);
  unlock_reader (app->slot);
  if (opt.verbose)
    log_info ("operation change_pin result: %s\n", gpg_strerror (err));
  return err;
}


/* Perform a VERIFY operation without doing anything lese.  This may
   be used to initialze a the PIN cache for long lasting other
   operations.  Its use is highly application dependent. */
gpg_error_t 
app_check_pin (app_t app, const char *keyidstr,
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
  err = lock_reader (app->slot, NULL /*FIXME*/);
  if (err)
    return err;
  err = app->fnc.check_pin (app, keyidstr, pincb, pincb_arg);
  unlock_reader (app->slot);
  if (opt.verbose)
    log_info ("operation check_pin result: %s\n", gpg_strerror (err));
  return err;
}


/* app-openpgp.c - The OpenPGP card application.
 *	Copyright (C) 2003, 2004 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#if GNUPG_MAJOR_VERSION == 1
/* This is used with GnuPG version < 1.9.  The code has been source
   copied from the current GnuPG >= 1.9  and is maintained over
   there. */
#include "options.h"
#include "errors.h"
#include "memory.h"
#include "util.h"
#include "i18n.h"
#include "cardglue.h"
#else /* GNUPG_MAJOR_VERSION != 1 */
#include "scdaemon.h"
#endif /* GNUPG_MAJOR_VERSION != 1 */

#include "iso7816.h"
#include "app-common.h"
#include "tlv.h"


static struct {
  int tag;
  int constructed;
  int get_from;  /* Constructed DO with this DO or 0 for direct access. */
  int binary;
  int dont_cache;
  int flush_on_error;
  char *desc;
} data_objects[] = {
  { 0x005E, 0,    0, 1, 0, 0, "Login Data" },
  { 0x5F50, 0,    0, 0, 0, 0, "URL" },
  { 0x0065, 1,    0, 1, 0, 0, "Cardholder Related Data"},
  { 0x005B, 0, 0x65, 0, 0, 0, "Name" },
  { 0x5F2D, 0, 0x65, 0, 0, 0, "Language preferences" },
  { 0x5F35, 0, 0x65, 0, 0, 0, "Sex" },
  { 0x006E, 1,    0, 1, 0, 0, "Application Related Data" },
  { 0x004F, 0, 0x6E, 1, 0, 0, "AID" },
  { 0x0073, 1,    0, 1, 0, 0, "Discretionary Data Objects" },
  { 0x0047, 0, 0x6E, 1, 0, 0, "Card Capabilities" },
  { 0x00C0, 0, 0x6E, 1, 0, 0, "Extended Card Capabilities" },
  { 0x00C1, 0, 0x6E, 1, 0, 0, "Algorithm Attributes Signature" },
  { 0x00C2, 0, 0x6E, 1, 0, 0, "Algorithm Attributes Decryption" },
  { 0x00C3, 0, 0x6E, 1, 0, 0, "Algorithm Attributes Authentication" },
  { 0x00C4, 0, 0x6E, 1, 0, 1, "CHV Status Bytes" },
  { 0x00C5, 0, 0x6E, 1, 0, 0, "Fingerprints" },
  { 0x00C6, 0, 0x6E, 1, 0, 0, "CA Fingerprints" },
  { 0x007A, 1,    0, 1, 0, 0, "Security Support Template" },
  { 0x0093, 0, 0x7A, 1, 1, 0, "Digital Signature Counter" },
  { 0 }
};


struct cache_s {
  struct cache_s *next;
  int tag;
  size_t length;
  unsigned char data[1];
};

struct app_local_s {
  struct cache_s *cache;
};


static unsigned long convert_sig_counter_value (const unsigned char *value,
                                                size_t valuelen);
static unsigned long get_sig_counter (APP app);

/* Deconstructor. */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      struct cache_s *c, *c2;

      for (c = app->app_local->cache; c; c = c2)
        {
          c2 = c->next;
          xfree (c);
        }
      xfree (app->app_local);
      app->app_local = NULL;
    }
}


/* Wrapper around iso7816_get_data which first tries to get the data
   from the cache. */
static gpg_error_t
get_cached_data (app_t app, int tag, 
                 unsigned char **result, size_t *resultlen)
{
  gpg_error_t err;
  int i;
  unsigned char *p;
  size_t len;
  struct cache_s *c;


  *result = NULL;
  *resultlen = 0;

  if (app->app_local)
    {
      for (c=app->app_local->cache; c; c = c->next)
        if (c->tag == tag)
          {
              p = xtrymalloc (c->length);
              if (!p)
                return gpg_error (gpg_err_code_from_errno (errno));
              memcpy (p, c->data, c->length);
              *resultlen = c->length;
              *result = p;
              return 0;
          }
    }
  
  err = iso7816_get_data (app->slot, tag, &p, &len);
  if (err)
    return err;
  *result = p;
  *resultlen = len;

  /* Check whether we should cache this object. */
  for (i=0; data_objects[i].tag; i++)
    if (data_objects[i].tag == tag)
      {
        if (data_objects[i].dont_cache)
          return 0;
        break;
      }

  /* No, cache it. */
  if (!app->app_local)
    app->app_local = xtrycalloc (1, sizeof *app->app_local);

  /* Note that we can safely ignore out of core errors. */
  if (app->app_local)
    {
      for (c=app->app_local->cache; c; c = c->next)
        assert (c->tag != tag);
      
      c = xtrymalloc (sizeof *c + len);
      if (c)
        {
          memcpy (c->data, p, len);
          c->length = len;
          c->tag = tag;
          c->next = app->app_local->cache;
          app->app_local->cache = c;
        }
    }

  return 0;
}

/* Remove DO at TAG from the cache. */
static void
flush_cache_item (app_t app, int tag)
{
  struct cache_s *c, *cprev;
  int i;

  if (!app->app_local)
    return;

  for (c=app->app_local->cache, cprev=NULL; c ; cprev=c, c = c->next)
    if (c->tag == tag)
      {
        if (cprev)
          cprev->next = c->next;
        else
          app->app_local->cache = c->next;
        xfree (c);

        for (c=app->app_local->cache; c ; c = c->next)
          assert (c->tag != tag); /* Oops: duplicated entry. */
        return;
      }

  /* Try again if we have an outer tag. */
  for (i=0; data_objects[i].tag; i++)
    if (data_objects[i].tag == tag && data_objects[i].get_from
        && data_objects[i].get_from != tag)
      flush_cache_item (app, data_objects[i].get_from);
}

/* Flush all entries from the cache which might be out of sync after
   an error. */
static void
flush_cache_after_error (app_t app)
{
  int i;

  for (i=0; data_objects[i].tag; i++)
    if (data_objects[i].flush_on_error)
      flush_cache_item (app, data_objects[i].tag);
}


/* Flush the entire cache. */
static void
flush_cache (app_t app)
{
  if (app && app->app_local)
    {
      struct cache_s *c, *c2;

      for (c = app->app_local->cache; c; c = c2)
        {
          c2 = c->next;
          xfree (c);
        }
      app->app_local->cache = NULL;
    }
}


/* Get the DO identified by TAG from the card in SLOT and return a
   buffer with its content in RESULT and NBYTES.  The return value is
   NULL if not found or a pointer which must be used to release the
   buffer holding value. */
static void *
get_one_do (app_t app, int tag, unsigned char **result, size_t *nbytes)
{
  int rc, i;
  unsigned char *buffer;
  size_t buflen;
  unsigned char *value;
  size_t valuelen;

  *result = NULL;
  *nbytes = 0;
  for (i=0; data_objects[i].tag && data_objects[i].tag != tag; i++)
    ;

  value = NULL;
  rc = -1;
  if (data_objects[i].tag && data_objects[i].get_from)
    {
      rc = get_cached_data (app, data_objects[i].get_from,
                            &buffer, &buflen);
      if (!rc)
        {
          const unsigned char *s;

          s = find_tlv (buffer, buflen, tag, &valuelen);
          if (!s)
            value = NULL; /* not found */
          else if (valuelen > buflen - (s - buffer))
            {
              log_error ("warning: constructed DO too short\n");
              value = NULL;
              xfree (buffer); buffer = NULL;
            }
          else
            value = buffer + (s - buffer);
        }
    }

  if (!value) /* Not in a constructed DO, try simple. */
    {
      rc = get_cached_data (app, tag, &buffer, &buflen);
      if (!rc)
        {
          value = buffer;
          valuelen = buflen;
        }
    }

  if (!rc)
    {
      *nbytes = valuelen;
      *result = value;
      return buffer;
    }
  return NULL;
}


static void
dump_all_do (int slot)
{
  int rc, i, j;
  unsigned char *buffer;
  size_t buflen;
  
  for (i=0; data_objects[i].tag; i++)
    {
      if (data_objects[i].get_from)
        continue;

      rc = iso7816_get_data (slot, data_objects[i].tag, &buffer, &buflen);
      if (gpg_err_code (rc) == GPG_ERR_NO_OBJ)
        ;
      else if (rc) 
        log_info ("DO `%s' not available: %s\n",
                  data_objects[i].desc, gpg_strerror (rc));
      else
        {
          if (data_objects[i].binary)
            {
              log_info ("DO `%s': ", data_objects[i].desc);
              log_printhex ("", buffer, buflen);
            }
          else
            log_info ("DO `%s': `%.*s'\n",
                      data_objects[i].desc,
                      (int)buflen, buffer); /* FIXME: sanitize */

          if (data_objects[i].constructed)
            {
              for (j=0; data_objects[j].tag; j++)
                {
                  const unsigned char *value;
                  size_t valuelen;
                  
                  if (j==i || data_objects[i].tag != data_objects[j].get_from)
                    continue;
                  value = find_tlv (buffer, buflen,
                                    data_objects[j].tag, &valuelen);
                  if (!value)
                    ; /* not found */
                  else if (valuelen > buflen - (value - buffer))
                    log_error ("warning: constructed DO too short\n");
                  else
                    {
                      if (data_objects[j].binary)
                        {
                          log_info ("DO `%s': ", data_objects[j].desc);
                          log_printhex ("", value, valuelen);
                        }
                      else
                        log_info ("DO `%s': `%.*s'\n",
                                  data_objects[j].desc,
                                  (int)valuelen, value); /* FIXME: sanitize */
                    }
                }
            }
        }
      xfree (buffer); buffer = NULL;
    }
}


/* Count the number of bits, assuming the A represents an unsigned big
   integer of length LEN bytes. */
static unsigned int
count_bits (const unsigned char *a, size_t len)
{
  unsigned int n = len * 8;
  int i;

  for (; len && !*a; len--, a++, n -=8)
    ;
  if (len)
    {
      for (i=7; i && !(*a & (1<<i)); i--)
        n--;
    }
  return n;
}

/* Note, that FPR must be at least 20 bytes. */
static int 
store_fpr (int slot, int keynumber, u32 timestamp,
           const unsigned char *m, size_t mlen,
           const unsigned char *e, size_t elen, 
           unsigned char *fpr, unsigned int card_version)
{
  unsigned int n, nbits;
  unsigned char *buffer, *p;
  int rc;
  
  for (; mlen && !*m; mlen--, m++) /* strip leading zeroes */
    ;
  for (; elen && !*e; elen--, e++) /* strip leading zeroes */
    ;

  n = 6 + 2 + mlen + 2 + elen;
  p = buffer = xtrymalloc (3 + n);
  if (!buffer)
    return gpg_error (gpg_err_code_from_errno (errno));
  
  *p++ = 0x99;     /* ctb */
  *p++ = n >> 8;   /* 2 byte length header */
  *p++ = n;
  *p++ = 4;        /* key packet version */
  *p++ = timestamp >> 24;
  *p++ = timestamp >> 16;
  *p++ = timestamp >>  8;
  *p++ = timestamp;
  *p++ = 1; /* RSA */
  nbits = count_bits (m, mlen);
  *p++ = nbits >> 8;
  *p++ = nbits;
  memcpy (p, m, mlen); p += mlen;
  nbits = count_bits (e, elen);
  *p++ = nbits >> 8;
  *p++ = nbits;
  memcpy (p, e, elen); p += elen;
    
  log_printhex ("fprbuf:", buffer, n+3);
  gcry_md_hash_buffer (GCRY_MD_SHA1, fpr, buffer, n+3);

  xfree (buffer);

  rc = iso7816_put_data (slot, (card_version > 0x0007? 0xC7 : 0xC6)
                               + keynumber, fpr, 20);
  if (rc)
    log_error ("failed to store the fingerprint: %s\n",gpg_strerror (rc));

  return rc;
}

       
static void
send_fpr_if_not_null (CTRL ctrl, const char *keyword,
                      int number, const unsigned char *fpr)
{                      
  int i;
  char buf[41];
  char numbuf[25];

  for (i=0; i < 20 && !fpr[i]; i++)
    ;
  if (i==20)
    return; /* All zero. */
  for (i=0; i< 20; i++)
    sprintf (buf+2*i, "%02X", fpr[i]);
  if (number == -1)
    *numbuf = 0; /* Don't print the key number */
  else
    sprintf (numbuf, "%d", number);
  send_status_info (ctrl, keyword,
                    numbuf, (size_t)strlen(numbuf),
                    buf, (size_t)strlen (buf), NULL, 0);
}

static void
send_key_data (CTRL ctrl, const char *name, 
               const unsigned char *a, size_t alen)
{
  char *p, *buf = xmalloc (alen*2+1);
  
  for (p=buf; alen; a++, alen--, p += 2)
    sprintf (p, "%02X", *a);

  send_status_info (ctrl, "KEY-DATA",
                    name, (size_t)strlen(name), 
                    buf, (size_t)strlen (buf),
                    NULL, 0);
  xfree (buf);
}

/* Implement the GETATTR command.  This is similar to the LEARN
   command but returns just one value via the status interface. */
static int 
do_getattr (APP app, CTRL ctrl, const char *name)
{
  static struct {
    const char *name;
    int tag;
    int special;
  } table[] = {
    { "DISP-NAME",    0x005B },
    { "LOGIN-DATA",   0x005E },
    { "DISP-LANG",    0x5F2D },
    { "DISP-SEX",     0x5F35 },
    { "PUBKEY-URL",   0x5F50 },
    { "KEY-FPR",      0x00C5, 3 },
    { "CA-FPR",       0x00C6, 3 },
    { "CHV-STATUS",   0x00C4, 1 },
    { "SIG-COUNTER",  0x0093, 2 },
    { "SERIALNO",     0x004F, -1 },
    { "AID",          0x004F },
    { NULL, 0 }
  };
  int idx, i;
  void *relptr;
  unsigned char *value;
  size_t valuelen;

  for (idx=0; table[idx].name && strcmp (table[idx].name, name); idx++)
    ;
  if (!table[idx].name)
    return gpg_error (GPG_ERR_INV_NAME); 
  
  if (table[idx].special == -1)
    {
      /* The serial number is very special.  We could have used the
         AID DO to retrieve it, but we have it already in the app
         context and the stamp argument is required anyway which we
         can't by other means. The AID DO is available anyway but not
         hex formatted. */
      char *serial;
      time_t stamp;
      char tmp[50];

      if (!app_get_serial_and_stamp (app, &serial, &stamp))
        {
          sprintf (tmp, "%lu", (unsigned long)stamp);
          send_status_info (ctrl, "SERIALNO",
                            serial, strlen (serial),
                            tmp, strlen (tmp),
                            NULL, 0);
          xfree (serial);
        }
      return 0;
    }

  relptr = get_one_do (app, table[idx].tag, &value, &valuelen);
  if (relptr)
    {
      if (table[idx].special == 1)
        {
          char numbuf[7*23];
          
          for (i=0,*numbuf=0; i < valuelen && i < 7; i++)
            sprintf (numbuf+strlen (numbuf), " %d", value[i]); 
          send_status_info (ctrl, table[idx].name,
                            numbuf, strlen (numbuf), NULL, 0);
        }
      else if (table[idx].special == 2)
        {
          char numbuf[50];

          sprintf (numbuf, "%lu", convert_sig_counter_value (value, valuelen));
          send_status_info (ctrl, table[idx].name,
                            numbuf, strlen (numbuf), NULL, 0);
        }
      else if (table[idx].special == 3)
        {
          if (valuelen >= 60)
            for (i=0; i < 3; i++)
              send_fpr_if_not_null (ctrl, table[idx].name, i+1, value+i*20);
        }
      else
        send_status_info (ctrl, table[idx].name, value, valuelen, NULL, 0);

      xfree (relptr);
    }
  return 0;
}


static int
do_learn_status (APP app, CTRL ctrl)
{
  do_getattr (app, ctrl, "DISP-NAME");
  do_getattr (app, ctrl, "DISP-LANG");
  do_getattr (app, ctrl, "DISP-SEX");
  do_getattr (app, ctrl, "PUBKEY-URL");
  do_getattr (app, ctrl, "LOGIN-DATA");
  do_getattr (app, ctrl, "KEY-FPR");
  do_getattr (app, ctrl, "CA-FPR");
  do_getattr (app, ctrl, "CHV-STATUS");
  do_getattr (app, ctrl, "SIG-COUNTER");

  return 0;
}


/* Verify CHV2 if required.  Depending on the configuration of the
   card CHV1 will also be verified. */
static int
verify_chv2 (app_t app,
             int (*pincb)(void*, const char *, char **),
             void *pincb_arg)
{
  int rc = 0;

  if (!app->did_chv2) 
    {
      char *pinvalue;

      rc = pincb (pincb_arg, "PIN", &pinvalue); 
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      if (strlen (pinvalue) < 6)
        {
          log_error ("prassphrase (CHV2) is too short; minimum length is 6\n");
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }

      rc = iso7816_verify (app->slot, 0x82, pinvalue, strlen (pinvalue));
      if (rc)
        {
          log_error ("verify CHV2 failed: %s\n", gpg_strerror (rc));
          xfree (pinvalue);
          flush_cache_after_error (app);
          return rc;
        }
      app->did_chv2 = 1;

      if (!app->did_chv1 && !app->force_chv1)
        {
          rc = iso7816_verify (app->slot, 0x81, pinvalue, strlen (pinvalue));
          if (gpg_err_code (rc) == GPG_ERR_BAD_PIN)
            rc = gpg_error (GPG_ERR_PIN_NOT_SYNCED);
          if (rc)
            {
              log_error ("verify CHV1 failed: %s\n", gpg_strerror (rc));
              xfree (pinvalue);
              flush_cache_after_error (app);
              return rc;
            }
          app->did_chv1 = 1;
        }
      xfree (pinvalue);
    }
  return rc;
}

/* Verify CHV3 if required. */
static int
verify_chv3 (APP app,
             int (*pincb)(void*, const char *, char **),
             void *pincb_arg)
{
  int rc = 0;

  if (!opt.allow_admin)
    {
      log_info ("access to admin commands is not configured\n");
      return gpg_error (GPG_ERR_EACCES);
    }
      
  if (!app->did_chv3) 
    {
      char *pinvalue;

      rc = pincb (pincb_arg, "Admin PIN", &pinvalue); 
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      if (strlen (pinvalue) < 6)
        {
          log_error ("prassphrase (CHV3) is too short; minimum length is 6\n");
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }

      rc = iso7816_verify (app->slot, 0x83, pinvalue, strlen (pinvalue));
      xfree (pinvalue);
      if (rc)
        {
          log_error ("verify CHV3 failed: %s\n", gpg_strerror (rc));
          flush_cache_after_error (app);
          return rc;
        }
      app->did_chv3 = 1;
    }
  return rc;
}


/* Handle the SETATTR operation. All arguments are already basically
   checked. */
static int 
do_setattr (APP app, const char *name,
            int (*pincb)(void*, const char *, char **),
            void *pincb_arg,
            const unsigned char *value, size_t valuelen)
{
  gpg_error_t rc;
  int idx;
  static struct {
    const char *name;
    int tag;
    int special;
  } table[] = {
    { "DISP-NAME",    0x005B },
    { "LOGIN-DATA",   0x005E },
    { "DISP-LANG",    0x5F2D },
    { "DISP-SEX",     0x5F35 },
    { "PUBKEY-URL",   0x5F50 },
    { "CHV-STATUS-1", 0x00C4, 1 },
    { "CA-FPR-1",     0x00CA },
    { "CA-FPR-2",     0x00CB },
    { "CA-FPR-3",     0x00CC },
    { NULL, 0 }
  };


  for (idx=0; table[idx].name && strcmp (table[idx].name, name); idx++)
    ;
  if (!table[idx].name)
    return gpg_error (GPG_ERR_INV_NAME); 

  rc = verify_chv3 (app, pincb, pincb_arg);
  if (rc)
    return rc;

  /* Flush the cache before writing it, so that the next get operation
     will reread the data from the card and thus get synced in case of
     errors (e.g. data truncated by the card). */
  flush_cache_item (app, table[idx].tag);
  rc = iso7816_put_data (app->slot, table[idx].tag, value, valuelen);
  if (rc)
    log_error ("failed to set `%s': %s\n", table[idx].name, gpg_strerror (rc));

  if (table[idx].special == 1)
    app->force_chv1 = (valuelen && *value == 0);

  return rc;
}


/* Handle the PASSWD command. */
static int 
do_change_pin (APP app, CTRL ctrl,  const char *chvnostr, int reset_mode,
               int (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  int rc = 0;
  int chvno = atoi (chvnostr);
  char *pinvalue;

  if (reset_mode && chvno == 3)
    {
      rc = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }
  else if (reset_mode || chvno == 3)
    {
      /* we always require that the PIN is entered. */
      app->did_chv3 = 0;
      rc = verify_chv3 (app, pincb, pincb_arg);
      if (rc)
        goto leave;
    }
  else if (chvno == 1 || chvno == 2)
    {
      /* CHV1 and CVH2 should always have the same value, thus we
         enforce it here.  */
      int save_force = app->force_chv1;

      app->force_chv1 = 0;
      app->did_chv1 = 0;
      app->did_chv2 = 0;
      rc = verify_chv2 (app, pincb, pincb_arg);
      app->force_chv1 = save_force;
      if (rc)
        goto leave;
    }
  else
    {
      rc = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }

  if (chvno == 3)
    app->did_chv3 = 0;
  else
    app->did_chv1 = app->did_chv2 = 0;

  rc = pincb (pincb_arg, chvno == 3? "New Admin PIN" : "New PIN", &pinvalue); 
  if (rc)
    {
      log_error ("error getting new PIN: %s\n", gpg_strerror (rc));
      goto leave;
    }

  if (reset_mode)
    {
      rc = iso7816_reset_retry_counter (app->slot, 0x81,
                                        pinvalue, strlen (pinvalue));
      if (!rc)
        rc = iso7816_reset_retry_counter (app->slot, 0x82,
                                          pinvalue, strlen (pinvalue));
    }
  else
    {
      if (chvno == 1 || chvno == 2)
        {
          rc = iso7816_change_reference_data (app->slot, 0x81, NULL, 0,
                                              pinvalue, strlen (pinvalue));
          if (!rc)
            rc = iso7816_change_reference_data (app->slot, 0x82, NULL, 0,
                                                pinvalue, strlen (pinvalue));
        }
      else
        rc = iso7816_change_reference_data (app->slot, 0x80 + chvno, NULL, 0,
                                            pinvalue, strlen (pinvalue));
    }
  xfree (pinvalue);
  if (rc)
    flush_cache_after_error (app);

 leave:
  return rc;
}



/* Handle the GENKEY command. */
static int 
do_genkey (APP app, CTRL ctrl,  const char *keynostr, unsigned int flags,
          int (*pincb)(void*, const char *, char **),
          void *pincb_arg)
{
  int rc;
  int i;
  char numbuf[30];
  unsigned char fprbuf[20];
  const unsigned char *fpr;
  const unsigned char *keydata, *m, *e;
  unsigned char *buffer;
  size_t buflen, keydatalen, n, mlen, elen;
  time_t created_at;
  int keyno = atoi (keynostr);
  int force = (flags & 1);
  time_t start_at;

  if (keyno < 1 || keyno > 3)
    return gpg_error (GPG_ERR_INV_ID);
  keyno--;

  /* We flush the cache to increase the traffic before a key
     generation.  This _might_ help a card to gather more entropy. */
  flush_cache (app);

  rc = iso7816_get_data (app->slot, 0x006E, &buffer, &buflen);
  if (rc)
    {
      log_error ("error reading application data\n");
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr = find_tlv (buffer, buflen, 0x00C5, &n);
  if (!fpr || n != 60)
    {
      rc = gpg_error (GPG_ERR_GENERAL);
      log_error ("error reading fingerprint DO\n");
      goto leave;
    }
  fpr += 20*keyno;
  for (i=0; i < 20 && !fpr[i]; i++)
    ;
  if (i!=20 && !force)
    {
      rc = gpg_error (GPG_ERR_EEXIST);
      log_error ("key already exists\n");
      goto leave;
    }
  else if (i!=20)
    log_info ("existing key will be replaced\n");
  else
    log_info ("generating new key\n");


  rc = verify_chv3 (app, pincb, pincb_arg);
  if (rc)
    goto leave;

  xfree (buffer); buffer = NULL;

#if 1
  log_info ("please wait while key is being generated ...\n");
  start_at = time (NULL);
  rc = iso7816_generate_keypair 
#else
#warning key generation temporary replaced by reading an existing key.
  rc = iso7816_read_public_key
#endif
                              (app->slot, 
                                 keyno == 0? "\xB6" :
                                 keyno == 1? "\xB8" : "\xA4",
                                 2,
                                 &buffer, &buflen);
  if (rc)
    {
      rc = gpg_error (GPG_ERR_CARD);
      log_error ("generating key failed\n");
      goto leave;
    }
  log_info ("key generation completed (%d seconds)\n",
            (int)(time (NULL) - start_at));
  keydata = find_tlv (buffer, buflen, 0x7F49, &keydatalen);
  if (!keydata)
    {
      rc = gpg_error (GPG_ERR_CARD);
      log_error ("response does not contain the public key data\n");
      goto leave;
    }
 
  m = find_tlv (keydata, keydatalen, 0x0081, &mlen);
  if (!m)
    {
      rc = gpg_error (GPG_ERR_CARD);
      log_error ("response does not contain the RSA modulus\n");
      goto leave;
    }
/*    log_printhex ("RSA n:", m, mlen); */
  send_key_data (ctrl, "n", m, mlen);

  e = find_tlv (keydata, keydatalen, 0x0082, &elen);
  if (!e)
    {
      rc = gpg_error (GPG_ERR_CARD);
      log_error ("response does not contain the RSA public exponent\n");
      goto leave;
    }
/*    log_printhex ("RSA e:", e, elen); */
  send_key_data (ctrl, "e", e, elen);

  created_at = gnupg_get_time ();
  sprintf (numbuf, "%lu", (unsigned long)created_at);
  send_status_info (ctrl, "KEY-CREATED-AT",
                    numbuf, (size_t)strlen(numbuf), NULL, 0);

  rc = store_fpr (app->slot, keyno, (u32)created_at,
                  m, mlen, e, elen, fprbuf, app->card_version);
  if (rc)
    goto leave;
  send_fpr_if_not_null (ctrl, "KEY-FPR", -1, fprbuf);


 leave:
  xfree (buffer);
  return rc;
}


static unsigned long
convert_sig_counter_value (const unsigned char *value, size_t valuelen)
{
  unsigned long ul;

  if (valuelen == 3 )
    ul = (value[0] << 16) | (value[1] << 8) | value[2];
  else
    {
      log_error ("invalid structure of OpenPGP card (DO 0x93)\n");
      ul = 0;
    }
  return ul;
}

static unsigned long
get_sig_counter (APP app)
{
  void *relptr;
  unsigned char *value;
  size_t valuelen;
  unsigned long ul;

  relptr = get_one_do (app, 0x0093, &value, &valuelen);
  if (!relptr)
    return 0;
  ul = convert_sig_counter_value (value, valuelen);
  xfree (relptr);
  return ul;
}

static int
compare_fingerprint (APP app, int keyno, unsigned char *sha1fpr)
{
  const unsigned char *fpr;
  unsigned char *buffer;
  size_t buflen, n;
  int rc, i;
  
  assert (keyno >= 1 && keyno <= 3);

  rc = get_cached_data (app, 0x006E, &buffer, &buflen);
  if (rc)
    {
      log_error ("error reading application data\n");
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr = find_tlv (buffer, buflen, 0x00C5, &n);
  if (!fpr || n != 60)
    {
      xfree (buffer);
      log_error ("error reading fingerprint DO\n");
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr += (keyno-1)*20;
  for (i=0; i < 20; i++)
    if (sha1fpr[i] != fpr[i])
      {
        xfree (buffer);
        return gpg_error (GPG_ERR_WRONG_SECKEY);
      }
  xfree (buffer);
  return 0;
}


  /* If a fingerprint has been specified check it against the one on
     the card.  This is allows for a meaningful error message in case
     the key on the card has been replaced but the shadow information
     known to gpg was not updated.  If there is no fingerprint we
     assume that this is okay. */
static int
check_against_given_fingerprint (APP app, const char *fpr, int keyno)
{
  unsigned char tmp[20];
  const char *s;
  int n;

  for (s=fpr, n=0; hexdigitp (s); s++, n++)
    ;
  if (n != 40)
    return gpg_error (GPG_ERR_INV_ID);
  else if (!*s)
    ; /* okay */
  else
    return gpg_error (GPG_ERR_INV_ID);

  for (s=fpr, n=0; n < 20; s += 2, n++)
        tmp[n] = xtoi_2 (s);
  return compare_fingerprint (app, keyno, tmp);
}



/* Compute a digital signature on INDATA which is expected to be the
   raw message digest. For this application the KEYIDSTR consists of
   the serialnumber and the fingerprint delimited by a slash.

   Note that this fucntion may return the error code
   GPG_ERR_WRONG_CARD to indicate that the card currently present does
   not match the one required for the requested action (e.g. the
   serial number does not match). */
static int 
do_sign (APP app, const char *keyidstr, int hashalgo,
         int (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  static unsigned char sha1_prefix[15] = /* Object ID is 1.3.14.3.2.26 */
  { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
    0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
  static unsigned char rmd160_prefix[15] = /* Object ID is 1.3.36.3.2.1 */
  { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
    0x02, 0x01, 0x05, 0x00, 0x04, 0x14 };
  int rc;
  unsigned char data[35];
  unsigned char tmp_sn[20]; /* actually 16 but we use it also for the fpr. */
  const char *s;
  int n;
  const char *fpr = NULL;
  unsigned long sigcount;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (indatalen != 20)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check whether an OpenPGP card of any version has been requested. */
  if (strlen (keyidstr) < 32 || strncmp (keyidstr, "D27600012401", 12))
    return gpg_error (GPG_ERR_INV_ID);
  
  for (s=keyidstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (n != 32)
    return gpg_error (GPG_ERR_INV_ID);
  else if (!*s)
    ; /* no fingerprint given: we allow this for now. */
  else if (*s == '/')
    fpr = s + 1; 
  else
    return gpg_error (GPG_ERR_INV_ID);

  for (s=keyidstr, n=0; n < 16; s += 2, n++)
    tmp_sn[n] = xtoi_2 (s);

  if (app->serialnolen != 16)
    return gpg_error (GPG_ERR_INV_CARD);
  if (memcmp (app->serialno, tmp_sn, 16))
    return gpg_error (GPG_ERR_WRONG_CARD);

  /* If a fingerprint has been specified check it against the one on
     the card.  This is allows for a meaningful error message in case
     the key on the card has been replaced but the shadow information
     known to gpg was not updated.  If there is no fingerprint, gpg
     will detect a bogus signature anyway due to the
     verify-after-signing feature. */
  rc = fpr? check_against_given_fingerprint (app, fpr, 1) : 0;
  if (rc)
    return rc;

  if (hashalgo == GCRY_MD_SHA1)
    memcpy (data, sha1_prefix, 15);
  else if (hashalgo == GCRY_MD_RMD160)
    memcpy (data, rmd160_prefix, 15);
  else 
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
  memcpy (data+15, indata, indatalen);

  sigcount = get_sig_counter (app);
  log_info ("signatures created so far: %lu\n", sigcount);

  if (!app->did_chv1 || app->force_chv1 ) 
    {
      char *pinvalue;

      {
        char *prompt;
        if (asprintf (&prompt, "PIN [sigs done: %lu]", sigcount) < 0)
          return gpg_error_from_errno (errno);
        rc = pincb (pincb_arg, prompt, &pinvalue); 
        free (prompt);
      }
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      if (strlen (pinvalue) < 6)
        {
          log_error ("prassphrase (CHV1) is too short; minimum length is 6\n");
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }

      rc = iso7816_verify (app->slot, 0x81, pinvalue, strlen (pinvalue));
      if (rc)
        {
          log_error ("verify CHV1 failed\n");
          xfree (pinvalue);
          flush_cache_after_error (app);
          return rc;
        }
      app->did_chv1 = 1;
      if (!app->did_chv2)
        {
          /* We should also verify CHV2. */
          rc = iso7816_verify (app->slot, 0x82, pinvalue, strlen (pinvalue));
          if (gpg_err_code (rc) == GPG_ERR_BAD_PIN)
            rc = gpg_error (GPG_ERR_PIN_NOT_SYNCED);
          if (rc)
            {
              log_error ("verify CHV2 failed\n");
              xfree (pinvalue);
              flush_cache_after_error (app);
              return rc;
            }
          app->did_chv2 = 1;
        }
      xfree (pinvalue);
    }

  rc = iso7816_compute_ds (app->slot, data, 35, outdata, outdatalen);
  return rc;
}

/* Compute a digital signature using the INTERNAL AUTHENTICATE command
   on INDATA which is expected to be the raw message digest. For this
   application the KEYIDSTR consists of the serialnumber and the
   fingerprint delimited by a slash.

   Note that this fucntion may return the error code
   GPG_ERR_WRONG_CARD to indicate that the card currently present does
   not match the one required for the requested action (e.g. the
   serial number does not match). */
static int 
do_auth (APP app, const char *keyidstr,
         int (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  int rc;
  unsigned char tmp_sn[20]; /* actually 16 but we use it also for the fpr. */
  const char *s;
  int n;
  const char *fpr = NULL;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (indatalen > 50) /* For a 1024 bit key. */
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check whether an OpenPGP card of any version has been requested. */
  if (strlen (keyidstr) < 32 || strncmp (keyidstr, "D27600012401", 12))
    return gpg_error (GPG_ERR_INV_ID);
  
  for (s=keyidstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (n != 32)
    return gpg_error (GPG_ERR_INV_ID);
  else if (!*s)
    ; /* no fingerprint given: we allow this for now. */
  else if (*s == '/')
    fpr = s + 1; 
  else
    return gpg_error (GPG_ERR_INV_ID);

  for (s=keyidstr, n=0; n < 16; s += 2, n++)
    tmp_sn[n] = xtoi_2 (s);

  if (app->serialnolen != 16)
    return gpg_error (GPG_ERR_INV_CARD);
  if (memcmp (app->serialno, tmp_sn, 16))
    return gpg_error (GPG_ERR_WRONG_CARD);

  /* If a fingerprint has been specified check it against the one on
     the card.  This is allows for a meaningful error message in case
     the key on the card has been replaced but the shadow information
     known to gpg was not updated.  If there is no fingerprint, gpg
     will detect a bogus signature anyway due to the
     verify-after-signing feature. */
  rc = fpr? check_against_given_fingerprint (app, fpr, 3) : 0;
  if (rc)
    return rc;

  rc = verify_chv2 (app, pincb, pincb_arg);
  if (!rc)
    rc = iso7816_internal_authenticate (app->slot, indata, indatalen,
                                        outdata, outdatalen);
  return rc;
}


static int 
do_decipher (APP app, const char *keyidstr,
             int (pincb)(void*, const char *, char **),
             void *pincb_arg,
             const void *indata, size_t indatalen,
             unsigned char **outdata, size_t *outdatalen )
{
  int rc;
  unsigned char tmp_sn[20]; /* actually 16 but we use it also for the fpr. */
  const char *s;
  int n;
  const char *fpr = NULL;

  if (!keyidstr || !*keyidstr || !indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check whether an OpenPGP card of any version has been requested. */
  if (strlen (keyidstr) < 32 || strncmp (keyidstr, "D27600012401", 12))
    return gpg_error (GPG_ERR_INV_ID);
  
  for (s=keyidstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (n != 32)
    return gpg_error (GPG_ERR_INV_ID);
  else if (!*s)
    ; /* no fingerprint given: we allow this for now. */
  else if (*s == '/')
    fpr = s + 1; 
  else
    return gpg_error (GPG_ERR_INV_ID);

  for (s=keyidstr, n=0; n < 16; s += 2, n++)
    tmp_sn[n] = xtoi_2 (s);

  if (app->serialnolen != 16)
    return gpg_error (GPG_ERR_INV_CARD);
  if (memcmp (app->serialno, tmp_sn, 16))
    return gpg_error (GPG_ERR_WRONG_CARD);

  /* If a fingerprint has been specified check it against the one on
     the card.  This is allows for a meaningful error message in case
     the key on the card has been replaced but the shadow information
     known to gpg was not updated.  If there is no fingerprint, the
     decryption will won't produce the right plaintext anyway. */
  rc = fpr? check_against_given_fingerprint (app, fpr, 2) : 0;
  if (rc)
    return rc;

  rc = verify_chv2 (app, pincb, pincb_arg);
  if (!rc)
    rc = iso7816_decipher (app->slot, indata, indatalen, 0,
                           outdata, outdatalen);
  return rc;
}


/* Perform a simple verify operation for CHV1 and CHV2, so that
   further operations won't ask for CHV2 and it is possible to do a
   cheap check on the PIN: If there is something wrong with the PIN
   entry system, only the regular CHV will get blocked and not the
   dangerous CHV3.  KEYIDSTR is the usual card's serial number; an
   optional fingerprint part will be ignored. */
static int 
do_check_pin (APP app, const char *keyidstr,
              int (pincb)(void*, const char *, char **),
              void *pincb_arg)
{
  unsigned char tmp_sn[20]; 
  const char *s;
  int n;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check whether an OpenPGP card of any version has been requested. */
  if (strlen (keyidstr) < 32 || strncmp (keyidstr, "D27600012401", 12))
    return gpg_error (GPG_ERR_INV_ID);
  
  for (s=keyidstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (n != 32)
    return gpg_error (GPG_ERR_INV_ID);
  else if (!*s)
    ; /* No fingerprint given: we allow this for now. */
  else if (*s == '/')
    ; /* We ignore a fingerprint. */
  else
    return gpg_error (GPG_ERR_INV_ID);

  for (s=keyidstr, n=0; n < 16; s += 2, n++)
    tmp_sn[n] = xtoi_2 (s);

  if (app->serialnolen != 16)
    return gpg_error (GPG_ERR_INV_CARD);
  if (memcmp (app->serialno, tmp_sn, 16))
    return gpg_error (GPG_ERR_WRONG_CARD);
  /* Yes, there is a race conditions: The user might pull the card
     right here and we won't notice that.  However this is not a
     problem and the check above is merely for a graceful failure
     between operations. */

  return verify_chv2 (app, pincb, pincb_arg);
}




/* Select the OpenPGP application on the card in SLOT.  This function
   must be used before any other OpenPGP application functions. */
int
app_select_openpgp (APP app)
{
  static char const aid[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
  int slot = app->slot;
  int rc;
  unsigned char *buffer;
  size_t buflen;
  void *relptr;
  
  rc = iso7816_select_application (slot, aid, sizeof aid);
  if (!rc)
    {
      app->apptype = "OPENPGP";

      app->did_chv1 = 0;
      app->did_chv2 = 0;
      app->did_chv3 = 0;

      /* The OpenPGP card returns the serial number as part of the
         AID; because we prefer to use OpenPGP serial numbers, we
         replace a possibly already set one from a EF.GDO with this
         one.  Note, that for current OpenPGP cards, no EF.GDO exists
         and thus it won't matter at all. */
      rc = iso7816_get_data (slot, 0x004F, &buffer, &buflen);
      if (rc)
        goto leave;
      if (opt.verbose)
        {
          log_info ("got AID: ");
          log_printhex ("", buffer, buflen);
        }
#if GNUPG_MAJOR_VERSION != 1
      /* A valid OpenPGP card should never need this but well the test
         is cheap. */
      rc = app_number_serialno (app);
      if (rc)
        goto leave;
#endif

      app->card_version = buffer[6] << 8;
      app->card_version |= buffer[7];
      xfree (app->serialno);
      app->serialno = buffer;
      app->serialnolen = buflen;
      buffer = NULL;

      relptr = get_one_do (app, 0x00C4, &buffer, &buflen);
      if (!relptr)
        {
          log_error ("can't access CHV Status Bytes - invalid OpenPGP card?\n");
          goto leave;
        }
      app->force_chv1 = (buflen && *buffer == 0);
      xfree (relptr);
        
      if (opt.verbose > 1)
        dump_all_do (slot);

      app->fnc.deinit = do_deinit;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = NULL;
      app->fnc.getattr = do_getattr;
      app->fnc.setattr = do_setattr;
      app->fnc.genkey = do_genkey;
      app->fnc.sign = do_sign;
      app->fnc.auth = do_auth;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = do_change_pin;
      app->fnc.check_pin = do_check_pin;
   }

leave:
  return rc;
}



/* This function is a hack to retrieve essential information about the
   card to be displayed by simple tools.  It mostly resembles what the
   LEARN command returns. All parameters return allocated strings or
   buffers or NULL if the data object is not available.  All returned
   values are sanitized. */
int
app_openpgp_cardinfo (APP app,
                      char **serialno,
                      char **disp_name,
                      char **pubkey_url,
                      unsigned char **fpr1,
                      unsigned char **fpr2,
                      unsigned char **fpr3)
{
  int rc;
  void *relptr;
  unsigned char *value;
  size_t valuelen;

  if (serialno)
    {
      time_t dummy;

      *serialno = NULL;
      rc = app_get_serial_and_stamp (app, serialno, &dummy);
      if (rc)
        {
          log_error ("error getting serial number: %s\n", gpg_strerror (rc));
          return rc;
        }
    }
      
  if (disp_name)
    {
      *disp_name = NULL;
      relptr = get_one_do (app, 0x005B, &value, &valuelen);
      if (relptr)
        {
          *disp_name = make_printable_string (value, valuelen, 0);
          xfree (relptr);
        }
    }

  if (pubkey_url)
    {
      *pubkey_url = NULL;
      relptr = get_one_do (app, 0x5F50, &value, &valuelen);
      if (relptr)
        {
          *pubkey_url = make_printable_string (value, valuelen, 0);
          xfree (relptr);
        }
    }

  if (fpr1)
    *fpr1 = NULL;
  if (fpr2)
    *fpr2 = NULL;
  if (fpr3)
    *fpr3 = NULL;
  relptr = get_one_do (app, 0x00C5, &value, &valuelen);
  if (relptr && valuelen >= 60)
    {
      if (fpr1)
        {
          *fpr1 = xmalloc (20);
          memcpy (*fpr1, value +  0, 20);
        }
      if (fpr2)
        {
          *fpr2 = xmalloc (20);
          memcpy (*fpr2, value + 20, 20);
        }
      if (fpr3)
        {
          *fpr3 = xmalloc (20);
          memcpy (*fpr3, value + 40, 20);
        }
    }
  xfree (relptr);

  return 0;
}



/* This function is currently only used by the sc-copykeys program to
   store a key on the smartcard.  APP ist the application handle,
   KEYNO is the number of the key and PINCB, PINCB_ARG are used to ask
   for the SO PIN.  TEMPLATE and TEMPLATE_LEN describe a buffer with
   the key template to store. CREATED_AT is the timestamp used to
   create the fingerprint. M, MLEN is the RSA modulus and E, ELEN the
   RSA public exponent. This function silently overwrites an existing
   key.*/
int 
app_openpgp_storekey (APP app, int keyno,
                      unsigned char *template, size_t template_len,
                      time_t created_at,
                      const unsigned char *m, size_t mlen,
                      const unsigned char *e, size_t elen,
                      int (*pincb)(void*, const char *, char **),
                      void *pincb_arg)
{
  int rc;
  unsigned char fprbuf[20];

  if (keyno < 1 || keyno > 3)
    return gpg_error (GPG_ERR_INV_ID);
  keyno--;

  rc = verify_chv3 (app, pincb, pincb_arg);
  if (rc)
    goto leave;


  rc = iso7816_put_data (app->slot,
                         (app->card_version > 0x0007? 0xE0 : 0xE9) + keyno,
                         template, template_len);
  if (rc)
    {
      log_error ("failed to store the key: rc=%s\n", gpg_strerror (rc));
      rc = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
 
/*    log_printhex ("RSA n:", m, mlen);  */
/*    log_printhex ("RSA e:", e, elen);  */

  rc = store_fpr (app->slot, keyno, (u32)created_at,
                  m, mlen, e, elen, fprbuf, app->card_version);

 leave:
  return rc;
}


/* Utility function for external tools: Read the public RSA key at
   KEYNO and return modulus and exponent in (M,MLEN) and (E,ELEN). */
int 
app_openpgp_readkey (APP app, int keyno, unsigned char **m, size_t *mlen,
                     unsigned char **e, size_t *elen)
{
  int rc;
  const unsigned char *keydata, *a;
  unsigned char *buffer;
  size_t buflen, keydatalen, alen;

  *m = NULL;
  *e = NULL;

  if (keyno < 1 || keyno > 3)
    return gpg_error (GPG_ERR_INV_ID);
  keyno--;

  rc = iso7816_read_public_key(app->slot, 
                               keyno == 0? "\xB6" :
                               keyno == 1? "\xB8" : "\xA4",
                               2,
                               &buffer, &buflen);
  if (rc)
    {
      rc = gpg_error (GPG_ERR_CARD);
      log_error ("reading key failed\n");
      goto leave;
    }

  keydata = find_tlv (buffer, buflen, 0x7F49, &keydatalen);
  if (!keydata)
    {
      log_error ("response does not contain the public key data\n");
      rc = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
 
  a = find_tlv (keydata, keydatalen, 0x0081, &alen);
  if (!a)
    {
      log_error ("response does not contain the RSA modulus\n");
      rc = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
  *mlen = alen;
  *m = xmalloc (alen);
  memcpy (*m, a, alen);
  
  a = find_tlv (keydata, keydatalen, 0x0082, &alen);
  if (!a)
    {
      log_error ("response does not contain the RSA public exponent\n");
      rc = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
  *elen = alen;
  *e = xmalloc (alen);
  memcpy (*e, a, alen);

 leave:
  xfree (buffer);
  if (rc)
    { 
      xfree (*m); *m = NULL;
      xfree (*e); *e = NULL;
    }
  return rc;
}

/* app-openpgp.c - The OpenPGP card application.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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
#include <dlfcn.h>

#include "scdaemon.h"
#include "app-common.h"
#include "iso7816.h"



static struct {
  int tag;
  int constructed;
  int get_from;  /* Constructed DO with this DO or 0 for direct access. */
  int binary;
  char *desc;
} data_objects[] = {
  { 0x005E, 0,    0, 1, "Login Data" },
  { 0x5F50, 0,    0, 0, "URL" },
  { 0x0065, 1,    0, 1, "Cardholder Related Data"},
  { 0x005B, 0, 0x65, 0, "Name" },
  { 0x5F2D, 0, 0x65, 0, "Language preferences" },
  { 0x5F35, 0, 0x65, 0, "Sex" },
  { 0x006E, 1,    0, 1, "Application Related Data" },
  { 0x004F, 0, 0x6E, 1, "AID" },
  { 0x0073, 1,    0, 1, "Discretionary Data Objects" },
  { 0x0047, 0, 0x6E, 1, "Card Capabilities" },
  { 0x00C0, 0, 0x6E, 1, "Extended Card Capabilities" },
  { 0x00C1, 0, 0x6E, 1, "Algorithm Attributes Signature" },
  { 0x00C2, 0, 0x6E, 1, "Algorithm Attributes Decryption" },
  { 0x00C3, 0, 0x6E, 1, "Algorithm Attributes Authentication" },
  { 0x00C4, 0, 0x6E, 1, "CHV Status Bytes" },
  { 0x00C5, 0, 0x6E, 1, "Fingerprints" },
  { 0x00C6, 0, 0x6E, 1, "CA Fingerprints" },
  { 0x007A, 1,    0, 1, "Security Support Template" },
  { 0x0093, 0, 0x7A, 1, "Digital Signature Counter" },
  { 0 }
};


/* Locate a TLV encoded data object in BUFFER of LENGTH and
   return a pointer to value as well as its length in NBYTES.  Return
   NULL if it was not found.  Note, that the function does not check
   whether the value fits into the provided buffer. 

   FIXME: Move this to an extra file, it is mostly duplicated from card.c.
*/
static const unsigned char *
find_tlv (const unsigned char *buffer, size_t length,
          int tag, size_t *nbytes, int nestlevel)
{
  const unsigned char *s = buffer;
  size_t n = length;
  size_t len;
  int this_tag;
  int composite;
    
  for (;;)
    {
      buffer = s;
      if (n < 2)
        return NULL; /* buffer definitely too short for tag and length. */
      if (!*s || *s == 0xff)
        { /* Skip optional filler between TLV objects. */
          s++;
          n--;
          continue;
        }
      composite = !!(*s & 0x20);
      if ((*s & 0x1f) == 0x1f)
        { /* more tag bytes to follow */
          s++;
          n--;
          if (n < 2)
            return NULL; /* buffer definitely too short for tag and length. */
          if ((*s & 0x1f) == 0x1f)
            return NULL; /* We support only up to 2 bytes. */
          this_tag = (s[-1] << 8) | (s[0] & 0x7f);
        }
      else
        this_tag = s[0];
      len = s[1];
      s += 2; n -= 2;
      if (len < 0x80)
        ;
      else if (len == 0x81)
        { /* One byte length follows. */
          if (!n)
            return NULL; /* we expected 1 more bytes with the length. */
          len = s[0];
          s++; n--;
        }
      else if (len == 0x82)
        { /* Two byte length follows. */
          if (n < 2)
            return NULL; /* we expected 2 more bytes with the length. */
          len = (s[0] << 8) | s[1];
          s += 2; n -= 2;
        }
      else
        return NULL; /* APDU limit is 65535, thus it does not make
                        sense to assume longer length fields. */

      if (composite && nestlevel < 100)
        { /* Dive into this composite DO after checking for too deep
             nesting. */
          const unsigned char *tmp_s;
          size_t tmp_len;
          
          tmp_s = find_tlv (s, len, tag, &tmp_len, nestlevel+1);
          if (tmp_s)
            {
              *nbytes = tmp_len;
              return tmp_s;
            }
        }

      if (this_tag == tag)
        {
          *nbytes = len;
          return s;
        }
      if (len > n)
        return NULL; /* buffer too short to skip to the next tag. */
      s += len; n -= len;
    }
}


/* Get the DO identified by TAG from the card in SLOT and return a
   buffer with its content in RESULT and NBYTES.  The return value is
   NULL if not found or a pointer which must be used to release the
   buffer holding value. */
static void *
get_one_do (int slot, int tag, unsigned char **result, size_t *nbytes)
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
      rc = iso7816_get_data (slot, data_objects[i].get_from,
                             &buffer, &buflen);
      if (!rc)
        {
          value = find_tlv (buffer, buflen, tag, &valuelen, 0);
          if (!value)
            ; /* not found */
          else if (valuelen > buflen - (value - buffer))
            {
              log_error ("warning: constructed DO too short\n");
              value = NULL;
              xfree (buffer); buffer = NULL;
            }
        }
    }

  if (!value) /* Not in a constructed DO, try simple. */
    {
      rc = iso7816_get_data (slot, tag, &buffer, &buflen);
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

#if 0 /* not used */
static void
dump_one_do (int slot, int tag)
{
  int rc, i;
  unsigned char *buffer;
  size_t buflen;
  const char *desc;
  int binary;
  const unsigned char *value;
  size_t valuelen;

  for (i=0; data_objects[i].tag && data_objects[i].tag != tag; i++)
    ;
  desc = data_objects[i].tag? data_objects[i].desc : "?";
  binary = data_objects[i].tag? data_objects[i].binary : 1;

  value = NULL;
  rc = -1;
  if (data_objects[i].tag && data_objects[i].get_from)
    {
      rc = iso7816_get_data (slot, data_objects[i].get_from,
                             &buffer, &buflen);
      if (!rc)
        {
          value = find_tlv (buffer, buflen, tag, &valuelen, 0);
          if (!value)
            ; /* not found */
          else if (valuelen > buflen - (value - buffer))
            {
              log_error ("warning: constructed DO too short\n");
              value = NULL;
              xfree (buffer); buffer = NULL;
            }
        }
    }

  if (!value) /* Not in a constructed DO, try simple. */
    {
      rc = iso7816_get_data (slot, tag, &buffer, &buflen);
      if (!rc)
        {
          value = buffer;
          valuelen = buflen;
        }
    }
  if (rc == 0x6a88)
    log_info ("DO `%s' not available\n", desc);
  else if (rc) 
    log_info ("DO `%s' not available (rc=%04X)\n", desc, rc);
  else
    {
      if (binary)
        {
          log_info ("DO `%s': ", desc);
          log_printhex ("", value, valuelen);
        }
      else
        log_info ("DO `%s': `%.*s'\n",
                  desc, (int)valuelen, value); /* FIXME: sanitize */
      xfree (buffer);
    }
}
#endif /*not used*/


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
      if (rc == 0x6a88)
        ;
      else if (rc) 
        log_info ("DO `%s' not available (rc=%04X)\n",
                  data_objects[i].desc, rc);
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
        }

      if (data_objects[i].constructed)
        {
          for (j=0; data_objects[j].tag; j++)
            {
              const unsigned char *value;
              size_t valuelen;

              if (j==i || data_objects[i].tag != data_objects[j].get_from)
                continue;
              value = find_tlv (buffer, buflen,
                                data_objects[j].tag, &valuelen, 0);
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
      xfree (buffer); buffer = NULL;
    }
}

/* Note, that FPR must be at least 20 bytes. */
static int 
store_fpr (int slot, int keynumber, u32 timestamp,
           const unsigned char *m, size_t mlen,
           const unsigned char *e, size_t elen, 
           unsigned char *fpr)
{
  unsigned int n;
  unsigned char *buffer, *p;
  int rc;
  
  n = 6 + 2 + mlen + 2 + elen;
  p = buffer = xtrymalloc (3 + n);
  if (!buffer)
    return out_of_core ();
  
  *p++ = 0x99;     /* ctb */
  *p++ = n >> 8;   /* 2 byte length header */
  *p++ = n;
  *p++ = 4;        /* key packet version */
  *p++ = timestamp >> 24;
  *p++ = timestamp >> 16;
  *p++ = timestamp >>  8;
  *p++ = timestamp;
  *p++ = 1; /* RSA */
  *p++ = mlen >> 8;
  *p++ = mlen;
  memcpy (p, m, mlen); p += mlen;
  *p++ = elen >> 8;
  *p++ = elen;
  memcpy (p, e, elen); p += elen;
    
  gcry_md_hash_buffer (GCRY_MD_SHA1, fpr, buffer, n+3);
  xfree (buffer);

  rc = iso7816_put_data (slot, 0xC6 + keynumber, fpr, 20);
  if (rc)
    log_error ("failed to store the fingerprint: rc=%04X\n", rc);

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



static int
do_learn_status (APP app, CTRL ctrl)
{
  void *relptr;
  unsigned char *value;
  size_t valuelen;
  int i;

  relptr = get_one_do (app->slot, 0x005B, &value, &valuelen);
  if (relptr)
    {
      send_status_info (ctrl, "DISP-NAME", value, valuelen, NULL, 0);
      xfree (relptr);
    }
  relptr = get_one_do (app->slot, 0x5FF0, &value, &valuelen);
  if (relptr)
    {
      send_status_info (ctrl, "PUBKEY-URL", value, valuelen, NULL, 0);
      xfree (relptr);
    }

  relptr = get_one_do (app->slot, 0x00C5, &value, &valuelen);
  if (relptr && valuelen >= 60)
    {
      for (i=0; i < 3; i++)
        send_fpr_if_not_null (ctrl, "KEY-FPR", i+1, value+i*20);
    }
  xfree (relptr);
  relptr = get_one_do (app->slot, 0x00C6, &value, &valuelen);
  if (relptr && valuelen >= 60)
    {
      for (i=0; i < 3; i++)
        send_fpr_if_not_null (ctrl, "CA-FPR", i+1, value+i*20);
    }
  xfree (relptr);
  return 0;
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

  log_debug ("app_openpgp#setattr `%s' value of length %u\n",
             name, (unsigned int)valuelen); /* fixme: name should be
                                               sanitized. */

  if (!app->did_chv3)
    {
      char *pinvalue;

/*        rc = pincb (pincb_arg, "Please enter the card's admin PIN (CHV3)", */
/*                    &pinvalue); */
      pinvalue = xstrdup ("12345678");
      rc = 0;
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      rc = iso7816_verify (app->slot, 0x83, pinvalue, strlen (pinvalue));
      xfree (pinvalue);
      if (rc)
        {
          log_error ("verify CHV3 failed\n");
          rc = gpg_error (GPG_ERR_GENERAL);
          return rc;
        }
      app->did_chv3 = 1;
    }

  log_debug ("setting `%s' to `%.*s'\n", name, (int)valuelen, value);
  if (!strcmp (name, "DISP-NAME"))
    {
      rc = iso7816_put_data (app->slot, 0x005B, value, valuelen);
      if (rc)
        {
          /* FIXME: If this fails we should *once* try again after
          doing a verify command, so that in case of a problem with
          tracking the verify operation we have a fallback. */
          /* FIXME: change this when iso7816 returns correct error
          codes. */
          log_error ("failed to set `Name'\n");
          rc = gpg_error (GPG_ERR_GENERAL);
        }
    }
  else
    rc = gpg_error (GPG_ERR_INV_NAME); 

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

  if (keyno < 1 || keyno > 3)
    return gpg_error (GPG_ERR_INV_ID);
  keyno--;

  rc = iso7816_get_data (app->slot, 0x006E, &buffer, &buflen);
  if (rc)
    {
      log_error ("error reading application data\n");
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr = find_tlv (buffer, buflen, 0x00C5, &n, 0);
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

  rc = iso7816_verify (app->slot, 0x83, "12345678", 8);
  if (rc)
    {
      log_error ("verify CHV3 failed: rc=%04X\n", rc);
      goto leave;
    }

  xfree (buffer); buffer = NULL;
  rc = iso7816_generate_keypair (app->slot, 
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
  keydata = find_tlv (buffer, buflen, 0x7F49, &keydatalen, 0);
  if (!keydata)
    {
      log_error ("response does not contain the public key data\n");
      goto leave;
    }
 
  m = find_tlv (keydata, keydatalen, 0x0081, &mlen, 0);
  if (!m)
    {
      log_error ("response does not contain the RSA modulus\n");
      goto leave;
    }
  log_printhex ("RSA n:", m, mlen);
  send_key_data (ctrl, "n", m, mlen);

  e = find_tlv (keydata, keydatalen, 0x0082, &elen, 0);
  if (!e)
    {
      log_error ("response does not contain the RSA public exponent\n");
      goto leave;
    }
  log_printhex ("RSA e:", e, elen);
  send_key_data (ctrl, "e", e, elen);

  created_at = gnupg_get_time ();
  sprintf (numbuf, "%lu", (unsigned long)created_at);
  send_status_info (ctrl, "KEY-CREATED-AT",
                    numbuf, (size_t)strlen(numbuf), NULL, 0);

  rc = store_fpr (app->slot, keyno, (u32)created_at,
                  m, mlen, e, elen, fprbuf);
  if (rc)
    goto leave;
  send_fpr_if_not_null (ctrl, "KEY-FPR", -1, fprbuf);


 leave:
  xfree (buffer);
  return rc;
}


/* Comopute a digital signature on INDATA which is expected to be the
   raw message digest. */
static int 
do_sign (APP app, const char *keyidstr, int hashalgo,
         int (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         void **outdata, size_t *outdatalen )
{
  static unsigned char sha1_prefix[15] = /* Object ID is 1.3.14.3.2.26 */
  { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
    0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
  static unsigned char rmd160_prefix[15] = /* Object ID is 1.3.36.3.2.1 */
  { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
    0x02, 0x01, 0x05, 0x00, 0x04, 0x14 };
  int rc;
  unsigned char data[35];

  /* We ignore KEYIDSTR, because the OpenPGP application has only one
     signing key and no way to specify a different one. */
  
  if (indatalen != 20)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (hashalgo == GCRY_MD_SHA1)
    memcpy (data, sha1_prefix, 15);
  else if (hashalgo == GCRY_MD_RMD160)
    memcpy (data, rmd160_prefix, 15);
  else 
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
  memcpy (data+15, indata, indatalen);


  if (!app->did_chv1)
    {
      char *pinvalue;

/*        rc = pincb (pincb_arg, "signature PIN", &pinvalue); */
      pinvalue = xstrdup ("123456");
      rc = 0;
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      rc = iso7816_verify (app->slot, 0x81, pinvalue, strlen (pinvalue));
      xfree (pinvalue);
      if (rc)
        {
          log_error ("verify CHV1 failed\n");
          rc = gpg_error (GPG_ERR_GENERAL);
          return rc;
        }
      app->did_chv1 = 1;
    }

  rc = iso7816_compute_ds (app->slot, data, 35, outdata, outdatalen);

  return rc;
}


/* Select the OpenPGP application on the card in SLOT.  This function
   must be used before any other OpenPGP application functions. */
int
app_select_openpgp (APP app, unsigned char **sn, size_t *snlen)
{
  static char const aid[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
  int slot = app->slot;
  int rc;
  unsigned char *buffer;
  size_t buflen;
  
  rc = iso7816_select_application (slot, aid, sizeof aid);
  if (!rc)
    {
      /* fixme: get the full AID and check that the version is okay
         with us. */
      rc = iso7816_get_data (slot, 0x004F, &buffer, &buflen);
      if (rc)
        goto leave;
      if (opt.verbose)
        {
          log_info ("got AID: ");
          log_printhex ("", buffer, buflen);
        }

      if (sn)
        {
          *sn = buffer;
          *snlen = buflen;
        }
      else
        xfree (buffer);

      dump_all_do (slot);

      app->fnc.learn_status = do_learn_status;
      app->fnc.setattr = do_setattr;
      app->fnc.genkey = do_genkey;
      app->fnc.sign = do_sign;
   }

leave:
  return rc;
}





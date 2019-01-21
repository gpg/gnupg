/* app-piv.c - The OpenPGP card application.
 * Copyright (C) 2019 g10 Code GmbH
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

/* Some notes:
 * - Specs for PIV are at http://dx.doi.org/10.6028/NIST.SP.800-73-4
 *
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "scdaemon.h"

#include "../common/util.h"
#include "../common/i18n.h"
#include "iso7816.h"
#include "app-common.h"
#include "../common/tlv.h"
#include "../common/host2net.h"
#include "apdu.h" /* We use apdu_send_direct.  */

#define PIV_ALGORITHM_3DES_ECB_0 0x00
#define PIV_ALGORITHM_2DES_ECB   0x01
#define PIV_ALGORITHM_2DES_CBC   0x02
#define PIV_ALGORITHM_3DES_ECB   0x03
#define PIV_ALGORITHM_3DES_CBC   0x04
#define PIV_ALGORITHM_RSA        0x07
#define PIV_ALGORITHM_AES128_ECB 0x08
#define PIV_ALGORITHM_AES128_CBC 0x09
#define PIV_ALGORITHM_AES192_ECB 0x0A
#define PIV_ALGORITHM_AES192_CBC 0x0B
#define PIV_ALGORITHM_AES256_ECB 0x0C
#define PIV_ALGORITHM_AES256_CBC 0x0D
#define PIV_ALGORITHM_ECC_P256   0x11
#define PIV_ALGORITHM_ECC_P384   0x14



/* A table describing the DOs of a PIV card.  */
struct data_object_s
{
  unsigned int tag;
  unsigned int mandatory:1;
  unsigned int acr_contact:2;     /* 0=always, 1=VCI, 2=PIN, 3=PINorOCC */
  unsigned int acr_contactless:2; /* 0=always, 1=VCI, 2=VCIandPIN,
                                                      3=VCIand(PINorOCC) */
  unsigned int binary:1;          /* Data is not human readable.  */
  unsigned int dont_cache:1;      /* Data item will not be cached.  */
  unsigned int flush_on_error:1;  /* Flush cached item on error.  */
  unsigned int keypair:1;         /* Has a public key for a keypair.  */
  char keyref[3];                 /* The key reference.  */
  char *oidsuffix; /* Suffix of the OID, prefix is "2.16.840.1.101.3.7." */
  char *desc;                     /* Description of the DO.  */
};
typedef struct data_object_s *data_object_t;
static struct data_object_s data_objects[] = {
  { 0x5FC107, 1, 0,1, 1, 0,0, 0, "",   "1.219.0", "Card Capability Container"},
  { 0x5FC102, 1, 0,0, 1, 0,0, 0, "",   "2.48.0",  "Cardholder Unique Id" },
  { 0x5FC105, 1, 0,1, 1, 0,0, 1, "9A", "2.1.1",   "Cert PIV Authentication" },
  { 0x5FC103, 1, 2,2, 1, 0,0, 0, "",   "2.96.16", "Cardholder Fingerprints" },
  { 0x5FC106, 1, 0,1, 1, 0,0, 0, "",   "2.144.0", "Security Object" },
  { 0x5FC108, 1, 2,2, 1, 0,0, 0, "",   "2.96.48", "Cardholder Facial Image" },
  { 0x5FC101, 1, 0,0, 1, 0,0, 1, "9E", "2.5.0",   "Cert Card Authentication"},
  { 0x5FC10A, 0, 0,1, 1, 0,0, 1, "9C", "2.1.0",   "Cert Digital Signature" },
  { 0x5FC10B, 0, 0,1, 1, 0,0, 1, "9D", "2.1.2",   "Cert Key Management" },
  { 0x5FC109, 0, 3,3, 0, 0,0, 0, "",   "2.48.1",  "Printed Information" },
  { 0x7E,     0, 0,0, 1, 0,0, 0, "",   "2.96.80", "Discovery Object" },
  { 0x5FC10C, 0, 0,1, 1, 0,0, 0, "",   "2.96.96", "Key History Object" },
  { 0x5FC10D, 0, 0,1, 1, 0,0, 0, "82", "2.16.1",  "Retired Cert Key Mgm 1" },
  { 0x5FC10E, 0, 0,1, 1, 0,0, 0, "83", "2.16.2",  "Retired Cert Key Mgm 2" },
  { 0x5FC10F, 0, 0,1, 1, 0,0, 0, "84", "2.16.3",  "Retired Cert Key Mgm 3" },
  { 0x5FC110, 0, 0,1, 1, 0,0, 0, "85", "2.16.4",  "Retired Cert Key Mgm 4" },
  { 0x5FC111, 0, 0,1, 1, 0,0, 0, "86", "2.16.5",  "Retired Cert Key Mgm 5" },
  { 0x5FC112, 0, 0,1, 1, 0,0, 0, "87", "2.16.6",  "Retired Cert Key Mgm 6" },
  { 0x5FC113, 0, 0,1, 1, 0,0, 0, "88", "2.16.7",  "Retired Cert Key Mgm 7" },
  { 0x5FC114, 0, 0,1, 1, 0,0, 0, "89", "2.16.8",  "Retired Cert Key Mgm 8" },
  { 0x5FC115, 0, 0,1, 1, 0,0, 0, "8A", "2.16.9",  "Retired Cert Key Mgm 9" },
  { 0x5FC116, 0, 0,1, 1, 0,0, 0, "8B", "2.16.10", "Retired Cert Key Mgm 10" },
  { 0x5FC117, 0, 0,1, 1, 0,0, 0, "8C", "2.16.11", "Retired Cert Key Mgm 11" },
  { 0x5FC118, 0, 0,1, 1, 0,0, 0, "8D", "2.16.12", "Retired Cert Key Mgm 12" },
  { 0x5FC119, 0, 0,1, 1, 0,0, 0, "8E", "2.16.13", "Retired Cert Key Mgm 13" },
  { 0x5FC11A, 0, 0,1, 1, 0,0, 0, "8F", "2.16.14", "Retired Cert Key Mgm 14" },
  { 0x5FC11B, 0, 0,1, 1, 0,0, 0, "90", "2.16.15", "Retired Cert Key Mgm 15" },
  { 0x5FC11C, 0, 0,1, 1, 0,0, 0, "91", "2.16.16", "Retired Cert Key Mgm 16" },
  { 0x5FC11D, 0, 0,1, 1, 0,0, 0, "92", "2.16.17", "Retired Cert Key Mgm 17" },
  { 0x5FC11E, 0, 0,1, 1, 0,0, 0, "93", "2.16.18", "Retired Cert Key Mgm 18" },
  { 0x5FC11F, 0, 0,1, 1, 0,0, 0, "94", "2.16.19", "Retired Cert Key Mgm 19" },
  { 0x5FC120, 0, 0,1, 1, 0,0, 0, "95", "2.16.20", "Retired Cert Key Mgm 20" },
  { 0x5FC121, 0, 2,2, 1, 0,0, 0, "",   "2.16.21", "Cardholder Iris Images" },
  { 0x7F61,   0, 0,0, 1, 0,0, 0, "",   "2.16.22", "BIT Group Template" },
  { 0x5FC122, 0, 0,0, 1, 0,0, 0, "",   "2.16.23", "SM Cert Signer" },
  { 0x5FC123, 0, 3,3, 1, 0,0, 0, "",   "2.16.24", "Pairing Code Ref Data" },
  { 0 }
  /* Other key reference values without a tag:
   * "00" Global PIN (not cleared by application switching)
   * "04" PIV Secure Messaging Key
   * "80" PIV Application PIN
   * "81" PIN Unblocking Key
   * "96" Primary Finger OCC
   * "97" Secondary Finger OCC
   * "98" Pairing Code
   * "9B" PIV Card Application Administration Key
   */
};


/* One cache item for DOs.  */
struct cache_s {
  struct cache_s *next;
  int tag;
  size_t length;
  unsigned char data[1];
};


/* Object with application specific data.  */
struct app_local_s {
  /* A linked list with cached DOs.  */
  struct cache_s *cache;

  /* Various flags.  */
  struct
  {
    unsigned int dummy:1;
  } flags;

};


/***** Local prototypes  *****/
static gpg_error_t get_keygrip_by_tag (app_t app, unsigned int tag,
                                       char **r_keygripstr);





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
 * from the cache.  With GET_IMMEDIATE passed as true, the cache is
 * bypassed.  The tag-53 container is also removed.  */
static gpg_error_t
get_cached_data (app_t app, int tag,
                 unsigned char **result, size_t *resultlen,
                 int get_immediate)
{
  gpg_error_t err;
  int i;
  unsigned char *p;
  const unsigned char *s;
  size_t len, n;
  struct cache_s *c;

  *result = NULL;
  *resultlen = 0;

  if (!get_immediate)
    {
      for (c=app->app_local->cache; c; c = c->next)
        if (c->tag == tag)
          {
            if(c->length)
              {
                p = xtrymalloc (c->length);
                if (!p)
                  return gpg_error_from_syserror ();
                memcpy (p, c->data, c->length);
                *result = p;
              }

            *resultlen = c->length;

            return 0;
          }
    }

  err = iso7816_get_data_odd (app->slot, 0, tag, &p, &len);
  if (err)
    return err;

  /* Unless the Discovery Object or the BIT Group Template is
   * requested, remove the outer container.
   * (SP800-73.4 Part 2, section 3.1.2)   */
  if (tag == 0x7E || tag == 0x7F61)
    ;
  else if (len && *p == 0x53 && (s = find_tlv (p, len, 0x53, &n)))
    {
      memmove (p, s, n);
      len = n;
    }

  if (len)
    *result = p;
  *resultlen = len;

  /* Check whether we should cache this object. */
  if (get_immediate)
    return 0;

  for (i=0; data_objects[i].tag; i++)
    if (data_objects[i].tag == tag)
      {
        if (data_objects[i].dont_cache)
          return 0;
        break;
      }

  /* Okay, cache it. */
  for (c=app->app_local->cache; c; c = c->next)
    log_assert (c->tag != tag);

  c = xtrymalloc (sizeof *c + len);
  if (c)
    {
      if (len)
        memcpy (c->data, p, len);
      else
        xfree (p);
      c->length = len;
      c->tag = tag;
      c->next = app->app_local->cache;
      app->app_local->cache = c;
    }

  return 0;
}


/* Get the DO identified by TAG from the card in SLOT and return a
 * buffer with its content in RESULT and NBYTES.  The return value is
 * NULL if not found or a pointer which must be used to release the
 * buffer holding value.  */
static void *
get_one_do (app_t app, int tag, unsigned char **result, size_t *nbytes,
            int *r_err)
{
  gpg_error_t err;
  int i;
  unsigned char *buffer;
  size_t buflen;
  unsigned char *value;
  size_t valuelen;
  gpg_error_t dummyerr;

  if (!r_err)
    r_err = &dummyerr;

  *result = NULL;
  *nbytes = 0;
  *r_err = 0;
  for (i=0; data_objects[i].tag && data_objects[i].tag != tag; i++)
    ;

  value = NULL;
  err = gpg_error (GPG_ERR_ENOENT);

  if (!value) /* Not in a constructed DO, try simple. */
    {
      err = get_cached_data (app, tag, &buffer, &buflen,
                             data_objects[i].dont_cache);
      if (!err)
        {
          value = buffer;
          valuelen = buflen;
        }
    }

  if (!err)
    {
      *nbytes = valuelen;
      *result = value;
      return buffer;
    }

  *r_err = err;
  return NULL;
}


static void
dump_all_do (int slot)
{
  gpg_error_t err;
  int i;
  unsigned char *buffer;
  size_t buflen;

  for (i=0; data_objects[i].tag; i++)
    {
      /* We don't try extended length APDU because such large DO would
         be pretty useless in a log file.  */
      err = iso7816_get_data_odd (slot, 0, data_objects[i].tag,
                                 &buffer, &buflen);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_ENOENT
              && !data_objects[i].mandatory)
            ;
          else
            log_info ("DO '%s' not available: %s\n",
                      data_objects[i].desc, gpg_strerror (err));
        }
      else
        {
          if (data_objects[i].binary)
            {
              log_info ("DO '%s': ", data_objects[i].desc);
              if (buflen > 16 && opt.verbose < 2)
                {
                  log_printhex (buffer, 16, NULL);
                  log_printf ("[...]\n");
                }
              else
                log_printhex (buffer, buflen, "");
            }
          else
            log_info ("DO '%s': '%.*s'\n",
                      data_objects[i].desc,
                      (int)buflen, buffer);

        }
      xfree (buffer); buffer = NULL;
    }
}


/* Parse the key reference KEYREFSTR which is expected to hold a key
 * reference for a PIN object.  Return the one octet keyref or -1 for
 * an invalid reference.  */
static int
parse_pin_keyref (const char *keyrefstr)
{
  if (!keyrefstr)
    return -1;
  else if (!ascii_strcasecmp (keyrefstr, "PIV.00"))
    return 0x00;
  else if (!ascii_strcasecmp (keyrefstr, "PIV.80"))
    return 0x80;
  else if (!ascii_strcasecmp (keyrefstr, "PIV.81"))
    return 0x81;
  else
    return -1;
}


/* Return an allocated string with the serial number in a format to be
 * show to the user.  With FAILMODE is true return NULL if such an
 * abbreviated S/N is not available, else return the full serial
 * number as a hex string.  May return NULL on malloc problem.  */
static char *
get_dispserialno (app_t app, int failmode)
{
  char *result;

  if (app->serialno && app->serialnolen == 3+1+4
      && !memcmp (app->serialno, "\xff\x02\x00", 3))
    {
      /* This is a 4 byte S/N of a Yubikey which seems to be printed
       * on the token in decimal.  Maybe they will print larger S/N
       * also in decimal but we can't be sure, thus do it only for
       * these 32 bit numbers.  */
      unsigned long sn;
      sn  = app->serialno[4] * 16777216;
      sn += app->serialno[5] * 65536;
      sn += app->serialno[6] * 256;
      sn += app->serialno[7];
      result = xtryasprintf ("yk-%lu", sn);
    }
  else if (failmode)
    result = NULL;  /* No Abbreviated S/N.  */
  else
    result = app_get_serialno (app);

  return result;
}


/* The verify command can be used to retrieve the security status of
 * the card.  Given the PIN name (e.g. "PIV.80" for thge application
 * pin, a status is returned:
 *
 *        -1 = Error retrieving the data,
 *        -2 = No such PIN,
 *        -3 = PIN blocked,
 *        -5 = Verify still valid,
 *    n >= 0 = Number of verification attempts left.
 */
static int
get_chv_status (app_t app, const char *keyrefstr)
{
  unsigned char apdu[4];
  unsigned int sw;
  int result;
  int keyref;

  keyref = parse_pin_keyref (keyrefstr);
  if (!keyrefstr)
    return -1;

  apdu[0] = 0x00;
  apdu[1] = ISO7816_VERIFY;
  apdu[2] = 0x00;
  apdu[3] = keyref;
  if (!iso7816_apdu_direct (app->slot, apdu, 4, 0, &sw, NULL, NULL))
    result = -5; /* No need to verification.  */
  else if (sw == 0x6a88)
    result = -2; /* No such PIN.  */
  else if (sw == 0x6983)
    result = -3; /* PIN is blocked.  */
  else if ((sw & 0xfff0) == 0x63C0)
    result = (sw & 0x000f);
  else
    result = -1; /* Error.  */

  return result;
}


/* Implementation of the GETATTR command.  This is similar to the
 * LEARN command but returns only one value via status lines.  */
static gpg_error_t
do_getattr (app_t app, ctrl_t ctrl, const char *name)
{
  static struct {
    const char *name;
    int tag;
    int special;
  } table[] = {
    { "SERIALNO",     0x0000, -1 },
    { "$AUTHKEYID",   0x0000, -2 }, /* Default key for ssh.  */
    { "$DISPSERIALNO",0x0000, -3 },
    { "CHV-STATUS",   0x0000, -4 }
  };
  gpg_error_t err = 0;
  int idx;
  void *relptr;
  unsigned char *value;
  size_t valuelen;

  for (idx=0; (idx < DIM (table)
               && ascii_strcasecmp (table[idx].name, name)); idx++)
    ;
  if (!(idx < DIM (table)))
    err = gpg_error (GPG_ERR_INV_NAME);
  else if (table[idx].special == -1)
    {
      char *serial = app_get_serialno (app);

      if (serial)
        {
          send_status_direct (ctrl, "SERIALNO", serial);
          xfree (serial);
        }
    }
  else if (table[idx].special == -2)
    {
      char const tmp[] = "PIV.9A"; /* Cert PIV Authenticate.  */
      send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
    }
  else if (table[idx].special == -3)
    {
      char *tmp = get_dispserialno (app, 1);

      if (tmp)
        {
          send_status_info (ctrl, table[idx].name,
                            tmp, strlen (tmp),
                            NULL, (size_t)0);
          xfree (tmp);
        }
      else
        err = gpg_error (GPG_ERR_INV_NAME);  /* No Abbreviated S/N.  */
    }
  else if (table[idx].special == -4) /* CHV-STATUS */
    {
      int tmp[3];

      tmp[0] = get_chv_status (app, "PIV.00");
      tmp[1] = get_chv_status (app, "PIV.80");
      tmp[2] = get_chv_status (app, "PIV.81");
      err = send_status_printf (ctrl, table[idx].name, "%d %d %d",
                                tmp[0], tmp[1], tmp[2]);
    }
  else
    {
      relptr = get_one_do (app, table[idx].tag, &value, &valuelen, &err);
      if (relptr)
        {
          send_status_info (ctrl, table[idx].name, value, valuelen, NULL, 0);
          xfree (relptr);
        }
    }

  return err;
}


/* Send the KEYPAIRINFO back.  DOBJ describes the data object carrying
 * the key.  This is used by the LEARN command. */
static gpg_error_t
send_keypair_and_cert_info (app_t app, ctrl_t ctrl, data_object_t dobj,
                            int only_keypair)
{
  gpg_error_t err = 0;
  char *keygripstr = NULL;
  char idbuf[50];

  err = get_keygrip_by_tag (app, dobj->tag, &keygripstr);
  if (err)
    goto leave;

  snprintf (idbuf, sizeof idbuf, "PIV.%s", dobj->keyref);
  send_status_info (ctrl, "KEYPAIRINFO",
                    keygripstr, strlen (keygripstr),
                    idbuf, strlen (idbuf),
                    NULL, (size_t)0);
  if (!only_keypair)
    {
      /* All certificates are of type 100 (Regular X.509 Cert).  */
      send_status_info (ctrl, "CERTINFO",
                        "100", 3,
                        idbuf, strlen (idbuf),
                        NULL, (size_t)0);
    }

 leave:
  xfree (keygripstr);
  return err;
}


/* Handle the LEARN command for OpenPGP.  */
static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  int i;

  (void)flags;

  for (i=0; data_objects[i].tag; i++)
    if (data_objects[i].keypair)
      send_keypair_and_cert_info (app, ctrl, data_objects + i, !!(flags & 1));

  return 0;
}


/* Core of do-readcert which fetches the certificate based on the
 * given tag and returns it in a freshly allocated buffer stored at
 * R_CERT and the length of the certificate stored at R_CERTLEN.  */
static gpg_error_t
readcert_by_tag (app_t app, unsigned int tag,
                 unsigned char **r_cert, size_t *r_certlen)
{
  gpg_error_t err;
  unsigned char *buffer;
  size_t buflen;
  void *relptr;
  const unsigned char *s;
  size_t n;

  *r_cert = NULL;
  *r_certlen = 0;

  relptr = get_one_do (app, tag, &buffer, &buflen, NULL);
  if (!relptr || !buflen)
   {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  s = find_tlv (buffer, buflen, 0x71, &n);
  if (!s || n != 1)
    {
      log_error ("piv: no or invalid CertInfo in 0x%X\n", tag);
      err = gpg_error (GPG_ERR_INV_CERT_OBJ);
      goto leave;
    }
  if (*s == 0x01)
    {
      log_error ("piv: gzip compression not yet supported (tag 0x%X)\n", tag);
      err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
      goto leave;
    }
  if (*s)
    {
      log_error ("piv: invalid CertInfo 0x%02x in 0x%X\n", *s, tag);
      err = gpg_error (GPG_ERR_INV_CERT_OBJ);
      goto leave;
    }

  /* Note: We don't check that the LRC octet has a length of zero as
   * required by the specs.  */

  /* Get the cert from the container.  */
  s = find_tlv (buffer, buflen, 0x70, &n);
  if (!s || !n)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  if (!(*r_cert = xtrymalloc (n)))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  memcpy (*r_cert, s, n);
  *r_certlen = n;
  err = 0;

 leave:
  xfree (relptr);
  return err;
}


/* Get the keygrip of a key from the certificate stored at TAG.
 * Caller must free the string at R_KEYGRIPSTR. */
static gpg_error_t
get_keygrip_by_tag (app_t app, unsigned int tag, char **r_keygripstr)
{
  gpg_error_t err;
  unsigned char *certbuf = NULL;
  size_t certbuflen;
  ksba_cert_t cert = NULL;

  *r_keygripstr = xtrymalloc (40+1);
  if (!r_keygripstr)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* We need to get the public key from the certificate.  */
  err = readcert_by_tag (app, tag, &certbuf, &certbuflen);
  if (err)
    goto leave;

  /* Compute the keygrip.  */
  err = ksba_cert_new (&cert);
  if (err)
    goto leave;
  err = ksba_cert_init_from_mem (cert, certbuf, certbuflen);
  if (err)
    goto leave;
  err = app_help_get_keygrip_string (cert, *r_keygripstr);


 leave:
  ksba_cert_release (cert);
  xfree (certbuf);
  if (err)
    {
      xfree (*r_keygripstr);
      *r_keygripstr = NULL;
    }
  return err;
}


/* Locate the data object from the given KEYREF.  The KEYREF may also
 * be the corresponding OID of the key object.  Returns the data
 * object or NULL if not found.  */
static data_object_t
find_dobj_by_keyref (app_t app, const char *keyref)
{
  int i;

  (void)app;

  if (!ascii_strncasecmp (keyref, "PIV.", 4))
    {
      keyref += 4;
      for (i=0; data_objects[i].tag; i++)
        if (*data_objects[i].keyref
            && !ascii_strcasecmp (keyref, data_objects[i].keyref))
          {
            return data_objects + i;
          }
    }
  else if (!strncmp (keyref, "2.16.840.1.101.3.7.", 19))
    {
      keyref += 19;
      for (i=0; data_objects[i].tag; i++)
        if (*data_objects[i].keyref
            && !strcmp (keyref, data_objects[i].oidsuffix))
          {
            return data_objects + i;
          }
    }

  return NULL;
}


/* Read a certificate from the card and returned in a freshly
 * allocated buffer stored at R_CERT and the length of the certificate
 * stored at R_CERTLEN.  CERTID is either the OID of the cert's
 * container or of the form "PIV.<two_hexdigit_keyref>"  */
static gpg_error_t
do_readcert (app_t app, const char *certid,
             unsigned char **r_cert, size_t *r_certlen)
{
  data_object_t dobj;

  *r_cert = NULL;
  *r_certlen = 0;

  dobj = find_dobj_by_keyref (app, certid);
  if (!dobj)
    return gpg_error (GPG_ERR_INV_ID);

  return readcert_by_tag (app, dobj->tag, r_cert, r_certlen);
}


/* Given a data object DOBJ return the corresponding PIV algorithm and
 * store it at R_ALGO.  The algorithm is taken from the corresponding
 * certificate or from a cache.  */
static gpg_error_t
get_key_algorithm_by_dobj (app_t app, data_object_t dobj, int *r_algo)
{
  gpg_error_t err;
  unsigned char *certbuf = NULL;
  size_t certbuflen;
  ksba_cert_t cert = NULL;
  ksba_sexp_t k_pkey = NULL;
  gcry_sexp_t s_pkey = NULL;
  gcry_sexp_t l1 = NULL;
  char *algoname = NULL;
  int algo;
  size_t n;
  const char *curve_name;

  *r_algo = 0;

  err = readcert_by_tag (app, dobj->tag, &certbuf, &certbuflen);
  if (err)
    goto leave;

  err = ksba_cert_new (&cert);
  if (err)
    goto leave;

  err = ksba_cert_init_from_mem (cert, certbuf, certbuflen);
  if (err)
    {
      log_error ("piv: failed to parse the certificate %s: %s\n",
                 dobj->keyref, gpg_strerror (err));
      goto leave;
    }
  xfree (certbuf);
  certbuf = NULL;

  k_pkey = ksba_cert_get_public_key (cert);
  if (!k_pkey)
    {
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }
  n = gcry_sexp_canon_len (k_pkey, 0, NULL, NULL);
  err = gcry_sexp_new (&s_pkey, k_pkey, n, 0);
  if (err)
    goto leave;

  l1 = gcry_sexp_find_token (s_pkey, "public-key", 0);
  if (!l1)
    {
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  {
    gcry_sexp_t l_tmp = gcry_sexp_cadr (l1);
    gcry_sexp_release (l1);
    l1 = l_tmp;
  }
  algoname = gcry_sexp_nth_string (l1, 0);
  if (!algoname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  algo = gcry_pk_map_name (algoname);
  switch (algo)
    {
    case GCRY_PK_RSA:
      algo = PIV_ALGORITHM_RSA;
      break;

    case GCRY_PK_ECC:
    case GCRY_PK_ECDSA:
    case GCRY_PK_ECDH:
      curve_name = gcry_pk_get_curve (s_pkey, 0, NULL);
      if (curve_name && !strcmp (curve_name, "NIST P-256"))
        algo = PIV_ALGORITHM_ECC_P256;
      else if (curve_name && !strcmp (curve_name, "NIST P-384"))
        algo = PIV_ALGORITHM_ECC_P384;
      else
        {
          err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
          log_error ("piv: certificate %s, curve '%s': %s\n",
                     dobj->keyref, curve_name, gpg_strerror (err));
          goto leave;
        }
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      log_error ("piv: certificate %s, pubkey algo '%s': %s\n",
                 dobj->keyref, algoname, gpg_strerror (err));
      goto leave;
    }
  *r_algo = algo;

 leave:
  gcry_free (algoname);
  gcry_sexp_release (l1);
  gcry_sexp_release (s_pkey);
  ksba_free (k_pkey);
  xfree (certbuf);
  return err;
}


/* Return an allocated string to be used as prompt.  Returns NULL on
 * malloc error.  */
static char *
make_prompt (app_t app, int remaining, const char *firstline)
{
  char *serial, *tmpbuf, *result;

  serial = get_dispserialno (app, 0);
  if (!serial)
    return NULL;

  /* TRANSLATORS: Put a \x1f right before a colon.  This can be
   * used by pinentry to nicely align the names and values.  Keep
   * the %s at the start and end of the string.  */
  result = xtryasprintf (_("%s"
                           "Number\x1f: %s%%0A"
                           "Holder\x1f: %s"
                           "%s"),
                         "\x1e",
                         serial,
                         "Unknown", /* Fixme */
                         "");
  xfree (serial);

  /* Append a "remaining attempts" info if needed.  */
  if (remaining != -1 && remaining < 3)
    {
      char *rembuf;

      /* TRANSLATORS: This is the number of remaining attempts to
       * enter a PIN.  Use %%0A (double-percent,0A) for a linefeed. */
      rembuf = xtryasprintf (_("Remaining attempts: %d"), remaining);
      if (rembuf)
        {
          tmpbuf = strconcat (firstline, "%0A%0A", result,
                              "%0A%0A", rembuf, NULL);
          xfree (rembuf);
        }
      else
        tmpbuf = NULL;
      xfree (result);
      result = tmpbuf;
    }
  else
    {
      tmpbuf = strconcat (firstline, "%0A%0A", result, NULL);
      xfree (result);
      result = tmpbuf;
    }

  return result;
}


/* Verify the Application PIN KEYREF.  */
static gpg_error_t
verify_pin (app_t app, int keyref,
            gpg_error_t (*pincb)(void*,const char *,char **), void *pincb_arg)
{
  gpg_error_t err;
  unsigned char apdu[4];
  unsigned int sw;
  int remaining;
  const char *label;
  char *prompt;
  char *pinvalue = NULL;
  unsigned int pinlen;
  char pinbuffer[8];
  int minlen, maxlen, padding, onlydigits;

  /* First check whether a verify is at all needed.  This is done with
   * P1 being 0 and no Lc and command data send.  */
  apdu[0] = 0x00;
  apdu[1] = ISO7816_VERIFY;
  apdu[2] = 0x00;
  apdu[3] = keyref;
  if (!iso7816_apdu_direct (app->slot, apdu, 4, 0, &sw, NULL, NULL))
    {
      /* No need to verification.  */
      return 0;  /* All fine.  */
    }
  if ((sw & 0xfff0) == 0x63C0)
    remaining = (sw & 0x000f); /* PIN has REMAINING tries left.  */
  else
    remaining = -1;

  if (remaining != -1)
    log_debug ("piv: PIN %2X has %d attempts left\n", keyref, remaining);

  switch (keyref)
    {
    case 0x00:
      minlen = 6;
      maxlen = 8;
      padding = 1;
      onlydigits = 1;
      label = _("||Please enter the Global-PIN of your PIV card");
      break;
    case 0x80:
      minlen = 6;
      maxlen = 8;
      padding = 1;
      onlydigits = 1;
      label = _("||Please enter the PIN of your PIV card");
      break;
    case 0x81:
      minlen = 8;
      maxlen = 8;
      padding = 0;
      onlydigits = 0;
      label = _("||Please enter the Unblocking Key of your PIV card");
      break;

    case 0x96:
    case 0x97:
    case 0x98:
    case 0x9B:
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

    default:
      return gpg_error (GPG_ERR_INV_ID);
    }
  log_assert (sizeof pinbuffer >= maxlen);


  /* Ask for the PIN.  */
  prompt = make_prompt (app, remaining, label);
  err = pincb (pincb_arg, prompt, &pinvalue);
  xfree (prompt);
  prompt = NULL;
  if (err)
    {
      log_info (_("PIN callback returned error: %s\n"), gpg_strerror (err));
      return err;
    }

  pinlen = pinvalue? strlen (pinvalue) : 0;
  if (pinlen < minlen)
    {
      log_error (_("PIN for is too short; minimum length is %d\n"), minlen);
      if (pinvalue)
        wipememory (pinvalue, pinlen);
      xfree (pinvalue);
      return gpg_error (GPG_ERR_BAD_PIN);
    }
  if (pinlen > maxlen)
    {
      log_error (_("PIN for is too long; maximum length is %d\n"), maxlen);
      wipememory (pinvalue, pinlen);
      xfree (pinvalue);
      return gpg_error (GPG_ERR_BAD_PIN);
    }
  if (onlydigits && strspn (pinvalue, "0123456789") != pinlen)
    {
      log_error (_("PIN has invalid characters; only digits are allowed\n"));
      wipememory (pinvalue, pinlen);
      xfree (pinvalue);
      return gpg_error (GPG_ERR_BAD_PIN);
    }
  memcpy (pinbuffer, pinvalue, pinlen);
  if (padding)
    {
      memset (pinbuffer + pinlen, 0xff, maxlen - pinlen);
      wipememory (pinvalue, pinlen);
      pinlen = maxlen;
    }
  else
    wipememory (pinvalue, pinlen);
  xfree (pinvalue);

  err = iso7816_verify (app->slot, keyref, pinbuffer, pinlen);
  wipememory (pinbuffer, pinlen);
  if (err)
    log_error ("PIN %02X verification failed: %s\n", keyref,gpg_strerror (err));

  return err;
}


/* Handle the PASSWD command.  Valid values for PWIDSTR are
 * key references related to PINs; in particular:
 *   PIV.00 - The Global PIN
 *   PIV.80 - The Application PIN
 *   PIV.81 - The PIN Unblocking key
 * The supported flags are:
 *   APP_CHANGE_FLAG_CLEAR   Clear the PIN verification state.
 */
static gpg_error_t
do_change_pin (app_t app, ctrl_t ctrl, const char *pwidstr,
               unsigned int flags,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  gpg_error_t err;
  int keyref;
  unsigned char apdu[4];

  char *newpin = NULL;
  char *oldpin = NULL;
  size_t newpinlen;
  size_t oldpinlen;
  const char *newdesc;
  int pwid;
  pininfo_t pininfo;

  (void)ctrl;

  /* The minimum and maximum lengths are enforced by PIV.  */
  memset (&pininfo, 0, sizeof pininfo);
  pininfo.minlen = 6;
  pininfo.maxlen = 8;

  keyref = parse_pin_keyref (pwidstr);
  if (keyref == -1)
    return gpg_error (GPG_ERR_INV_ID);

  if ((flags & ~APP_CHANGE_FLAG_CLEAR))
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* First see whether the special --clear mode has been requested.  */
  if ((flags & APP_CHANGE_FLAG_CLEAR))
    {
      apdu[0] = 0x00;
      apdu[1] = ISO7816_VERIFY;
      apdu[2] = 0xff;
      apdu[3] = keyref;
      err = iso7816_apdu_direct (app->slot, apdu, 4, 0, NULL, NULL, NULL);
      goto leave;
    }

  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);

 leave:
  xfree (oldpin);
  xfree (newpin);
  return err;
}


/* Perform a simple verify operation for the PIN specified by PWIDSTR.
 * For valid values see do_change_pin.  */
static gpg_error_t
do_check_pin (app_t app, const char *pwidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg)
{
  int keyref;

  keyref = parse_pin_keyref (pwidstr);
  if (keyref == -1)
    return gpg_error (GPG_ERR_INV_ID);

  return verify_pin (app, keyref, pincb, pincb_arg);
}


/* Compute a digital signature using the GENERAL AUTHENTICATE command
 * on INDATA which is expected to be the raw message digest.  The
 * KEYIDSTR has the key reference or its OID (e.g. "PIV.9A").  The
 * result is stored at (R_OUTDATA,R_OUTDATALEN); on error (NULL,0) is
 * stored there and an error code returned.  For ECDSA the result is
 * the simple concatenation of R and S without any DER encoding.  R
 * and S are left extended with zeroes to make sure they have an equal
 * length.
 */
static gpg_error_t
do_auth (app_t app, const char *keyidstr,
         gpg_error_t (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata_arg, size_t indatalen,
         unsigned char **r_outdata, size_t *r_outdatalen)
{
  const unsigned char *indata = indata_arg;
  gpg_error_t err;
  data_object_t dobj;
  unsigned char tmpl[2+2+2+128];
  size_t tmpllen;
  unsigned char *outdata = NULL;
  size_t outdatalen;
  const unsigned char *s;
  size_t n;
  int keyref, algo;

  if (!keyidstr || !*keyidstr)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  /* Fixme: Shall we support the KEYID/FINGERPRINT syntax?  Does it
   * make sense for X.509 certs?  */

  dobj = find_dobj_by_keyref (app, keyidstr);
  if (!dobj)
    {
      err = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }
  keyref = xtoi_2 (dobj->keyref);

  err = get_key_algorithm_by_dobj (app, dobj, &algo);
  if (err)
    goto leave;

  /* We need to remove the ASN.1 prefix from INDATA.  We use TEMPL as
   * a temporary buffer for the OID.  */
  if (algo == PIV_ALGORITHM_ECC_P256)
    {
      tmpllen = sizeof tmpl;
      err = gcry_md_get_asnoid (GCRY_MD_SHA256, &tmpl, &tmpllen);
      if (err)
        {
          err = gpg_error (GPG_ERR_INTERNAL);
          log_debug ("piv: no OID for hash algo %d\n", GCRY_MD_SHA256);
          goto leave;
        }
      if (indatalen != tmpllen + 32 || memcmp (indata, tmpl, tmpllen))
        {
          err = GPG_ERR_INV_VALUE;
          log_error ("piv: bad formatted input for ECC-P256 auth\n");
          goto leave;
        }
      indata +=tmpllen;
      indatalen -= tmpllen;
    }
  else if (algo == PIV_ALGORITHM_ECC_P384)
    {
      tmpllen = sizeof tmpl;
      err = gcry_md_get_asnoid (GCRY_MD_SHA384, &tmpl, &tmpllen);
      if (err)
        {
          err = gpg_error (GPG_ERR_INTERNAL);
          log_debug ("piv: no OID for hash algo %d\n", GCRY_MD_SHA384);
          goto leave;
        }
      if (indatalen != tmpllen + 48 || memcmp (indata, tmpl, tmpllen))
        {
          err = GPG_ERR_INV_VALUE;
          log_error ("piv: bad formatted input for ECC-P384 auth\n");
          goto leave;
        }
      indata += tmpllen;
      indatalen -= tmpllen;
    }
  else if (algo == PIV_ALGORITHM_RSA)
    {
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      log_error ("piv: FIXME: implement RSA authentication\n");
      goto leave;
    }
  else
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      log_debug ("piv: unknown PIV  algo %d from helper function\n", algo);
      goto leave;
    }

  /* Because we don't have a dynamic template builder we make sure
   * that we can encode all lengths in one octet.  FIXME: Use add_tls
   * from app-openpgp as a base for an strconcat like function. */
  if (indatalen >= 100)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  /* Now verify the Application PIN.  */
  err = verify_pin (app, 0x80, pincb, pincb_arg);
  if (err)
    return err;

  /* Build the Dynamic Authentication Template.  */
  tmpl[0] = 0x7c;
  tmpl[1] = indatalen + 4;
  tmpl[2] = 0x82; /* Response. */
  tmpl[3] = 0;    /* Must be 0 to get the tag in the answer.  */
  tmpl[4] = 0x81; /* Challenge. */
  tmpl[5] = indatalen;
  memcpy (tmpl+6, indata, indatalen);
  tmpllen = indatalen + 6;

  /* Note: the -1 requests command chaining.  */
  err = iso7816_general_authenticate (app->slot, -1,
                                      algo, keyref,
                                      tmpl, (int)tmpllen, 0,
                                      &outdata, &outdatalen);
  if (err)
    goto leave;

  /* Parse the response.  */
  if (outdatalen && *outdata == 0x7c
      && (s = find_tlv (outdata, outdatalen, 0x82, &n)))
    {
      const unsigned char *rval, *sval;
      size_t rlen, rlenx, slen, slenx, resultlen;
      char *result;
      /* The result of an ECDSA signature is
       *   SEQUENCE { r INTEGER, s INTEGER }
       * We re-pack that by concatenating R and S and making sure that
       * both have the same length.  We simplify parsing by using
       * find_tlv and not a proper DER parser.  */
      s = find_tlv (s, n, 0x30, &n);
      if (!s)
        goto bad_der;
      rval = find_tlv (s, n, 0x02, &rlen);
      if (!rval)
        goto bad_der;
      log_assert (n >= (rval-s)+rlen);
      sval = find_tlv (rval+rlen, n-((rval-s)+rlen), 0x02, &slen);
      if (!rval)
        goto bad_der;
      rlenx = slenx = 0;
      if (rlen > slen)
        slenx = rlen - slen;
      else if (slen > rlen)
        rlenx = slen - rlen;

      resultlen = rlen + rlenx + slen + slenx;
      result = xtrycalloc (1, resultlen);
      if (!result)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (result + rlenx, rval, rlen);
      memcpy (result + rlenx + rlen + slenx, sval, slen);
      xfree (outdata);
      outdata = result;
      outdatalen = resultlen;
    }
  else
    {
    bad_der:
      err = gpg_error (GPG_ERR_CARD);
      log_error ("piv: response does not contain a proper result\n");
      goto leave;
    }

 leave:
  if (err)
    {
      xfree (outdata);
      *r_outdata = NULL;
      *r_outdatalen = 0;
    }
  else
    {
      *r_outdata = outdata;
      *r_outdatalen = outdatalen;
    }
  return err;
}


/* Select the PIV application on the card in SLOT.  This function must
 * be used before any other PIV application functions. */
gpg_error_t
app_select_piv (app_t app)
{
  static char const aid[] = { 0xA0, 0x00, 0x00, 0x03, 0x08, /* RID=NIST */
                              0x00, 0x00, 0x10, 0x00        /* PIX=PIV  */ };
  int slot = app->slot;
  gpg_error_t err;
  unsigned char *apt = NULL;
  size_t aptlen;
  const unsigned char *s;
  size_t n;

  /* Note that we select using the AID without the 2 octet version
   * number.  This allows for better reporting of future specs.  We
   * need to use the use-zero-for-P2-flag.  */
  err = iso7816_select_application_ext (slot, aid, sizeof aid, 0x0001,
                                        &apt, &aptlen);
  if (err)
    goto leave;

  app->apptype = "PIV";
  app->did_chv1 = 0;
  app->did_chv2 = 0;
  app->did_chv3 = 0;
  app->app_local = NULL;

  /* Check the Application Property Template.  */
  if (opt.verbose)
    {
      /* We  use a separate log_info to avoid the "DBG:" prefix.  */
      log_info ("piv: APT=");
      log_printhex (apt, aptlen, "");
    }

  s = find_tlv (apt, aptlen, 0x4F, &n);
  if (!s || n != 6 || memcmp (s, aid+5, 4))
    {
      /* The PIX does not match.  */
      log_error ("piv: missing or invalid DO 0x4F in APT\n");
      err = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
  if (s[4] != 1 || s[5] != 0)
    {
      log_error ("piv: unknown PIV version %u.%u\n", s[4], s[5]);
      err = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
  app->card_version = ((s[4] << 8) | s[5]);

  s = find_tlv (apt, aptlen, 0x79, &n);
  if (!s || n < 7)
    {
      log_error ("piv: missing or invalid DO 0x79 in APT\n");
      err = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
  s = find_tlv (s, n, 0x4F, &n);
  if (!s || n != 5 || memcmp (s, aid, 5))
    {
      /* The RID does not match.  */
      log_error ("piv: missing or invalid DO 0x79.4F in APT\n");
      err = gpg_error (GPG_ERR_CARD);
      goto leave;
    }

  app->app_local = xtrycalloc (1, sizeof *app->app_local);
  if (!app->app_local)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }


  /* FIXME: Parse the optional and conditional DOs in the APT.  */

  if (opt.verbose)
    dump_all_do (slot);

  app->fnc.deinit = do_deinit;
  app->fnc.learn_status = do_learn_status;
  app->fnc.readcert = do_readcert;
  app->fnc.readkey = NULL;
  app->fnc.getattr = do_getattr;
  /* app->fnc.setattr = do_setattr; */
  /* app->fnc.writecert = do_writecert; */
  /* app->fnc.writekey = do_writekey; */
  /* app->fnc.genkey = do_genkey; */
  /* app->fnc.sign = do_sign; */
  app->fnc.auth = do_auth;
  /* app->fnc.decipher = do_decipher; */
  app->fnc.change_pin = do_change_pin;
  app->fnc.check_pin = do_check_pin;


leave:
  xfree (apt);
  if (err)
    do_deinit (app);
  return err;
}

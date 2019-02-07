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
 * - Access control matrix:
 *   | Action       | 9B  | PIN | PUK |                              |
 *   |--------------+-----+-----+-----+------------------------------|
 *   | Generate key | yes |     |     |                              |
 *   | Change 9B    | yes |     |     |                              |
 *   | Change retry | yes | yes |     | Yubikey only                 |
 *   | Import key   | yes |     |     |                              |
 *   | Import cert  | yes |     |     |                              |
 *   | Change CHUID | yes |     |     |                              |
 *   | Reset card   |     |     |     | PIN and PUK in blocked state |
 *   | Verify PIN   |     | yes |     |                              |
 *   | Sign data    |     | yes |     |                              |
 *   | Decrypt data |     | yes |     |                              |
 *   | Change PIN   |     | yes |     |                              |
 *   | Change PUK   |     |     | yes |                              |
 *   | Unblock PIN  |     |     | yes | New PIN required             |
 *   |---------------------------------------------------------------|
 *   (9B indicates the 24 byte PIV Card Application Administration Key)
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
  /* Other key reference values without a data object:
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


/* A cache item used by genkey.  */
struct genkey_result_s {
  struct genkey_result_s *next;
  int keyref;
  gcry_sexp_t s_pkey;
};


/* Object with application specific data.  */
struct app_local_s {
  /* A linked list with cached DOs.  */
  struct cache_s *cache;

  /* A list with results from recent genkey operations.  */
  struct genkey_result_s *genkey_results;

  /* Various flags.  */
  struct
  {
    unsigned int yubikey:1;  /* This is on a Yubikey.  */
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
      struct genkey_result_s *gr, *gr2;

      for (c = app->app_local->cache; c; c = c2)
        {
          c2 = c->next;
          xfree (c);
        }
      for (gr = app->app_local->genkey_results; gr; gr = gr2)
        {
          gr2 = gr->next;
          gcry_sexp_release (gr->s_pkey);
          xfree (gr);
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


/* Remove data object described by TAG from the cache.  If TAG is 0
 * all cache iterms are flushed.  */
static void
flush_cached_data (app_t app, int tag)
{
  struct cache_s *c, *cprev;

  for (c=app->app_local->cache, cprev=NULL; c; cprev=c, c = c->next)
    if (c->tag == tag || !tag)
      {
        if (cprev)
          cprev->next = c->next;
        else
          app->app_local->cache = c->next;
        xfree (c);

        for (c=app->app_local->cache; c ; c = c->next)
          {
            log_assert (c->tag != tag); /* Oops: duplicated entry. */
          }
        return;
      }
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


/* Create a TLV tag and value and store it at BUFFER.  Return the
 * length of tag and length.  A LENGTH greater than 65535 is
 * truncated.  TAG must be less or equal to 2^16.  If BUFFER is NULL,
 * only the required length is computed.  */
static size_t
add_tlv (unsigned char *buffer, unsigned int tag, size_t length)
{
  if (length > 0xffff)
    length = 0xffff;

  if (buffer)
    {
      unsigned char *p = buffer;

      if (tag > 0xff)
        *p++ = tag >> 8;
      *p++ = tag;
      if (length < 128)
        *p++ = length;
      else if (length < 256)
        {
          *p++ = 0x81;
          *p++ = length;
        }
      else
        {
          *p++ = 0x82;
          *p++ = length >> 8;
          *p++ = length;
        }

      return p - buffer;
    }
  else
    {
      size_t n = 0;

      if (tag > 0xff)
        n++;
      n++;
      if (length < 128)
        n++;
      else if (length < 256)
        n += 2;
      else
        n += 3;
      return n;
    }
}


/* Wrapper around iso7816_put_data_odd which also sets the tag into
 * the '5C' data object.  The varargs are tuples of (int,size_t,void)
 * with the tag, the length and the actual data.  A (0,0,NULL) tuple
 * terminates the list.  Up to 10 tuples are supported.  */
static gpg_error_t
put_data (int slot, unsigned int tag, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  struct {
    int tag;
    size_t len;
    const void *data;
  } argv[10];
  int i, argc;
  unsigned char data5c[5];
  size_t data5clen;
  unsigned char *data = NULL;
  size_t datalen;
  unsigned char *p;
  size_t n;

  /* Collect all args.  Check that length is <= 2^16 to match the
   * behaviour of add_tlv.  */
  va_start (arg_ptr, tag);
  argc = 0;
  while (((argv[argc].tag = va_arg (arg_ptr, int))))
    {
      argv[argc].len = va_arg (arg_ptr, size_t);
      argv[argc].data = va_arg (arg_ptr, const void *);
      if (argc >= DIM (argv)-1 || argv[argc].len > 0xffff)
        {
          va_end (arg_ptr);
          return GPG_ERR_EINVAL;
        }
      argc++;
    }
  va_end (arg_ptr);

  /* Build the TLV with the tag to be updated.  */
  data5c[0] = 0x5c; /* Tag list */
  if (tag <= 0xff)
    {
      data5c[1] = 1;
      data5c[2] = tag;
      data5clen = 3;
    }
  else if (tag <= 0xffff)
    {
      data5c[1] = 2;
      data5c[2] = (tag >> 8);
      data5c[3] = tag;
      data5clen = 4;
    }
  else
    {
      data5c[1] = 3;
      data5c[2] = (tag >> 16);
      data5c[3] = (tag >> 8);
      data5c[4] = tag;
      data5clen = 5;
    }

  /* Compute the required buffer length and allocate the buffer.  */
  n = 0;
  for (i=0; i < argc; i++)
    {
      n += add_tlv (NULL, argv[i].tag, argv[i].len);
      n += argv[i].len;
    }
  datalen = data5clen + add_tlv (NULL, 0x53, n) + n;
  data = xtrymalloc (datalen);
  if (!data)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Copy that data to the buffer.  */
  p = data;
  memcpy (p, data5c, data5clen);
  p += data5clen;
  p += add_tlv (p, 0x53, n);
  for (i=0; i < argc; i++)
    {
      p += add_tlv (p, argv[i].tag, argv[i].len);
      memcpy (p, argv[i].data, argv[i].len);
      p += argv[i].len;
    }
  log_assert ( data + datalen == p );
  log_printhex (data, datalen, "Put data");
  err = iso7816_put_data_odd (slot, -1 /* use command chaining */,
                              0x3fff, data, datalen);

 leave:
  xfree (data);
  return err;
}


/* Parse the key reference KEYREFSTR which is expected to hold a key
 * reference for a CHV object.  Return the one octet keyref or -1 for
 * an invalid reference.  */
static int
parse_chv_keyref (const char *keyrefstr)
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

  keyref = parse_chv_keyref (keyrefstr);
  if (!keyrefstr)
    return -1;

  apdu[0] = 0x00;
  apdu[1] = ISO7816_VERIFY;
  apdu[2] = 0x00;
  apdu[3] = keyref;
  if (!iso7816_apdu_direct (app->slot, apdu, 4, 0, &sw, NULL, NULL))
    result = -5; /* No need to verification.  */
  else if (sw == 0x6a88 || sw == 0x6a80)
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
    { "CHV-STATUS",   0x0000, -4 },
    { "CHV-USAGE",    0x007E, -5 }
  };
  gpg_error_t err = 0;
  int idx;
  void *relptr;
  unsigned char *value;
  size_t valuelen;
  const unsigned char *s;
  size_t n;

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
      int tmp[4];

      tmp[0] = get_chv_status (app, "PIV.00");
      tmp[1] = get_chv_status (app, "PIV.80");
      tmp[2] = get_chv_status (app, "PIV.81");
      err = send_status_printf (ctrl, table[idx].name, "%d %d %d",
                                tmp[0], tmp[1], tmp[2]);
    }
  else if (table[idx].special == -5) /* CHV-USAGE (aka PIN Usage Policy) */
    {
      /* We return 2 hex bytes or nothing in case the discovery object
       * is not supported.  */
      relptr = get_one_do (app, table[idx].tag, &value, &valuelen, &err);
      if (relptr)
        {
          s = find_tlv (value, valuelen, 0x7E, &n);
          if (s && n && (s = find_tlv (s, n, 0x5F2F, &n)) && n >=2 )
            err = send_status_printf (ctrl, table[idx].name, "%02X %02X",
                                      s[0], s[1]);
          xfree (relptr);
        }
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


/* Authenticate the card using the Card Application Administration
 * Key.  (VALUE,VALUELEN) has that 24 byte key.  */
static gpg_error_t
auth_adm_key (app_t app, const unsigned char *value, size_t valuelen)
{
  gpg_error_t err;
  unsigned char tmpl[4+24];
  size_t tmpllen;
  unsigned char *outdata = NULL;
  size_t outdatalen;
  const unsigned char *s;
  char witness[8];
  size_t n;
  gcry_cipher_hd_t cipher = NULL;

  /* Prepare decryption.  */
  err = gcry_cipher_open (&cipher, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, 0);
  if (err)
    goto leave;
  err = gcry_cipher_setkey (cipher, value, valuelen);
  if (err)
    goto leave;

  /* Request a witness.  */
  tmpl[0] = 0x7c;
  tmpl[1] = 0x02;
  tmpl[2] = 0x80;
  tmpl[3] = 0;    /* (Empty witness requests a witness.)  */
  tmpllen = 4;
  err = iso7816_general_authenticate (app->slot, 0,
                                      PIV_ALGORITHM_3DES_ECB_0, 0x9B,
                                      tmpl, tmpllen, 0,
                                      &outdata, &outdatalen);
  if (err)
    goto leave;
  if (!(outdatalen && *outdata == 0x7c
        && (s = find_tlv (outdata, outdatalen, 0x80, &n))
        && n == 8))
    {
      err = gpg_error (GPG_ERR_CARD);
      log_error ("piv: improper witness received\n");
      goto leave;
    }
  err = gcry_cipher_decrypt (cipher, witness, 8, s, 8);
  if (err)
    goto leave;

  /* Return decrypted witness and send our challenge.  */
  tmpl[0] = 0x7c;
  tmpl[1] = 22;
  tmpl[2] = 0x80;
  tmpl[3] = 8;
  memcpy (tmpl+4, witness, 8);
  tmpl[12] = 0x81;
  tmpl[13] = 8;
  gcry_create_nonce (tmpl+14, 8);
  tmpl[22] = 0x80;
  tmpl[23] = 0;
  tmpllen = 24;
  xfree (outdata);
  err = iso7816_general_authenticate (app->slot, 0,
                                      PIV_ALGORITHM_3DES_ECB_0, 0x9B,
                                      tmpl, tmpllen, 0,
                                      &outdata, &outdatalen);
  if (err)
    goto leave;
  if (!(outdatalen && *outdata == 0x7c
        && (s = find_tlv (outdata, outdatalen, 0x82, &n))
        && n == 8))
    {
      err = gpg_error (GPG_ERR_CARD);
      log_error ("piv: improper challenge received\n");
      goto leave;
    }
  /* (We reuse the witness buffer.) */
  err = gcry_cipher_decrypt (cipher, witness, 8, s, 8);
  if (err)
    goto leave;
  if (memcmp (witness, tmpl+14, 8))
    {
      err = gpg_error (GPG_ERR_BAD_SIGNATURE);
      goto leave;
    }

 leave:
   xfree (outdata);
   gcry_cipher_close (cipher);
   return err;
}


/* Set a new admin key.  */
static gpg_error_t
set_adm_key (app_t app, const unsigned char *value, size_t valuelen)
{
  gpg_error_t err;
  unsigned char apdu[8+24];
  unsigned int sw;

  /* Check whether it is a weak key and that it is of proper length.  */
  {
    gcry_cipher_hd_t cipher;

    err = gcry_cipher_open (&cipher, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, 0);
    if (!err)
      {
        err = gcry_cipher_setkey (cipher, value, valuelen);
        gcry_cipher_close (cipher);
      }
    if (err)
      goto leave;
  }

  if (app->app_local->flags.yubikey)
    {
      /* This is a Yubikey.  */
      if (valuelen != 24)
        {
          err = gpg_error (GPG_ERR_INV_LENGTH);
          goto leave;
        }

      /* We use a proprietary Yubikey command.  */
      apdu[0] = 0;
      apdu[1] = 0xff;
      apdu[2] = 0xff;
      apdu[3] = 0xff;  /* touch policy: 0xff=never, 0xfe = always.  */
      apdu[4] = 3 + 24;
      apdu[5] = PIV_ALGORITHM_3DES_ECB;
      apdu[6] = 0x9b;
      apdu[7] = 24;
      memcpy (apdu+8, value, 24);
      err = iso7816_apdu_direct (app->slot, apdu, 8+24, 0, &sw, NULL, NULL);
      wipememory (apdu+8, 24);
      if (err)
        log_error ("piv: setting admin key failed; sw=%04x\n", sw);
    }
  else
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);


 leave:
   return err;
}


/* Handle the SETATTR operation. All arguments are already basically
 * checked. */
static gpg_error_t
do_setattr (app_t app, const char *name,
            gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg,
            const unsigned char *value, size_t valuelen)
{
  gpg_error_t err;
  static struct {
    const char *name;
    unsigned short tag;
    unsigned short flush_tag;  /* The tag which needs to be flushed or 0. */
    int special;               /* Special mode to use for thus NAME.  */
  } table[] = {
    /* Authenticate using the PIV Card Application Administration Key
     * (0x0B).  Note that Yubico calls this key the "management key"
     * which we don't do because that term is too similar to "Cert
     * Management Key" (0x9D).  */
    { "AUTH-ADM-KEY", 0x0000, 0x0000, 1 },
    { "SET-ADM-KEY",  0x0000, 0x0000, 2 }
  };
  int idx;

  (void)pincb;
  (void)pincb_arg;

  for (idx=0; (idx < DIM (table)
               && ascii_strcasecmp (table[idx].name, name)); idx++)
    ;
  if (!(idx < DIM (table)))
    return gpg_error (GPG_ERR_INV_NAME);

  /* Flush the cache before writing it, so that the next get operation
   * will reread the data from the card and thus get synced in case of
   * errors (e.g. data truncated by the card). */
  if (table[idx].tag)
    flush_cached_data (app, table[idx].flush_tag? table[idx].flush_tag
                       /* */                    : table[idx].tag);

  switch (table[idx].special)
    {
    case 1:
      err = auth_adm_key (app, value, valuelen);
      break;

    case 2:
      err = set_adm_key (app, value, valuelen);
      break;

    default:
      err = gpg_error (GPG_ERR_BUG);
      break;
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


/* Handle the LEARN command.  */
static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  int i;

  (void)flags;

  do_getattr (app, ctrl, "CHV-USAGE");
  do_getattr (app, ctrl, "CHV-STATUS");

  for (i=0; data_objects[i].tag; i++)
    if (data_objects[i].keypair)
      send_keypair_and_cert_info (app, ctrl, data_objects + i, !!(flags & 1));


  return 0;
}


/* Core of do_readcert which fetches the certificate based on the
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


/* Return the keyref from DOBJ as an integer.  If it does not exist,
 * return -1.  */
static int
keyref_from_dobj (data_object_t dobj)
{
  if (!dobj || !hexdigitp (dobj->keyref) || !hexdigitp (dobj->keyref+1))
    return -1;
  return xtoi_2 (dobj->keyref);
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


/* Return a public key in a freshly allocated buffer.  This will only
 * work for a freshly generated key as long as no reset of the
 * application has been performed.  This is because we return a cached
 * result from key generation.  If no cached result is available, the
 * error GPG_ERR_UNSUPPORTED_OPERATION is returned so that the higher
 * layer can then to get the key by reading the matching certificate.
 * On success a canonical encoded S-expression with the public key is
 * stored at (R_PK,R_PKLEN); the caller must release that buffer.  On
 * error R_PK and R_PKLEN are not changed and an error code is
 * returned.
 */
static gpg_error_t
do_readkey (app_t app, int advanced, const char *keyrefstr,
            unsigned char **r_pk, size_t *r_pklen)
{
  gpg_error_t err;
  data_object_t dobj;
  int keyref;
  struct genkey_result_s *gres;
  unsigned char *pk = NULL;
  size_t pklen;

  dobj = find_dobj_by_keyref (app, keyrefstr);
  if ((keyref = keyref_from_dobj (dobj)) == -1)
    {
      err = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }
  for (gres = app->app_local->genkey_results; gres; gres = gres->next)
    if (gres->keyref == keyref)
      break;
  if (!gres || !gres->s_pkey)
    {
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      goto leave;
    }

  err = make_canon_sexp (gres->s_pkey, &pk, &pklen);
  if (err)
    goto leave;
  if (advanced)
    {
      /* FIXME: How ugly - we should move that to command.c */
      char *p = canon_sexp_to_string (pk, pklen);
      if (!p)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      xfree (pk);
      pk = p;
      pklen = strlen (pk);
    }

  *r_pk = pk;
  pk = NULL;
  *r_pklen = pklen;

 leave:
  xfree (pk);
  return err;
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


/* Helper for verify_chv to ask for the PIN and to prepare/pad it.  On
 * success the result is stored at (R_PIN,R_PINLEN).  */
static gpg_error_t
ask_and_prepare_chv (app_t app, int keyref, int ask_new, int remaining,
                     gpg_error_t (*pincb)(void*,const char *,char **),
                     void *pincb_arg, char **r_pin, unsigned int *r_pinlen)
{
  gpg_error_t err;
  const char *label;
  char *prompt;
  char *pinvalue = NULL;
  unsigned int pinlen;
  char *pinbuffer = NULL;
  int minlen, maxlen, padding, onlydigits;

  *r_pin = NULL;
  *r_pinlen = 0;

  if (ask_new)
    remaining = -1;

  if (remaining != -1)
    log_debug ("piv: CHV %02X has %d attempts left\n", keyref, remaining);

  switch (keyref)
    {
    case 0x00:
      minlen = 6;
      maxlen = 8;
      padding = 1;
      onlydigits = 1;
      label = (ask_new? _("|N|Please enter the new Global-PIN")
               /**/   : _("||Please enter the Global-PIN of your PIV card"));
      break;
    case 0x80:
      minlen = 6;
      maxlen = 8;
      padding = 1;
      onlydigits = 1;
      label = (ask_new? _("|N|Please enter the new PIN")
               /**/   : _("||Please enter the PIN of your PIV card"));
      break;
    case 0x81:
      minlen = 8;
      maxlen = 8;
      padding = 0;
      onlydigits = 0;
      label = (ask_new? _("|N|Please enter the new Unblocking Key")
               /**/   :_("||Please enter the Unblocking Key of your PIV card"));
      break;

    case 0x96:
    case 0x97:
    case 0x98:
    case 0x9B:
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

    default:
      return gpg_error (GPG_ERR_INV_ID);
    }

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

  pinbuffer = xtrymalloc_secure (maxlen);
  if (!pinbuffer)
    {
      err = gpg_error_from_syserror ();
      wipememory (pinvalue, pinlen);
      xfree (pinvalue);
      return err;
    }

  memcpy (pinbuffer, pinvalue, pinlen);
  wipememory (pinvalue, pinlen);
  xfree (pinvalue);
  if (padding)
    {
      memset (pinbuffer + pinlen, 0xff, maxlen - pinlen);
      pinlen = maxlen;
    }

  *r_pin = pinbuffer;
  *r_pinlen = pinlen;

  return 0;
}


/* Verify the card holder verification identified by KEYREF.  This is
 * either the Appication PIN or the Global PIN. */
static gpg_error_t
verify_chv (app_t app, int keyref,
            gpg_error_t (*pincb)(void*,const char *,char **), void *pincb_arg)
{
  gpg_error_t err;
  unsigned char apdu[4];
  unsigned int sw;
  int remaining;
  char *pin = NULL;
  unsigned int pinlen;

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

  err = ask_and_prepare_chv (app, keyref, 0, remaining, pincb, pincb_arg,
                             &pin, &pinlen);
  if (err)
    return err;

  err = iso7816_verify (app->slot, keyref, pin, pinlen);
  wipememory (pin, pinlen);
  xfree (pin);
  if (err)
    log_error ("CHV %02X verification failed: %s\n",
               keyref, gpg_strerror (err));

  return err;
}


/* Handle the PASSWD command.  Valid values for PWIDSTR are
 * key references related to PINs; in particular:
 *   PIV.00 - The Global PIN
 *   PIV.80 - The Application PIN
 *   PIV.81 - The PIN Unblocking key
 * The supported flags are:
 *   APP_CHANGE_FLAG_CLEAR   Clear the PIN verification state.
 *   APP_CHANGE_FLAG_RESET   Reset a PIN using the PUK.  Only
 *                           allowed with PIV.80.
 */
static gpg_error_t
do_change_chv (app_t app, ctrl_t ctrl, const char *pwidstr,
               unsigned int flags,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  gpg_error_t err;
  int keyref, targetkeyref;
  unsigned char apdu[4];
  unsigned int sw;
  int remaining;
  char *oldpin = NULL;
  unsigned int oldpinlen;
  char *newpin = NULL;
  unsigned int newpinlen;

  (void)ctrl;

  /* Check for unknown flags.  */
  if ((flags & ~(APP_CHANGE_FLAG_CLEAR|APP_CHANGE_FLAG_RESET)))
    {
      err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
      goto leave;
    }

  /* Parse the keyref.  */
  targetkeyref = keyref = parse_chv_keyref (pwidstr);
  if (keyref == -1)
    {
      err = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }

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

  /* Prepare reset mode.  */
  if ((flags & APP_CHANGE_FLAG_RESET))
    {
      if (keyref == 0x81)
        {
          err = gpg_error (GPG_ERR_INV_ID); /* Can't reset the PUK.  */
          goto leave;
        }
      /* Set the keyref to the PUK and keep the TARGETKEYREF.  */
      keyref = 0x81;
    }

  /* Get the remaining tries count.  This is done by using the check
   * for verified state feature.  */
  apdu[0] = 0x00;
  apdu[1] = ISO7816_VERIFY;
  apdu[2] = 0x00;
  apdu[3] = keyref;
  if (!iso7816_apdu_direct (app->slot, apdu, 4, 0, &sw, NULL, NULL))
    remaining = -1; /* Already verified, thus full number of tries.  */
  else if ((sw & 0xfff0) == 0x63C0)
    remaining = (sw & 0x000f); /* PIN has REMAINING tries left.  */
  else
    remaining = -1;

  /* Ask for the old pin or puk.  */
  err = ask_and_prepare_chv (app, keyref, 0, remaining, pincb, pincb_arg,
                             &oldpin, &oldpinlen);
  if (err)
    return err;

  /* Verify the old pin so that we don't prompt for the new pin if the
   * old is wrong.  This is not possible for the PUK, though. */
  if (keyref != 0x81)
    {
      err = iso7816_verify (app->slot, keyref, oldpin, oldpinlen);
      if (err)
        {
          log_error ("CHV %02X verification failed: %s\n",
                     keyref, gpg_strerror (err));
          goto leave;
        }
    }

  /* Ask for the new pin.  */
  err = ask_and_prepare_chv (app, targetkeyref, 1, -1, pincb, pincb_arg,
                             &newpin, &newpinlen);
  if (err)
    return err;

  if ((flags & APP_CHANGE_FLAG_RESET))
    {
      char *buf = xtrymalloc_secure (oldpinlen + newpinlen);
      if (!buf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (buf, oldpin, oldpinlen);
      memcpy (buf+oldpinlen, newpin, newpinlen);
      err = iso7816_reset_retry_counter_with_rc (app->slot, targetkeyref,
                                                 buf, oldpinlen+newpinlen);
      xfree (buf);
      if (err)
        log_error ("resetting CHV %02X using CHV %02X failed: %s\n",
                   targetkeyref, keyref, gpg_strerror (err));
    }
  else
    {
      err = iso7816_change_reference_data (app->slot, keyref,
                                           oldpin, oldpinlen,
                                           newpin, newpinlen);
      if (err)
        log_error ("CHV %02X changing PIN failed: %s\n",
                   keyref, gpg_strerror (err));
    }

 leave:
  xfree (oldpin);
  xfree (newpin);
  return err;
}


/* Perform a simple verify operation for the PIN specified by PWIDSTR.
 * For valid values see do_change_chv.  */
static gpg_error_t
do_check_chv (app_t app, const char *pwidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg)
{
  int keyref;

  keyref = parse_chv_keyref (pwidstr);
  if (keyref == -1)
    return gpg_error (GPG_ERR_INV_ID);

  return verify_chv (app, keyref, pincb, pincb_arg);
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
  if ((keyref = keyref_from_dobj (dobj)) == -1)
    {
      err = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }

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
  err = verify_chv (app, 0x80, pincb, pincb_arg);
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


/* Check whether a key for DOBJ already exists.  We detect this by
 * reading the certificate described by DOBJ.  If FORCE is TRUE a
 * diagnositic will be printed but no error returned if the key
 * already exists.  The flag GENERATING is used to select a
 * diagnositic. */
static gpg_error_t
does_key_exist (app_t app, data_object_t dobj, int generating, int force)
{
  void *relptr;
  unsigned char *buffer;
  size_t buflen;
  int found;

  relptr = get_one_do (app, dobj->tag, &buffer, &buflen, NULL);
  found = (relptr && buflen);
  xfree (relptr);

  if (found && !force)
    {
      log_error ("piv: %s", _("key already exists\n"));
      return gpg_error (GPG_ERR_EEXIST);
    }

  if (found)
    log_info ("piv: %s", _("existing key will be replaced\n"));
  else if (generating)
    log_info ("piv: %s", _("generating new key\n"));
  else
    log_info ("piv: %s", _("writing new key\n"));
  return 0;
}


/* Parse an RSA response object, consisting of the content of tag
 * 0x7f49, into a gcrypt s-expresstion object and store that R_SEXP.
 * On error NULL is stored at R_SEXP. */
static gpg_error_t
genkey_parse_rsa (const unsigned char *data, size_t datalen,
                  gcry_sexp_t *r_sexp)
{
  gpg_error_t err;
  const unsigned char *m, *e;
  unsigned char *mbuf = NULL;
  unsigned char *ebuf = NULL;
  size_t mlen, elen;

  *r_sexp = NULL;

  m = find_tlv (data, datalen, 0x0081, &mlen);
  if (!m)
    {
      log_error (_("response does not contain the RSA modulus\n"));
      err = gpg_error (GPG_ERR_CARD);
      goto leave;
    }

  e = find_tlv (data, datalen, 0x0082, &elen);
  if (!e)
    {
      log_error (_("response does not contain the RSA public exponent\n"));
      err = gpg_error (GPG_ERR_CARD);
      goto leave;
    }

  for (; mlen && !*m; mlen--, m++) /* Strip leading zeroes */
    ;
  for (; elen && !*e; elen--, e++) /* Strip leading zeroes */
    ;

  mbuf = xtrymalloc (mlen + 1);
  if (!mbuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  /* Prepend numbers with a 0 if needed.  */
  if (mlen && (*m & 0x80))
    {
      *mbuf = 0;
      memcpy (mbuf+1, m, mlen);
      mlen++;
    }
  else
    memcpy (mbuf, m, mlen);

  ebuf = xtrymalloc (elen + 1);
  if (!ebuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  /* Prepend numbers with a 0 if needed.  */
  if (elen && (*e & 0x80))
    {
      *ebuf = 0;
      memcpy (ebuf+1, e, elen);
      elen++;
    }
  else
    memcpy (ebuf, e, elen);

  err = gcry_sexp_build (r_sexp, NULL, "(public-key(rsa(n%b)(e%b)))",
                         (int)mlen, mbuf, (int)elen, ebuf);

 leave:
  xfree (mbuf);
  xfree (ebuf);
  return err;
}


/* Create a new keypair for KEYREF.  If KEYTYPE is NULL a default
 * keytype is selected, else it may be one of the strings:
 *  "rsa2048", "nistp256, or "nistp384".
 *
 * Supported FLAGS are:
 *   APP_GENKEY_FLAG_FORCE   Overwrite existing key.
 *
 * Note that CREATETIME is not used for PIV cards.
 *
 * Because there seems to be no way to read the public key we need to
 * retrieve it from a certificate.  The GnuPG system however requires
 * the use of app_readkey to fetch the public key from the card to
 * create the certificate; to support this we temporary store the
 * generated public key in the local context for use by app_readkey.
 */
static gpg_error_t
do_genkey (app_t app, ctrl_t ctrl, const char *keyrefstr, const char *keytype,
           unsigned int flags, time_t createtime,
           gpg_error_t (*pincb)(void*, const char *, char **),
           void *pincb_arg)
{
  gpg_error_t err;
  data_object_t dobj;
  unsigned char *buffer = NULL;
  size_t buflen;
  int force = !!(flags & APP_GENKEY_FLAG_FORCE);
  int mechanism;
  time_t start_at;
  int keyref;
  unsigned char tmpl[5];
  size_t tmpllen;
  const unsigned char *keydata;
  size_t keydatalen;
  gcry_sexp_t s_pkey = NULL;
  struct genkey_result_s *gres;

  (void)ctrl;
  (void)createtime;
  (void)pincb;
  (void)pincb_arg;

  if (!keytype)
    keytype = "rsa2048";

  if (!strcmp (keytype, "rsa2048"))
    mechanism = PIV_ALGORITHM_RSA;
  else if (!strcmp (keytype, "nistp256"))
    mechanism = PIV_ALGORITHM_ECC_P256;
  else if (!strcmp (keytype, "nistp384"))
    mechanism = PIV_ALGORITHM_ECC_P384;
  else
    return gpg_error (GPG_ERR_UNKNOWN_CURVE);

  /* We flush the cache to increase the I/O traffic before a key
   * generation.  This _might_ help the card to gather more entropy
   * and is anyway a prerequisite for does_key_exist. */
  flush_cached_data (app, 0);

  /* Check whether a key already exists.  */
  dobj = find_dobj_by_keyref (app, keyrefstr);
  if ((keyref = keyref_from_dobj (dobj)) == -1)
    {
      err = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }
  err = does_key_exist (app, dobj, 1, force);
  if (err)
    goto leave;


  /* FIXME: Check that the authentication has already been done.  */



  /* Create the key. */
  log_info (_("please wait while key is being generated ...\n"));
  start_at = time (NULL);
  tmpl[0] = 0xac;
  tmpl[1] = 3;
  tmpl[2] = 0x80;
  tmpl[3] = 1;
  tmpl[4] = mechanism;
  tmpllen = 5;
  err = iso7816_generate_keypair (app->slot, 0, 0, keyref,
                                  tmpl, tmpllen, 0, &buffer, &buflen);
  if (err)
    {
      log_error (_("generating key failed\n"));
      return gpg_error (GPG_ERR_CARD);
    }

  {
    int nsecs = (int)(time (NULL) - start_at);
    log_info (ngettext("key generation completed (%d second)\n",
                       "key generation completed (%d seconds)\n",
                       nsecs), nsecs);
  }

  /* Parse the result and store it as an s-expression in a dedicated
   * cache for later retrieval by app_readkey.  */
  keydata = find_tlv (buffer, buflen, 0x7F49, &keydatalen);
  if (!keydata || !keydatalen)
    {
      err = gpg_error (GPG_ERR_CARD);
      log_error (_("response does not contain the public key data\n"));
      goto leave;
    }

  if (mechanism == PIV_ALGORITHM_RSA)
    err = genkey_parse_rsa (keydata, keydatalen, &s_pkey);
  else
    err = gpg_error (GPG_ERR_BUG);
  if (err)
    goto leave;

  for (gres = app->app_local->genkey_results; gres; gres = gres->next)
    if (gres->keyref == keyref)
      break;
  if (!gres)
    {
      gres = xtrycalloc (1, sizeof *gres);
      if (!gres)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      gres->keyref = keyref;
      gres->next = app->app_local->genkey_results;
      app->app_local->genkey_results = gres;
    }
  else
    gcry_sexp_release (gres->s_pkey);
  gres->s_pkey = s_pkey;
  s_pkey = NULL;


 leave:
  gcry_sexp_release (s_pkey);
  xfree (buffer);
  return err;
}


/* Write the certificate (CERT,CERTLEN) to the card at CERTREFSTR.
 * CERTREFSTR is either the OID of the certificate's container data
 * object or of the form "PIV.<two_hexdigit_keyref>". */
static gpg_error_t
do_writecert (app_t app, ctrl_t ctrl,
              const char *certrefstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const unsigned char *cert, size_t certlen)
{
  gpg_error_t err;
  data_object_t dobj;

  (void)ctrl;
  (void)pincb;     /* Not used; instead authentication is needed.  */
  (void)pincb_arg;

  dobj = find_dobj_by_keyref (app, certrefstr);
  if (!dobj || !*dobj->keyref)
    return gpg_error (GPG_ERR_INV_ID);

  /* FIXME: Check that the authentication has already been done.  */

  flush_cached_data (app, dobj->tag);

  err = put_data (app->slot, dobj->tag,
                  (int)0x70, (size_t)certlen, cert,/* Certificate */
                  (int)0x71, (size_t)1,       "",  /* No compress */
                  (int)0xfe, (size_t)0,       "",  /* Empty LRC. */
                  (int)0,    (size_t)0,       NULL);
  if (err)
    log_error ("piv: failed to write cert to %s: %s\n",
               dobj->keyref, gpg_strerror (err));


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

  if (app->cardtype && !strcmp (app->cardtype, "yubikey"))
    app->app_local->flags.yubikey = 1;


  /* FIXME: Parse the optional and conditional DOs in the APT.  */

  if (opt.verbose)
    dump_all_do (slot);

  app->fnc.deinit = do_deinit;
  app->fnc.learn_status = do_learn_status;
  app->fnc.readcert = do_readcert;
  app->fnc.readkey = do_readkey;
  app->fnc.getattr = do_getattr;
  app->fnc.setattr = do_setattr;
  app->fnc.writecert = do_writecert;
  /* app->fnc.writekey = do_writekey; */
  app->fnc.genkey = do_genkey;
  /* app->fnc.sign = do_sign; */
  app->fnc.auth = do_auth;
  /* app->fnc.decipher = do_decipher; */
  app->fnc.change_pin = do_change_chv;
  app->fnc.check_pin = do_check_chv;


leave:
  xfree (apt);
  if (err)
    do_deinit (app);
  return err;
}

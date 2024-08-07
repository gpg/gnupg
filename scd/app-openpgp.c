/* app-openpgp.c - The OpenPGP card application.
 * Copyright (C) 2003-2005, 2007-2009,
 *               2013-2015 Free Software Foundation, Inc.
 * Copyright (C) 2003-2005, 2007-2009, 2013-2015, 2020 g10 Code GmbH
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

   CHV means Card Holder Verification and is nothing else than a PIN
   or password.  That term seems to have been used originally with GSM
   cards.  Version v2 of the specs changes the term to the clearer
   term PW for password.  We use the terms here interchangeable
   because we do not want to change existing strings i18n wise.

   Version 2 of the specs also drops the separate PW2 which was
   required in v1 due to ISO requirements.  It is now possible to have
   one physical PW but two reference to it so that they can be
   individually be verified (e.g. to implement a forced verification
   for one key).  Thus you will noticed the use of PW2 with the verify
   command but not with change_reference_data because the latter
   operates directly on the physical PW.

   The Reset Code (RC) as implemented by v2 cards uses the same error
   counter as the PW2 of v1 cards.  By default no RC is set and thus
   that error counter is set to 0.  After setting the RC the error
   counter will be initialized to 3.

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
#include "../common/tlv.h"
#include "../common/host2net.h"
#include "../common/openpgpdefs.h"


#define KDF_DATA_LENGTH_MIN  90
#define KDF_DATA_LENGTH_MAX 110

/* The AID of this application.  */
static char const openpgp_aid[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };


/* A table describing the DOs of the card.  */
static struct {
  int tag;
  int constructed;
  int get_from;  /* Constructed DO with this DO or 0 for direct access. */
  unsigned int binary:1;
  unsigned int dont_cache:1;
  unsigned int flush_on_error:1;
  unsigned int get_immediate_in_v11:1; /* Enable a hack to bypass the cache of
                                 this data object if it is used in 1.1
                                 and later versions of the card.  This
                                 does not work with composite DO and
                                 is currently only useful for the CHV
                                 status bytes. */
  unsigned int try_extlen:2;           /* Large object; try to use an extended
                                 length APDU when !=0.  The size is
                                 determined by extcap.max_certlen
                                 when == 1, and by extcap.max_special_do
                                 when == 2.  */
  char *desc;
} data_objects[] = {
  { 0x005E, 0,    0, 1, 0, 0, 0, 2, "Login Data" },
  { 0x5F50, 0,    0, 0, 0, 0, 0, 2, "URL" },
  { 0x5F52, 0,    0, 1, 0, 0, 0, 0, "Historical Bytes" },
  { 0x0065, 1,    0, 1, 0, 0, 0, 0, "Cardholder Related Data"},
  { 0x005B, 0, 0x65, 0, 0, 0, 0, 0, "Name" },
  { 0x5F2D, 0, 0x65, 0, 0, 0, 0, 0, "Language preferences" },
  { 0x5F35, 0, 0x65, 0, 0, 0, 0, 0, "Salutation" },
  { 0x006E, 1,    0, 1, 0, 0, 0, 0, "Application Related Data" },
  { 0x004F, 0, 0x6E, 1, 0, 0, 0, 0, "AID" },
  { 0x0073, 1,    0, 1, 0, 0, 0, 0, "Discretionary Data Objects" },
  { 0x0047, 0, 0x6E, 1, 1, 0, 0, 0, "Card Capabilities" },
  { 0x00C0, 0, 0x6E, 1, 1, 0, 0, 0, "Extended Card Capabilities" },
  { 0x00C1, 0, 0x6E, 1, 1, 0, 0, 0, "Algorithm Attributes Signature" },
  { 0x00C2, 0, 0x6E, 1, 1, 0, 0, 0, "Algorithm Attributes Decryption" },
  { 0x00C3, 0, 0x6E, 1, 1, 0, 0, 0, "Algorithm Attributes Authentication" },
  { 0x00C4, 0, 0x6E, 1, 0, 1, 1, 0, "CHV Status Bytes" },
  { 0x00C5, 0, 0x6E, 1, 0, 0, 0, 0, "Fingerprints" },
  { 0x00C6, 0, 0x6E, 1, 0, 0, 0, 0, "CA Fingerprints" },
  { 0x00CD, 0, 0x6E, 1, 0, 0, 0, 0, "Generation time" },
  { 0x007A, 1,    0, 1, 0, 0, 0, 0, "Security Support Template" },
  { 0x0093, 0, 0x7A, 1, 1, 0, 0, 0, "Digital Signature Counter" },
  { 0x0101, 0,    0, 0, 0, 0, 0, 2, "Private DO 1"},
  { 0x0102, 0,    0, 0, 0, 0, 0, 2, "Private DO 2"},
  { 0x0103, 0,    0, 0, 0, 0, 0, 2, "Private DO 3"},
  { 0x0104, 0,    0, 0, 0, 0, 0, 2, "Private DO 4"},
  { 0x7F21, 1,    0, 1, 0, 0, 0, 1, "Cardholder certificate"},
  /* V3.0 */
  { 0x7F74, 0, 0x6E, 1, 0, 0, 0, 0, "General Feature Management"},
  { 0x00D5, 0,    0, 1, 0, 0, 0, 0, "AES key data"},
  { 0x00D6, 0, 0x6E, 1, 0, 0, 0, 0, "UIF for Signature"},
  { 0x00D7, 0, 0x6E, 1, 0, 0, 0, 0, "UIF for Decryption"},
  { 0x00D8, 0, 0x6E, 1, 0, 0, 0, 0, "UIF for Authentication"},
  { 0x00F9, 0,    0, 1, 0, 0, 0, 0, "KDF data object"},
  { 0x00FA, 0,    0, 1, 0, 0, 0, 2, "Algorithm Information"},
  { 0 }
};


/* Type of keys.  */
typedef enum
  {
    KEY_TYPE_ECC,
    KEY_TYPE_RSA,
  }
key_type_t;


/* The format of RSA private keys.  */
typedef enum
  {
    RSA_UNKNOWN_FMT,
    RSA_STD,
    RSA_STD_N,
    RSA_CRT,
    RSA_CRT_N
  }
rsa_key_format_t;


/* One cache item for DOs.  */
struct cache_s {
  struct cache_s *next;
  int tag;
  size_t length;
  unsigned char data[1];
};


/* Object with application (i.e. OpenPGP card) specific data.  */
struct app_local_s {
  /* A linked list with cached DOs.  */
  struct cache_s *cache;

  /* Keep track of the public keys.  */
  struct
  {
    int read_done;   /* True if we have at least tried to read them.  */
    unsigned char *key; /* This is a malloced buffer with a canonical
                           encoded S-expression encoding a public
                           key. Might be NULL if key is not
                           available.  */
    size_t keylen;      /* The length of the above S-expression.  This
                           is usually only required for cross checks
                           because the length of an S-expression is
                           implicitly available.  */
    unsigned char keygrip_str[41]; /* The keygrip, null terminated */
  } pk[3];

  unsigned char status_indicator; /* The card status indicator.  */

  unsigned int manufacturer:16;   /* Manufacturer ID from the s/n.  */

  /* Keep track of the ISO card capabilities.  */
  struct
  {
    unsigned int cmd_chaining:1;  /* Command chaining is supported.  */
    unsigned int ext_lc_le:1;     /* Extended Lc and Le are supported.  */
  } cardcap;

  /* Keep track of extended card capabilities.  */
  struct
  {
    unsigned int is_v2:1;              /* Compatible to v2 or later.        */
    unsigned int is_v3:1;              /* Comatible to v3 or later.         */
    unsigned int has_button:1;         /* Has confirmation button or not.   */

    unsigned int sm_supported:1;       /* Secure Messaging is supported.    */
    unsigned int get_challenge:1;
    unsigned int key_import:1;
    unsigned int change_force_chv:1;
    unsigned int private_dos:1;
    unsigned int algo_attr_change:1;   /* Algorithm attributes changeable.  */
    unsigned int has_decrypt:1;        /* Support symmetric decryption.     */
    unsigned int kdf_do:1;             /* Support KDF DO.                   */

    unsigned int sm_algo:2;            /* Symmetric crypto algo for SM.     */
    unsigned int pin_blk2:1;           /* PIN block 2 format supported.     */
    unsigned int mse:1;                /* MSE command supported.            */
    unsigned int max_certlen:16;       /* Maximum size of DO 7F21.          */
    unsigned int max_get_challenge:16; /* Maximum size for get_challenge.   */
    unsigned int max_special_do:16;    /* Maximum size for special DOs.     */
  } extcap;

  /* Flags used to control the application.  */
  struct
  {
    unsigned int no_sync:1;   /* Do not sync CHV1 and CHV2 */
    unsigned int def_chv2:1;  /* Use 123456 for CHV2.  */
  } flags;

  /* Flags used to override certain behavior.  */
  struct
  {
    unsigned int cache_6e:1;
  } override;

  /* Pinpad request specified on card.  */
  struct
  {
    unsigned int disabled:1;    /* No pinpad use because of KDF DO.  */
    unsigned int specified:1;
    int fixedlen_user;
    int fixedlen_admin;
  } pinpad;

  struct
  {
    key_type_t key_type;
    const char *keyalgo;         /* Algorithm in standard string format.  */
    union {
      struct {
        unsigned int n_bits;     /* Size of the modulus in bits.  The rest
                                    of this strucuire is only valid if
                                    this is not 0.  */
        unsigned int e_bits;     /* Size of the public exponent in bits.  */
        rsa_key_format_t format;
      } rsa;
      struct {
        const char *curve;       /* Canonical name defined in openpgp-oid.c */
        int algo;
        unsigned int flags;
      } ecc;
    };
   } keyattr[3];

};

#define ECC_FLAG_DJB_TWEAK (1 << 0)
#define ECC_FLAG_PUBKEY    (1 << 1)


/***** Local prototypes  *****/
static unsigned long convert_sig_counter_value (const unsigned char *value,
                                                size_t valuelen);
static unsigned long get_sig_counter (app_t app);
static gpg_error_t do_auth (app_t app, ctrl_t ctrl, const char *keyidstr,
                            gpg_error_t (*pincb)(void*, const char *, char **),
                            void *pincb_arg,
                            const void *indata, size_t indatalen,
                            unsigned char **outdata, size_t *outdatalen);
static const char *get_algorithm_attribute_string (const unsigned char *buffer,
                                                   size_t buflen);
static gpg_error_t parse_algorithm_attribute (app_t app, int keyno);
static gpg_error_t change_keyattr_from_string
                           (app_t app, ctrl_t ctrl,
                            gpg_error_t (*pincb)(void*, const char *, char **),
                            void *pincb_arg,
                            const char *keyref, const char *keyalgo,
                            const void *value, size_t valuelen);


/* Return the OpenPGP card manufacturer name. */
const char *
app_openpgp_manufacturer (unsigned int no)
{
  /* Note:  Make sure that there is no colon or linefeed in the string. */
  switch (no)
    {
    case 0x0001: return "PPC Card Systems";
    case 0x0002: return "Prism";
    case 0x0003: return "OpenFortress";
    case 0x0004: return "Wewid";
    case 0x0005: return "ZeitControl";
    case 0x0006: return "Yubico";
    case 0x0007: return "OpenKMS";
    case 0x0008: return "LogoEmail";
    case 0x0009: return "Fidesmo";
    case 0x000A: return "VivoKey";
    case 0x000B: return "Feitian Technologies";
    case 0x000D: return "Dangerous Things";
    case 0x000E: return "Excelsecu";

    case 0x002A: return "Magrathea";
    case 0x0042: return "GnuPG e.V.";

    case 0x1337: return "Warsaw Hackerspace";
    case 0x2342: return "warpzone"; /* hackerspace Muenster.  */
    case 0x4354: return "Confidential Technologies";   /* cotech.de */
    case 0x5343: return "SSE Carte à puce";
    case 0x5443: return "TIF-IT e.V.";
    case 0x63AF: return "Trustica";
    case 0xBA53: return "c-base e.V.";
    case 0xBD0E: return "Paranoidlabs";
    case 0xF517: return "FSIJ";
    case 0xF5EC: return "F-Secure";

      /* 0x0000 and 0xFFFF are defined as test cards per spec,
       * 0xFF00 to 0xFFFE are assigned for use with randomly created
       * serial numbers.  */
    case 0x0000:
    case 0xffff: return "test card";
    default: return (no & 0xff00) == 0xff00? "unmanaged S/N range":"unknown";
    }
}




/* Deconstructor. */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      struct cache_s *c, *c2;
      int i;

      for (c = app->app_local->cache; c; c = c2)
        {
          c2 = c->next;
          xfree (c);
        }

      for (i=0; i < DIM (app->app_local->pk); i++)
        {
          xfree (app->app_local->pk[i].key);
          app->app_local->pk[i].read_done = 0;
        }
      xfree (app->app_local);
      app->app_local = NULL;
    }
}


/* This is a helper to do a wipememory followed by a free.  In general
 * we do not need this if the buffer has been allocated in secure
 * memory.  However at some places we can't make that sure and thus we
 * better to an extra wipe here.  */
static void
wipe_and_free (void *p, size_t len)
{
  if (p)
    {
      if (len)
        wipememory (p, len);
      xfree (p);
    }
}


/* Similar to wipe_and_free but assumes P is eitehr NULL or a proper
 * string.  */
static void
wipe_and_free_string (char *p)
{
  if (p)
    {
      wipememory (p, strlen (p));
      xfree (p);
    }
}


/* Wrapper around iso7816_get_data which first tries to get the data
   from the cache.  With GET_IMMEDIATE passed as true, the cache is
   bypassed.  With TRY_EXTLEN extended lengths APDUs are use if
   supported by the card.  */
static gpg_error_t
get_cached_data (app_t app, int tag,
                 unsigned char **result, size_t *resultlen,
                 int get_immediate, int try_extlen)
{
  gpg_error_t err;
  int i;
  unsigned char *p;
  size_t len;
  struct cache_s *c;
  int exmode;

  *result = NULL;
  *resultlen = 0;

  if (tag == 0x6E && app->app_local->override.cache_6e)
    get_immediate = 0;

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

  if (try_extlen && app->app_local->cardcap.ext_lc_le)
    {
      if (try_extlen == 1)
        exmode = app->app_local->extcap.max_certlen;
      else if (try_extlen == 2 && app->app_local->extcap.is_v3)
        exmode = app->app_local->extcap.max_special_do;
      else
        exmode = 0;
    }
  else
    exmode = 0;

  err = iso7816_get_data (app_get_slot (app), exmode, tag, &p, &len);
  if (err)
    return err;
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
          {
            log_assert (c->tag != tag); /* Oops: duplicated entry. */
          }
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
get_one_do (app_t app, int tag, unsigned char **result, size_t *nbytes,
            int *r_rc)
{
  int rc, i;
  unsigned char *buffer;
  size_t buflen;
  unsigned char *value;
  size_t valuelen;
  int dummyrc;
  int exmode;

  if (!r_rc)
    r_rc = &dummyrc;

  *result = NULL;
  *nbytes = 0;
  *r_rc = 0;
  for (i=0; data_objects[i].tag && data_objects[i].tag != tag; i++)
    ;

  if (app->appversion > 0x0100 && data_objects[i].get_immediate_in_v11)
    {
      exmode = 0;
      rc = iso7816_get_data (app_get_slot (app), exmode, tag, &buffer, &buflen);
      if (rc)
        {
          *r_rc = rc;
          return NULL;
        }
      *result = buffer;
      *nbytes = buflen;
      return buffer;
    }

  value = NULL;
  rc = -1;
  if (data_objects[i].tag && data_objects[i].get_from)
    {
      rc = get_cached_data (app, data_objects[i].get_from,
                            &buffer, &buflen,
                            (data_objects[i].dont_cache
                             || data_objects[i].get_immediate_in_v11),
                            data_objects[i].try_extlen);
      if (!rc)
        {
          const unsigned char *s;

          s = find_tlv_unchecked (buffer, buflen, tag, &valuelen);
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
      rc = get_cached_data (app, tag, &buffer, &buflen,
                            (data_objects[i].dont_cache
                             || data_objects[i].get_immediate_in_v11),
                            data_objects[i].try_extlen);
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
  *r_rc = rc;
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

      /* We don't try extended length APDU because such large DO would
         be pretty useless in a log file.  */
      rc = iso7816_get_data (slot, 0, data_objects[i].tag, &buffer, &buflen);
      if (gpg_err_code (rc) == GPG_ERR_NO_OBJ)
        ;
      else if (rc)
        log_info ("DO '%s' not available: %s\n",
                  data_objects[i].desc, gpg_strerror (rc));
      else
        {
          if (data_objects[i].binary)
            {
              log_info ("DO '%s': ", data_objects[i].desc);
              log_printhex (buffer, buflen, "");
            }
          else
            log_info ("DO '%s': '%.*s'\n",
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
                  value = find_tlv_unchecked (buffer, buflen,
                                              data_objects[j].tag, &valuelen);
                  if (!value)
                    ; /* not found */
                  else if (valuelen > buflen - (value - buffer))
                    log_error ("warning: constructed DO too short\n");
                  else
                    {
                      if (data_objects[j].binary)
                        {
                          log_info ("DO '%s': ", data_objects[j].desc);
                          if (valuelen > 200)
                            log_info ("[%u]\n", (unsigned int)valuelen);
                          else
                            log_printhex (value, valuelen, "");
                        }
                      else
                        log_info ("DO '%s': '%.*s'\n",
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

static unsigned int
count_sos_bits (const unsigned char *a, size_t len)
{
  unsigned int n = len * 8;
  int i;

  if (len == 0 || *a == 0)
    return n;

  for (i=7; i && !(*a & (1<<i)); i--)
    n--;

  return n;
}

/* GnuPG makes special use of the login-data DO, this function parses
   the login data to store the flags for later use.  It may be called
   at any time and should be called after changing the login-data DO.

   Everything up to a LF is considered a mailbox or account name.  If
   the first LF is followed by DC4 (0x14) control sequence are
   expected up to the next LF.  Control sequences are separated by FS
   (0x18) and consist of key=value pairs.  There are two keys defined:

    F=<flags>

    Where FLAGS is a plain hexadecimal number representing flag values.
    The lsb is here the rightmost bit.  Defined flags bits are:

      Bit 0 = CHV1 and CHV2 are not synchronized
      Bit 1 = CHV2 has been set to the default PIN of "123456"
              (this implies that bit 0 is also set).

    P=<pinpad-request>

    Where PINPAD_REQUEST is in the format of: <n> or <n>,<m>.
    N for user PIN, M for admin PIN.  If M is missing it means M=N.
    0 means to force not to use pinpad.

*/
static void
parse_login_data (app_t app)
{
  unsigned char *buffer, *p;
  size_t buflen, len;
  void *relptr;

  /* Set defaults.  */
  app->app_local->flags.no_sync = 0;
  app->app_local->flags.def_chv2 = 0;
  app->app_local->pinpad.specified = 0;
  app->app_local->pinpad.fixedlen_user = -1;
  app->app_local->pinpad.fixedlen_admin = -1;

  /* Read the DO.  */
  relptr = get_one_do (app, 0x005E, &buffer, &buflen, NULL);
  if (!relptr)
    return; /* Ooops. */
  for (; buflen; buflen--, buffer++)
    if (*buffer == '\n')
      break;
  if (buflen < 2 || buffer[1] != '\x14')
    {
      xfree (relptr);
      return; /* No control sequences.  */
    }

  buflen--;
  buffer++;
  do
    {
      buflen--;
      buffer++;
      if (buflen > 1 && *buffer == 'F' && buffer[1] == '=')
        {
          /* Flags control sequence found.  */
          int lastdig = 0;

          /* For now we are only interested in the last digit, so skip
             any leading digits but bail out on invalid characters. */
          for (p=buffer+2, len = buflen-2; len && hexdigitp (p); p++, len--)
            lastdig = xtoi_1 (p);
          buffer = p;
          buflen = len;
          if (len && !(*p == '\n' || *p == '\x18'))
            goto next;  /* Invalid characters in field.  */
          app->app_local->flags.no_sync = !!(lastdig & 1);
          app->app_local->flags.def_chv2 = (lastdig & 3) == 3;
        }
      else if (buflen > 1 && *buffer == 'P' && buffer[1] == '=')
        {
          /* Pinpad request control sequence found.  */
          buffer += 2;
          buflen -= 2;

          if (buflen)
            {
              if (digitp (buffer))
                {
                  char *q;
                  int n, m;

                  n = strtol (buffer, &q, 10);
                  if (q >= (char *)buffer + buflen
                      || *q == '\x18' || *q == '\n')
                    m = n;
                  else
                    {
                      if (*q++ != ',' || !digitp (q))
                        goto next;
                      m = strtol (q, &q, 10);
                    }

                  if (buflen < ((unsigned char *)q - buffer))
                    break;

                  buflen -= ((unsigned char *)q - buffer);
                  buffer = q;

                  if (buflen && !(*buffer == '\n' || *buffer == '\x18'))
                    goto next;
                  app->app_local->pinpad.specified = 1;
                  app->app_local->pinpad.fixedlen_user = n;
                  app->app_local->pinpad.fixedlen_admin = m;
                }
            }
        }
    next:
      /* Skip to FS (0x18) or LF (\n).  */
      for (; buflen && *buffer != '\x18' && *buffer != '\n'; buflen--)
        buffer++;
    }
  while (buflen && *buffer != '\n');

  xfree (relptr);
}


#define MAX_ARGS_STORE_FPR 3

/* Note, that FPR must be at least 20 bytes.  If UPDATE is not set,
 * the fingerprint and the creation date is not actually stored but
 * the fingerprint is only returned in FPR.  */
static gpg_error_t
store_fpr (app_t app, int update, int keynumber, u32 timestamp,
           unsigned char *fpr, int algo, ...)
{
  unsigned int n, nbits;
  unsigned char *buffer, *p;
  int tag, tag2;
  int rc;
  const unsigned char *m[MAX_ARGS_STORE_FPR];
  size_t mlen[MAX_ARGS_STORE_FPR];
  va_list ap;
  int argc;
  int i;

  n = 6;    /* key packet version, 4-byte timestamps, and algorithm */
  if (algo == PUBKEY_ALGO_ECDH)
    argc = 3;
  else
    argc = 2;

  va_start (ap, algo);
  for (i = 0; i < argc; i++)
    {
      m[i] = va_arg (ap, const unsigned char *);
      mlen[i] = va_arg (ap, size_t);
      if (algo == PUBKEY_ALGO_RSA || i == 1)
        n += 2;
      n += mlen[i];
    }
  va_end (ap);

  p = buffer = xtrymalloc (3 + n);
  if (!buffer)
    return gpg_error_from_syserror ();

  *p++ = 0x99;     /* ctb */
  *p++ = n >> 8;   /* 2 byte length header */
  *p++ = n;
  *p++ = 4;        /* key packet version */
  *p++ = timestamp >> 24;
  *p++ = timestamp >> 16;
  *p++ = timestamp >>  8;
  *p++ = timestamp;
  *p++ = algo;

  for (i = 0; i < argc; i++)
    {
      if (algo == PUBKEY_ALGO_RSA)
        {
          nbits = count_bits (m[i], mlen[i]);
          *p++ = nbits >> 8;
          *p++ = nbits;
        }
      else if (i == 1)
        {
          nbits = count_sos_bits (m[i], mlen[i]);
          *p++ = nbits >> 8;
          *p++ = nbits;
        }
      memcpy (p, m[i], mlen[i]);
      p += mlen[i];
    }

  gcry_md_hash_buffer (GCRY_MD_SHA1, fpr, buffer, n+3);

  xfree (buffer);

  if (!update)
    return 0;

  tag = (app->appversion > 0x0007? 0xC7 : 0xC6) + keynumber;
  flush_cache_item (app, 0xC5);
  tag2 = 0xCE + keynumber;
  flush_cache_item (app, 0xCD);

  rc = iso7816_put_data (app_get_slot (app), 0, tag, fpr, 20);
  if (rc)
    log_error (_("failed to store the fingerprint: %s\n"),gpg_strerror (rc));

  if (!rc && app->appversion > 0x0100)
    {
      unsigned char buf[4];

      buf[0] = timestamp >> 24;
      buf[1] = timestamp >> 16;
      buf[2] = timestamp >>  8;
      buf[3] = timestamp;

      rc = iso7816_put_data (app_get_slot (app), 0, tag2, buf, 4);
      if (rc)
        log_error (_("failed to store the creation date: %s\n"),
                   gpg_strerror (rc));
    }

  return rc;
}


static void
send_fpr_if_not_null (ctrl_t ctrl, const char *keyword,
                      int number, const unsigned char *fpr)
{
  int i;
  char buf[41];
  char numbuf[25];

  for (i=0; i < 20 && !fpr[i]; i++)
    ;
  if (i==20)
    return; /* All zero. */
  bin2hex (fpr, 20, buf);
  if (number == -1)
    *numbuf = 0; /* Don't print the key number */
  else
    sprintf (numbuf, "%d", number);
  send_status_info (ctrl, keyword,
                    numbuf, (size_t)strlen(numbuf),
                    buf, (size_t)strlen (buf), NULL, 0);
}

static void
send_fprtime_if_not_null (ctrl_t ctrl, const char *keyword,
                          int number, const unsigned char *stamp)
{
  char numbuf1[50], numbuf2[50];
  unsigned long value;

  value = buf32_to_ulong (stamp);
  if (!value)
    return;
  sprintf (numbuf1, "%d", number);
  sprintf (numbuf2, "%lu", value);
  send_status_info (ctrl, keyword,
                    numbuf1, (size_t)strlen(numbuf1),
                    numbuf2, (size_t)strlen(numbuf2), NULL, 0);
}

static void
send_key_data (ctrl_t ctrl, const char *name,
               const unsigned char *a, size_t alen)
{
  char *buffer, *buf;
  size_t buflen;

  buffer = buf = bin2hex (a, alen, NULL);
  if (!buffer)
    {
      log_error ("memory allocation error in send_key_data\n");
      return;
    }
  buflen = strlen (buffer);

  /* 768 is the hexified size for the modulus of an 3072 bit key.  We
     use extra chunks to transmit larger data (i.e for 4096 bit).  */
  for ( ;buflen > 768; buflen -= 768, buf += 768)
    send_status_info (ctrl, "KEY-DATA",
                      "-", 1,
                      buf, 768,
                      NULL, 0);
  send_status_info (ctrl, "KEY-DATA",
                    name, (size_t)strlen(name),
                    buf, buflen,
                    NULL, 0);
  xfree (buffer);
}


static void
send_key_attr (ctrl_t ctrl, app_t app, const char *keyword, int keyno)
{
  char buffer[200];

  log_assert (keyno >=0 && keyno < DIM(app->app_local->keyattr));

  /* Note that the code in gpg-card supports prefixing the key number
   * with "OPENPGP." but older code does not yet support this.  There
   * is also a discrepancy with the algorithm numbers: We should use
   * the gcrypt numbers but the current code assumes OpenPGP numbers.  */
  if (app->app_local->keyattr[keyno].key_type == KEY_TYPE_RSA)
    snprintf (buffer, sizeof buffer, "%d 1 rsa%u %u %d",
              keyno+1,
              app->app_local->keyattr[keyno].rsa.n_bits,
              app->app_local->keyattr[keyno].rsa.e_bits,
              app->app_local->keyattr[keyno].rsa.format);
  else if (app->app_local->keyattr[keyno].key_type == KEY_TYPE_ECC)
    {
      snprintf (buffer, sizeof buffer, "%d %d %s",
                keyno+1,
                app->app_local->keyattr[keyno].ecc.algo,
                app->app_local->keyattr[keyno].ecc.curve);
    }
  else
    snprintf (buffer, sizeof buffer, "%d 0 0 UNKNOWN", keyno+1);

  send_status_direct (ctrl, keyword, buffer);
}


#define RSA_SMALL_SIZE_KEY 1952
#define RSA_SMALL_SIZE_OP  2048

static int
determine_rsa_response (app_t app, int keyno)
{
  int size;

  size = 2 + 3 /* header */
    + 4 /* tag+len */ + (app->app_local->keyattr[keyno].rsa.n_bits+7)/8
    + 2 /* tag+len */ + (app->app_local->keyattr[keyno].rsa.e_bits+7)/8;

  return size;
}


/* Implement the GETATTR command.  This is similar to the LEARN
   command but returns just one value via the status interface. */
static gpg_error_t
do_getattr (app_t app, ctrl_t ctrl, const char *name)
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
    { "KEY-TIME",     0x00CD, 4 },
    { "KEY-ATTR",     0x0000, -5 },
    { "CA-FPR",       0x00C6, 3 },
    { "CHV-STATUS",   0x00C4, 1 },
    { "SIG-COUNTER",  0x0093, 2 },
    { "SERIALNO",     0x004F, -1 },
    { "AID",          0x004F },
    { "EXTCAP",       0x0000, -2 },
    { "PRIVATE-DO-1", 0x0101 },
    { "PRIVATE-DO-2", 0x0102 },
    { "PRIVATE-DO-3", 0x0103 },
    { "PRIVATE-DO-4", 0x0104 },
    { "$AUTHKEYID",   0x0000, -3 },
    { "$ENCRKEYID",   0x0000, -6 },
    { "$SIGNKEYID",   0x0000, -7 },
    { "$DISPSERIALNO",0x0000, -4 },
    { "UIF-1",        0x00D6, 0 },
    { "UIF-2",        0x00D7, 0 },
    { "UIF-3",        0x00D8, 0 },
    { "KDF",          0x00F9, 5 },
    { "MANUFACTURER", 0x0000, -8 },
    { "UIF",          0x0000, -9 },  /* Shortcut for all UIF */
    { "KEY-STATUS",   0x00DE,  6 },
    { "KEY-ATTR-INFO", 0x00FA,  7 },
    { NULL, 0 }
  };
  int idx, i, rc;
  void *relptr;
  unsigned char *value;
  size_t valuelen;

  for (idx=0; table[idx].name && strcmp (table[idx].name, name); idx++)
    ;
  if (!table[idx].name)
    return gpg_error (GPG_ERR_INV_NAME);

  if (table[idx].special == -1)
    {
      /* The serial number is very special.  We can't use the AID
         DO (0x4f) because this is the serialno per specs with the
         correct appversion.  We might however use a serialno with the
         version set to 0.0 and that is what we need to return.  */
      char *serial = app_get_serialno (app);

      if (serial)
        {
          send_status_direct (ctrl, "SERIALNO", serial);
          xfree (serial);
        }
      return 0;
    }
  if (table[idx].special == -2)
    {
      char tmp[110];

      /* Noet that with v3 cards mcl3 is used for all certificates.  */
      snprintf (tmp, sizeof tmp,
                "gc=%d ki=%d fc=%d pd=%d mcl3=%u aac=%d "
                "sm=%d si=%u dec=%d bt=%d kdf=%d",
                app->app_local->extcap.get_challenge,
                app->app_local->extcap.key_import,
                app->app_local->extcap.change_force_chv,
                app->app_local->extcap.private_dos,
                app->app_local->extcap.max_certlen,
                app->app_local->extcap.algo_attr_change,
                (app->app_local->extcap.sm_supported
                 ? (app->app_local->extcap.sm_algo == 0? CIPHER_ALGO_3DES :
                    (app->app_local->extcap.sm_algo == 1?
                     CIPHER_ALGO_AES : CIPHER_ALGO_AES256))
                 : 0),
                app->app_local->status_indicator,
                app->app_local->extcap.has_decrypt,
                app->app_local->extcap.has_button,
                app->app_local->extcap.kdf_do);
      send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      return 0;
    }
  if (table[idx].special == -3)
    {
      char const tmp[] = "OPENPGP.3";
      send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      return 0;
    }
  if (table[idx].special == -4)
    {
      char *serial;

      if ((serial = app_get_dispserialno (app, 0)))
        {
          send_status_info (ctrl, table[idx].name,
                            serial, strlen (serial), NULL, 0);
          xfree (serial);
          return 0;
        }
      return gpg_error (GPG_ERR_INV_NAME);
    }
  if (table[idx].special == -5)
    {
      for (i=0; i < 3; i++)
        send_key_attr (ctrl, app, table[idx].name, i);
      return 0;
    }
  if (table[idx].special == -6)
    {
      char const tmp[] = "OPENPGP.2";
      send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      return 0;
    }
  if (table[idx].special == -7)
    {
      char const tmp[] = "OPENPGP.1";
      send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      return 0;
    }
  if (table[idx].special == -8)
    {
      return send_status_printf
        (ctrl, table[idx].name, "%u %s",
         app->app_local->manufacturer,
         app_openpgp_manufacturer (app->app_local->manufacturer));
    }
  if (table[idx].special == -9)
    {
      rc = do_getattr (app, ctrl, "UIF-1");
      if (!rc)
        rc = do_getattr (app, ctrl, "UIF-2");
      if (!rc)
        rc = do_getattr (app, ctrl, "UIF-3");
      return rc;
    }

  relptr = get_one_do (app, table[idx].tag, &value, &valuelen, &rc);
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
      else if (table[idx].special == 4)
        {
          if (valuelen >= 12)
            for (i=0; i < 3; i++)
              send_fprtime_if_not_null (ctrl, table[idx].name, i+1, value+i*4);
        }
      else if (table[idx].special == 5)
        {
          if ((valuelen == KDF_DATA_LENGTH_MIN
               || valuelen == KDF_DATA_LENGTH_MAX)
              && (value[2] == 0x03))
            app->app_local->pinpad.disabled = 1;
          else
            app->app_local->pinpad.disabled = 0;

          send_status_info (ctrl, table[idx].name, value, valuelen, NULL, 0);
        }
      else if (table[idx].special == 6)
        {
          for (i=0,rc=0; !rc && i+1 < valuelen; i += 2)
            rc = send_status_printf (ctrl, table[idx].name, "OPENPGP.%u %u",
                                     value[i], value[i+1]);
          if (gpg_err_code (rc) == GPG_ERR_NO_OBJ)
            rc = gpg_error (GPG_ERR_NOT_SUPPORTED);
        }
      else if (table[idx].special == 7)
        {
          const unsigned char *p = value;
          int tag;
          size_t len;

          if (valuelen < 2)
            return gpg_error (GPG_ERR_INV_OBJ);

          tag = p[0];
          len = p[1];

          /* Does it comes tag+len at the head?  */
          if (tag == 0x00FA)
            {
              p += 2;

              if (len == 0x81)
                {
                  if (valuelen < 3)
                    return gpg_error (GPG_ERR_INV_OBJ);
                  len = *p++;
                }
              else if (len == 0x82)
                {
                  if (valuelen < 4)
                    return gpg_error (GPG_ERR_INV_OBJ);
                  len = *p++;
                  len = (len << 8) | *p++;
                }

              valuelen -= (p - value);
              value = (unsigned char *)p;

              if (valuelen != len)
                {
                  if (opt.verbose)
                    log_info ("Yubikey bug: length %zu != %zu", valuelen, len);

                  if (APP_CARD(app)->cardtype != CARDTYPE_YUBIKEY)
                    return gpg_error (GPG_ERR_INV_OBJ);
                }
            }

          for (; p < value + valuelen; p += len)
            {
              const char *key_algo_str;
              int keyrefno;

              if (p + 2 > value + valuelen)
                break;

              tag = *p++;
              len = *p++;

              if (tag < 0xc1)
                continue;

              if (tag == 0xda)
                keyrefno = 0x81;
              else
                keyrefno = tag - 0xc1 + 1;

              if (p + len > value + valuelen)
                break;

              key_algo_str = get_algorithm_attribute_string (p, len);

              send_status_printf (ctrl, table[idx].name, "OPENPGP.%u %s",
                                  keyrefno, key_algo_str);
            }
        }
      else
        send_status_info (ctrl, table[idx].name, value, valuelen, NULL, 0);

      xfree (relptr);
    }
  else
    {
      if (table[idx].special == 5)
        app->app_local->pinpad.disabled = 0;
    }
  return rc;
}


/* Return the DISP-NAME without any padding characters.  Caller must
 * free the result.  If not found or empty NULL is returned.  */
static char *
get_disp_name (app_t app)
{
  int rc;
  void *relptr;
  unsigned char *value;
  size_t valuelen;
  char *string;
  char *p, *given;
  char *result;

  relptr = get_one_do (app, 0x005B, &value, &valuelen, &rc);
  if (!relptr)
    return NULL;

  string = xtrymalloc (valuelen + 1);
  if (!string)
    {
      xfree (relptr);
      return NULL;
    }
  memcpy (string, value, valuelen);
  string[valuelen] = 0;
  xfree (relptr);

  /* Swap surname and given name.  */
  given = strstr (string, "<<");
  for (p = string; *p; p++)
    if (*p == '<')
      *p = ' ';

  if (given && given[2])
    {
      *given = 0;
      given += 2;
      result = strconcat (given, " ", string, NULL);
    }
  else
    {
      result = string;
      string = NULL;
    }

  xfree (string);
  return result;
}


/* Return the number of remaining tries for the standard or the admin
 * pw.  Returns -1 on card error.  */
static int
get_remaining_tries (app_t app, int adminpw)
{
  void *relptr;
  unsigned char *value;
  size_t valuelen;
  int remaining;

  relptr = get_one_do (app, 0x00C4, &value, &valuelen, NULL);
  if (!relptr || valuelen < 7)
    {
      log_error (_("error retrieving CHV status from card\n"));
      xfree (relptr);
      return -1;
    }
  remaining = value[adminpw? 6 : 4];
  xfree (relptr);
  return remaining;
}


/* Retrieve the fingerprint from the card inserted in SLOT and write
   the according hex representation to FPR.  Caller must have provide
   a buffer at FPR of least 41 bytes.  Returns 0 on success or an
   error code. */
static gpg_error_t
retrieve_fpr_from_card (app_t app, int keyno, char *fpr)
{
  gpg_error_t err = 0;
  void *relptr;
  unsigned char *value;
  size_t valuelen;

  log_assert (keyno >=0 && keyno <= 2);

  relptr = get_one_do (app, 0x00C5, &value, &valuelen, NULL);
  if (relptr && valuelen >= 60)
    bin2hex (value+keyno*20, 20, fpr);
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);
  xfree (relptr);
  return err;
}


/* Retrieve the creation time of the fingerprint for key KEYNO from
 * the card inserted in the slot of APP and store it at R_FPRTIME.
 * Returns 0 on success or an error code.  */
static gpg_error_t
retrieve_fprtime_from_card (app_t app, int keyno, u32 *r_fprtime)
{
  gpg_error_t err = 0;
  void *relptr;
  unsigned char *value;
  size_t valuelen;
  u32 fprtime;

  log_assert (keyno >=0 && keyno <= 2);

  relptr = get_one_do (app, 0x00CD, &value, &valuelen, NULL);
  if (relptr && valuelen >= 4*(keyno+1))
    {
      fprtime = buf32_to_u32 (value + 4*keyno);
      if (!fprtime)
        err = gpg_error (GPG_ERR_NOT_FOUND);
      else
        *r_fprtime = fprtime;
    }
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);
  xfree (relptr);
  return err;
}


/* Retrieve the public key material for the RSA key, whose fingerprint
   is FPR, from gpg output, which can be read through the stream FP.
   The RSA modulus will be stored at the address of M and MLEN, the
   public exponent at E and ELEN.  Returns zero on success, an error
   code on failure.  Caller must release the allocated buffers at M
   and E if the function returns success.  */
static gpg_error_t
retrieve_key_material (FILE *fp, const char *hexkeyid,
                       const unsigned char **m, size_t *mlen,
                       const unsigned char **e, size_t *elen)
{
  gcry_error_t err = 0;
  char *line = NULL;    /* read_line() buffer. */
  size_t line_size = 0; /* Helper for for read_line. */
  int found_key = 0;    /* Helper to find a matching key. */
  unsigned char *m_new = NULL;
  unsigned char *e_new = NULL;
  size_t m_new_n = 0;
  size_t e_new_n = 0;

  /* Loop over all records until we have found the subkey
     corresponding to the fingerprint. Inm general the first record
     should be the pub record, but we don't rely on that.  Given that
     we only need to look at one key, it is sufficient to compare the
     keyid so that we don't need to look at "fpr" records. */
  for (;;)
    {
      char *p;
      char *fields[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
      int nfields;
      size_t max_length;
      gcry_mpi_t mpi;
      int i;

      max_length = 4096;
      i = read_line (fp, &line, &line_size, &max_length);
      if (!i)
        break; /* EOF. */
      if (i < 0)
        {
          err = gpg_error_from_syserror ();
          goto leave; /* Error. */
        }
      if (!max_length)
        {
          err = gpg_error (GPG_ERR_TRUNCATED);
          goto leave;  /* Line truncated - we better stop processing.  */
        }

      /* Parse the line into fields. */
      for (nfields=0, p=line; p && nfields < DIM (fields); nfields++)
        {
          fields[nfields] = p;
          p = strchr (p, ':');
          if (p)
            *(p++) = 0;
        }
      if (!nfields)
        continue; /* No fields at all - skip line.  */

      if (!found_key)
        {
          if ( (!strcmp (fields[0], "sub") || !strcmp (fields[0], "pub") )
               && nfields > 4 && !strcmp (fields[4], hexkeyid))
            found_key = 1;
          continue;
        }

      if ( !strcmp (fields[0], "sub") || !strcmp (fields[0], "pub") )
        break; /* Next key - stop.  */

      if ( strcmp (fields[0], "pkd") )
        continue; /* Not a key data record.  */
      if ( nfields < 4 || (i = atoi (fields[1])) < 0 || i > 1
           || (!i && m_new) || (i && e_new))
        {
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave; /* Error: Invalid key data record or not an RSA key.  */
        }

      err = gcry_mpi_scan (&mpi, GCRYMPI_FMT_HEX, fields[3], 0, NULL);
      if (err)
        mpi = NULL;
      else if (!i)
        err = gcry_mpi_aprint (GCRYMPI_FMT_STD, &m_new, &m_new_n, mpi);
      else
        err = gcry_mpi_aprint (GCRYMPI_FMT_STD, &e_new, &e_new_n, mpi);
      gcry_mpi_release (mpi);
      if (err)
        goto leave;
    }

  if (m_new && e_new)
    {
      *m = m_new;
      *mlen = m_new_n;
      m_new = NULL;
      *e = e_new;
      *elen = e_new_n;
      e_new = NULL;
    }
  else
    err = gpg_error (GPG_ERR_GENERAL);

 leave:
  xfree (m_new);
  xfree (e_new);
  xfree (line);
  return err;
}


static gpg_error_t
rsa_read_pubkey (app_t app, ctrl_t ctrl, int meta_update,
                 u32 created_at,  int keyno,
                 const unsigned char *data, size_t datalen, gcry_sexp_t *r_sexp)
{
  gpg_error_t err;
  const unsigned char *m, *e;
  size_t mlen, elen;
  unsigned char *mbuf = NULL, *ebuf = NULL;

  m = find_tlv (data, datalen, 0x0081, &mlen);
  if (!m)
    {
      log_error (_("response does not contain the RSA modulus\n"));
      return gpg_error (GPG_ERR_CARD);
    }

  e = find_tlv (data, datalen, 0x0082, &elen);
  if (!e)
    {
      log_error (_("response does not contain the RSA public exponent\n"));
      return gpg_error (GPG_ERR_CARD);
    }

  if (ctrl)
    {
      send_key_data (ctrl, "n", m, mlen);
      send_key_data (ctrl, "e", e, elen);
    }

  for (; mlen && !*m; mlen--, m++) /* strip leading zeroes */
    ;
  for (; elen && !*e; elen--, e++) /* strip leading zeroes */
    ;

  if (ctrl)
    {
      unsigned char fprbuf[20];

      /* If META_UPDATE is not set we only compute but not store the
       * fingerprint.  This might return a wrong fingerprint if
       * CREATED_AT is not set.  */
      err = store_fpr (app, meta_update, keyno,
                       created_at, fprbuf, PUBKEY_ALGO_RSA,
                       m, mlen, e, elen);
      if (err)
        return err;

      send_fpr_if_not_null (ctrl, "KEY-FPR", -1, fprbuf);
    }

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


/* Determine KDF hash algorithm and KEK encryption algorithm by CURVE.  */
static const unsigned char*
ecdh_params (const char *curve)
{
  unsigned int nbits;

  openpgp_curve_to_oid (curve, &nbits, NULL);

  /* See RFC-6637 for those constants.
         0x03: Number of bytes
         0x01: Version for this parameter format
         KEK digest algorithm
         KEK cipher algorithm

     Take care: They should match the parameters as used in g10/ecdh.c
     as long as the ecdh-param is not fully support (as in gnupg 2.2).
  */
  if (nbits <= 256)
    return (const unsigned char*)"\x03\x01\x08\x07";
  else if (nbits <= 384)
    return (const unsigned char*)"\x03\x01\x09\x08";  /* gnupg 2.2 only */
  else
    return (const unsigned char*)"\x03\x01\x0a\x09";
}

static gpg_error_t
ecc_read_pubkey (app_t app, ctrl_t ctrl, int meta_update,
                 u32 created_at, int keyno,
                 const unsigned char *data, size_t datalen, gcry_sexp_t *r_sexp)
{
  gpg_error_t err;
  unsigned char *qbuf = NULL;
  const unsigned char *ecc_q;
  size_t ecc_q_len;
  gcry_mpi_t oid = NULL;
  int n;
  const char *curve;
  const char *oidstr;
  const unsigned char *oidbuf;
  size_t oid_len;
  int algo;
  const char *format;

  ecc_q = find_tlv (data, datalen, 0x0086, &ecc_q_len);
  if (!ecc_q)
    {
      log_error (_("response does not contain the EC public key\n"));
      return gpg_error (GPG_ERR_CARD);
    }

  curve = app->app_local->keyattr[keyno].ecc.curve;
  oidstr = openpgp_curve_to_oid (curve, NULL, NULL);
  err = openpgp_oid_from_str (oidstr, &oid);
  if (err)
    return err;
  oidbuf = gcry_mpi_get_opaque (oid, &n);
  if (!oidbuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  oid_len = (n+7)/8;

  qbuf = xtrymalloc (ecc_q_len + 1);
  if (!qbuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if ((app->app_local->keyattr[keyno].ecc.flags & ECC_FLAG_DJB_TWEAK))
    {               /* Prepend 0x40 prefix.  */
      *qbuf = 0x40;
      memcpy (qbuf+1, ecc_q, ecc_q_len);
      ecc_q_len++;
    }
  else
    memcpy (qbuf, ecc_q, ecc_q_len);

  if (ctrl)
    {
      send_key_data (ctrl, "q", qbuf, ecc_q_len);
      send_key_data (ctrl, "curve", oidbuf, oid_len);
    }

  algo = app->app_local->keyattr[keyno].ecc.algo;
  if (keyno == 1)
    {
      if (ctrl)
        send_key_data (ctrl, "kdf/kek", ecdh_params (curve), (size_t)4);
    }

  if (ctrl)
    {
      unsigned char fprbuf[20];

      /* If META_UPDATE is not set we only compute but not store the
       * fingerprint.  This might return a wrong fingerprint if
       * CREATED_AT is not set or the ECDH params do not match the
       * current defaults. */
      err = store_fpr (app, meta_update, keyno,
                       created_at, fprbuf, algo, oidbuf, oid_len,
                       qbuf, ecc_q_len, ecdh_params (curve), (size_t)4);
      if (err)
        goto leave;

      send_fpr_if_not_null (ctrl, "KEY-FPR", -1, fprbuf);
    }

  if (!(app->app_local->keyattr[keyno].ecc.flags & ECC_FLAG_DJB_TWEAK))
    format = "(public-key(ecc(curve%s)(q%b)))";
  else if (keyno == 1)
    format = "(public-key(ecc(curve%s)(flags djb-tweak)(q%b)))";
  else
    format = "(public-key(ecc(curve%s)(flags eddsa)(q%b)))";

  err = gcry_sexp_build (r_sexp, NULL, format,
                         app->app_local->keyattr[keyno].ecc.curve,
                         (int)ecc_q_len, qbuf);
 leave:
  gcry_mpi_release (oid);
  xfree (qbuf);
  return err;
}


static gpg_error_t
store_keygrip (app_t app, int keyno)
{
  gpg_error_t err;
  unsigned char grip[20];

  err = keygrip_from_canon_sexp (app->app_local->pk[keyno].key,
                                 app->app_local->pk[keyno].keylen,
                                 grip);
  if (err)
    return err;

  bin2hex (grip, 20, app->app_local->pk[keyno].keygrip_str);
  return 0;
}


/* Parse tag-length-value data for public key in BUFFER of BUFLEN
 * length.  Key of KEYNO in APP is updated with an S-expression of
 * public key.  If CTRL is not NULL, the fingerprint is computed with
 * CREATED_AT and key data and fingerprint are send back to the client
 * side.  If also META_UPDATE is true the fingerprint and the creation
 * date are also written to the card.
 */
static gpg_error_t
read_public_key (app_t app, ctrl_t ctrl, int meta_update,
                 u32 created_at, int keyno,
                 const unsigned char *buffer, size_t buflen)
{
  gpg_error_t err;
  const unsigned char *data;
  size_t datalen;
  gcry_sexp_t s_pkey = NULL;

  data = find_tlv (buffer, buflen, 0x7F49, &datalen);
  if (!data)
    {
      log_error (_("response does not contain the public key data\n"));
      return gpg_error (GPG_ERR_CARD);
    }

  if (app->app_local->keyattr[keyno].key_type == KEY_TYPE_RSA)
    err = rsa_read_pubkey (app, ctrl, meta_update, created_at, keyno,
                           data, datalen, &s_pkey);
  else if (app->app_local->keyattr[keyno].key_type == KEY_TYPE_ECC)
    err = ecc_read_pubkey (app, ctrl, meta_update, created_at, keyno,
                           data, datalen, &s_pkey);
  else
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  if (!err)
    {
      unsigned char *keybuf;
      size_t len;

      len = gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, NULL, 0);
      keybuf = xtrymalloc (len);
      if (!keybuf)
        {
          err = gpg_error_from_syserror ();
          gcry_sexp_release (s_pkey);
          return err;
        }

      gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, keybuf, len);
      gcry_sexp_release (s_pkey);

      app->app_local->pk[keyno].key = keybuf;
      /* Decrement for trailing '\0' */
      app->app_local->pk[keyno].keylen = len - 1;

      err = store_keygrip (app, keyno);
    }

  return err;
}


/* Get the public key for KEYNO and store it as an S-expression with
   the APP handle.  On error that field gets cleared.  If we already
   know about the public key we will just return.  Note that this does
   not mean a key is available; this is solely indicated by the
   presence of the app->app_local->pk[KEYNO].key field.

   Note that GnuPG 1.x does not need this and it would be too time
   consuming to send it just for the fun of it. However, given that we
   use the same code in gpg 1.4, we can't use the gcry S-expression
   here but need to open encode it. */
static gpg_error_t
get_public_key (app_t app, int keyno)
{
  gpg_error_t err = 0;
  unsigned char *buffer;
  const unsigned char *m, *e;
  size_t buflen;
  size_t mlen = 0;
  size_t elen = 0;
  char *keybuf = NULL;
  gcry_sexp_t s_pkey;
  size_t len;

  if (keyno < 0 || keyno > 2)
    return gpg_error (GPG_ERR_INV_ID);

  /* Already cached? */
  if (app->app_local->pk[keyno].read_done)
    return 0;

  xfree (app->app_local->pk[keyno].key);
  app->app_local->pk[keyno].key = NULL;
  app->app_local->pk[keyno].keylen = 0;

  m = e = NULL; /* (avoid cc warning) */

  if (app->appversion > 0x0100)
    {
      int exmode, le_value;

      /* We may simply read the public key out of these cards.  */
      if (app->app_local->cardcap.ext_lc_le
          && app->app_local->keyattr[keyno].key_type == KEY_TYPE_RSA
          && app->app_local->keyattr[keyno].rsa.n_bits > RSA_SMALL_SIZE_KEY)
        {
          exmode = 1;    /* Use extended length.  */
          le_value = determine_rsa_response (app, keyno);
        }
      else
        {
          exmode = 0;
          le_value = 256; /* Use legacy value. */
        }

      err = iso7816_read_public_key (app_get_slot (app), exmode,
                                     (keyno == 0? "\xB6" :
                                      keyno == 1? "\xB8" : "\xA4"),
                                     2, le_value, &buffer, &buflen);
      if (err)
        {
          /* Yubikey returns wrong code.  Fix it up.  */
          if (APP_CARD(app)->cardtype == CARDTYPE_YUBIKEY)
            err = gpg_error (GPG_ERR_NO_OBJ);
	  /* Yubikey NEO (!CARDTYPE_YUBIKEY) also returns wrong code.
           * Fix it up.  */
	  else if (gpg_err_code (err) == GPG_ERR_CARD)
            err = gpg_error (GPG_ERR_NO_OBJ);
          log_error (_("reading public key failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      /* Note that we use 0 for the creation date and thus the - via
       * status lines - returned fingerprint will only be valid if the
       * key has also been created with that date.  A similar problem
       * occurs with the ECDH params which are fixed in the code.  */
      err = read_public_key (app, NULL, 0, 0U, keyno, buffer, buflen);
    }
  else
    {
      /* Due to a design problem in v1.0 cards we can't get the public
         key out of these cards without doing a verify on CHV3.
         Clearly that is not an option and thus we try to locate the
         key using an external helper.

         The helper we use here is gpg itself, which should know about
         the key in any case.  */

      char fpr[41];
      char *hexkeyid;
      char *command = NULL;
      FILE *fp;
      int ret;

      buffer = NULL; /* We don't need buffer.  */

      err = retrieve_fpr_from_card (app, keyno, fpr);
      if (err)
        {
          log_error ("error while retrieving fpr from card: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      hexkeyid = fpr + 24;

      ret = gpgrt_asprintf
        (&command, "%s --list-keys --with-colons --with-key-data '%s'",
         gnupg_module_name (GNUPG_MODULE_NAME_GPG), fpr);
      if (ret < 0)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      fp = popen (command, "r");
      xfree (command);
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          log_error ("running gpg failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      err = retrieve_key_material (fp, hexkeyid, &m, &mlen, &e, &elen);
      pclose (fp);
      if (err)
        {
          log_error ("error while retrieving key material through pipe: %s\n",
                     gpg_strerror (err));
          goto leave;
        }

      err = gcry_sexp_build (&s_pkey, NULL, "(public-key(rsa(n%b)(e%b)))",
                             (int)mlen, m, (int)elen, e);
      if (err)
        goto leave;

      len = gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, NULL, 0);

      keybuf = xtrymalloc (len);
      if (!keybuf)
        {
          err = gpg_error_from_syserror ();
          gcry_sexp_release (s_pkey);
          goto leave;
        }

      gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, keybuf, len);
      gcry_sexp_release (s_pkey);

      app->app_local->pk[keyno].key = (unsigned char*)keybuf;
      /* Decrement for trailing '\0' */
      app->app_local->pk[keyno].keylen = len - 1;
      err = store_keygrip (app, keyno);
    }

 leave:
  /* Set a flag to indicate that we tried to read the key.  */
  if (!err)
    app->app_local->pk[keyno].read_done = 1;

  xfree (buffer);
  return err;
}


static const char *
get_usage_string (int keyno)
{
  const char *usage;
  switch (keyno)
    {
    case 0: usage = "sc"; break;
    case 1: usage = "e";  break;
    case 2: usage = "sa"; break;
    default: usage = "-";  break;
    }
  return usage;
}


/* Send the KEYPAIRINFO back. KEY needs to be in the range [1,3].
   This is used by the LEARN command. */
static gpg_error_t
send_keypair_info (app_t app, ctrl_t ctrl, int key)
{
  int keyno = key - 1;
  gpg_error_t err = 0;
  const char *usage;
  u32 fprtime;
  char *algostr = NULL;

  err = get_public_key (app, keyno);
  if (err)
    goto leave;

  log_assert (keyno >= 0 && keyno <= 2);
  if (!app->app_local->pk[keyno].key)
    goto leave; /* No such key - ignore. */

  usage = get_usage_string (keyno);

  if (retrieve_fprtime_from_card (app, keyno, &fprtime))
    fprtime = 0;

  {
    gcry_sexp_t s_pkey;
    if (gcry_sexp_new (&s_pkey, app->app_local->pk[keyno].key,
                       app->app_local->pk[keyno].keylen, 0))
      algostr = xtrystrdup ("?");
    else
      {
        algostr = pubkey_algo_string (s_pkey, NULL);
        gcry_sexp_release (s_pkey);
      }
  }
  if (!algostr)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = send_status_printf (ctrl, "KEYPAIRINFO", "%s OPENPGP.%d %s %lu %s",
                            app->app_local->pk[keyno].keygrip_str,
                            keyno+1, usage, (unsigned long)fprtime, algostr);

 leave:
  xfree (algostr);
  return err;
}


/* Handle the LEARN command for OpenPGP.  */
static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err = 0;

  (void)flags;

  err = do_getattr (app, ctrl, "EXTCAP");
  if (!err)
    err = do_getattr (app, ctrl, "MANUFACTURER");
  if (!err)
    err = do_getattr (app, ctrl, "DISP-NAME");
  if (!err)
    err = do_getattr (app, ctrl, "DISP-LANG");
  if (!err)
    err = do_getattr (app, ctrl, "DISP-SEX");
  if (!err)
    err = do_getattr (app, ctrl, "PUBKEY-URL");
  if (!err)
    err = do_getattr (app, ctrl, "LOGIN-DATA");
  if (!err)
    err = do_getattr (app, ctrl, "KEY-FPR");
  if (!err && app->appversion > 0x0100)
    err = do_getattr (app, ctrl, "KEY-TIME");
  if (!err)
    err = do_getattr (app, ctrl, "CA-FPR");
  if (!err)
    err = do_getattr (app, ctrl, "CHV-STATUS");
  if (!err)
    err = do_getattr (app, ctrl, "SIG-COUNTER");
  if (!err && app->app_local->extcap.kdf_do)
    {
      err = do_getattr (app, ctrl, "KDF");
      if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
        err = 0;
    }
  if (!err && app->app_local->extcap.has_button)
    err = do_getattr (app, ctrl, "UIF");
  if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
    err = 0;
  if (!err && app->app_local->extcap.private_dos)
    {
      if (!err)
        err = do_getattr (app, ctrl, "PRIVATE-DO-1");
      if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
        err = 0;
      if (!err)
        err = do_getattr (app, ctrl, "PRIVATE-DO-2");
      if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
        err = 0;
      if (!err && app->did_chv2)
        err = do_getattr (app, ctrl, "PRIVATE-DO-3");
      if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
        err = 0;
      if (!err && app->did_chv3)
        err = do_getattr (app, ctrl, "PRIVATE-DO-4");
      if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
        err = 0;
    }
  if (!err)
    err = send_keypair_info (app, ctrl, 1);
  if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
    err = 0;
  if (!err)
    err = send_keypair_info (app, ctrl, 2);
  if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
    err = 0;
  if (!err)
    err = send_keypair_info (app, ctrl, 3);
  if (gpg_err_code (err) == GPG_ERR_NO_OBJ)
    err = 0;
  /* Note: We do not send the Cardholder Certificate, because that is
     relatively long and for OpenPGP applications not really needed.  */
  return err;
}


/* Handle the READKEY command for OpenPGP.  On success a canonical
   encoded S-expression with the public key will get stored at PK and
   its length (for assertions) at PKLEN; the caller must release that
   buffer. On error PK and PKLEN are not changed and an error code is
   returned.  */
static gpg_error_t
do_readkey (app_t app, ctrl_t ctrl, const char *keyid, unsigned int flags,
            unsigned char **pk, size_t *pklen)
{
  gpg_error_t err;
  int keyno;
  unsigned char *buf;

  (void)ctrl;

  if (strlen (keyid) == 40)
    {
      const unsigned char *keygrip_str;

      for (keyno = 0; keyno < 3; keyno++)
        {
          keygrip_str = app->app_local->pk[keyno].keygrip_str;
          if (!strncmp (keygrip_str, keyid, 40))
            break;
        }

      if (keyno >= 3)
        return gpg_error (GPG_ERR_INV_ID);
    }
  else if (!ascii_strcasecmp (keyid, "OPENPGP.1"))
    keyno = 0;
  else if (!ascii_strcasecmp (keyid, "OPENPGP.2"))
    keyno = 1;
  else if (!ascii_strcasecmp (keyid, "OPENPGP.3"))
    keyno = 2;
  else
    return gpg_error (GPG_ERR_INV_ID);

  err = get_public_key (app, keyno);
  if (err)
    return err;

  buf = app->app_local->pk[keyno].key;
  if (!buf)
    return gpg_error (GPG_ERR_NO_PUBKEY);

  if ((flags & APP_READKEY_FLAG_ADVANCED))
    {
      gcry_sexp_t s_key;

      err = gcry_sexp_new (&s_key, buf, app->app_local->pk[keyno].keylen, 0);
      if (err)
        return err;

      *pklen = gcry_sexp_sprint (s_key, GCRYSEXP_FMT_ADVANCED, NULL, 0);
      *pk = xtrymalloc (*pklen);
      if (!*pk)
        {
          err = gpg_error_from_syserror ();
          *pklen = 0;
          return err;
        }

      gcry_sexp_sprint (s_key, GCRYSEXP_FMT_ADVANCED, *pk, *pklen);
      gcry_sexp_release (s_key);
      /* Decrement for trailing '\0' */
      *pklen = *pklen - 1;
    }
  else
    {
      *pklen = app->app_local->pk[keyno].keylen;
      *pk = xtrymalloc (*pklen);
      if (!*pk)
        {
          err = gpg_error_from_syserror ();
          *pklen = 0;
          return err;
        }
      memcpy (*pk, buf, *pklen);
    }

  return 0;
}

/* Read the standard certificate of an OpenPGP v2 card.  It is
   returned in a freshly allocated buffer with that address stored at
   CERT and the length of the certificate stored at CERTLEN.  */
static gpg_error_t
do_readcert (app_t app, const char *certid,
             unsigned char **cert, size_t *certlen)
{
  gpg_error_t err;
  int occurrence = 0;

  *cert = NULL;
  *certlen = 0;
  if (strlen (certid) == 40)
    {
      int keyno;
      const unsigned char *keygrip_str;

      for (keyno = 0; keyno < 3; keyno++)
        {
          keygrip_str = app->app_local->pk[keyno].keygrip_str;
          if (!strncmp (keygrip_str, certid, 40))
            break;
        }

      if (keyno == 2)
        ;
      else if (keyno == 1)
        occurrence = 1;
      else if (keyno == 0)
        occurrence = 2;
      else
        return gpg_error (GPG_ERR_INV_ID);
    }
  else if (!ascii_strcasecmp (certid, "OPENPGP.3"))
    ;
  else if (!ascii_strcasecmp (certid, "OPENPGP.2"))
    occurrence = 1;
  else if (!ascii_strcasecmp (certid, "OPENPGP.1"))
    occurrence = 2;
  else
    return gpg_error (GPG_ERR_INV_ID);
  if (!app->app_local->extcap.is_v3 && occurrence)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);
  if (!app->app_local->extcap.is_v2)
    return gpg_error (GPG_ERR_NOT_FOUND);

  if (occurrence)
    {
      int exmode;

      err = iso7816_select_data (app_get_slot (app), occurrence, 0x7F21);
      if (!err)
        {
          if (app->app_local->cardcap.ext_lc_le)
            exmode = app->app_local->extcap.max_certlen;
          else
            exmode = 0;

          err = iso7816_get_data (app_get_slot (app), exmode, 0x7F21,
                                  cert, certlen);
          /* We reset the curDO even for an error.  */
          iso7816_select_data (app_get_slot (app), 0, 0x7F21);
        }

      if (err)
        err = gpg_error (GPG_ERR_NOT_FOUND);
    }
  else
    {
      unsigned char *buffer;
      size_t buflen;
      void *relptr;

      relptr = get_one_do (app, 0x7F21, &buffer, &buflen, NULL);
      if (!relptr)
        return gpg_error (GPG_ERR_NOT_FOUND);

      if (!buflen)
        err = gpg_error (GPG_ERR_NOT_FOUND);
      else if (!(*cert = xtrymalloc (buflen)))
        err = gpg_error_from_syserror ();
      else
        {
          memcpy (*cert, buffer, buflen);
          *certlen = buflen;
          err = 0;
        }
      xfree (relptr);
    }

  return err;
}


/* Decide if we use the pinpad of the reader for PIN input according
   to the user preference on the card, and the capability of the
   reader.  This routine is only called when the reader has pinpad.
   Returns 0 if we use pinpad, 1 otherwise.  */
static int
check_pinpad_request (app_t app, pininfo_t *pininfo, int admin_pin)
{
  if (app->app_local->pinpad.disabled)
    return 1;

  if (app->app_local->pinpad.specified == 0) /* No preference on card.  */
    {
      if (pininfo->fixedlen == 0) /* Reader has varlen capability.  */
        return 0;                 /* Then, use pinpad.  */
      else
        /*
         * Reader has limited capability, and it may not match PIN of
         * the card.
         */
        return 1;
    }

  if (admin_pin)
    pininfo->fixedlen = app->app_local->pinpad.fixedlen_admin;
  else
    pininfo->fixedlen = app->app_local->pinpad.fixedlen_user;

  if (pininfo->fixedlen == 0    /* User requests disable pinpad.  */
      || pininfo->fixedlen < pininfo->minlen
      || pininfo->fixedlen > pininfo->maxlen
      /* Reader doesn't have the capability to input a PIN which
       * length is FIXEDLEN.  */)
    return 1;

  return 0;
}


/* Return a string with information about the card for use in a
 * prompt.  Returns NULL on memory failure.  */
static char *
get_prompt_info (app_t app, int chvno, unsigned long sigcount, int remaining)
{
  char *serial, *disp_name, *rembuf, *tmpbuf, *result;

  serial = app_get_dispserialno (app, 0);
  if (!serial)
    return NULL;

  disp_name = get_disp_name (app);
  if (chvno == 1)
    {
      /* TRANSLATORS: Put a \x1f right before a colon.  This can be
       * used by pinentry to nicely align the names and values.  Keep
       * the %s at the start and end of the string.  */
      result = xtryasprintf (_("%s"
                               "Number\x1f: %s%%0A"
                               "Holder\x1f: %s%%0A"
                               "Counter\x1f: %lu"
                               "%s"),
                             "\x1e",
                             serial,
                             disp_name? disp_name:"",
                             sigcount,
                             "");
    }
  else
    {
      result = xtryasprintf (_("%s"
                               "Number\x1f: %s%%0A"
                               "Holder\x1f: %s"
                               "%s"),
                             "\x1e",
                             serial,
                             disp_name? disp_name:"",
                             "");
    }
  xfree (disp_name);
  xfree (serial);

  if (remaining != -1)
    {
      /* TRANSLATORS: This is the number of remaining attempts to
       * enter a PIN.  Use %%0A (double-percent,0A) for a linefeed. */
      rembuf = xtryasprintf (_("Remaining attempts: %d"), remaining);
      if (!rembuf)
        {
          xfree (result);
          return NULL;
        }
      tmpbuf = strconcat (result, "%0A%0A", rembuf, NULL);
      xfree (rembuf);
      if (!tmpbuf)
        {
          xfree (result);
          return NULL;
        }
      xfree (result);
      result = tmpbuf;
    }

  return result;
}


/* Compute hash if KDF-DO is available.  CHVNO must be 0 for reset
 * code, 1 or 2 for user pin and 3 for admin pin.  PIN is the original
 * PIN as entered by the user.  R_PINVALUE and r_PINLEN will receive a
 * newly allocated buffer with a possible modified pin.  */
static gpg_error_t
pin2hash_if_kdf (app_t app, int chvno, const char *pin,
                 char **r_pinvalue, size_t *r_pinlen)
{
  gpg_error_t err = 0;
  void *relptr = NULL;
  unsigned char *buffer;
  size_t pinlen, buflen;
  char *dek = NULL;
  size_t deklen = 32;

  *r_pinvalue = NULL;
  *r_pinlen = 0;

  pinlen = strlen (pin);
  if (app->app_local->extcap.kdf_do
      && (relptr = get_one_do (app, 0x00F9, &buffer, &buflen, NULL))
      && buflen >= KDF_DATA_LENGTH_MIN && (buffer[2] == 0x03))
    {
      const char *salt;
      unsigned long s2k_count;
      int salt_index;

      dek = xtrymalloc (deklen);
      if (!dek)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      s2k_count = (((unsigned int)buffer[8] << 24)
                   | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11]);

      if (buflen == KDF_DATA_LENGTH_MIN)
        salt_index =14;
      else if (buflen == KDF_DATA_LENGTH_MAX)
        salt_index = (chvno==3 ? 34 : (chvno==0 ? 24 : 14));
      else
        {
          err = gpg_error (GPG_ERR_INV_DATA);
          goto leave;
        }

      salt = &buffer[salt_index];
      err = gcry_kdf_derive (pin, pinlen,
                             GCRY_KDF_ITERSALTED_S2K,
                             DIGEST_ALGO_SHA256, salt, 8,
                             s2k_count, deklen, dek);
      if (!err)
        {
          *r_pinlen = deklen;
          *r_pinvalue = dek;
          dek = NULL;
        }
   }
  else
    {
      /* Just copy the PIN to a malloced buffer.  */
      *r_pinvalue = xtrymalloc_secure (pinlen + 1);
      if (!*r_pinvalue)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      strcpy (*r_pinvalue, pin);
      *r_pinlen = pinlen;
    }

 leave:
  xfree (relptr);
  return err;
}


/* Verify a CHV either using the pinentry or if possible by
   using a pinpad.  PINCB and PINCB_ARG describe the usual callback
   for the pinentry.  CHVNO must be either 1 or 2. SIGCOUNT is only
   used with CHV1.  PINVALUE is the address of a pointer which will
   receive a newly allocated block with the actual PIN (this is useful
   in case that PIN shall be used for another verify operation).  The
   caller needs to free this value.  If the function returns with
   success and NULL is stored at PINVALUE, the caller should take this
   as an indication that the pinpad has been used.
   */
static gpg_error_t
verify_a_chv (app_t app, ctrl_t ctrl,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg, int chvno, unsigned long sigcount,
              char **r_pinvalue, size_t *r_pinlen)
{
  int rc = 0;
  char *prompt_buffer = NULL;
  const char *prompt;
  pininfo_t pininfo;
  int minlen = 6;
  int remaining;
  char *pin = NULL;

  (void)ctrl;  /* Reserved for use by a PIN cache.  */

  log_assert (chvno == 1 || chvno == 2);

  *r_pinvalue = NULL;
  *r_pinlen = 0;

  remaining = get_remaining_tries (app, 0);
  if (remaining == -1)
    return gpg_error (GPG_ERR_CARD);

  if (chvno == 2 && app->app_local->flags.def_chv2)
    {
      /* Special case for def_chv2 mechanism. */
      if (opt.verbose)
        log_info (_("using default PIN as %s\n"), "CHV2");
      rc = iso7816_verify (app_get_slot (app), 0x82, "123456", 6);
      if (rc)
        {
          /* Verification of CHV2 with the default PIN failed,
             although the card pretends to have the default PIN set as
             CHV2.  We better disable the def_chv2 flag now. */
          log_info (_("failed to use default PIN as %s: %s"
                      " - disabling further default use\n"),
                    "CHV2", gpg_strerror (rc));
          app->app_local->flags.def_chv2 = 0;
        }
      return rc;
    }

  memset (&pininfo, 0, sizeof pininfo);
  pininfo.fixedlen = -1;
  pininfo.minlen = minlen;

  {
    const char *firstline = _("||Please unlock the card");
    char *infoblock = get_prompt_info (app, chvno, sigcount,
                                       remaining < 3? remaining : -1);

    prompt_buffer = strconcat (firstline, "%0A%0A", infoblock, NULL);
    if (prompt_buffer)
      prompt = prompt_buffer;
    else
      prompt = firstline;  /* ENOMEM fallback.  */

    xfree (infoblock);
  }

  if (!opt.disable_pinpad
      && !iso7816_check_pinpad (app_get_slot (app), ISO7816_VERIFY, &pininfo)
      && !check_pinpad_request (app, &pininfo, 0))
    {
      /* The reader supports the verify command through the pinpad.
         Note that the pincb appends a text to the prompt telling the
         user to use the pinpad. */
      rc = pincb (pincb_arg, prompt, NULL);
      prompt = NULL;
      xfree (prompt_buffer);
      prompt_buffer = NULL;
      if (rc)
        {
          log_info (_("PIN callback returned error: %s\n"),
                    gpg_strerror (rc));
          return rc;
        }
      rc = iso7816_verify_kp (app_get_slot (app), 0x80+chvno, &pininfo);
      /* Dismiss the prompt. */
      pincb (pincb_arg, NULL, NULL);
    }
  else
    {
      /* The reader has no pinpad or we don't want to use it. */
      rc = pincb (pincb_arg, prompt, &pin);
      prompt = NULL;
      xfree (prompt_buffer);
      prompt_buffer = NULL;
      if (rc)
        {
          log_info (_("PIN callback returned error: %s\n"),
                    gpg_strerror (rc));
          return rc;
        }

      if (strlen (pin) < minlen)
        {
          log_error (_("PIN for CHV%d is too short;"
                       " minimum length is %d\n"), chvno, minlen);
          wipe_and_free_string (pin);
          return gpg_error (GPG_ERR_BAD_PIN);
        }

      rc = pin2hash_if_kdf (app, chvno, pin, r_pinvalue, r_pinlen);
      if (!rc)
        rc = iso7816_verify (app_get_slot (app),
                             0x80 + chvno, *r_pinvalue, *r_pinlen);
    }

  wipe_and_free_string (pin);
  if (rc)
    {
      log_error (_("verify CHV%d failed: %s\n"), chvno, gpg_strerror (rc));
      xfree (*r_pinvalue);
      *r_pinvalue = NULL;
      *r_pinlen = 0;
      flush_cache_after_error (app);
    }

  return rc;
}


/* Verify CHV2 if required.  Depending on the configuration of the
   card CHV1 will also be verified. */
static gpg_error_t
verify_chv2 (app_t app, ctrl_t ctrl,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg)
{
  int rc;
  char *pinvalue;
  size_t pinlen;
  int i;

  if (app->did_chv2)
    return 0;  /* We already verified CHV2.  */

  /* Make sure we have load the public keys.  */
  for (i = 0; i < 3; i++)
    get_public_key (app, i);

  if (app->app_local->pk[1].key || app->app_local->pk[2].key)
    {
      rc = verify_a_chv (app, ctrl, pincb, pincb_arg, 2, 0, &pinvalue, &pinlen);
      if (rc)
        return rc;
      app->did_chv2 = 1;

      if (!app->did_chv1 && !app->force_chv1 && pinvalue && !opt.pcsc_shared)
        {
          /* For convenience we verify CHV1 here too.  We do this only if
             the card is not configured to require a verification before
             each CHV1 controlled operation (force_chv1) and if we are not
             using the pinpad (PINVALUE == NULL). */
          rc = iso7816_verify (app->slot, 0x81, pinvalue, pinlen);
          if (gpg_err_code (rc) == GPG_ERR_BAD_PIN)
            rc = gpg_error (GPG_ERR_PIN_NOT_SYNCED);
          if (rc)
            {
              log_error (_("verify CHV%d failed: %s\n"), 1, gpg_strerror (rc));
              flush_cache_after_error (app);
            }
          else
            {
              app->did_chv1 = 1;
              /* Note that we are not able to cache the CHV 1 here because
               * it is possible that due to the use of a KDF-DO PINVALUE
               * has the hashed binary PIN of length PINLEN.  */
            }
        }
    }
  else
    {
      rc = verify_a_chv (app, ctrl, pincb, pincb_arg, 1, 0, &pinvalue, &pinlen);
      if (rc)
        return rc;
    }

  wipe_and_free (pinvalue, pinlen);

  return rc;
}


/* Build the prompt to enter the Admin PIN.  The prompt depends on the
   current state of the card.  */
static gpg_error_t
build_enter_admin_pin_prompt (app_t app, char **r_prompt)
{
  int remaining;
  char *prompt;
  char *infoblock;

  *r_prompt = NULL;

  remaining = get_remaining_tries (app, 1);
  if (remaining == -1)
    return gpg_error (GPG_ERR_CARD);
  if (!remaining)
    {
      log_info (_("card is permanently locked!\n"));
      return gpg_error (GPG_ERR_BAD_PIN);
    }

  log_info (ngettext("%d Admin PIN attempt remaining before card"
                     " is permanently locked\n",
                     "%d Admin PIN attempts remaining before card"
                     " is permanently locked\n",
                     remaining), remaining);

  infoblock = get_prompt_info (app, 3, 0, remaining < 3? remaining : -1);

  /* TRANSLATORS: Do not translate the "|A|" prefix but keep it at
     the start of the string.  Use %0A (single percent) for a linefeed.  */
  prompt = strconcat (_("|A|Please enter the Admin PIN"),
                      "%0A%0A", infoblock, NULL);
  xfree (infoblock);
  if (!prompt)
    return gpg_error_from_syserror ();

  *r_prompt = prompt;
  return 0;
}


/* Verify CHV3 if required. */
static gpg_error_t
verify_chv3 (app_t app, ctrl_t ctrl,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg)
{
  int rc = 0;

  (void)ctrl;  /* Reserved for use by a PIN cache.  */

  if (!opt.allow_admin)
    {
      log_info (_("access to admin commands is not configured\n"));
      return gpg_error (GPG_ERR_EACCES);
    }

  if (!app->did_chv3)
    {
      pininfo_t pininfo;
      int minlen = 8;
      char *prompt;

      memset (&pininfo, 0, sizeof pininfo);
      pininfo.fixedlen = -1;
      pininfo.minlen = minlen;

      rc = build_enter_admin_pin_prompt (app, &prompt);
      if (rc)
        return rc;

      if (!opt.disable_pinpad
          && !iso7816_check_pinpad (app_get_slot (app),
                                    ISO7816_VERIFY, &pininfo)
          && !check_pinpad_request (app, &pininfo, 1))
        {
          /* The reader supports the verify command through the pinpad. */
          rc = pincb (pincb_arg, prompt, NULL);
          xfree (prompt);
          prompt = NULL;
          if (rc)
            {
              log_info (_("PIN callback returned error: %s\n"),
                        gpg_strerror (rc));
              return rc;
            }
          rc = iso7816_verify_kp (app_get_slot (app), 0x83, &pininfo);
          /* Dismiss the prompt. */
          pincb (pincb_arg, NULL, NULL);
        }
      else
        {
          char *pin;
          char *pinvalue;
          size_t pinlen;

          rc = pincb (pincb_arg, prompt, &pin);
          xfree (prompt);
          prompt = NULL;
          if (rc)
            {
              log_info (_("PIN callback returned error: %s\n"),
                        gpg_strerror (rc));
              return rc;
            }

          if (strlen (pin) < minlen)
            {
              log_error (_("PIN for CHV%d is too short;"
                           " minimum length is %d\n"), 3, minlen);
              wipe_and_free_string (pin);
              return gpg_error (GPG_ERR_BAD_PIN);
            }

          rc = pin2hash_if_kdf (app, 3, pin, &pinvalue, &pinlen);
          if (!rc)
            rc = iso7816_verify (app_get_slot (app), 0x83, pinvalue, pinlen);
          wipe_and_free_string (pin);
          wipe_and_free (pinvalue, pinlen);
        }

      if (rc)
        {
          log_error (_("verify CHV%d failed: %s\n"), 3, gpg_strerror (rc));
          flush_cache_after_error (app);
          return rc;
        }
      app->did_chv3 = 1;
    }
  return rc;
}


/* Handle the SETATTR operation. All arguments are already basically
   checked. */
static gpg_error_t
do_setattr (app_t app, ctrl_t ctrl, const char *name,
            gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg,
            const unsigned char *value, size_t valuelen)
{
  gpg_error_t rc;
  int idx;
  static struct {
    const char *name;
    int tag;
    int flush_tag;  /* The tag which needs to be flushed or 0. */
    int need_chv;
    int special;
    unsigned int need_v2:1;
    unsigned int need_v3:1;
  } table[] = {
    { "DISP-NAME",    0x005B, 0,      3 },
    { "LOGIN-DATA",   0x005E, 0,      3, 2 },
    { "DISP-LANG",    0x5F2D, 0,      3 },
    { "DISP-SEX",     0x5F35, 0,      3 },
    { "PUBKEY-URL",   0x5F50, 0,      3 },
    { "CHV-STATUS-1", 0x00C4, 0,      3, 1 },
    { "CA-FPR-1",     0x00CA, 0x00C6, 3 },
    { "CA-FPR-2",     0x00CB, 0x00C6, 3 },
    { "CA-FPR-3",     0x00CC, 0x00C6, 3 },
    { "PRIVATE-DO-1", 0x0101, 0,      2 },
    { "PRIVATE-DO-2", 0x0102, 0,      3 },
    { "PRIVATE-DO-3", 0x0103, 0,      2 },
    { "PRIVATE-DO-4", 0x0104, 0,      3 },
    { "CERT-1",       0x7F21, 0,      3,11, 1, 1 },
    { "CERT-2",       0x7F21, 0,      3,12, 1, 1 },
    { "CERT-3",       0x7F21, 0,      3, 0, 1 },
    { "SM-KEY-ENC",   0x00D1, 0,      3, 0, 1 },
    { "SM-KEY-MAC",   0x00D2, 0,      3, 0, 1 },
    { "KEY-ATTR",     0,      0,      0, 3, 1 },
    { "AESKEY",       0x00D5, 0,      3, 0, 1 },
    { "UIF-1",        0x00D6, 0,      3, 5, 1 },
    { "UIF-2",        0x00D7, 0,      3, 5, 1 },
    { "UIF-3",        0x00D8, 0,      3, 5, 1 },
    { "KDF",          0x00F9, 0,      3, 4, 1 },
    { NULL, 0 }
  };
  int exmode;

  for (idx=0; table[idx].name && strcmp (table[idx].name, name); idx++)
    ;
  if (!table[idx].name)
    return gpg_error (GPG_ERR_INV_NAME);
  if (table[idx].need_v2 && !app->app_local->extcap.is_v2)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);
  if (table[idx].need_v3 && !app->app_local->extcap.is_v3)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  if (table[idx].special == 5 && app->app_local->extcap.has_button == 0)
    return gpg_error (GPG_ERR_INV_OBJ);

  if (table[idx].special == 3)
    return change_keyattr_from_string (app, ctrl, pincb, pincb_arg,
                                       NULL, NULL, value, valuelen);

  switch (table[idx].need_chv)
    {
    case 2:
      rc = verify_chv2 (app, ctrl, pincb, pincb_arg);
      break;
    case 3:
      rc = verify_chv3 (app, ctrl, pincb, pincb_arg);
      break;
    default:
      rc = 0;
    }
  if (rc)
    return rc;

  /* Flush the cache before writing it, so that the next get operation
     will reread the data from the card and thus get synced in case of
     errors (e.g. data truncated by the card). */
  flush_cache_item (app, table[idx].flush_tag? table[idx].flush_tag
                    /* */                    : table[idx].tag);

  if (app->app_local->cardcap.ext_lc_le && valuelen > 254)
    exmode = 1;    /* Use extended length w/o a limit.  */
  else if (app->app_local->cardcap.cmd_chaining && valuelen > 254)
    exmode = -254; /* Command chaining with max. 254 bytes.  */
  else
    exmode = 0;

  if (table[idx].special == 11 || table[idx].special == 12) /* CERT-1 or -2 */
    {
      rc = iso7816_select_data (app_get_slot (app),
                                table[idx].special == 11? 2 : 1,
                                table[idx].tag);
      if (!rc)
        {
          rc = iso7816_put_data (app_get_slot (app),
                                 exmode, table[idx].tag, value, valuelen);
          /* We better reset the curDO.  */
          iso7816_select_data (app_get_slot (app), 0, table[idx].tag);
        }
    }
  else  /* Standard.  */
    rc = iso7816_put_data (app_get_slot (app),
                           exmode, table[idx].tag, value, valuelen);

  if (rc)
    log_error ("failed to set '%s': %s\n", table[idx].name, gpg_strerror (rc));

  if (table[idx].special == 1)
    app->force_chv1 = (valuelen && *value == 0);
  else if (table[idx].special == 2)
    parse_login_data (app);
  else if (table[idx].special == 4)
    {
      app->did_chv1 = 0;
      app->did_chv2 = 0;
      app->did_chv3 = 0;

      if ((valuelen == KDF_DATA_LENGTH_MIN || valuelen == KDF_DATA_LENGTH_MAX)
          && (value[2] == 0x03))
        app->app_local->pinpad.disabled = 1;
      else
        app->app_local->pinpad.disabled = 0;
    }

  return rc;
}


/* Handle the WRITECERT command for OpenPGP.  This writes the standard
 * certificate to the card; CERTID needs to be set to "OPENPGP.3".
 * PINCB and PINCB_ARG are the usual arguments for the pinentry
 * callback.  */
static gpg_error_t
do_writecert (app_t app, ctrl_t ctrl,
              const char *certidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const unsigned char *certdata, size_t certdatalen)
{
  const char *name;
  if (!ascii_strcasecmp (certidstr, "OPENPGP.3"))
    name = "CERT-3";
  else if (!ascii_strcasecmp (certidstr, "OPENPGP.2"))
    name = "CERT-2";
  else if (!ascii_strcasecmp (certidstr, "OPENPGP.1"))
    name = "CERT-1";
  else
    return gpg_error (GPG_ERR_INV_ID);

  if (!certdata || !certdatalen)
    return gpg_error (GPG_ERR_INV_ARG);
  if (!app->app_local->extcap.is_v2)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);
  /* do_setattr checks that CERT-2 and CERT-1 requires a v3 card.  */

  if (certdatalen > app->app_local->extcap.max_certlen)
    return gpg_error (GPG_ERR_TOO_LARGE);
  return do_setattr (app, ctrl, name, pincb, pincb_arg,
                     certdata, certdatalen);
}



/* Handle the PASSWD command.  The following combinations are
   possible:

    Flags  CHVNO Vers.  Description
    RESET    1   1      Verify CHV3 and set a new CHV1 and CHV2
    RESET    1   2      Verify PW3 and set a new PW1.
    RESET    2   1      Verify CHV3 and set a new CHV1 and CHV2.
    RESET    2   2      Verify PW3 and set a new Reset Code.
    RESET    3   any    Returns GPG_ERR_INV_ID.
     -       1   1      Verify CHV2 and set a new CHV1 and CHV2.
     -       1   2      Verify PW1 and set a new PW1.
     -       2   1      Verify CHV2 and set a new CHV1 and CHV2.
     -       2   2      Verify Reset Code and set a new PW1.
     -       3   any    Verify CHV3/PW3 and set a new CHV3/PW3.

   The CHVNO can be prefixed with "OPENPGP.".
 */
static gpg_error_t
do_change_pin (app_t app, ctrl_t ctrl,  const char *chvnostr,
               unsigned int flags,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  int rc = 0;
  int chvno;
  char *resetcode = NULL;
  char *oldpinvalue = NULL;
  char *pinvalue = NULL;
  int reset_mode = !!(flags & APP_CHANGE_FLAG_RESET);
  int set_resetcode = 0;
  int use_resetcode = 0;
  pininfo_t pininfo;
  int use_pinpad = 0;
  int minlen = 6;

  if (digitp (chvnostr))
    chvno = atoi (chvnostr);
  else if (!ascii_strcasecmp (chvnostr, "OPENPGP.1"))
    chvno = 1;
  else if (!ascii_strcasecmp (chvnostr, "OPENPGP.2"))
    chvno = 2;
  else if (!ascii_strcasecmp (chvnostr, "OPENPGP.3"))
    chvno = 3;
  else
    return gpg_error (GPG_ERR_INV_ID);

  if (digitp (chvnostr))
    chvno = atoi (chvnostr);
  else if (!ascii_strcasecmp (chvnostr, "OPENPGP.1"))
    chvno = 1;
  else if (!ascii_strcasecmp (chvnostr, "OPENPGP.2"))
    chvno = 2;
  else if (!ascii_strcasecmp (chvnostr, "OPENPGP.3"))
    chvno = 3;
  else
    return gpg_error (GPG_ERR_INV_ID);

  memset (&pininfo, 0, sizeof pininfo);
  pininfo.fixedlen = -1;
  pininfo.minlen = minlen;

  if ((flags & APP_CHANGE_FLAG_CLEAR))
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  if (reset_mode && chvno == 3)
    {
      rc = gpg_error (GPG_ERR_INV_ID);
      goto leave;
    }

  if (!app->app_local->extcap.is_v2)
    {
      /* Version 1 cards.  */

      if (reset_mode || chvno == 3)
        {
          /* We always require that the PIN is entered. */
          app->did_chv3 = 0;
          rc = verify_chv3 (app, ctrl, pincb, pincb_arg);
          if (rc)
            goto leave;
        }
      else if (chvno == 1 || chvno == 2)
        {
          /* On a v1.x card CHV1 and CVH2 should always have the same
             value, thus we enforce it here.  */
          int save_force = app->force_chv1;

          app->force_chv1 = 0;
          app->did_chv1 = 0;
          app->did_chv2 = 0;
          rc = verify_chv2 (app, ctrl, pincb, pincb_arg);
          app->force_chv1 = save_force;
          if (rc)
            goto leave;
        }
      else
        {
          rc = gpg_error (GPG_ERR_INV_ID);
          goto leave;
        }
    }
  else
    {
      /* Version 2 cards.  */

      if (!opt.disable_pinpad
          && !iso7816_check_pinpad (app_get_slot (app),
                                    ISO7816_CHANGE_REFERENCE_DATA, &pininfo)
          && !check_pinpad_request (app, &pininfo, chvno == 3))
        use_pinpad = 1;

      if (reset_mode)
        {
          /* To reset a PIN the Admin PIN is required. */
          use_pinpad = 0;
          app->did_chv3 = 0;
          rc = verify_chv3 (app, ctrl, pincb, pincb_arg);
          if (rc)
            goto leave;

          if (chvno == 2)
            set_resetcode = 1;
        }
      else if (chvno == 1 || chvno == 3)
        {
          if (!use_pinpad)
            {
              char *promptbuf = NULL;
              const char *prompt;

              if (chvno == 3)
                {
                  minlen = 8;
                  rc = build_enter_admin_pin_prompt (app, &promptbuf);
                  if (rc)
                    goto leave;
                  prompt = promptbuf;
                }
              else
                prompt = _("||Please enter the PIN");
              rc = pincb (pincb_arg, prompt, &oldpinvalue);
              xfree (promptbuf);
              promptbuf = NULL;
              if (rc)
                {
                  log_info (_("PIN callback returned error: %s\n"),
                            gpg_strerror (rc));
                  goto leave;
                }

              if (strlen (oldpinvalue) < minlen)
                {
                  log_info (_("PIN for CHV%d is too short;"
                              " minimum length is %d\n"), chvno, minlen);
                  rc = gpg_error (GPG_ERR_BAD_PIN);
                  goto leave;
                }
            }
        }
      else if (chvno == 2)
        {
          /* There is no PW2 for v2 cards.  We use this condition to
             allow a PW reset using the Reset Code.  */
          void *relptr;
          unsigned char *value;
          size_t valuelen;
          int remaining;

          use_pinpad = 0;
          minlen = 8;
          relptr = get_one_do (app, 0x00C4, &value, &valuelen, NULL);
          if (!relptr || valuelen < 7)
            {
              log_error (_("error retrieving CHV status from card\n"));
              xfree (relptr);
              rc = gpg_error (GPG_ERR_CARD);
              goto leave;
            }
          remaining = value[5];
          xfree (relptr);
          if (!remaining)
            {
              log_error (_("Reset Code not or not anymore available\n"));
              rc = gpg_error (GPG_ERR_BAD_PIN);
              goto leave;
            }

          rc = pincb (pincb_arg,
                      _("|R|Please enter the Reset Code for the card"),
                      &resetcode);
          if (rc)
            {
              log_info (_("PIN callback returned error: %s\n"),
                        gpg_strerror (rc));
              goto leave;
            }
          if (strlen (resetcode) < minlen)
            {
              log_info (_("Reset Code is too short; minimum length is %d\n"),
                        minlen);
              rc = gpg_error (GPG_ERR_BAD_PIN);
              goto leave;
            }
          use_resetcode = 1;
        }
      else
        {
          rc = gpg_error (GPG_ERR_INV_ID);
          goto leave;
        }
    } /* End version 2 cards.  */

  if (chvno == 3)
    app->did_chv3 = 0;
  else
    app->did_chv1 = app->did_chv2 = 0;

  if (!use_pinpad)
    {
      /* TRANSLATORS: Do not translate the "|*|" prefixes but
         keep it at the start of the string.  We need this elsewhere
         to get some infos on the string. */
      rc = pincb (pincb_arg, set_resetcode? _("|RN|New Reset Code") :
                  chvno == 3? _("|AN|New Admin PIN") : _("|N|New PIN"),
                  &pinvalue);
      if (rc || pinvalue == NULL)
        {
          log_error (_("error getting new PIN: %s\n"), gpg_strerror (rc));
          goto leave;
        }

      if (set_resetcode)
        {
          size_t bufferlen = strlen (pinvalue);

          if (bufferlen != 0 && bufferlen < 8)
            {
              log_error (_("Reset Code is too short; minimum length is %d\n"), 8);
              rc = gpg_error (GPG_ERR_BAD_RESET_CODE);
              goto leave;
            }
        }
      else if (use_resetcode)
        {
          minlen = 6; /* Reset from the RC value to the PIN value.  */
          if (strlen (pinvalue) < minlen)
            {
              log_info (_("PIN for CHV%d is too short;"
                          " minimum length is %d\n"), 1, minlen);
              rc = gpg_error (GPG_ERR_BAD_PIN);
              goto leave;
            }
        }
      else
        {
          if (chvno == 3)
            minlen = 8;

          if (strlen (pinvalue) < minlen)
            {
              log_info (_("PIN for CHV%d is too short;"
                          " minimum length is %d\n"), chvno, minlen);
              rc = gpg_error (GPG_ERR_BAD_PIN);
              goto leave;
            }
        }
    }


  if (resetcode)
    {
      char *result1 = NULL;
      char *result2 = NULL;
      char *buffer = NULL;
      size_t resultlen1=0, resultlen2=0, bufferlen=0;

      rc = pin2hash_if_kdf (app, 0, resetcode, &result1, &resultlen1);
      if (!rc)
        rc = pin2hash_if_kdf (app, 1, pinvalue, &result2, &resultlen2);
      if (!rc)
        {
          bufferlen = resultlen1 + resultlen2;
          buffer = xtrymalloc (bufferlen);
          if (!buffer)
            rc = gpg_error_from_syserror ();
          else
            {
              memcpy (buffer, result1, resultlen1);
              memcpy (buffer+resultlen1, result2, resultlen2);
            }
        }
      if (!rc)
        rc = iso7816_reset_retry_counter_with_rc (app_get_slot (app), 0x81,
                                                  buffer, bufferlen);
      wipe_and_free (result1, resultlen1);
      wipe_and_free (result2, resultlen2);
      wipe_and_free (buffer, bufferlen);
    }
  else if (set_resetcode)
    {
      size_t bufferlen;
      char *buffer = NULL;

      rc = pin2hash_if_kdf (app, 0, pinvalue, &buffer, &bufferlen);
      if (!rc)
        rc = iso7816_put_data (app_get_slot (app),
                               0, 0xD3, buffer, bufferlen);

      wipe_and_free (buffer, bufferlen);
    }
  else if (reset_mode)
    {
      char *buffer = NULL;
      size_t bufferlen;

      rc = pin2hash_if_kdf (app, 1, pinvalue, &buffer, &bufferlen);
      if (!rc)
        rc = iso7816_reset_retry_counter (app_get_slot (app),
                                          0x81, buffer, bufferlen);
      if (!rc && !app->app_local->extcap.is_v2)
        rc = iso7816_reset_retry_counter (app_get_slot (app),
                                          0x82, buffer, bufferlen);
      wipe_and_free (buffer, bufferlen);
    }
  else if (!app->app_local->extcap.is_v2)
    {
      /* Version 1 cards.  */
      if (chvno == 1 || chvno == 2)
        {
          rc = iso7816_change_reference_data (app_get_slot (app),
                                              0x81, NULL, 0,
                                              pinvalue, strlen (pinvalue));
          if (!rc)
            rc = iso7816_change_reference_data (app_get_slot (app),
                                                0x82, NULL, 0,
                                                pinvalue, strlen (pinvalue));
        }
      else /* CHVNO == 3 */
        {
          rc = iso7816_change_reference_data (app_get_slot (app),
                                              0x80 + chvno, NULL, 0,
                                              pinvalue, strlen (pinvalue));
        }
    }
  else
    {
      /* Version 2 cards.  */
      log_assert (chvno == 1 || chvno == 3);

      if (use_pinpad)
        {
          rc = pincb (pincb_arg,
                      chvno == 3 ?
                      _("||Please enter the Admin PIN and New Admin PIN") :
                      _("||Please enter the PIN and New PIN"), NULL);
          if (rc)
            {
              log_info (_("PIN callback returned error: %s\n"),
                        gpg_strerror (rc));
              goto leave;
            }
          rc = iso7816_change_reference_data_kp (app->slot, 0x80 + chvno, 0,
                                                 &pininfo);
          pincb (pincb_arg, NULL, NULL); /* Dismiss the prompt. */
        }
      else
        {
          char *buffer1 = NULL;
          char *buffer2 = NULL;
          size_t bufferlen1, bufferlen2 = 0;

          rc = pin2hash_if_kdf (app, chvno, oldpinvalue, &buffer1, &bufferlen1);
          if (!rc)
            rc = pin2hash_if_kdf (app, chvno, pinvalue, &buffer2, &bufferlen2);
          if (!rc)
            rc = iso7816_change_reference_data (app->slot, 0x80 + chvno,
                                                buffer1, bufferlen1,
                                                buffer2, bufferlen2);
          wipe_and_free (buffer1, bufferlen1);
          wipe_and_free (buffer2, bufferlen2);
        }
    }

  wipe_and_free_string (pinvalue);
  if (rc)
    flush_cache_after_error (app);

 leave:
  wipe_and_free_string (resetcode);
  wipe_and_free_string (oldpinvalue);
  return rc;
}


/* Check whether a key already exists.  KEYIDX is the index of the key
   (0..2).  If FORCE is TRUE a diagnositic will be printed but no
   error returned if the key already exists.  The flag GENERATING is
   only used to print correct messages. */
static gpg_error_t
does_key_exist (app_t app, int keyidx, int generating, int force)
{
  const unsigned char *fpr;
  unsigned char *buffer;
  size_t buflen, n;
  int i;

  log_assert (keyidx >=0 && keyidx <= 2);

  if (iso7816_get_data (app_get_slot (app), 0, 0x006E, &buffer, &buflen))
    {
      log_error (_("error reading application data\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr = find_tlv (buffer, buflen, 0x00C5, &n);
  if (!fpr || n < 60)
    {
      log_error (_("error reading fingerprint DO\n"));
      xfree (buffer);
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr += 20*keyidx;
  for (i=0; i < 20 && !fpr[i]; i++)
    ;
  xfree (buffer);
  if (i!=20 && !force)
    {
      log_error (_("key already exists\n"));
      return gpg_error (GPG_ERR_EEXIST);
    }
  else if (i!=20)
    log_info (_("existing key will be replaced\n"));
  else if (generating)
    log_info (_("generating new key\n"));
  else
    log_info (_("writing new key\n"));
  return 0;
}


/* Create a TLV tag and value and store it at BUFFER.  Return the length
   of tag and length.  A LENGTH greater than 65535 is truncated. */
static size_t
add_tlv (unsigned char *buffer, unsigned int tag, size_t length)
{
  unsigned char *p = buffer;

  log_assert (tag <= 0xffff);
  if ( tag > 0xff )
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
      if (length > 0xffff)
        length = 0xffff;
      *p++ = 0x82;
      *p++ = length >> 8;
      *p++ = length;
    }

  return p - buffer;
}


static gpg_error_t
build_privkey_template (app_t app, int keyno,
                        const unsigned char *rsa_n, size_t rsa_n_len,
                        const unsigned char *rsa_e, size_t rsa_e_len,
                        const unsigned char *rsa_p, size_t rsa_p_len,
                        const unsigned char *rsa_q, size_t rsa_q_len,
                        const unsigned char *rsa_u, size_t rsa_u_len,
                        const unsigned char *rsa_dp, size_t rsa_dp_len,
                        const unsigned char *rsa_dq, size_t rsa_dq_len,
                        unsigned char **result, size_t *resultlen)
{
  size_t rsa_e_reqlen;
  unsigned char privkey[7*(1+3+3)];
  size_t privkey_len;
  unsigned char exthdr[2+2+3];
  size_t exthdr_len;
  unsigned char suffix[2+3];
  size_t suffix_len;
  unsigned char *tp;
  size_t datalen;
  unsigned char *template;
  size_t template_size;

  *result = NULL;
  *resultlen = 0;

  switch (app->app_local->keyattr[keyno].rsa.format)
    {
    case RSA_STD:
    case RSA_STD_N:
    case RSA_CRT:
    case RSA_CRT_N:
      break;

    default:
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  /* Get the required length for E. Rounded up to the nearest byte  */
  rsa_e_reqlen = (app->app_local->keyattr[keyno].rsa.e_bits + 7) / 8;
  log_assert (rsa_e_len <= rsa_e_reqlen);

  /* Build the 7f48 cardholder private key template.  */
  datalen = 0;
  tp = privkey;

  tp += add_tlv (tp, 0x91, rsa_e_reqlen);
  datalen += rsa_e_reqlen;

  tp += add_tlv (tp, 0x92, rsa_p_len);
  datalen += rsa_p_len;

  tp += add_tlv (tp, 0x93, rsa_q_len);
  datalen += rsa_q_len;

  if (app->app_local->keyattr[keyno].rsa.format == RSA_CRT
      || app->app_local->keyattr[keyno].rsa.format == RSA_CRT_N)
    {
      tp += add_tlv (tp, 0x94, rsa_u_len);
      datalen += rsa_u_len;
      tp += add_tlv (tp, 0x95, rsa_dp_len);
      datalen += rsa_dp_len;
      tp += add_tlv (tp, 0x96, rsa_dq_len);
      datalen += rsa_dq_len;
    }

  if (app->app_local->keyattr[keyno].rsa.format == RSA_STD_N
      || app->app_local->keyattr[keyno].rsa.format == RSA_CRT_N)
    {
      tp += add_tlv (tp, 0x97, rsa_n_len);
      datalen += rsa_n_len;
    }
  privkey_len = tp - privkey;

  /* Build the extended header list without the private key template.  */
  tp = exthdr;
  *tp++ = keyno ==0 ? 0xb6 : keyno == 1? 0xb8 : 0xa4;
  *tp++ = 0;
  tp += add_tlv (tp, 0x7f48, privkey_len);
  exthdr_len = tp - exthdr;

  /* Build the 5f48 suffix of the data.  */
  tp = suffix;
  tp += add_tlv (tp, 0x5f48, datalen);
  suffix_len = tp - suffix;

  /* Now concatenate everything.  */
  template_size = (1 + 3   /* 0x4d and len. */
                   + exthdr_len
                   + privkey_len
                   + suffix_len
                   + datalen);
  tp = template = xtrymalloc_secure (template_size);
  if (!template)
    return gpg_error_from_syserror ();

  tp += add_tlv (tp, 0x4d, exthdr_len + privkey_len + suffix_len + datalen);
  memcpy (tp, exthdr, exthdr_len);
  tp += exthdr_len;
  memcpy (tp, privkey, privkey_len);
  tp += privkey_len;
  memcpy (tp, suffix, suffix_len);
  tp += suffix_len;

  memcpy (tp, rsa_e, rsa_e_len);
  if (rsa_e_len < rsa_e_reqlen)
    {
      /* Right justify E. */
      memmove (tp + rsa_e_reqlen - rsa_e_len, tp, rsa_e_len);
      memset (tp, 0, rsa_e_reqlen - rsa_e_len);
    }
  tp += rsa_e_reqlen;

  memcpy (tp, rsa_p, rsa_p_len);
  tp += rsa_p_len;

  memcpy (tp, rsa_q, rsa_q_len);
  tp += rsa_q_len;

  if (app->app_local->keyattr[keyno].rsa.format == RSA_CRT
      || app->app_local->keyattr[keyno].rsa.format == RSA_CRT_N)
    {
      memcpy (tp, rsa_u, rsa_u_len);
      tp += rsa_u_len;
      memcpy (tp, rsa_dp, rsa_dp_len);
      tp += rsa_dp_len;
      memcpy (tp, rsa_dq, rsa_dq_len);
      tp += rsa_dq_len;
    }

  if (app->app_local->keyattr[keyno].rsa.format == RSA_STD_N
      || app->app_local->keyattr[keyno].rsa.format == RSA_CRT_N)
    {
      memcpy (tp, rsa_n, rsa_n_len);
      tp += rsa_n_len;
    }

  /* Sanity check.  We don't know the exact length because we
     allocated 3 bytes for the first length header.  */
  log_assert (tp - template <= template_size);

  *result = template;
  *resultlen = tp - template;
  return 0;
}


static gpg_error_t
build_ecc_privkey_template (app_t app, int keyno,
                            const unsigned char *ecc_d, size_t ecc_d_len,
                            size_t ecc_d_fixed_len,
                            const unsigned char *ecc_q, size_t ecc_q_len,
                            unsigned char **result, size_t *resultlen)
{
  unsigned char privkey[2*(1+3)];
  size_t privkey_len;
  unsigned char exthdr[2+2+3];
  size_t exthdr_len;
  unsigned char suffix[2+3];
  size_t suffix_len;
  unsigned char *tp;
  size_t datalen;
  unsigned char *template;
  size_t template_size;
  int pubkey_required;

  /* This case doesn't occur in GnuPG 2.3 or later, because
     agent/sexp-secret.c does the fixup.  */
  if (ecc_d_fixed_len < ecc_d_len)
    {
      if (ecc_d_fixed_len != ecc_d_len - 1 || *ecc_d)
        return gpg_error (GPG_ERR_INV_OBJ);

      /* Remove the additional zero.  */
      ecc_d_len--;
      ecc_d++;
    }

  pubkey_required = !!(app->app_local->keyattr[keyno].ecc.flags
                       & ECC_FLAG_PUBKEY);

  *result = NULL;
  *resultlen = 0;

  /* Build the 7f48 cardholder private key template.  */
  datalen = 0;
  tp = privkey;

  tp += add_tlv (tp, 0x92, ecc_d_fixed_len);
  datalen += ecc_d_fixed_len;

  if (pubkey_required)
    {
      tp += add_tlv (tp, 0x99, ecc_q_len);
      datalen += ecc_q_len;
    }

  privkey_len = tp - privkey;


  /* Build the extended header list without the private key template.  */
  tp = exthdr;
  *tp++ = keyno ==0 ? 0xb6 : keyno == 1? 0xb8 : 0xa4;
  *tp++ = 0;
  tp += add_tlv (tp, 0x7f48, privkey_len);
  exthdr_len = tp - exthdr;

  /* Build the 5f48 suffix of the data.  */
  tp = suffix;
  tp += add_tlv (tp, 0x5f48, datalen);
  suffix_len = tp - suffix;

  /* Now concatenate everything.  */
  template_size = (1 + 1   /* 0x4d and len. */
                   + exthdr_len
                   + privkey_len
                   + suffix_len
                   + datalen);
  if (exthdr_len + privkey_len + suffix_len + datalen >= 128)
    template_size++;
  tp = template = xtrymalloc_secure (template_size);
  if (!template)
    return gpg_error_from_syserror ();

  tp += add_tlv (tp, 0x4d, exthdr_len + privkey_len + suffix_len + datalen);
  memcpy (tp, exthdr, exthdr_len);
  tp += exthdr_len;
  memcpy (tp, privkey, privkey_len);
  tp += privkey_len;
  memcpy (tp, suffix, suffix_len);
  tp += suffix_len;

  if (ecc_d_fixed_len > ecc_d_len)
    {
      memset (tp, 0, ecc_d_fixed_len - ecc_d_len);
      memcpy (tp + ecc_d_fixed_len - ecc_d_len, ecc_d, ecc_d_len);
    }
  else
    memcpy (tp, ecc_d, ecc_d_len);
  tp += ecc_d_fixed_len;

  if (pubkey_required)
    {
      memcpy (tp, ecc_q, ecc_q_len);
      tp += ecc_q_len;
    }

  log_assert (tp - template == template_size);

  *result = template;
  *resultlen = tp - template;
  return 0;
}


/* Helper for do_writekey to change the size of a key.  Note that
   this deletes the entire key without asking.  */
static gpg_error_t
change_keyattr (app_t app, ctrl_t ctrl,
                int keyno, const unsigned char *buf, size_t buflen,
                gpg_error_t (*pincb)(void*, const char *, char **),
                void *pincb_arg)
{
  gpg_error_t err;

  log_assert (keyno >=0 && keyno <= 2);

  /* Prepare for storing the key.  */
  err = verify_chv3 (app, ctrl, pincb, pincb_arg);
  if (err)
    return err;

  /* Change the attribute.  */
  err = iso7816_put_data (app_get_slot (app), 0, 0xC1+keyno, buf, buflen);
  if (err)
    log_error ("error changing key attribute of OPENPGP.%d\n",
               keyno+1);
  else
    log_info ("key attribute of OPENPGP.%d changed\n", keyno+1);
  flush_cache (app);
  err = parse_algorithm_attribute (app, keyno);
  app->did_chv1 = 0;
  app->did_chv2 = 0;
  app->did_chv3 = 0;
  return err;
}


static gpg_error_t
change_rsa_keyattr (app_t app, ctrl_t ctrl, int keyno, unsigned int nbits,
                    gpg_error_t (*pincb)(void*, const char *, char **),
                    void *pincb_arg)
{
  gpg_error_t err = 0;
  unsigned char *buf;
  size_t buflen;
  void *relptr;

  /* Read the current attributes into a buffer.  */
  relptr = get_one_do (app, 0xC1+keyno, &buf, &buflen, NULL);
  if (!relptr)
    err = gpg_error (GPG_ERR_CARD);
  else if (buflen < 6)
    {
      /* Attributes too short.  */
      xfree (relptr);
      err = gpg_error (GPG_ERR_CARD);
    }
  else
    {
      /* If key attribute was RSA, we only change n_bits and don't
         touch anything else.  Before we do so, we round up NBITS to a
         sensible way in the same way as gpg's key generation does it.
         This may help to sort out problems with a few bits too short
         keys.  */
      nbits = ((nbits + 31) / 32) * 32;
      buf[1] = (nbits >> 8);
      buf[2] = nbits;

      /* If it was not RSA, we need to fill other parts.  */
      if (buf[0] != PUBKEY_ALGO_RSA)
        {
          buf[0] = PUBKEY_ALGO_RSA;
          buf[3] = 0;
          buf[4] = 32;
          buf[5] = 0;
          buflen = 6;
        }

      err = change_keyattr (app, ctrl, keyno, buf, buflen, pincb, pincb_arg);
      xfree (relptr);
    }

  return err;
}


/* Helper to process an setattr command for name KEY-ATTR.
 *
 * If KEYREF and KEYALGO are NULL (VALUE,VALUELEN) are expected to
 * contain one of the following strings:
 *       RSA: "--force <key> <algo> rsa<nbits>"
 *       ECC: "--force <key> <algo> <curvename>"
 *
 * If KEYREF and KEYALGO is given the key attribute for KEYREF are
 * changed to what is described by KEYALGO (e.g. "rsa3072", "rsa2048",
 * or "ed25519").
 */
static gpg_error_t
change_keyattr_from_string (app_t app, ctrl_t ctrl,
                            gpg_error_t (*pincb)(void*, const char *, char **),
                            void *pincb_arg,
                            const char *keyref, const char *keyalgo,
                            const void *value, size_t valuelen)
{
  gpg_error_t err = 0;
  char *string = NULL;
  int key, keyno, algo;
  unsigned int nbits = 0;
  const char *oidstr = NULL; /* OID of the curve.  */
  char *endp;

  if (keyref && keyalgo && *keyref && *keyalgo)
    {
      if (!ascii_strcasecmp (keyref, "OPENPGP.1"))
        keyno = 0;
      else if (!ascii_strcasecmp (keyref, "OPENPGP.2"))
        keyno = 1;
      else if (!ascii_strcasecmp (keyref, "OPENPGP.3"))
        keyno = 2;
      else
        {
          err = gpg_error (GPG_ERR_INV_ID);
          goto leave;
        }

      if (!strncmp (keyalgo, "rsa", 3) && digitp (keyalgo+3))
        {
          errno = 0;
          nbits = strtoul (keyalgo+3, &endp, 10);
          if (errno || *endp)
            {
              err = gpg_error (GPG_ERR_INV_DATA);
              goto leave;
            }
          algo = PUBKEY_ALGO_RSA;
        }
      else if ((!strncmp (keyalgo, "dsa", 3) || !strncmp (keyalgo, "elg", 3))
               && digitp (keyalgo+3))
        {
          err = gpg_error (GPG_ERR_PUBKEY_ALGO);
          goto leave;
        }
      else
        {
          nbits = 0;
          oidstr = openpgp_curve_to_oid (keyalgo, NULL, &algo);
          if (!oidstr)
            {
              err = gpg_error (GPG_ERR_INV_DATA);
              goto leave;
            }
          if (!algo)
            algo = keyno == 1? PUBKEY_ALGO_ECDH : PUBKEY_ALGO_ECDSA;
        }

    }
  else if (!keyref && !keyalgo && value)
    {
      int n;

      /* VALUE is expected to be a string but not guaranteed to be
       * terminated.  Thus copy it to an allocated buffer first. */
      string = xtrymalloc (valuelen+1);
      if (!string)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (string, value, valuelen);
      string[valuelen] = 0;

      /* Because this function deletes the key we require the string
       * "--force" in the data to make clear that something serious
       * might happen.  */
      n = 0;
      sscanf (string, "--force %d %d %n", &key, &algo, &n);
      if (n < 12)
        {
          err = gpg_error (GPG_ERR_INV_DATA);
          goto leave;
        }
      keyno = key - 1;
      if (algo == PUBKEY_ALGO_RSA)
        {
          errno = 0;
          nbits = strtoul (string+n+3, NULL, 10);
          if (errno)
            {
              err = gpg_error (GPG_ERR_INV_DATA);
              goto leave;
            }
        }
      else if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ECDSA
               || algo == PUBKEY_ALGO_EDDSA)
        {
          oidstr = openpgp_curve_to_oid (string+n, NULL, NULL);
          if (!oidstr)
            {
              err = gpg_error (GPG_ERR_INV_DATA);
              goto leave;
            }
        }
      else
        {
          err = gpg_error (GPG_ERR_PUBKEY_ALGO);
          goto leave;
        }
    }
  else
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (keyno < 0 || keyno > 2)
    err = gpg_error (GPG_ERR_INV_ID);
  else if (algo == PUBKEY_ALGO_RSA)
    {
      if (nbits < 1024)
        err = gpg_error (GPG_ERR_TOO_SHORT);
      else if (nbits > 4096)
        err = gpg_error (GPG_ERR_TOO_LARGE);
      else
        err = change_rsa_keyattr (app, ctrl, keyno, nbits, pincb, pincb_arg);
    }
  else if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ECDSA
           || algo == PUBKEY_ALGO_EDDSA)
    {
      gcry_mpi_t oid;
      const unsigned char *oidbuf;
      size_t oid_len;
      unsigned int n;

      /* Check that the requested algo matches the properties of the
       * key slot.  */
      if (keyno == 1 && algo != PUBKEY_ALGO_ECDH)
        err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
      else if (keyno != 1 && algo == PUBKEY_ALGO_ECDH)
        err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
      else
        err = 0;
      if (err)
        goto leave;

      /* Convert the OID string to an OpenPGP formatted OID.  */
      err = openpgp_oid_from_str (oidstr, &oid);
      if (err)
        goto leave;

      oidbuf = gcry_mpi_get_opaque (oid, &n);
      oid_len = (n+7)/8;

      /* Create the template.  */
      xfree (string);
      string = xtrymalloc (1 + oid_len);
      if (!string)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      string[0] = algo;
      memcpy (string+1, oidbuf+1, oid_len-1);
      err = change_keyattr (app, ctrl,keyno, string, oid_len, pincb, pincb_arg);
      gcry_mpi_release (oid);
    }
  else
    err = gpg_error (GPG_ERR_PUBKEY_ALGO);

 leave:
  xfree (string);
  return err;
}


static gpg_error_t
rsa_writekey (app_t app, ctrl_t ctrl,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg, int keyno,
              const unsigned char *buf, size_t buflen, int depth)
{
  gpg_error_t err;
  const unsigned char *tok;
  size_t toklen;
  int last_depth1, last_depth2;
  const unsigned char *rsa_n = NULL;
  const unsigned char *rsa_e = NULL;
  const unsigned char *rsa_p = NULL;
  const unsigned char *rsa_q = NULL;
  size_t rsa_n_len, rsa_e_len, rsa_p_len, rsa_q_len;
  unsigned int nbits;
  unsigned int maxbits;
  unsigned char *template = NULL;
  unsigned char *tp;
  size_t template_len;
  unsigned char fprbuf[20];
  u32 created_at = 0;

  if (app->app_local->keyattr[keyno].key_type != KEY_TYPE_RSA)
    {
      log_error (_("unsupported algorithm: %s"), "RSA");
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  last_depth1 = depth;
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP);
          goto leave;
        }
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        goto leave;
      if (tok && toklen == 1)
        {
          const unsigned char **mpi;
          size_t *mpi_len;

          switch (*tok)
            {
            case 'n': mpi = &rsa_n; mpi_len = &rsa_n_len; break;
            case 'e': mpi = &rsa_e; mpi_len = &rsa_e_len; break;
            case 'p': mpi = &rsa_p; mpi_len = &rsa_p_len; break;
            case 'q': mpi = &rsa_q; mpi_len = &rsa_q_len;break;
            default: mpi = NULL;  mpi_len = NULL; break;
            }
          if (mpi && *mpi)
            {
              err = gpg_error (GPG_ERR_DUP_VALUE);
              goto leave;
            }
          if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
            goto leave;
          if (tok && mpi)
            {
              /* Strip off leading zero bytes and save. */
              for (;toklen && !*tok; toklen--, tok++)
                ;
              *mpi = tok;
              *mpi_len = toklen;
            }
        }
      /* Skip until end of list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        goto leave;
    }
  /* Parse other attributes. */
  last_depth1 = depth;
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP);
          goto leave;
        }
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        goto leave;
      if (tok && toklen == 10 && !memcmp ("created-at", tok, toklen))
        {
          if ((err = parse_sexp (&buf,&buflen,&depth,&tok,&toklen)))
            goto leave;
          if (tok)
            {
              for (created_at=0; toklen && *tok && *tok >= '0' && *tok <= '9';
                   tok++, toklen--)
                created_at = created_at*10 + (*tok - '0');
            }
        }
      /* Skip until end of list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        goto leave;
    }


  /* Check that we have all parameters and that they match the card
     description. */
  if (!created_at)
    {
      log_error (_("creation timestamp missing\n"));
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  maxbits = app->app_local->keyattr[keyno].rsa.n_bits;
  nbits = rsa_n? count_bits (rsa_n, rsa_n_len) : 0;
  if (opt.verbose)
    log_info ("RSA modulus size is %u bits\n", nbits);
  if (nbits && nbits != maxbits
      && app->app_local->extcap.algo_attr_change)
    {
      /* Try to switch the key to a new length.  */
      err = change_rsa_keyattr (app, ctrl, keyno, nbits, pincb, pincb_arg);
      if (!err)
        maxbits = app->app_local->keyattr[keyno].rsa.n_bits;
    }
  if (nbits != maxbits)
    {
      log_error (_("RSA modulus missing or not of size %d bits\n"),
                 (int)maxbits);
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  maxbits = app->app_local->keyattr[keyno].rsa.e_bits;
  if (maxbits > 32 && !app->app_local->extcap.is_v2)
    maxbits = 32; /* Our code for v1 does only support 32 bits.  */
  nbits = rsa_e? count_bits (rsa_e, rsa_e_len) : 0;
  if (nbits < 2 || nbits > maxbits)
    {
      log_error (_("RSA public exponent missing or larger than %d bits\n"),
                 (int)maxbits);
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  maxbits = app->app_local->keyattr[keyno].rsa.n_bits/2;
  nbits = rsa_p? count_bits (rsa_p, rsa_p_len) : 0;
  if (nbits != maxbits)
    {
      log_error (_("RSA prime %s missing or not of size %d bits\n"),
                 "P", (int)maxbits);
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }
  nbits = rsa_q? count_bits (rsa_q, rsa_q_len) : 0;
  if (nbits != maxbits)
    {
      log_error (_("RSA prime %s missing or not of size %d bits\n"),
                 "Q", (int)maxbits);
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  /* We need to remove the cached public key.  */
  xfree (app->app_local->pk[keyno].key);
  app->app_local->pk[keyno].key = NULL;
  app->app_local->pk[keyno].keylen = 0;
  app->app_local->pk[keyno].read_done = 0;


  if (app->app_local->extcap.is_v2)
    {
      unsigned char *rsa_u, *rsa_dp, *rsa_dq;
      size_t rsa_u_len, rsa_dp_len, rsa_dq_len;
      gcry_mpi_t mpi_e, mpi_p, mpi_q;
      gcry_mpi_t mpi_u = gcry_mpi_snew (0);
      gcry_mpi_t mpi_dp = gcry_mpi_snew (0);
      gcry_mpi_t mpi_dq = gcry_mpi_snew (0);
      gcry_mpi_t mpi_tmp = gcry_mpi_snew (0);
      int exmode;

      /* Calculate the u, dp and dq components needed by RSA_CRT cards */
      gcry_mpi_scan (&mpi_e, GCRYMPI_FMT_USG, rsa_e, rsa_e_len, NULL);
      gcry_mpi_scan (&mpi_p, GCRYMPI_FMT_USG, rsa_p, rsa_p_len, NULL);
      gcry_mpi_scan (&mpi_q, GCRYMPI_FMT_USG, rsa_q, rsa_q_len, NULL);

      gcry_mpi_invm (mpi_u, mpi_q, mpi_p);
      gcry_mpi_sub_ui (mpi_tmp, mpi_p, 1);
      gcry_mpi_invm (mpi_dp, mpi_e, mpi_tmp);
      gcry_mpi_sub_ui (mpi_tmp, mpi_q, 1);
      gcry_mpi_invm (mpi_dq, mpi_e, mpi_tmp);

      gcry_mpi_aprint (GCRYMPI_FMT_USG, &rsa_u, &rsa_u_len, mpi_u);
      gcry_mpi_aprint (GCRYMPI_FMT_USG, &rsa_dp, &rsa_dp_len, mpi_dp);
      gcry_mpi_aprint (GCRYMPI_FMT_USG, &rsa_dq, &rsa_dq_len, mpi_dq);

      gcry_mpi_release (mpi_e);
      gcry_mpi_release (mpi_p);
      gcry_mpi_release (mpi_q);
      gcry_mpi_release (mpi_u);
      gcry_mpi_release (mpi_dp);
      gcry_mpi_release (mpi_dq);
      gcry_mpi_release (mpi_tmp);

      /* Build the private key template as described in section 4.3.3.7 of
         the OpenPGP card specs version 2.0.  */
      err = build_privkey_template (app, keyno,
                                    rsa_n, rsa_n_len,
                                    rsa_e, rsa_e_len,
                                    rsa_p, rsa_p_len,
                                    rsa_q, rsa_q_len,
                                    rsa_u, rsa_u_len,
                                    rsa_dp, rsa_dp_len,
                                    rsa_dq, rsa_dq_len,
                                    &template, &template_len);
      xfree(rsa_u);
      xfree(rsa_dp);
      xfree(rsa_dq);

      if (err)
        goto leave;

      /* Prepare for storing the key.  */
      err = verify_chv3 (app, ctrl, pincb, pincb_arg);
      if (err)
        goto leave;

      /* Store the key. */
      if (app->app_local->cardcap.ext_lc_le && template_len > 254)
        exmode = 1;    /* Use extended length w/o a limit.  */
      else if (app->app_local->cardcap.cmd_chaining && template_len > 254)
        exmode = -254;
      else
        exmode = 0;
      err = iso7816_put_data_odd (app_get_slot (app), exmode, 0x3fff,
                                  template, template_len);
    }
  else
    {
      /* Build the private key template as described in section 4.3.3.6 of
         the OpenPGP card specs version 1.1:
         0xC0   <length> public exponent
         0xC1   <length> prime p
         0xC2   <length> prime q
      */
      log_assert (rsa_e_len <= 4);
      template_len = (1 + 1 + 4
                      + 1 + 1 + rsa_p_len
                      + 1 + 1 + rsa_q_len);
      template = tp = xtrymalloc_secure (template_len);
      if (!template)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      *tp++ = 0xC0;
      *tp++ = 4;
      memcpy (tp, rsa_e, rsa_e_len);
      if (rsa_e_len < 4)
        {
          /* Right justify E. */
          memmove (tp+4-rsa_e_len, tp, rsa_e_len);
          memset (tp, 0, 4-rsa_e_len);
        }
      tp += 4;

      *tp++ = 0xC1;
      *tp++ = rsa_p_len;
      memcpy (tp, rsa_p, rsa_p_len);
      tp += rsa_p_len;

      *tp++ = 0xC2;
      *tp++ = rsa_q_len;
      memcpy (tp, rsa_q, rsa_q_len);
      tp += rsa_q_len;

      log_assert (tp - template == template_len);

      /* Prepare for storing the key.  */
      err = verify_chv3 (app, ctrl, pincb, pincb_arg);
      if (err)
        goto leave;

      /* Store the key. */
      err = iso7816_put_data (app_get_slot (app), 0,
                              (app->appversion > 0x0007? 0xE0:0xE9)+keyno,
                              template, template_len);
    }
  if (err)
    {
      log_error (_("failed to store the key: %s\n"), gpg_strerror (err));
      goto leave;
    }

  err = store_fpr (app, 1, keyno, created_at, fprbuf, PUBKEY_ALGO_RSA,
                   rsa_n, rsa_n_len, rsa_e, rsa_e_len);
  if (err)
    goto leave;


 leave:
  xfree (template);
  return err;
}


static gpg_error_t
ecc_writekey (app_t app, ctrl_t ctrl,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg, int keyno,
              const unsigned char *buf, size_t buflen, int depth)
{
  gpg_error_t err;
  const unsigned char *tok;
  size_t toklen;
  int last_depth1, last_depth2;
  const unsigned char *ecc_q = NULL;
  const unsigned char *ecc_d = NULL;
  size_t ecc_q_len, ecc_d_len;
  const unsigned char *ecdh_param = NULL;
  size_t ecdh_param_len = 0;
  const char *curve = NULL;
  u32 created_at = 0;
  const char *oidstr;
  int flag_djb_tweak = 0;
  int algo;
  gcry_mpi_t oid = NULL;
  const unsigned char *oidbuf;
  unsigned int n;
  size_t oid_len;
  unsigned char fprbuf[20];
  size_t ecc_d_fixed_len;

  /* (private-key(ecc(curve%s)(q%m)(d%m))(created-at%d)(ecdh-params%s)):
     curve = "NIST P-256" */
  /* (private-key(ecc(curve%s)(q%m)(d%m))(created-at%d)):
     curve = "secp256k1" */
  /* (private-key(ecc(curve%s)(flags eddsa)(q%m)(d%m))(created-at%d)):
      curve = "Ed25519" */
  /* (private-key(ecc(curve%s)(q%m)(d%m))(created-at%d)):
      curve = "Ed448" */
  last_depth1 = depth;
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP);
          goto leave;
        }
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        goto leave;

      if (tok && toklen == 5 && !memcmp (tok, "curve", 5))
        {
          char *curve_name;

          if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
            goto leave;

          curve_name = xtrymalloc (toklen+1);
          if (!curve_name)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }

          memcpy (curve_name, tok, toklen);
          curve_name[toklen] = 0;
          curve = openpgp_is_curve_supported (curve_name, NULL, NULL);
          xfree (curve_name);
        }
      else if (tok && toklen == 5 && !memcmp (tok, "flags", 5))
        {
          if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
            goto leave;

          if (tok)
            {
              if ((toklen == 5 && !memcmp (tok, "eddsa", 5))
                  || (toklen == 9 && !memcmp (tok, "djb-tweak", 9)))
                flag_djb_tweak = 1;
            }
        }
      else if (tok && toklen == 1)
        {
          const unsigned char **buf2;
          size_t *buf2len;
          int native = flag_djb_tweak;

          switch (*tok)
            {
            case 'q': buf2 = &ecc_q; buf2len = &ecc_q_len; break;
            case 'd': buf2 = &ecc_d; buf2len = &ecc_d_len; native = 0; break;
            default: buf2 = NULL;  buf2len = NULL; break;
            }
          if (buf2 && *buf2)
            {
              err = gpg_error (GPG_ERR_DUP_VALUE);
              goto leave;
            }
          if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
            goto leave;
          if (tok && buf2)
            {
              if (!native)
                /* Strip off leading zero bytes and save. */
                for (;toklen && !*tok; toklen--, tok++)
                  ;

              *buf2 = tok;
              *buf2len = toklen;
            }
        }
      /* Skip until end of list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        goto leave;
    }
  /* Parse other attributes. */
  last_depth1 = depth;
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP);
          goto leave;
        }
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        goto leave;

      if (tok && toklen == 10 && !memcmp ("created-at", tok, toklen))
        {
          if ((err = parse_sexp (&buf,&buflen,&depth,&tok,&toklen)))
            goto leave;
          if (tok)
            {
              for (created_at=0; toklen && *tok && *tok >= '0' && *tok <= '9';
                   tok++, toklen--)
                created_at = created_at*10 + (*tok - '0');
            }
        }
      else if (tok && toklen == 11 && !memcmp ("ecdh-params", tok, toklen))
        {
          if ((err = parse_sexp (&buf,&buflen,&depth,&tok,&toklen)))
            goto leave;
          if (tok)
            {
              ecdh_param = tok;
              ecdh_param_len = toklen;
            }
        }

      /* Skip until end of list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        goto leave;
    }


  /* Check that we have all parameters and that they match the card
     description. */
  if (!curve)
    {
      log_error (_("unsupported curve\n"));
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  if (!created_at)
    {
      log_error (_("creation timestamp missing\n"));
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  if (flag_djb_tweak && keyno != 1)
    algo = PUBKEY_ALGO_EDDSA;
  else if (keyno == 1)
    algo = PUBKEY_ALGO_ECDH;
  else if (!strcmp (curve, "Ed448"))
    algo = PUBKEY_ALGO_EDDSA;
  else
    algo = PUBKEY_ALGO_ECDSA;

  if (algo == PUBKEY_ALGO_ECDH && !ecdh_param)
    {
      /* In case this is used by older clients we fallback to our
       * default ecc parameters.  */
      log_info ("opgp: using default ecdh parameters\n");
      ecdh_param = ecdh_params (curve);
      ecdh_param_len = 4;
    }

  oidstr = openpgp_curve_to_oid (curve, &n, NULL);
  ecc_d_fixed_len = (n+7)/8;
  err = openpgp_oid_from_str (oidstr, &oid);
  if (err)
    goto leave;
  oidbuf = gcry_mpi_get_opaque (oid, &n);
  if (!oidbuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  oid_len = (n+7)/8;

  if (app->app_local->keyattr[keyno].key_type != KEY_TYPE_ECC
      || app->app_local->keyattr[keyno].ecc.curve != curve
      || (flag_djb_tweak !=
          (app->app_local->keyattr[keyno].ecc.flags & ECC_FLAG_DJB_TWEAK)))
    {
      if (app->app_local->extcap.algo_attr_change)
        {
          unsigned char *keyattr;

          if (!oid_len)
            {
              err = gpg_error (GPG_ERR_INTERNAL);
              goto leave;
            }
          keyattr = xtrymalloc (oid_len);
          if (!keyattr)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          keyattr[0] = algo;
          memcpy (keyattr+1, oidbuf+1, oid_len-1);
          err = change_keyattr (app, ctrl, keyno, keyattr,
                                oid_len, pincb, pincb_arg);
          xfree (keyattr);
          if (err)
            goto leave;
        }
      else
        {
          log_error ("key attribute on card doesn't match\n");
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto leave;
        }
    }

  if (opt.verbose)
    log_info ("ECC private key size is %u bytes\n", (unsigned int)ecc_d_len);

  /* We need to remove the cached public key.  */
  xfree (app->app_local->pk[keyno].key);
  app->app_local->pk[keyno].key = NULL;
  app->app_local->pk[keyno].keylen = 0;
  app->app_local->pk[keyno].read_done = 0;

  if (app->app_local->extcap.is_v2)
    {
      /* Build the private key template as described in section 4.3.3.7 of
         the OpenPGP card specs version 2.0.  */
      unsigned char *template;
      size_t template_len;
      int exmode;

      err = build_ecc_privkey_template (app, keyno,
                                        ecc_d, ecc_d_len, ecc_d_fixed_len,
                                        ecc_q, ecc_q_len,
                                        &template, &template_len);
      if (err)
        goto leave;

      /* Prepare for storing the key.  */
      err = verify_chv3 (app, ctrl, pincb, pincb_arg);
      if (err)
        {
          xfree (template);
          goto leave;
        }

      /* Store the key. */
      if (app->app_local->cardcap.ext_lc_le && template_len > 254)
        exmode = 1;    /* Use extended length w/o a limit.  */
      else if (app->app_local->cardcap.cmd_chaining && template_len > 254)
        exmode = -254;
      else
        exmode = 0;
      err = iso7816_put_data_odd (app_get_slot (app), exmode, 0x3fff,
                                  template, template_len);
      xfree (template);
    }
  else
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);

  if (err)
    {
      log_error (_("failed to store the key: %s\n"), gpg_strerror (err));
      goto leave;
    }

  err = store_fpr (app, 1, keyno, created_at, fprbuf, algo, oidbuf, oid_len,
                   ecc_q, ecc_q_len, ecdh_param, ecdh_param_len);

 leave:
  gcry_mpi_release (oid);
  return err;
}

/* Handle the WRITEKEY command for OpenPGP.  This function expects a
   canonical encoded S-expression with the secret key in KEYDATA and
   its length (for assertions) in KEYDATALEN.  KEYID needs to be the
   usual keyid which for OpenPGP is the string "OPENPGP.n" with
   n=1,2,3.  Bit 0 of FLAGS indicates whether an existing key shall
   get overwritten.  PINCB and PINCB_ARG are the usual arguments for
   the pinentry callback.  */
static gpg_error_t
do_writekey (app_t app, ctrl_t ctrl,
             const char *keyid, unsigned int flags,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const unsigned char *keydata, size_t keydatalen)
{
  gpg_error_t err;
  int force = (flags & 1);
  int keyno;
  const unsigned char *buf, *tok;
  size_t buflen, toklen;
  int depth;
  char *algostr = NULL;

  if (!strcmp (keyid, "OPENPGP.1"))
    keyno = 0;
  else if (!strcmp (keyid, "OPENPGP.2"))
    keyno = 1;
  else if (!strcmp (keyid, "OPENPGP.3"))
    keyno = 2;
  else
    return gpg_error (GPG_ERR_INV_ID);

  err = does_key_exist (app, keyno, 0, force);
  if (err)
    return err;


  /*
     Parse the S-expression
   */
  buf = keydata;
  buflen = keydatalen;
  depth = 0;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    goto leave;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    goto leave;
  if (!tok || toklen != 11 || memcmp ("private-key", tok, toklen))
    {
      if (!tok)
        ;
      else if (toklen == 21 && !memcmp ("protected-private-key", tok, toklen))
        log_info ("protected-private-key passed to writekey\n");
      else if (toklen == 20 && !memcmp ("shadowed-private-key", tok, toklen))
        log_info ("shadowed-private-key passed to writekey\n");
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    goto leave;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    goto leave;

  if (tok && toklen == 3 && (!memcmp ("rsa", tok, toklen)
                             || !memcmp ("ecc", tok, toklen)))
    {
      gcry_sexp_t stmp;
      if (!gcry_sexp_new (&stmp, keydata, keydatalen, 0))
        algostr = pubkey_algo_string (stmp, NULL);
      else
        algostr = NULL;
      gcry_sexp_release (stmp);
      if (app->app_local->keyattr[keyno].keyalgo && algostr
          && strcmp (app->app_local->keyattr[keyno].keyalgo, algostr))
        {
          log_info ("openpgp: changing key attribute from %s to %s\n",
                    app->app_local->keyattr[keyno].keyalgo, algostr);
          err = change_keyattr_from_string (app, ctrl, pincb, pincb_arg,
                                            keyid, algostr, NULL, 0);
          if (err)
            return err;
        }

      if (*tok == 'r')
        err = rsa_writekey (app, ctrl, pincb, pincb_arg, keyno,
                            buf, buflen, depth);
      else
        err = ecc_writekey (app, ctrl, pincb, pincb_arg, keyno,
                            buf, buflen, depth);
    }
  else
    {
      err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
    }

 leave:
  xfree (algostr);
  return err;
}



/* Handle the GENKEY command. */
static gpg_error_t
do_genkey (app_t app, ctrl_t ctrl,  const char *keyref, const char *keyalgo,
           unsigned int flags, time_t createtime,
           gpg_error_t (*pincb)(void*, const char *, char **),
           void *pincb_arg)
{
  gpg_error_t err;
  char numbuf[30];
  const char *keynostr;
  unsigned char *buffer = NULL;
  const unsigned char *keydata;
  size_t buflen, keydatalen;
  u32 created_at;
  int keyno;
  int force = !!(flags & APP_GENKEY_FLAG_FORCE);
  time_t start_at;
  int exmode = 0;
  int le_value = 256; /* Use legacy value. */

  /* Strip the OpenPGP prefix which is for historical reasons optional.  */
  keynostr = keyref;
  if (!ascii_strncasecmp (keynostr, "OPENPGP.", 8))
    keynostr += 8;

  keyno = atoi (keynostr) - 1;
  if (!digitp (keynostr) || keyno < 0 || keyno > 2)
    return gpg_error (GPG_ERR_INV_ID);

  /* We flush the cache to increase the traffic before a key
     generation.  This _might_ help a card to gather more entropy. */
  flush_cache (app);

  /* Obviously we need to remove the cached public key.  */
  xfree (app->app_local->pk[keyno].key);
  app->app_local->pk[keyno].key = NULL;
  app->app_local->pk[keyno].keylen = 0;
  app->app_local->pk[keyno].read_done = 0;

  /* Check whether a key already exists.  */
  err = does_key_exist (app, keyno, 1, force);
  if (err)
    return err;

  if (keyalgo && app->app_local->keyattr[keyno].keyalgo
      && strcmp (keyalgo, app->app_local->keyattr[keyno].keyalgo))
    {
      /* Specific algorithm requested which is not the currently
       * configured algorithm.  Change it.  */
      log_info ("openpgp: changing key attribute from %s to %s\n",
                 app->app_local->keyattr[keyno].keyalgo, keyalgo);
      err = change_keyattr_from_string (app, ctrl, pincb, pincb_arg,
                                        keyref, keyalgo, NULL, 0);
      if (err)
        return err;
    }

  if (app->app_local->keyattr[keyno].key_type == KEY_TYPE_RSA)
    {
      unsigned int keybits = app->app_local->keyattr[keyno].rsa.n_bits;

      /* Because we send the key parameter back via status lines we need
         to put a limit on the max. allowed keysize.  2048 bit will
         already lead to a 527 byte long status line and thus a 4096 bit
         key would exceed the Assuan line length limit.  */
      if (keybits > 4096)
        return gpg_error (GPG_ERR_TOO_LARGE);

      if (app->app_local->cardcap.ext_lc_le && keybits > RSA_SMALL_SIZE_KEY
          && app->app_local->keyattr[keyno].key_type == KEY_TYPE_RSA)
        {
          exmode = 1;    /* Use extended length w/o a limit.  */
          le_value = determine_rsa_response (app, keyno);
          /* No need to check le_value because it comes from a 16 bit
             value and thus can't create an overflow on a 32 bit
             system.  */
        }
    }

  /* Prepare for key generation by verifying the Admin PIN.  */
  err = verify_chv3 (app, ctrl, pincb, pincb_arg);
  if (err)
    return err;


  log_info (_("please wait while key is being generated ...\n"));
  start_at = time (NULL);
  err = iso7816_generate_keypair (app_get_slot (app), exmode, 0x80, 0,
                                  (keyno == 0? "\xB6" :
                                   keyno == 1? "\xB8" : "\xA4"),
                                  2, le_value, &buffer, &buflen);
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

  keydata = find_tlv (buffer, buflen, 0x7F49, &keydatalen);
  if (!keydata)
    {
      err = gpg_error (GPG_ERR_CARD);
      log_error (_("response does not contain the public key data\n"));
      goto leave;
    }

  created_at = (u32)(createtime? createtime : gnupg_get_time ());
  sprintf (numbuf, "%u", created_at);
  send_status_info (ctrl, "KEY-CREATED-AT",
                    numbuf, (size_t)strlen(numbuf), NULL, 0);

  err = read_public_key (app, ctrl, 1, created_at, keyno, buffer, buflen);
 leave:
  xfree (buffer);
  return err;
}


static unsigned long
convert_sig_counter_value (const unsigned char *value, size_t valuelen)
{
  unsigned long ul;

  if (valuelen == 3 )
    ul = (value[0] << 16) | (value[1] << 8) | value[2];
  else
    {
      log_error (_("invalid structure of OpenPGP card (DO 0x93)\n"));
      ul = 0;
    }
  return ul;
}

static unsigned long
get_sig_counter (app_t app)
{
  void *relptr;
  unsigned char *value;
  size_t valuelen;
  unsigned long ul;

  relptr = get_one_do (app, 0x0093, &value, &valuelen, NULL);
  if (!relptr)
    return 0;
  ul = convert_sig_counter_value (value, valuelen);
  xfree (relptr);
  return ul;
}

static gpg_error_t
compare_fingerprint (app_t app, int keyno, unsigned char *sha1fpr)
{
  const unsigned char *fpr;
  unsigned char *buffer;
  size_t buflen, n;
  int rc, i;

  log_assert (keyno >= 0 && keyno <= 2);

  rc = get_cached_data (app, 0x006E, &buffer, &buflen, 0, 0);
  if (rc)
    {
      log_error (_("error reading application data\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr = find_tlv (buffer, buflen, 0x00C5, &n);
  if (!fpr || n < 60)
    {
      xfree (buffer);
      log_error (_("error reading fingerprint DO\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }
  fpr += keyno*20;
  for (i=0; i < 20; i++)
    if (sha1fpr[i] != fpr[i])
      {
        xfree (buffer);
        log_info (_("fingerprint on card does not match requested one\n"));
        return gpg_error (GPG_ERR_WRONG_SECKEY);
      }
  xfree (buffer);
  return 0;
}


/* If a fingerprint has been specified check it against the one on the
   card.  This allows for a meaningful error message in case the key
   on the card has been replaced but the shadow information known to
   gpg has not been updated.  If there is no fingerprint we assume
   that this is okay. */
static gpg_error_t
check_against_given_fingerprint (app_t app, const char *fpr, int key)
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
  return compare_fingerprint (app, key-1, tmp);
}


/* Check KEYIDSTR, if it's valid.
   When KEYNO is 0, it means it's for PIN check.
   Otherwise, KEYNO corresponds to the slot (signing, decipher and auth).
   KEYIDSTR is either:
    (1) Serial number
    (2) Serial number "/" fingerprint
    (3) Serial number "[CHV3]"
    (4) keygrip

   When KEYNO is 0 and KEYIDSTR is for a keygrip, the keygrip should
   be to be compared is the first one (keygrip for signing).
   When KEYNO is 1, KEYIDSTR is for a keygrip, and R_USE_AUTH is not
   NULL, OpenPGP.1 is first tested and then OpenPGP.3.  In the latter
   case 1 is stored at R_USE_AUTH
 */
static int
check_keyidstr (app_t app, const char *keyidstr, int keyno, int *r_use_auth)
{
  int rc;
  const char *s;
  int n;
  const char *fpr = NULL;
  int i;

  if (r_use_auth)
    *r_use_auth = 0;

  /* Make sure we have load the public keys.  */
  for (i = 0; i < 3; i++)
    get_public_key (app, i);

  if (strlen (keyidstr) < 32)
    return gpg_error (GPG_ERR_INV_ID);
  else
    {
      char *serial;

      for (s=keyidstr, n=0; hexdigitp (s); s++, n++)
        ;

      /* Check if it's a keygrip */
      if (n == 40)
        {
          const unsigned char *keygrip_str;

          keygrip_str = app->app_local->pk[keyno?keyno-1:0].keygrip_str;
          if (!strncmp (keygrip_str, keyidstr, 40))
            return 0;
          else if (keyno == 1 && r_use_auth
                   && !strncmp (app->app_local->pk[2].keygrip_str,
                                keyidstr, 40))
            {
              *r_use_auth = 1;
              return 0;
            }
          else
            return gpg_error (GPG_ERR_INV_ID);
        }

      /* For a description of the serialno compare function see
       * is_same_serialno.  We don't use that function because here we
       * are working on a hex string.  */
      if (n != 32 || ascii_strncasecmp (keyidstr, "D27600012401", 12))
        return gpg_error (GPG_ERR_INV_ID);
      else if (!*s)
        ; /* no fingerprint given: we allow this for now. */
      else if (*s == '/')
        fpr = s + 1;

      serial = app_get_serialno (app);
      if (!serial || strlen (serial) != 32
          || ascii_memcasecmp (serial, "D27600012401", 12)
          || ascii_memcasecmp (serial+16, keyidstr+16, 16))
        {
          xfree (serial);
          return gpg_error (GPG_ERR_WRONG_CARD);
        }

      xfree (serial);
    }

  /* If a fingerprint has been specified check it against the one on
     the card.  This is allows for a meaningful error message in case
     the key on the card has been replaced but the shadow information
     known to gpg was not updated.  If there is no fingerprint, gpg
     will detect a bogus signature anyway due to the
     verify-after-signing feature. */
  rc = (fpr&&keyno)? check_against_given_fingerprint (app, fpr, keyno) : 0;

  return rc;
}


/* Compute a digital signature on INDATA which is expected to be the
   raw message digest. For this application the KEYIDSTR consists of
   the serialnumber and the fingerprint delimited by a slash.

   Note that this function may return the error code
   GPG_ERR_WRONG_CARD to indicate that the card currently present does
   not match the one required for the requested action (e.g. the
   serial number does not match).

   As a special feature a KEYIDSTR of "OPENPGP.3" redirects the
   operation to the auth command.
*/
static gpg_error_t
do_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
         gpg_error_t (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  static unsigned char rmd160_prefix[15] = /* Object ID is 1.3.36.3.2.1 */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
      0x02, 0x01, 0x05, 0x00, 0x04, 0x14  };
  static unsigned char sha1_prefix[15] =   /* (1.3.14.3.2.26) */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14  };
  static unsigned char sha224_prefix[19] = /* (2.16.840.1.101.3.4.2.4) */
    { 0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
      0x1C  };
  static unsigned char sha256_prefix[19] = /* (2.16.840.1.101.3.4.2.1) */
    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
      0x00, 0x04, 0x20  };
  static unsigned char sha384_prefix[19] = /* (2.16.840.1.101.3.4.2.2) */
    { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
      0x00, 0x04, 0x30  };
  static unsigned char sha512_prefix[19] = /* (2.16.840.1.101.3.4.2.3) */
    { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
      0x00, 0x04, 0x40  };
  int rc;
  unsigned char data[19+64];
  size_t datalen;
  unsigned long sigcount;
  int use_auth = 0;
  int exmode, le_value;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Strip off known prefixes.  */
#define X(a,b,c,d) \
  if (hashalgo == GCRY_MD_ ## a                               \
      && (d)                                                  \
      && indatalen == sizeof b ## _prefix + (c)               \
      && !memcmp (indata, b ## _prefix, sizeof b ## _prefix)) \
    {                                                         \
      indata = (const char*)indata + sizeof b ## _prefix;     \
      indatalen -= sizeof b ## _prefix;                       \
    }

  if (indatalen == 20)
    ;  /* Assume a plain SHA-1 or RMD160 digest has been given.  */
  else X(SHA1,   sha1,   20, 1)
  else X(RMD160, rmd160, 20, 1)
  else X(SHA224, sha224, 28, app->app_local->extcap.is_v2)
  else X(SHA256, sha256, 32, app->app_local->extcap.is_v2)
  else X(SHA384, sha384, 48, app->app_local->extcap.is_v2)
  else X(SHA512, sha512, 64, app->app_local->extcap.is_v2)
  else if ((indatalen == 28 || indatalen == 32
            || indatalen == 48 || indatalen ==64)
           && app->app_local->extcap.is_v2)
    ;  /* Assume a plain SHA-3 digest has been given.  */
  else
    {
      log_error (_("card does not support digest algorithm %s\n"),
                 gcry_md_algo_name (hashalgo));
      /* Or the supplied digest length does not match an algorithm.  */
      return gpg_error (GPG_ERR_INV_VALUE);
    }
#undef X

  /* Check whether an OpenPGP card of any version has been requested. */
  if (!strcmp (keyidstr, "OPENPGP.1"))
    ;
  else if (!strcmp (keyidstr, "OPENPGP.3"))
    use_auth = 1;
  else
    {
      rc = check_keyidstr (app, keyidstr, 1, &use_auth);
      if (rc)
        return rc;
    }

  /* Concatenate prefix and digest.  */
#define X(a,b,d) \
  if (hashalgo == GCRY_MD_ ## a && (d) )                      \
    {                                                         \
      datalen = sizeof b ## _prefix + indatalen;              \
      log_assert (datalen <= sizeof data);                    \
      memcpy (data, b ## _prefix, sizeof b ## _prefix);       \
      memcpy (data + sizeof b ## _prefix, indata, indatalen); \
    }

  if (use_auth
      || app->app_local->keyattr[use_auth? 2: 0].key_type == KEY_TYPE_RSA)
    {
      X(SHA1,   sha1,   1)
      else X(RMD160, rmd160, 1)
      else X(SHA224, sha224, app->app_local->extcap.is_v2)
      else X(SHA256, sha256, app->app_local->extcap.is_v2)
      else X(SHA384, sha384, app->app_local->extcap.is_v2)
      else X(SHA512, sha512, app->app_local->extcap.is_v2)
      else
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    }
  else
    {
      datalen = indatalen;
      memcpy (data, indata, indatalen);
    }
#undef X

  /* Redirect to the AUTH command if asked to. */
  if (use_auth)
    {
      return do_auth (app, ctrl, "OPENPGP.3", pincb, pincb_arg,
                      data, datalen,
                      outdata, outdatalen);
    }

  /* Show the number of signature done using this key.  */
  sigcount = get_sig_counter (app);
  log_info (_("signatures created so far: %lu\n"), sigcount);

  /* Check CHV if needed.  */
  if (!app->did_chv1 || app->force_chv1)
    {
      char *pinvalue;
      size_t pinlen;

      rc = verify_a_chv (app, ctrl, pincb, pincb_arg, 1, sigcount,
                         &pinvalue, &pinlen);
      if (rc)
        return rc;

      app->did_chv1 = 1;

      /* For cards with versions < 2 we want to keep CHV1 and CHV2 in
         sync, thus we verify CHV2 here using the given PIN.  Cards
         with version2 to not have the need for a separate CHV2 and
         internally use just one.  Obviously we can't do that if the
         pinpad has been used. */
      if (!app->did_chv2 && pinvalue && !app->app_local->extcap.is_v2)
        {
          rc = iso7816_verify (app_get_slot (app), 0x82, pinvalue, pinlen);
          if (gpg_err_code (rc) == GPG_ERR_BAD_PIN)
            rc = gpg_error (GPG_ERR_PIN_NOT_SYNCED);
          if (rc)
            {
              log_error (_("verify CHV%d failed: %s\n"), 2, gpg_strerror (rc));
              wipe_and_free (pinvalue, pinlen);
              flush_cache_after_error (app);
              return rc;
            }
          app->did_chv2 = 1;
        }
      wipe_and_free (pinvalue, pinlen);
    }


  if (app->app_local->cardcap.ext_lc_le
      && app->app_local->keyattr[0].key_type == KEY_TYPE_RSA
      && app->app_local->keyattr[0].rsa.n_bits > RSA_SMALL_SIZE_OP)
    {
      exmode = 1;    /* Use extended length.  */
      le_value = app->app_local->keyattr[0].rsa.n_bits / 8;
    }
  else
    {
      exmode = 0;
      le_value = 0;
    }
  rc = iso7816_compute_ds (app_get_slot (app), exmode, data, datalen, le_value,
                           outdata, outdatalen);
  if (!rc && app->force_chv1)
    app->did_chv1 = 0;

  return rc;
}

/* Compute a digital signature using the INTERNAL AUTHENTICATE command
   on INDATA which is expected to be the raw message digest. For this
   application the KEYIDSTR consists of the serialnumber and the
   fingerprint delimited by a slash.  Optionally the id OPENPGP.3 may
   be given.

   Note that this function may return the error code
   GPG_ERR_WRONG_CARD to indicate that the card currently present does
   not match the one required for the requested action (e.g. the
   serial number does not match). */
static gpg_error_t
do_auth (app_t app, ctrl_t ctrl, const char *keyidstr,
         gpg_error_t (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  int rc;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (app->app_local->keyattr[2].key_type == KEY_TYPE_RSA
      && indatalen > 101) /* For a 2048 bit key. */
    return gpg_error (GPG_ERR_INV_VALUE);

  if (app->app_local->keyattr[2].key_type == KEY_TYPE_ECC)
    {
      if (!(app->app_local->keyattr[2].ecc.flags & ECC_FLAG_DJB_TWEAK)
          && (indatalen == 51 || indatalen == 67 || indatalen == 83))
        {
          const char *p = (const char *)indata + 19;
          indata = p;
          indatalen -= 19;
        }
      else
        {
          const char *p = (const char *)indata + 15;
          indata = p;
          indatalen -= 15;
        }
    }

  /* Check whether an OpenPGP card of any version has been requested. */
  if (!ascii_strcasecmp (keyidstr, "OPENPGP.3"))
    ;
  else
    {
      rc = check_keyidstr (app, keyidstr, 3, NULL);
      if (rc)
        return rc;
    }

  rc = verify_chv2 (app, ctrl, pincb, pincb_arg);
  if (!rc)
    {
      int exmode, le_value;

      if (app->app_local->cardcap.ext_lc_le
          && app->app_local->keyattr[2].key_type == KEY_TYPE_RSA
          && app->app_local->keyattr[2].rsa.n_bits > RSA_SMALL_SIZE_OP)
        {
          exmode = 1;    /* Use extended length.  */
          le_value = app->app_local->keyattr[2].rsa.n_bits / 8;
        }
      else if (app->app_local->cardcap.cmd_chaining && indatalen > 254)
        {
          exmode = -254; /* Command chaining with max. 254 bytes.  */
          le_value = 0;
        }
      else if (indatalen > 255)
        {
          if (!app->app_local->cardcap.ext_lc_le)
            return gpg_error (GPG_ERR_TOO_LARGE);

          exmode = 1;
          le_value = 0;
        }
      else
        {
          exmode = 0;
          le_value = 0;
        }
      rc = iso7816_internal_authenticate (app_get_slot (app), exmode,
                                          indata, indatalen, le_value,
                                          outdata, outdatalen);
    }
  return rc;
}


static gpg_error_t
do_decipher (app_t app, ctrl_t ctrl, const char *keyidstr,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const void *indata, size_t indatalen,
             unsigned char **outdata, size_t *outdatalen,
             unsigned int *r_info)
{
  int rc;
  int n;
  int exmode, le_value;
  unsigned char *fixbuf = NULL;
  int padind = 0;
  int fixuplen = 0;

  if (!keyidstr || !*keyidstr || !indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check whether an OpenPGP card of any version has been requested. */
  if (!ascii_strcasecmp (keyidstr, "OPENPGP.2"))
    ;
  else
    {
      rc = check_keyidstr (app, keyidstr, 2, NULL);
      if (rc)
        return rc;
    }

  rc = verify_chv2 (app, ctrl, pincb, pincb_arg);
  if (rc)
    return rc;

  if ((indatalen == 16 + 1 || indatalen == 32 + 1)
      && ((char *)indata)[0] == 0x02)
    {
      /* PSO:DECIPHER with symmetric key.  */
      padind = -1;
    }
  else if (app->app_local->keyattr[1].key_type == KEY_TYPE_RSA)
    {
      /* We might encounter a couple of leading zeroes in the
         cryptogram.  Due to internal use of MPIs these leading zeroes
         are stripped.  However the OpenPGP card expects exactly 128
         bytes for the cryptogram (for a 1k key).  Thus we need to fix
         it up.  We do this for up to 16 leading zero bytes; a
         cryptogram with more than this is with a very high
         probability anyway broken.  If a signed conversion was used
         we may also encounter one leading zero followed by the correct
         length.  We fix that as well.  */
      if (indatalen >= (128-16) && indatalen < 128)      /* 1024 bit key.  */
        fixuplen = 128 - indatalen;
      else if (indatalen >= (192-16) && indatalen < 192) /* 1536 bit key.  */
        fixuplen = 192 - indatalen;
      else if (indatalen >= (256-16) && indatalen < 256) /* 2048 bit key.  */
        fixuplen = 256 - indatalen;
      else if (indatalen >= (384-16) && indatalen < 384) /* 3072 bit key.  */
        fixuplen = 384 - indatalen;
      else if (indatalen >= (512-16) && indatalen < 512) /* 4096 bit key.  */
        fixuplen = 512 - indatalen;
      else if (!*(const char *)indata && (indatalen == 129
                                          || indatalen == 193
                                          || indatalen == 257
                                          || indatalen == 385
                                          || indatalen == 513))
        fixuplen = -1;
      else
        fixuplen = 0;

      if (fixuplen > 0)
        {
          /* While we have to prepend stuff anyway, we can also
             include the padding byte here so that iso1816_decipher
             does not need to do another data mangling.  */
          fixuplen++;

          fixbuf = xtrymalloc (fixuplen + indatalen);
          if (!fixbuf)
            return gpg_error_from_syserror ();

          memset (fixbuf, 0, fixuplen);
          memcpy (fixbuf+fixuplen, indata, indatalen);
          indata = fixbuf;
          indatalen = fixuplen + indatalen;
          padind = -1; /* Already padded.  */
        }
      else if (fixuplen < 0)
        {
          /* We use the extra leading zero as the padding byte.  */
          padind = -1;
        }
    }
  else if (app->app_local->keyattr[1].key_type == KEY_TYPE_ECC)
    {
      int old_format_len = 0;

      if ((app->app_local->keyattr[1].ecc.flags & ECC_FLAG_DJB_TWEAK))
        {
          if (indatalen > 32 && (indatalen % 2))
            { /*
               * Skip the prefix.  It may be 0x40 (in new format), or MPI
               * head of 0x00 (in old format).
               */
              indata = (const char *)indata + 1;
              indatalen--;
            }
          else if (indatalen < 32)
            { /*
               * Old format trancated by MPI handling.
               */
              old_format_len = indatalen;
              indatalen = 32;
            }
        }

      n = 0;
      if (indatalen < 128)
        fixuplen = 7;
      else
        fixuplen = 10;

      fixbuf = xtrymalloc (fixuplen + indatalen);
      if (!fixbuf)
        return gpg_error_from_syserror ();

      /* Build 'Cipher DO' */
      fixbuf[n++] = '\xa6';
      if (indatalen < 128)
        fixbuf[n++] = (char)(indatalen+5);
      else
        {
          fixbuf[n++] = 0x81;
          fixbuf[n++] = (char)(indatalen+7);
        }
      fixbuf[n++] = '\x7f';
      fixbuf[n++] = '\x49';
      if (indatalen < 128)
        fixbuf[n++] = (char)(indatalen+2);
      else
        {
          fixbuf[n++] = 0x81;
          fixbuf[n++] = (char)(indatalen+3);
        }
      fixbuf[n++] = '\x86';
      if (indatalen < 128)
        fixbuf[n++] = (char)indatalen;
      else
        {
          fixbuf[n++] = 0x81;
          fixbuf[n++] = (char)indatalen;
        }

      if (old_format_len)
        {
          memset (fixbuf+fixuplen, 0, 32 - old_format_len);
          memcpy (fixbuf+fixuplen + 32 - old_format_len,
                  indata, old_format_len);
        }
      else
        {
          memcpy (fixbuf+fixuplen, indata, indatalen);
        }
      indata = fixbuf;
      indatalen = fixuplen + indatalen;

      padind = -1;
    }
  else
    return gpg_error (GPG_ERR_INV_VALUE);

  if (app->app_local->cardcap.ext_lc_le
      && (indatalen > 254
          || (app->app_local->keyattr[1].key_type == KEY_TYPE_RSA
              && app->app_local->keyattr[1].rsa.n_bits > RSA_SMALL_SIZE_OP)))
    {
      exmode = 1;    /* Extended length w/o a limit.  */
      le_value = app->app_local->keyattr[1].rsa.n_bits / 8;
    }
  else if (app->app_local->cardcap.cmd_chaining && indatalen > 254)
    {
      exmode = -254; /* Command chaining with max. 254 bytes.  */
      le_value = 0;
    }
  else
    exmode = le_value = 0;

  rc = iso7816_decipher (app_get_slot (app), exmode,
                         indata, indatalen, le_value, padind,
                         outdata, outdatalen);
  xfree (fixbuf);
  if (app->app_local->keyattr[1].key_type == KEY_TYPE_ECC)
    {
      unsigned char prefix = 0;

      if (app->app_local->keyattr[1].ecc.flags & ECC_FLAG_DJB_TWEAK)
        prefix = 0x40;
      else if ((*outdatalen % 2) == 0) /* No 0x04 -> x-coordinate only */
        prefix = 0x41;

      if (prefix)
        { /* Add the prefix */
          fixbuf = xtrymalloc (*outdatalen + 1);
          if (!fixbuf)
            {
              xfree (*outdata);
              return gpg_error_from_syserror ();
            }
          fixbuf[0] = prefix;
          memcpy (fixbuf+1, *outdata, *outdatalen);
          xfree (*outdata);
          *outdata = fixbuf;
          *outdatalen = *outdatalen + 1;
        }
    }

  if (gpg_err_code (rc) == GPG_ERR_CARD /* actual SW is 0x640a */
      && app->app_local->manufacturer == 5
      && app->appversion == 0x0200)
    log_info ("NOTE: Cards with manufacturer id 5 and s/n <= 346 (0x15a)"
              " do not work with encryption keys > 2048 bits\n");

  *r_info |= APP_DECIPHER_INFO_NOPAD;

  return rc;
}


/* Perform a simple verify operation for CHV1 and CHV2, so that
   further operations won't ask for CHV2 and it is possible to do a
   cheap check on the PIN: If there is something wrong with the PIN
   entry system, only the regular CHV will get blocked and not the
   dangerous CHV3.  KEYIDSTR is the usual card's serial number; an
   optional fingerprint part will be ignored.

   There is a special mode if the keyidstr is "<serialno>[CHV3]" with
   the "[CHV3]" being a literal string:  The Admin Pin is checked if
   and only if the retry counter is still at 3. */
static gpg_error_t
do_check_pin (app_t app, ctrl_t ctrl, const char *keyidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg)
{
  int rc;
  int admin_pin = 0;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);

  rc = check_keyidstr (app, keyidstr, 0, NULL);
  if (rc)
    return rc;

  if ((strlen (keyidstr) >= 32+6 && !strcmp (keyidstr+32, "[CHV3]"))
      || (strlen (keyidstr) >= 40+6 && !strcmp (keyidstr+40, "[CHV3]")))
    admin_pin = 1;

  /* Yes, there is a race conditions: The user might pull the card
     right here and we won't notice that.  However this is not a
     problem and the check above is merely for a graceful failure
     between operations. */

  if (admin_pin)
    {
      void *relptr;
      unsigned char *value;
      size_t valuelen;
      int count;

      relptr = get_one_do (app, 0x00C4, &value, &valuelen, NULL);
      if (!relptr || valuelen < 7)
        {
          log_error (_("error retrieving CHV status from card\n"));
          xfree (relptr);
          return gpg_error (GPG_ERR_CARD);
        }
      count = value[6];
      xfree (relptr);

      if (!count)
        {
          log_info (_("card is permanently locked!\n"));
          return gpg_error (GPG_ERR_BAD_PIN);
        }
      else if (count < 3)
        {
          log_info (_("verification of Admin PIN is currently prohibited "
                      "through this command\n"));
          return gpg_error (GPG_ERR_GENERAL);
        }

      app->did_chv3 = 0; /* Force verification.  */
      return verify_chv3 (app, ctrl, pincb, pincb_arg);
    }
  else
    return verify_chv2 (app, ctrl, pincb, pincb_arg);
}


/* Show information about card capabilities.  */
static void
show_caps (struct app_local_s *s)
{
  log_info ("Version-2+ .....: %s\n", s->extcap.is_v2? "yes":"no");
  log_info ("Version-3+ .....: %s\n", s->extcap.is_v3? "yes":"no");
  log_info ("Button .........: %s\n", s->extcap.has_button? "yes":"no");

  log_info ("SM-Support .....: %s", s->extcap.sm_supported? "yes":"no");
  if (s->extcap.sm_supported)
    log_printf (" (%s)", s->extcap.sm_algo==2? "3DES":
                (s->extcap.sm_algo==2? "AES-128" : "AES-256"));
  log_info ("Get-Challenge ..: %s", s->extcap.get_challenge? "yes":"no");
  if (s->extcap.get_challenge)
    log_printf (" (%u bytes max)", s->extcap.max_get_challenge);
  log_info ("Key-Import .....: %s\n", s->extcap.key_import? "yes":"no");
  log_info ("Change-Force-PW1: %s\n", s->extcap.change_force_chv? "yes":"no");
  log_info ("Private-DOs ....: %s\n", s->extcap.private_dos? "yes":"no");
  log_info ("Algo-Attr-Change: %s\n", s->extcap.algo_attr_change? "yes":"no");
  log_info ("Symmetric Crypto: %s\n", s->extcap.has_decrypt? "yes":"no");
  log_info ("KDF-Support ....: %s\n", s->extcap.kdf_do? "yes":"no");
  log_info ("Max-Cert-Len ...: %u\n", s->extcap.max_certlen);
  if (s->extcap.is_v3)
    {
      log_info ("PIN-Block-2 ....: %s\n", s->extcap.pin_blk2? "yes":"no");
      log_info ("MSE-Support ....: %s\n", s->extcap.mse? "yes":"no");
      log_info ("Max-Special-DOs : %u\n", s->extcap.max_special_do);
    }
  log_info ("Cmd-Chaining ...: %s\n", s->cardcap.cmd_chaining?"yes":"no");
  log_info ("Ext-Lc-Le ......: %s\n", s->cardcap.ext_lc_le?"yes":"no");
  log_info ("Status-Indicator: %02X\n", s->status_indicator);

  log_info ("GnuPG-No-Sync ..: %s\n",  s->flags.no_sync? "yes":"no");
  log_info ("GnuPG-Def-PW2 ..: %s\n",  s->flags.def_chv2? "yes":"no");
}


/* Parse the historical bytes in BUFFER of BUFLEN and store them in
   APPLOC.  */
static void
parse_historical (struct app_local_s *apploc,
                  const unsigned char * buffer, size_t buflen)
{
  /* Example buffer: 00 31 C5 73 C0 01 80 00 90 00  */
  if (buflen < 4)
    {
      log_error ("warning: historical bytes are too short\n");
      return; /* Too short.  */
    }
  if (*buffer)
    {
      log_error ("warning: bad category indicator in historical bytes\n");
      return;
    }

  /* Skip category indicator.  */
  buffer++;
  buflen--;

  /* Get the status indicator.  */
  apploc->status_indicator = buffer[buflen-3];
  buflen -= 3;

  /* Parse the compact TLV.  */
  while (buflen)
    {
      unsigned int tag = (*buffer & 0xf0) >> 4;
      unsigned int len = (*buffer & 0x0f);
      if (len+1 > buflen)
        {
          log_error ("warning: bad Compact-TLV in historical bytes\n");
          return; /* Error.  */
        }
      buffer++;
      buflen--;
      if (tag == 7 && len == 3)
        {
          /* Card capabilities.  */
          apploc->cardcap.cmd_chaining = !!(buffer[2] & 0x80);
          apploc->cardcap.ext_lc_le    = !!(buffer[2] & 0x40);
        }
      buffer += len;
      buflen -= len;
    }
}


/*
 * Check if the OID in an DER encoding is available by GnuPG/libgcrypt,
 * and return the canonical curve name.  Return NULL if not available.
 * The constant string is not allocated dynamically, never free it.
 */
static const char *
ecc_curve (const unsigned char *buf, size_t buflen)
{
  gcry_mpi_t oid;
  char *oidstr;
  const char *result;
  unsigned char *oidbuf;

  oidbuf = xtrymalloc (buflen + 1);
  if (!oidbuf)
    return NULL;

  memcpy (oidbuf+1, buf, buflen);
  oidbuf[0] = buflen;
  oid = gcry_mpi_set_opaque (NULL, oidbuf, (buflen+1) * 8);
  if (!oid)
    {
      xfree (oidbuf);
      return NULL;
    }

  oidstr = openpgp_oid_to_str (oid);
  gcry_mpi_release (oid);
  if (!oidstr)
    return NULL;

  result = openpgp_oid_to_curve (oidstr, 1);
  xfree (oidstr);
  return result;
}


static const char *
get_algorithm_attribute_string (const unsigned char *buffer,
                                size_t buflen)
{
  enum gcry_pk_algos galgo;
  const char *curve;
  unsigned int nbits = 0;

  galgo = map_openpgp_pk_to_gcry (*buffer);
  nbits = 0;
  curve = NULL;

  if (*buffer == PUBKEY_ALGO_RSA && (buflen == 5 || buflen == 6))
    nbits = (buffer[1]<<8 | buffer[2]);
  else if (*buffer == PUBKEY_ALGO_ECDH || *buffer == PUBKEY_ALGO_ECDSA
           || *buffer == PUBKEY_ALGO_EDDSA)
    {
      int oidlen = buflen - 1;

      if (buffer[buflen-1] == 0x00 || buffer[buflen-1] == 0xff)
        { /* Found "pubkey required"-byte for private key template.  */
          oidlen--;
        }

      curve = ecc_curve (buffer + 1, oidlen);
    }
  else if (opt.verbose)
    log_printhex (buffer, buflen, "");

  return get_keyalgo_string (galgo, nbits, curve);
}


/* Parse and optionally show the algorithm attributes for KEYNO.
   KEYNO must be in the range 0..2.  */
static gpg_error_t
parse_algorithm_attribute (app_t app, int keyno)
{
  unsigned char *buffer;
  size_t buflen;
  void *relptr;
  const char desc[3][5] = {"sign", "encr", "auth"};
  enum gcry_pk_algos galgo;
  unsigned int nbits;
  const char *curve;
  gpg_error_t err = 0;

  log_assert (keyno >=0 && keyno <= 2);

  app->app_local->keyattr[keyno].key_type = KEY_TYPE_RSA;
  app->app_local->keyattr[keyno].rsa.n_bits = 0;

  relptr = get_one_do (app, 0xC1+keyno, &buffer, &buflen, NULL);
  if (!relptr)
    {
      log_error ("error reading DO 0x%02X\n", 0xc1+keyno);
      return gpg_error (GPG_ERR_CARD);
    }
  if (buflen < 1)
    {
      log_error ("error reading DO 0x%02X\n", 0xc1+keyno);
      xfree (relptr);
      return gpg_error (GPG_ERR_CARD);
    }

  if (opt.verbose)
    log_info ("Key-Attr-%s ..: ", desc[keyno]);

  galgo = map_openpgp_pk_to_gcry (*buffer);
  nbits = 0;
  curve = NULL;

  if (*buffer == PUBKEY_ALGO_RSA && (buflen == 5 || buflen == 6))
    {
      app->app_local->keyattr[keyno].rsa.n_bits = (buffer[1]<<8 | buffer[2]);
      app->app_local->keyattr[keyno].rsa.e_bits = (buffer[3]<<8 | buffer[4]);
      app->app_local->keyattr[keyno].rsa.format = 0;
      if (buflen < 6)
        app->app_local->keyattr[keyno].rsa.format = RSA_STD;
      else
        app->app_local->keyattr[keyno].rsa.format = (buffer[5] == 0? RSA_STD   :
                                                     buffer[5] == 1? RSA_STD_N :
                                                     buffer[5] == 2? RSA_CRT   :
                                                     buffer[5] == 3? RSA_CRT_N :
                                                     RSA_UNKNOWN_FMT);

      nbits = app->app_local->keyattr[keyno].rsa.n_bits;
      if (opt.verbose)
        log_printf
          ("RSA, n=%u, e=%u, fmt=%s\n",
           app->app_local->keyattr[keyno].rsa.n_bits,
           app->app_local->keyattr[keyno].rsa.e_bits,
           app->app_local->keyattr[keyno].rsa.format == RSA_STD?  "std"  :
           app->app_local->keyattr[keyno].rsa.format == RSA_STD_N?"std+n":
           app->app_local->keyattr[keyno].rsa.format == RSA_CRT?  "crt"  :
           app->app_local->keyattr[keyno].rsa.format == RSA_CRT_N?"crt+n":"?");
    }
  else if (*buffer == PUBKEY_ALGO_ECDH || *buffer == PUBKEY_ALGO_ECDSA
           || *buffer == PUBKEY_ALGO_EDDSA)
    {
      int oidlen = buflen - 1;

      app->app_local->keyattr[keyno].ecc.algo = *buffer;
      app->app_local->keyattr[keyno].ecc.flags = 0;

      if (APP_CARD(app)->cardtype == CARDTYPE_YUBIKEY)
        {
          /* Yubikey implementations vary.
           * Firmware version 5.2 returns "pubkey required"-byte with
           * 0x00, but after removal and second time insertion, it
           * returns bogus value there.
           * Firmware version 5.4 returns none.
           */
          curve = ecc_curve (buffer + 1, oidlen);
          if (!curve)
            curve = ecc_curve (buffer + 1, oidlen - 1);
        }
      else
        {
          if (buffer[buflen-1] == 0x00 || buffer[buflen-1] == 0xff)
            { /* Found "pubkey required"-byte for private key template.  */
              oidlen--;
              if (buffer[buflen-1] == 0xff)
                app->app_local->keyattr[keyno].ecc.flags |= ECC_FLAG_PUBKEY;
            }
          curve = ecc_curve (buffer + 1, oidlen);
        }

      if (!curve)
        {
          log_printhex (buffer+1, buflen-1, "Curve with OID not supported: ");
          err = gpg_error (GPG_ERR_CARD);
        }
      else
        {
          app->app_local->keyattr[keyno].key_type = KEY_TYPE_ECC;
          app->app_local->keyattr[keyno].ecc.curve = curve;
          if ((*buffer == PUBKEY_ALGO_EDDSA
               && !strcmp (app->app_local->keyattr[keyno].ecc.curve,
                           "Ed25519"))
              || (*buffer == PUBKEY_ALGO_ECDH
                  && !strcmp (app->app_local->keyattr[keyno].ecc.curve,
                              "Curve25519")))
            app->app_local->keyattr[keyno].ecc.flags |= ECC_FLAG_DJB_TWEAK;
          if (opt.verbose)
            log_printf
              ("ECC, curve=%s%s\n", app->app_local->keyattr[keyno].ecc.curve,
               !(app->app_local->keyattr[keyno].ecc.flags & ECC_FLAG_DJB_TWEAK)?
               "": keyno==1? " (djb-tweak)": " (eddsa)");
        }
    }
  else if (opt.verbose)
    log_printhex (buffer, buflen, "");

  app->app_local->keyattr[keyno].keyalgo
    = get_keyalgo_string (galgo, nbits, curve);

  if (opt.verbose)
    log_info ("Key-Algo-%s ..: %s\n",
              desc[keyno], app->app_local->keyattr[keyno].keyalgo);

  xfree (relptr);
  return err;
}

/* Select the OpenPGP application on the card in SLOT.  This function
   must be used before any other OpenPGP application functions. */
gpg_error_t
app_select_openpgp (app_t app)
{
  int slot = app_get_slot (app);
  gpg_error_t err;
  unsigned char *buffer;
  size_t buflen;
  void *relptr;

  /* Note that the card can't cope with P2=0xCO, thus we need to pass a
     special flag value. */
  err = iso7816_select_application (slot,
                                    openpgp_aid, sizeof openpgp_aid, 0x0001);
  if (!err)
    {
      unsigned int manufacturer;

      app->apptype = APPTYPE_OPENPGP;

      app->did_chv1 = 0;
      app->did_chv2 = 0;
      app->did_chv3 = 0;
      app->app_local = NULL;

      /* The OpenPGP card returns the serial number as part of the
         AID; because we prefer to use OpenPGP serial numbers, we
         replace a possibly already set one from a EF.GDO with this
         one.  Note, that for current OpenPGP cards, no EF.GDO exists
         and thus it won't matter at all. */
      err = iso7816_get_data (slot, 0, 0x004F, &buffer, &buflen);
      if (err)
        goto leave;
      if (opt.verbose)
        {
          log_info ("AID: ");
          log_printhex (buffer, buflen, "");
        }

      app->appversion = buffer[6] << 8;
      app->appversion |= buffer[7];
      manufacturer = (buffer[8]<<8 | buffer[9]);

      xfree (app->serialno);
      app->serialno = buffer;
      app->serialnolen = buflen;
      buffer = NULL;
      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      /* We want to temporary cache the DO 6E.  */
      app->app_local->override.cache_6e = 1;

      app->app_local->manufacturer = manufacturer;

      if (app->appversion >= 0x0200)
        app->app_local->extcap.is_v2 = 1;

      if (app->appversion >= 0x0300)
        app->app_local->extcap.is_v3 = 1;

      /* Read the historical bytes.  */
      relptr = get_one_do (app, 0x5f52, &buffer, &buflen, NULL);
      if (relptr)
        {
          if (opt.verbose)
            {
              log_info ("Historical Bytes: ");
              log_printhex (buffer, buflen, "");
            }
          parse_historical (app->app_local, buffer, buflen);
          xfree (relptr);
        }

      /* Read the force-chv1 flag.  */
      relptr = get_one_do (app, 0x00C4, &buffer, &buflen, NULL);
      if (!relptr)
        {
          log_error (_("can't access %s - invalid OpenPGP card?\n"),
                     "CHV Status Bytes");
          err = gpg_error (GPG_ERR_CARD);
          goto leave;
        }
      app->force_chv1 = (buflen && *buffer == 0);
      xfree (relptr);

      /* Read the extended capabilities.  */
      relptr = get_one_do (app, 0x00C0, &buffer, &buflen, NULL);
      if (!relptr)
        {
          log_error (_("can't access %s - invalid OpenPGP card?\n"),
                     "Extended Capability Flags" );
          err = gpg_error (GPG_ERR_CARD);
          goto leave;
        }
      if (buflen)
        {
          app->app_local->extcap.sm_supported     = !!(*buffer & 0x80);
          app->app_local->extcap.get_challenge    = !!(*buffer & 0x40);
          app->app_local->extcap.key_import       = !!(*buffer & 0x20);
          app->app_local->extcap.change_force_chv = !!(*buffer & 0x10);
          app->app_local->extcap.private_dos      = !!(*buffer & 0x08);
          app->app_local->extcap.algo_attr_change = !!(*buffer & 0x04);
          app->app_local->extcap.has_decrypt      = !!(*buffer & 0x02);
          app->app_local->extcap.kdf_do           = !!(*buffer & 0x01);
        }
      if (buflen >= 10)
        {
          /* Available with cards of v2 or later.  */
          app->app_local->extcap.sm_algo = buffer[1];
          app->app_local->extcap.max_get_challenge
                                               = (buffer[2] << 8 | buffer[3]);
          app->app_local->extcap.max_certlen = (buffer[4] << 8 | buffer[5]);

          /* Interpretation is different between v2 and v3, unfortunately.  */
          if (app->app_local->extcap.is_v3)
            {
              app->app_local->extcap.max_special_do
                = (buffer[6] << 8 | buffer[7]);
              app->app_local->extcap.pin_blk2 = !!(buffer[8] & 0x01);
              app->app_local->extcap.mse= !!(buffer[9] & 0x01);
            }
        }
      xfree (relptr);

      /* Some of the first cards accidentally don't set the
         CHANGE_FORCE_CHV bit but allow it anyway. */
      if (app->appversion <= 0x0100 && manufacturer == 1)
        app->app_local->extcap.change_force_chv = 1;

      /* Check optional DO of "General Feature Management" for button.  */
      relptr = get_one_do (app, 0x7f74, &buffer, &buflen, NULL);
      if (relptr)
        {
          /* It must be: 03 81 01 20 */
          app->app_local->extcap.has_button = 1;
        }

      parse_login_data (app);

      if (opt.verbose)
        show_caps (app->app_local);

      err = parse_algorithm_attribute (app, 0);
      if (!err)
        err = parse_algorithm_attribute (app, 1);
      if (!err)
        err = parse_algorithm_attribute (app, 2);
      if (err)
        goto leave;

      if (opt.verbose > 1)
        dump_all_do (slot);

      app->app_local->override.cache_6e = 0;
      flush_cache_item (app, 0x6E);

      app->fnc.deinit = do_deinit;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.readkey = do_readkey;
      app->fnc.getattr = do_getattr;
      app->fnc.setattr = do_setattr;
      app->fnc.writecert = do_writecert;
      app->fnc.writekey = do_writekey;
      app->fnc.genkey = do_genkey;
      app->fnc.sign = do_sign;
      app->fnc.auth = do_auth;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = do_change_pin;
      app->fnc.check_pin = do_check_pin;
   }

leave:
  if (err)
    do_deinit (app);
  return err;
}

/* card-p15.c - PKCS-15 based card access
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
#include <time.h>

#include <opensc-pkcs15.h>
#include <ksba.h>

#include "scdaemon.h"
#include "card-common.h"





/* See card.c for interface description */
static int
p15_enum_keypairs (CARD card, int idx,
                   unsigned char *keygrip, char **keyid)
{
  int rc;
  KsbaError krc;
  struct sc_pkcs15_object *objs[32], *tmpobj;
  int nobjs;
  struct sc_pkcs15_prkey_info *pinfo;
  struct sc_pkcs15_cert_info *certinfo;
  struct sc_pkcs15_cert      *certder;
  KsbaCert cert;

  rc = sc_pkcs15_get_objects (card->p15card, SC_PKCS15_TYPE_PRKEY_RSA, 
                              objs, DIM (objs));
  if (rc < 0) 
    {
      log_error ("private keys enumeration failed: %s\n", sc_strerror (rc));
      return GNUPG_Card_Error;
    }
  nobjs = rc;
  rc = 0;
  if (idx >= nobjs)
    return -1;
  pinfo = objs[idx]->data;
  
  /* now we need to read the certificate so that we can calculate the
     keygrip */
  rc = sc_pkcs15_find_cert_by_id (card->p15card, &pinfo->id, &tmpobj);
  if (rc)
    {
      log_info ("certificate for private key %d not found: %s\n",
                idx, sc_strerror (rc));
      /* note, that we return the ID anyway */
      rc = GNUPG_Missing_Certificate;
      goto return_keyid;
    }
  certinfo = tmpobj->data;
  rc = sc_pkcs15_read_certificate (card->p15card, certinfo, &certder);
  if (rc)
    {
      log_info ("failed to read certificate for private key %d: %s\n",
                idx, sc_strerror (rc));
      return GNUPG_Card_Error;
    }

  cert = ksba_cert_new ();
  if (!cert)
    {
      sc_pkcs15_free_certificate (certder);
      return GNUPG_Out_Of_Core;
    }
  krc = ksba_cert_init_from_mem (cert, certder->data, certder->data_len);
  sc_pkcs15_free_certificate (certder);
  if (krc)
    {
      log_error ("failed to parse the certificate for private key %d: %s\n",
                 idx, ksba_strerror (krc));
      ksba_cert_release (cert);
      return GNUPG_Card_Error;
    }
  if (card_help_get_keygrip (cert, keygrip))
    {
      log_error ("failed to calculate the keygrip of private key %d\n", idx);
      ksba_cert_release (cert);
      return GNUPG_Card_Error;
    }      
  ksba_cert_release (cert);

  rc = 0;
 return_keyid:
  if (keyid)
    {
      char *p;
      int i;

      *keyid = p = xtrymalloc (9+pinfo->id.len*2+1);
      if (!*keyid)
        return GNUPG_Out_Of_Core;
      p = stpcpy (p, "P15-5015.");
      for (i=0; i < pinfo->id.len; i++, p += 2)
        sprintf (p, "%02X", pinfo->id.value[i]);
      *p = 0;
    }
  
  return rc;
}



static int
idstr_to_id (const char *idstr, struct sc_pkcs15_id *id)
{
  const char *s;
  int n;

  /* For now we only support the standard DF */
  if (strncmp (idstr, "P15-5015.", 9) ) 
    return GNUPG_Invalid_Id;
  for (s=idstr+9, n=0; hexdigitp (s); s++, n++)
    ;
  if (*s || (n&1))
    return GNUPG_Invalid_Id; /* invalid or odd number of digits */
  n /= 2;
  if (!n || n > SC_PKCS15_MAX_ID_SIZE)
    return GNUPG_Invalid_Id; /* empty or too large */
  for (s=idstr+9, n=0; *s; s += 2, n++)
    id->value[n] = xtoi_2 (s);
  id->len = n;
  return 0;
}


/* See card.c for interface description */
static int
p15_read_cert (CARD card, const char *certidstr,
               unsigned char **cert, size_t *ncert)
{
  struct sc_pkcs15_object *tmpobj;
  struct sc_pkcs15_id certid;
  struct sc_pkcs15_cert_info *certinfo;
  struct sc_pkcs15_cert      *certder;
  int rc;

  if (!card || !certidstr || !cert || !ncert)
    return GNUPG_Invalid_Value;
  if (!card->p15card)
    return GNUPG_No_PKCS15_App;

  rc = idstr_to_id (certidstr, &certid);
  if (rc)
    return rc;

  rc = sc_pkcs15_find_cert_by_id (card->p15card, &certid, &tmpobj);
  if (rc)
    {
      log_info ("certificate '%s' not found: %s\n", 
                certidstr, sc_strerror (rc));
      return -1;
    }
  certinfo = tmpobj->data;
  rc = sc_pkcs15_read_certificate (card->p15card, certinfo, &certder);
  if (rc)
    {
      log_info ("failed to read certificate '%s': %s\n",
                certidstr, sc_strerror (rc));
      return GNUPG_Card_Error;
    }

  *cert = xtrymalloc (certder->data_len);
  if (!*cert)
    {
      sc_pkcs15_free_certificate (certder);
      return GNUPG_Out_Of_Core;
    }
  memcpy (*cert, certder->data, certder->data_len);
  *ncert = certder->data_len;
  sc_pkcs15_free_certificate (certder);
  return 0;
}



/* See card.c for interface description */
static int 
p15_sign (CARD card, const char *keyidstr, int hashalgo,
          int (pincb)(void*, const char *, char **),
          void *pincb_arg,
          const void *indata, size_t indatalen,
          void **outdata, size_t *outdatalen )
{
  unsigned int cryptflags = 0;
  struct sc_pkcs15_id keyid;
  struct sc_pkcs15_pin_info *pin;
  struct sc_pkcs15_object *keyobj, *pinobj;
  char *pinvalue;
  int rc;
  unsigned char *outbuf = NULL;
  size_t outbuflen;

  if (hashalgo != GCRY_MD_SHA1)
    return GNUPG_Unsupported_Algorithm;

  rc = idstr_to_id (keyidstr, &keyid);
  if (rc)
    return rc;

  rc = sc_pkcs15_find_prkey_by_id (card->p15card, &keyid, &keyobj);
  if (rc < 0)
    {
      log_error ("private key not found: %s\n", sc_strerror(rc));
      rc = GNUPG_No_Secret_Key;
      goto leave;
    }
  rc = 0;

  rc = sc_pkcs15_find_pin_by_auth_id (card->p15card,
                                      &keyobj->auth_id, &pinobj);
  if (rc)
    {
      log_error ("failed to find PIN by auth ID: %s\n", sc_strerror (rc));
      rc = GNUPG_Bad_PIN_Method;
      goto leave;
    }
  pin = pinobj->data;

  /* Fixme: pack this into a verification loop */
  /* Fixme: we might want to pass pin->min_length and 
     pin->stored_length */
  rc = pincb (pincb_arg, pinobj->label, &pinvalue);
  if (rc)
    {
      log_info ("PIN callback returned error: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  rc = sc_pkcs15_verify_pin (card->p15card, pin,
                             pinvalue, strlen (pinvalue));
  xfree (pinvalue);
  if (rc)
    {
      log_info ("PIN verification failed: %s\n", sc_strerror (rc));
      rc = GNUPG_Bad_PIN;
      goto leave;
    }

/*    cryptflags |= SC_PKCS15_HASH_SHA1; */
/*    cryptflags |= SC_PKCS15_PAD_PKCS1_V1_5; */

  outbuflen = 1024; 
  outbuf = xtrymalloc (outbuflen);
  if (!outbuf)
    return GNUPG_Out_Of_Core;
  
  rc = sc_pkcs15_compute_signature (card->p15card, keyobj,
                                    cryptflags,
                                    indata, indatalen,
                                    outbuf, outbuflen );
  if (rc < 0)
    {
      log_error ("failed to create signature: %s\n", sc_strerror (rc));
      rc = GNUPG_Card_Error;
    }
  else
    {
      *outdatalen = rc;
      *outdata = outbuf;
      outbuf = NULL;
      rc = 0;
    }


leave:
  xfree (outbuf);
  return rc;
}


/* See card.c for description */
static int 
p15_decipher (CARD card, const char *keyidstr,
              int (pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              void **outdata, size_t *outdatalen )
{
  struct sc_pkcs15_id keyid;
  struct sc_pkcs15_pin_info *pin;
  struct sc_pkcs15_object *keyobj, *pinobj;
  char *pinvalue;
  int rc;
  unsigned char *outbuf = NULL;
  size_t outbuflen;

  rc = idstr_to_id (keyidstr, &keyid);
  if (rc)
    return rc;

  rc = sc_pkcs15_find_prkey_by_id (card->p15card, &keyid, &keyobj);
  if (rc < 0)
    {
      log_error ("private key not found: %s\n", sc_strerror(rc));
      rc = GNUPG_No_Secret_Key;
      goto leave;
    }
  rc = 0;

  rc = sc_pkcs15_find_pin_by_auth_id (card->p15card,
                                      &keyobj->auth_id, &pinobj);
  if (rc)
    {
      log_error ("failed to find PIN by auth ID: %s\n", sc_strerror (rc));
      rc = GNUPG_Bad_PIN_Method;
      goto leave;
    }
  pin = pinobj->data;

  /* Fixme: pack this into a verification loop */
  /* Fixme: we might want to pass pin->min_length and 
     pin->stored_length */
  rc = pincb (pincb_arg, pinobj->label, &pinvalue);
  if (rc)
    {
      log_info ("PIN callback returned error: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  rc = sc_pkcs15_verify_pin (card->p15card, pin,
                             pinvalue, strlen (pinvalue));
  xfree (pinvalue);
  if (rc)
    {
      log_info ("PIN verification failed: %s\n", sc_strerror (rc));
      rc = GNUPG_Bad_PIN;
      goto leave;
    }

  outbuflen = indatalen < 256? 256 : indatalen; 
  outbuf = xtrymalloc (outbuflen);
  if (!outbuf)
    return GNUPG_Out_Of_Core;

  /* OpenSC does not yet support decryption for cryptflex cards */  
/*    rc = sc_pkcs15_decipher (card->p15card, key, */
/*                             indata, indatalen, */
/*                             outbuf, outbuflen); */
  rc = sc_pkcs15_compute_signature (card->p15card, keyobj,
                                    0,
                                    indata, indatalen,
                                    outbuf, outbuflen );
  if (rc < 0)
    {
      log_error ("failed to decipger the data: %s\n", sc_strerror (rc));
      rc = GNUPG_Card_Error;
    }
  else
    {
      *outdatalen = rc;
      *outdata = outbuf;
      outbuf = NULL;
      rc = 0;
    }


leave:
  xfree (outbuf);
  return rc;
}




/* Bind our operations to the card */
void
card_p15_bind (CARD card)
{
  card->fnc.enum_keypairs = p15_enum_keypairs;
  card->fnc.read_cert     = p15_read_cert;
  card->fnc.sign          = p15_sign;
  card->fnc.decipher      = p15_decipher;
}

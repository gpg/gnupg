/* card-p15.c - PKCS-15 based card access
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
#include <time.h>

#ifdef HAVE_OPENSC
#include <opensc/pkcs15.h>

#include "scdaemon.h"
#include <ksba.h>
#include "card-common.h"


struct p15private_s {
  int n_prkey_rsa_objs;
  struct sc_pkcs15_object *prkey_rsa_objs[32];
  int n_cert_objs;
  struct sc_pkcs15_object *cert_objs[32];
};


/* Allocate private data. */
static int 
init_private_data (CARD card)
{
  struct p15private_s *priv;
  int rc;

  if (card->p15priv)
    return 0; /* already done. */

  priv = xtrycalloc (1, sizeof *priv);
  if (!priv)
    return gpg_error (gpg_err_code_from_errno (errno));

  /* OpenSC (0.7.0) is a bit strange in that the get_objects functions
     tries to be a bit too clever and implicitly does an enumeration
     which eventually leads to the fact that every call to this
     fucntion returns one more macthing object.  The old code in
     p15_enum_keypairs assume that it would alwyas return the same
     numer of objects and used this to figure out what the last object
     enumerated is.  We now do an enum_objects just once and keep it
     in the private data. */
  rc = sc_pkcs15_get_objects (card->p15card, SC_PKCS15_TYPE_PRKEY_RSA, 
                              priv->prkey_rsa_objs,
                              DIM (priv->prkey_rsa_objs));
  if (rc < 0) 
    {
      log_error ("private keys enumeration failed: %s\n", sc_strerror (rc));
      xfree (priv);
      return gpg_error (GPG_ERR_CARD);
    }
  priv->n_prkey_rsa_objs = rc;

  /* Read all certificate objects. */
  rc = sc_pkcs15_get_objects (card->p15card, SC_PKCS15_TYPE_CERT_X509, 
                              priv->cert_objs,
                              DIM (priv->cert_objs));
  if (rc < 0) 
    {
      log_error ("private keys enumeration failed: %s\n", sc_strerror (rc));
      xfree (priv);
      return gpg_error (GPG_ERR_CARD);
    }
  priv->n_cert_objs = rc;

  card->p15priv = priv;
  return 0;
}


/* Release private data used in this module. */
void
p15_release_private_data (CARD card)
{
  if (!card->p15priv)
    return;
  xfree (card->p15priv);
  card->p15priv = NULL;
}



/* See card.c for interface description */
static int
p15_enum_keypairs (CARD card, int idx,
                   unsigned char *keygrip, char **keyid)
{
  int rc;
  struct p15private_s *priv;
  struct sc_pkcs15_object *tmpobj;
  int nobjs;
  struct sc_pkcs15_prkey_info *pinfo;
  struct sc_pkcs15_cert_info *certinfo;
  struct sc_pkcs15_cert      *certder;
  ksba_cert_t cert;

  rc = init_private_data (card);
  if (rc) 
      return rc;
  priv = card->p15priv;
  nobjs = priv->n_prkey_rsa_objs;
  rc = 0;
  if (idx >= nobjs)
    return -1;
  pinfo = priv->prkey_rsa_objs[idx]->data;
  
  /* now we need to read the certificate so that we can calculate the
     keygrip */
  rc = sc_pkcs15_find_cert_by_id (card->p15card, &pinfo->id, &tmpobj);
  if (rc)
    {
      log_info ("certificate for private key %d not found: %s\n",
                idx, sc_strerror (rc));
      /* note, that we return the ID anyway */
      rc = gpg_error (GPG_ERR_MISSING_CERT);
      goto return_keyid;
    }
  certinfo = tmpobj->data;
  rc = sc_pkcs15_read_certificate (card->p15card, certinfo, &certder);
  if (rc)
    {
      log_info ("failed to read certificate for private key %d: %s\n",
                idx, sc_strerror (rc));
      return gpg_error (GPG_ERR_CARD);
    }

  rc = ksba_cert_new (&cert);
  if (rc)
    {
      sc_pkcs15_free_certificate (certder);
      return rc;
    }
  rc = ksba_cert_init_from_mem (cert, certder->data, certder->data_len);
  sc_pkcs15_free_certificate (certder);
  if (rc)
    {
      log_error ("failed to parse the certificate for private key %d: %s\n",
                 idx, gpg_strerror (rc));
      ksba_cert_release (cert);
      return rc;
    }
  if (card_help_get_keygrip (cert, keygrip))
    {
      log_error ("failed to calculate the keygrip of private key %d\n", idx);
      ksba_cert_release (cert);
      return gpg_error (GPG_ERR_CARD);
    }      
  ksba_cert_release (cert);

  rc = 0;
 return_keyid:
  if (keyid)
    {
      char *p;

      *keyid = p = xtrymalloc (9+pinfo->id.len*2+1);
      if (!*keyid)
        return gpg_error (gpg_err_code_from_errno (errno));
      p = stpcpy (p, "P15-5015.");
      bin2hex (pinfo->id.value, pinfo->id.len, p);
    }
  
  return rc;
}

/* See card.c for interface description */
static int
p15_enum_certs (CARD card, int idx, char **certid, int *type)
{
  int rc;
  struct p15private_s *priv;
  struct sc_pkcs15_object *obj;
  struct sc_pkcs15_cert_info *cinfo;
  int nobjs;

  rc = init_private_data (card);
  if (rc) 
      return rc;
  priv = card->p15priv;
  nobjs = priv->n_cert_objs;
  rc = 0;
  if (idx >= nobjs)
    return -1;
  obj =  priv->cert_objs[idx];
  cinfo = obj->data;
  
  if (certid)
    {
      char *p;
      int i;

      *certid = p = xtrymalloc (9+cinfo->id.len*2+1);
      if (!*certid)
        return gpg_error (gpg_err_code_from_errno (errno));
      p = stpcpy (p, "P15-5015.");
      bin2hex (cinfo->id.value, cinfo->id.len, p);
    }
  if (type)
    {
      if (!obj->df)
        *type = 0; /* unknown */
      else if (obj->df->type == SC_PKCS15_CDF)
        *type = 100;
      else if (obj->df->type == SC_PKCS15_CDF_TRUSTED)
        *type = 101;
      else if (obj->df->type == SC_PKCS15_CDF_USEFUL)
        *type = 102;
      else 
        *type = 0; /* error -> unknown */
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
    return gpg_error (GPG_ERR_INV_ID);
  for (s=idstr+9, n=0; hexdigitp (s); s++, n++)
    ;
  if (*s || (n&1))
    return gpg_error (GPG_ERR_INV_ID); /*invalid or odd number of digits*/
  n /= 2;
  if (!n || n > SC_PKCS15_MAX_ID_SIZE)
    return gpg_error (GPG_ERR_INV_ID); /* empty or too large */
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
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!card->p15card)
    return gpg_error (GPG_ERR_NO_PKCS15_APP);

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
      return gpg_error (GPG_ERR_CARD);
    }

  *cert = xtrymalloc (certder->data_len);
  if (!*cert)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      sc_pkcs15_free_certificate (certder);
      return tmperr;
    }
  memcpy (*cert, certder->data, certder->data_len);
  *ncert = certder->data_len;
  sc_pkcs15_free_certificate (certder);
  return 0;
}





static int
p15_prepare_key (CARD card, const char *keyidstr,
                 int (pincb)(void*, const char *, char **),
                 void *pincb_arg, struct sc_pkcs15_object **r_keyobj)
{
  struct sc_pkcs15_id keyid;
  struct sc_pkcs15_pin_info *pin;
  struct sc_pkcs15_object *keyobj, *pinobj;
  char *pinvalue;
  int rc;

  rc = idstr_to_id (keyidstr, &keyid);
  if (rc)
    return rc;

  rc = sc_pkcs15_find_prkey_by_id (card->p15card, &keyid, &keyobj);
  if (rc < 0)
    {
      log_error ("private key not found: %s\n", sc_strerror(rc));
      return gpg_error (GPG_ERR_NO_SECKEY);
    }

  rc = sc_pkcs15_find_pin_by_auth_id (card->p15card,
                                      &keyobj->auth_id, &pinobj);
  if (rc)
    {
      log_error ("failed to find PIN by auth ID: %s\n", sc_strerror (rc));
      return gpg_error (GPG_ERR_BAD_PIN_METHOD);
    }
  pin = pinobj->data;

  /* Fixme: pack this into a verification loop */
  /* Fixme: we might want to pass pin->min_length and 
     pin->stored_length */
  rc = pincb (pincb_arg, pinobj->label, &pinvalue);
  if (rc)
    {
      log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
      return rc;
    }

  rc = sc_pkcs15_verify_pin (card->p15card, pin,
                             pinvalue, strlen (pinvalue));
  xfree (pinvalue);
  if (rc)
    {
      log_info ("PIN verification failed: %s\n", sc_strerror (rc));
      return gpg_error (GPG_ERR_BAD_PIN);
    }

  /* fixme: check wheter we need to release KEYOBJ in case of an error */
  *r_keyobj = keyobj;
  return 0;
}


/* See card.c for interface description */
static int 
p15_sign (CARD card, const char *keyidstr, int hashalgo,
          int (pincb)(void*, const char *, char **),
          void *pincb_arg,
          const void *indata, size_t indatalen,
          unsigned char **outdata, size_t *outdatalen )
{
  unsigned int cryptflags;
  struct sc_pkcs15_object *keyobj;
  int rc;
  unsigned char *outbuf = NULL;
  size_t outbuflen;

  if (hashalgo != GCRY_MD_SHA1)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  rc = p15_prepare_key (card, keyidstr, pincb, pincb_arg, &keyobj);
  if (rc)
    return rc;

  cryptflags = SC_ALGORITHM_RSA_PAD_PKCS1;

  outbuflen = 1024; 
  outbuf = xtrymalloc (outbuflen);
  if (!outbuf)
    return gpg_error (gpg_err_code_from_errno (errno));
  
  rc = sc_pkcs15_compute_signature (card->p15card, keyobj,
                                    cryptflags,
                                    indata, indatalen,
                                    outbuf, outbuflen );
  if (rc < 0)
    {
      log_error ("failed to create signature: %s\n", sc_strerror (rc));
      rc = gpg_error (GPG_ERR_CARD);
    }
  else
    {
      *outdatalen = rc;
      *outdata = outbuf;
      outbuf = NULL;
      rc = 0;
    }

  xfree (outbuf);
  return rc;
}


/* See card.c for description */
static int 
p15_decipher (CARD card, const char *keyidstr,
              int (pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              unsigned char **outdata, size_t *outdatalen )
{
  struct sc_pkcs15_object *keyobj;
  int rc;
  unsigned char *outbuf = NULL;
  size_t outbuflen;

  rc = p15_prepare_key (card, keyidstr, pincb, pincb_arg, &keyobj);
  if (rc)
    return rc;

  if (card && card->scard && card->scard->driver
      && !strcasecmp (card->scard->driver->short_name, "tcos"))
    {
      /* very ugly hack to force the use of a local key.  We need this
         until we have fixed the initialization code for TCOS cards */
      struct sc_pkcs15_prkey_info *prkey = keyobj->data;
      if ( !(prkey->key_reference & 0x80))
        {
          prkey->key_reference |= 0x80;
          log_debug ("using TCOS hack to force the use of local keys\n");
        }
      if (*keyidstr && keyidstr[strlen(keyidstr)-1] == '6')
        {
          prkey->key_reference |= 1;
          log_debug ("warning: using even more TCOS hacks\n");
        }
    }

  outbuflen = indatalen < 256? 256 : indatalen; 
  outbuf = xtrymalloc (outbuflen);
  if (!outbuf)
    return gpg_error (gpg_err_code_from_errno (errno));

  rc = sc_pkcs15_decipher (card->p15card, keyobj, 
                           0,
                           indata, indatalen, 
                           outbuf, outbuflen); 
  if (rc < 0)
    {
      log_error ("failed to decipher the data: %s\n", sc_strerror (rc));
      rc = gpg_error (GPG_ERR_CARD);
    }
  else
    {
      *outdatalen = rc;
      *outdata = outbuf;
      outbuf = NULL;
      rc = 0;
    }

  xfree (outbuf);
  return rc;
}



/* Bind our operations to the card */
void
card_p15_bind (CARD card)
{
  card->fnc.enum_keypairs = p15_enum_keypairs;
  card->fnc.enum_certs    = p15_enum_certs;
  card->fnc.read_cert     = p15_read_cert;
  card->fnc.sign          = p15_sign;
  card->fnc.decipher      = p15_decipher;
}
#endif /*HAVE_OPENSC*/

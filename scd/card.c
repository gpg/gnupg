/* card.c - SCdaemon card functions
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



struct card_ctx_s {
  int reader;   /* used reader */
  struct sc_context *ctx;
  struct sc_card *scard;
  struct sc_pkcs15_card *p15card; /* only if there is a pkcs15 application */
  
};

/* Map the SC error codes to the GNUPG ones */
static int
map_sc_err (int rc)
{
  switch (rc)
    {
    case 0: rc = 0; break;
    case SC_ERROR_CMD_TOO_SHORT:         rc = GNUPG_Card_Error; break;
    case SC_ERROR_CMD_TOO_LONG:          rc = GNUPG_Card_Error; break;
    case SC_ERROR_NOT_SUPPORTED:         rc = GNUPG_Not_Supported; break;
    case SC_ERROR_TRANSMIT_FAILED:       rc = GNUPG_Card_Error; break;
    case SC_ERROR_FILE_NOT_FOUND:        rc = GNUPG_Card_Error; break;
    case SC_ERROR_INVALID_ARGUMENTS:     rc = GNUPG_Card_Error; break;
    case SC_ERROR_PKCS15_APP_NOT_FOUND:  rc = GNUPG_No_PKCS15_App; break;
    case SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND: rc = GNUPG_Card_Error; break;
    case SC_ERROR_OUT_OF_MEMORY:         rc = GNUPG_Out_Of_Core; break;
    case SC_ERROR_NO_READERS_FOUND:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_OBJECT_NOT_VALID:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_ILLEGAL_RESPONSE:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_PIN_CODE_INCORRECT:    rc = GNUPG_Card_Error; break;
    case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED: rc = GNUPG_Card_Error; break;
    case SC_ERROR_CONNECTING_TO_RES_MGR: rc = GNUPG_Card_Error; break;
    case SC_ERROR_INVALID_ASN1_OBJECT:   rc = GNUPG_Card_Error; break;
    case SC_ERROR_BUFFER_TOO_SMALL:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_CARD_NOT_PRESENT:      rc = GNUPG_Card_Not_Present; break;
    case SC_ERROR_RESOURCE_MANAGER:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_CARD_REMOVED:          rc = GNUPG_Card_Removed; break;
    case SC_ERROR_INVALID_PIN_LENGTH:    rc = GNUPG_Card_Error; break;
    case SC_ERROR_UNKNOWN_SMARTCARD:     rc = GNUPG_Card_Error; break;
    case SC_ERROR_UNKNOWN_REPLY:         rc = GNUPG_Card_Error; break;
    case SC_ERROR_OBJECT_NOT_FOUND:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_CARD_RESET:            rc = GNUPG_Card_Reset; break;
    case SC_ERROR_ASN1_OBJECT_NOT_FOUND: rc = GNUPG_Card_Error; break;
    case SC_ERROR_ASN1_END_OF_CONTENTS:  rc = GNUPG_Card_Error; break;
    case SC_ERROR_TOO_MANY_OBJECTS:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_INVALID_CARD:          rc = GNUPG_Invalid_Card; break;
    case SC_ERROR_WRONG_LENGTH:          rc = GNUPG_Card_Error; break;
    case SC_ERROR_RECORD_NOT_FOUND:      rc = GNUPG_Card_Error; break;
    case SC_ERROR_INTERNAL:              rc = GNUPG_Card_Error; break;
    default: rc = GNUPG_Card_Error; break;
    }
  return rc;
}


/* Create a new context for the card and figures out some basic
   information of the card.  Detects whether a PKCS_15 application is
   stored.

   Common errors: GNUPG_Card_Not_Present */
int
card_open (CARD *rcard)
{
  CARD card;
  int rc;

  card = xtrycalloc (1, sizeof *card);
  if (!card)
    return GNUPG_Out_Of_Core;
  card->reader = 0;
  
  rc = sc_establish_context (&card->ctx);
  if (rc)
    {
      log_error ("failed to establish SC context: %s\n", sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }
  if (card->reader >= card->ctx->reader_count)
    {
      log_error ("no card reader available\n");
      rc = GNUPG_Card_Error;
    }
  card->ctx->error_file = log_get_stream ();
  card->ctx->debug_file = log_get_stream ();
  if (sc_detect_card_presence (card->ctx->reader[card->reader], 0) != 1)
    {
      rc = GNUPG_Card_Not_Present;
      goto leave;
    }

  rc = sc_connect_card (card->ctx->reader[card->reader], 0, &card->scard);
  if (rc)
    {
      log_error ("failed to connect card in reader %d: %s\n",
                 card->reader, sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }
  if (opt.verbose)
    log_info ("connected to card in reader %d using driver `%s'\n",
              card->reader, card->scard->driver->name);

  rc = sc_lock (card->scard);
  if (rc)
    {
      log_error ("can't lock card in reader %d: %s\n",
                 card->reader, sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }

  rc = sc_pkcs15_bind (card->scard, &card->p15card);
  if (rc == SC_ERROR_PKCS15_APP_NOT_FOUND)
    rc = 0; /* okay */
  else if (rc)
    {
      log_error ("binding of existing PKCS-15 failed in reader %d: %s\n",
                 card->reader, sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }
    
 leave:
  if (rc)
    card_close (card);
  else
    *rcard = card;
  return rc;
}


/* Close a card and release all resources */
void
card_close (CARD card)
{
  if (card)
    {
      if (card->p15card)
        {
          sc_pkcs15_unbind (card->p15card);
          card->p15card = NULL;
        }
      if (card->scard)
        {
          sc_unlock (card->scard);
          sc_disconnect_card (card->scard, 0);
          card->scard = NULL;
	}
      if (card->ctx)
        {
          sc_destroy_context (card->ctx);
          card->ctx = NULL;
        }
      xfree (card);
    }      
}

/* Retrieve the serial number and the time of the last update of the
   card.  The serial number is returned as a malloced string (hex
   encoded) in SERIAL and the time of update is returned in STAMP.
   If no update time is available the returned value is 0.  The serial
   is mandatory for a PKCS_15 application and an error will be
   returned if this value is not availbale.  For non-PKCS-15 cards a
   serial number is constructed by other means. Caller must free
   SERIAL unless the fucntion returns an error. */
int 
card_get_serial_and_stamp (CARD card, char **serial, time_t *stamp)
{
  char *s;

  if (!card || !serial || !stamp)
    return GNUPG_Invalid_Value;

  *serial = NULL;
  *stamp = 0; /* not available */
  if (!card->p15card)
    { /* fixme: construct a serial number */
      /* We should lookup the iso 7812-1 and 8583-3 - argh ISO practice is
         suppressing innovation - IETF rules! */
      return GNUPG_No_PKCS15_App;
    }
  s = card->p15card->serial_number;
  if (!s || !hexdigitp (s) )
    return GNUPG_Invalid_Card; /* the serial number is mandatory */
  *serial = xstrdup (s);
  if (!*serial)
    return GNUPG_Out_Of_Core;
  return 0;
}



/* Get the keygrip from CERT, return 0 on success */
static int
get_keygrip (KsbaCert cert, unsigned char *array)
{
  GCRY_SEXP s_pkey;
  int rc;
  KsbaSexp p;
  size_t n;
  
  p = ksba_cert_get_public_key (cert);
  if (!p)
    return -1; /* oops */
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    return -1; /* libksba did not return a proper S-expression */
  rc = gcry_sexp_sscan ( &s_pkey, NULL, p, n);
  xfree (p);
  if (rc)
    return -1; /* can't parse that S-expression */
  array = gcry_pk_get_keygrip (s_pkey, array);
  gcry_sexp_release (s_pkey);
  if (!array)
    return -1; /* failed to calculate the keygrip */
  return 0;
}



/* Enumerate all keypairs on the card and return the Keygrip as well
   as the internal identification of the key.  KEYGRIP must be a
   caller provided buffer with a size of 20 bytes which will receive
   the KEYGRIP of the keypair.  If KEYID is not NULL, it returns the
   ID field of the key in allocated memory, NKEYID will then receive
   the length of it.  The function returns -1 when all keys have been
   enumerated.  Note that the error GNUPG_Missing_Certificate may be
   returned if there is just the private key but no public key (ie.e a
   certificate) available.  Applications might want to continue
   enumerating after this error.*/
int
card_enum_keypairs (CARD card, int idx,
                    unsigned char *keygrip,
                    unsigned char **keyid, size_t *nkeyid)
{
  int rc;
  KsbaError krc;
  struct sc_pkcs15_object *objs[32], *tmpobj;
  int nobjs;
  struct sc_pkcs15_prkey_info *pinfo;
  struct sc_pkcs15_cert_info *certinfo;
  struct sc_pkcs15_cert      *certder;
  KsbaCert cert;

  if (keyid)
    *keyid = NULL;
  if (nkeyid)
    *nkeyid = 0;

  if (!card || !keygrip || !card->p15card)
    return GNUPG_Invalid_Value;
  if (idx < 0)
    return GNUPG_Invalid_Index;
	
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
      /* but we should return the ID anyway */
      if (keyid)
        {
          *keyid = xtrymalloc (pinfo->id.len);
          if (!*keyid)
            return GNUPG_Out_Of_Core;
          memcpy (*keyid, pinfo->id.value, pinfo->id.len);
        }
      if (nkeyid)
        *nkeyid = pinfo->id.len;
      return GNUPG_Missing_Certificate;
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
  if (get_keygrip (cert, keygrip))
    {
      log_error ("failed to calculate the keygrip of private key %d\n", idx);
      ksba_cert_release (cert);
      return GNUPG_Card_Error;
    }      
  ksba_cert_release (cert);

  /* return the iD */
  if (keyid)
    {
      *keyid = xtrymalloc (pinfo->id.len);
      if (!*keyid)
        return GNUPG_Out_Of_Core;
      memcpy (*keyid, pinfo->id.value, pinfo->id.len);
    }
  if (nkeyid)
    *nkeyid = pinfo->id.len;
  
  return 0;
}



static int
idstr_to_id (const char *idstr, struct sc_pkcs15_id *id)
{
  const char *s;
  int n;

  /* For now we only support the standard DF */
  if (strncmp (idstr, "3F005015.", 9) ) 
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

/* Read the certificate identified by CERTIDSTR which is the
   hexadecimal encoded ID of the certificate, prefixed with the string
   "3F005015.". The certificate is return in DER encoded form in CERT
   and NCERT. */
int
card_read_cert (CARD card, const char *certidstr,
                unsigned char **cert, size_t *ncert)
{
  struct sc_pkcs15_object *tmpobj;
  struct sc_pkcs15_id certid;
  struct sc_pkcs15_cert_info *certinfo;
  struct sc_pkcs15_cert      *certder;
  int rc;

  if (!card || !certidstr || !card->p15card || !cert || !ncert)
    return GNUPG_Invalid_Value;

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



/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
int 
card_create_signature (CARD card, const char *keyidstr, int hashalgo,
                       int (pincb)(void*, const char *, char **),
                       void *pincb_arg,
                       const void *indata, size_t indatalen,
                       void **outdata, size_t *outdatalen )
{
  unsigned int cryptflags = 0;
  struct sc_pkcs15_id keyid;
  struct sc_pkcs15_prkey_info *key;
  struct sc_pkcs15_pin_info *pin;
  struct sc_pkcs15_object *keyobj, *pinobj;
  char *pinvalue;
  int rc;
  unsigned char *outbuf = NULL;
  size_t outbuflen;

  if (!card || !card->p15card || !indata || !indatalen
      || !outdata || !outdatalen || !pincb)
    return GNUPG_Invalid_Value;
  
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
  key = keyobj->data;

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
  
  rc = sc_pkcs15_compute_signature (card->p15card, key,
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



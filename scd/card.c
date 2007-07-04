/* card.c - SCdaemon card functions
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
#endif

#include "scdaemon.h"
#include <ksba.h>

#include "card-common.h"

/* Map the SC error codes to the GNUPG ones */
gpg_error_t
map_sc_err (int rc)
{
  gpg_err_code_t e;

  switch (rc)
    {
    case 0: e = 0; break;
#ifdef HAVE_OPENSC
    case SC_ERROR_NOT_SUPPORTED:         e = GPG_ERR_NOT_SUPPORTED; break;
    case SC_ERROR_PKCS15_APP_NOT_FOUND:  e = GPG_ERR_NO_PKCS15_APP; break;
    case SC_ERROR_OUT_OF_MEMORY:         e = GPG_ERR_ENOMEM; break;
    case SC_ERROR_CARD_NOT_PRESENT:      e = GPG_ERR_CARD_NOT_PRESENT; break;
    case SC_ERROR_CARD_REMOVED:          e = GPG_ERR_CARD_REMOVED; break;
    case SC_ERROR_INVALID_CARD:          e = GPG_ERR_INV_CARD; break;
#endif
    default: e = GPG_ERR_CARD; break;
    }
  /* It does not make much sense to further distingusih the error
     source between OpenSC and SCD.  Thus we use SCD as source
     here. */
  return gpg_err_make (GPG_ERR_SOURCE_SCD, e);
}

/* Get the keygrip from CERT, return 0 on success */
int
card_help_get_keygrip (ksba_cert_t cert, unsigned char *array)
{
  gcry_sexp_t s_pkey;
  int rc;
  ksba_sexp_t p;
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







/* Create a new context for the card and figures out some basic
   information of the card.  Detects whether a PKCS_15 application is
   stored.

   Common errors: GPG_ERR_CARD_NOT_PRESENT */
int
card_open (CARD *rcard)
{
#ifdef HAVE_OPENSC
  CARD card;
  int rc;

  if (opt.disable_opensc)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  card = xtrycalloc (1, sizeof *card);
  if (!card)
    return gpg_error (gpg_err_code_from_errno (errno));
  card->reader = 0;
  
  rc = sc_establish_context (&card->ctx, "scdaemon");
  if (rc)
    {
      log_error ("failed to establish SC context: %s\n", sc_strerror (rc));
      rc = map_sc_err (rc);
      goto leave;
    }
  if (card->reader >= card->ctx->reader_count)
    {
      log_error ("no card reader available\n");
      rc = gpg_error (GPG_ERR_CARD);
      goto leave;
    }
  card->ctx->error_file = log_get_stream ();
  card->ctx->debug = opt.debug_sc;
  card->ctx->debug_file = log_get_stream ();

  if (sc_detect_card_presence (card->ctx->reader[card->reader], 0) != 1)
    {
      rc = gpg_error (GPG_ERR_CARD_NOT_PRESENT);
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

    
 leave:
  if (rc)
    card_close (card);
  else
    *rcard = card;

  return rc;
#else
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif
}


/* Close a card and release all resources */
void
card_close (CARD card)
{
  if (card)
    {
#ifdef HAVE_OPENSC
      if (card->p15card)
        {
          sc_pkcs15_unbind (card->p15card);
          card->p15card = NULL;
        }
      if (card->p15priv)
        p15_release_private_data (card);
      if (card->scard)
        {
          sc_unlock (card->scard);
          sc_disconnect_card (card->scard, 0);
          card->scard = NULL;
	}
      if (card->ctx)
        {
          sc_release_context (card->ctx);
          card->ctx = NULL;
        }
#endif
      xfree (card);
    }      
}

/* Locate a simple TLV encoded data object in BUFFER of LENGTH and
   return a pointer to value as well as its length in NBYTES.  Return
   NULL if it was not found.  Note, that the function does not check
   whether the value fits into the provided buffer. */
#ifdef HAVE_OPENSC
static const char *
find_simple_tlv (const unsigned char *buffer, size_t length,
                 int tag, size_t *nbytes)
{
  const char *s = buffer;
  size_t n = length;
  size_t len;
    
  for (;;)
    {
      buffer = s;
      if (n < 2)
        return NULL; /* buffer too short for tag and length. */
      len = s[1];
      s += 2; n -= 2;
      if (len == 255)
        {
          if (n < 2)
            return NULL; /* we expected 2 more bytes with the length. */
          len = (s[0] << 8) | s[1];
          s += 2; n -= 2;
        }
      if (*buffer == tag)
        {
          *nbytes = len;
          return s;
        }
      if (len > n)
        return NULL; /* buffer too short to skip to the next tag. */
      s += len; n -= len;
    }
}
#endif /*HAVE_OPENSC*/

/* Find the ICC Serial Number within the provided BUFFER of LENGTH
   (which should contain the GDO file) and return it as a hex encoded
   string and allocated string in SERIAL.  Return an error code when
   the ICCSN was not found. */
#ifdef HAVE_OPENSC
static int
find_iccsn (const unsigned char *buffer, size_t length, char **serial)
{
  size_t n;
  const unsigned char *s;
  char *p;

  s = find_simple_tlv (buffer, length, 0x5A, &n);
  if (!s)
    return gpg_error (GPG_ERR_CARD);
  length -= s - buffer;
  if (n > length)
    {
      /* Oops, it does not fit into the buffer.  This is an invalid
         encoding (or the buffer is too short.  However, I have some
         test cards with such an invalid encoding and therefore I use
         this ugly workaround to return something I can further
         experiment with. */
      if (n == 0x0D && length+1 == n)
        {
          log_debug ("enabling BMI testcard workaround\n");
          n--;
        }
      else
        return gpg_error (GPG_ERR_CARD); /* Bad encoding; does
					    not fit into buffer. */
    }
  if (!n)
    return gpg_error (GPG_ERR_CARD); /* Well, that is too short. */

  *serial = p = xtrymalloc (2*n+1);
  if (!*serial)
    return gpg_error (gpg_err_code_from_errno (errno));
  for (; n; n--, p += 2, s++)
    sprintf (p, "%02X", *s);
  *p = 0;
  return 0;
}
#endif /*HAVE_OPENSC*/

/* Retrieve the serial number and the time of the last update of the
   card.  The serial number is returned as a malloced string (hex
   encoded) in SERIAL and the time of update is returned in STAMP.
   If no update time is available the returned value is 0.  The serial
   is mandatory for a PKCS_15 application and an error will be
   returned if this value is not availbale.  For non-PKCS-15 cards a
   serial number is constructed by other means. Caller must free
   SERIAL unless the function returns an error. */
int 
card_get_serial_and_stamp (CARD card, char **serial, time_t *stamp)
{
#ifdef HAVE_OPENSC
  int rc;
  struct sc_path path;
  struct sc_file *file;
  unsigned char buf[256];
  int buflen;
#endif

  if (!card || !serial || !stamp)
    return gpg_error (GPG_ERR_INV_VALUE);

  *serial = NULL;
  *stamp = 0; /* not available */

#ifdef HAVE_OPENSC
  if (!card->fnc.initialized)
    {
      card->fnc.initialized = 1;
      /* The first use of this card tries to figure out the type of the card 
         and sets up the function pointers. */
      rc = sc_pkcs15_bind (card->scard, &card->p15card);
      if (rc)
        {
          if (rc != SC_ERROR_PKCS15_APP_NOT_FOUND)
            log_error ("binding of existing PKCS-15 failed in reader %d: %s\n",
                       card->reader, sc_strerror (rc));
          card->p15card = NULL;
          rc = 0;
        }
      if (card->p15card)
        card_p15_bind (card);
      card->fnc.initialized = 1;
    }
      

  /* We should lookup the iso 7812-1 and 8583-3 - argh ISO
     practice is suppressing innovation - IETF rules!  So we
     always get the serialnumber from the 2F02 GDO file.  */
  /* FIXME: in case we can't parse the 2F02 EF and we have a P15 card,
     we should get the serial number from the respective P15 file */
  sc_format_path ("3F002F02", &path);
  rc = sc_select_file (card->scard, &path, &file);
  if (rc)
    {
      log_error ("sc_select_file failed: %s\n", sc_strerror (rc));
      return gpg_error (GPG_ERR_CARD);
    }
  if (file->type != SC_FILE_TYPE_WORKING_EF
      || file->ef_structure != SC_FILE_EF_TRANSPARENT)
    {
      log_error ("wrong type or structure of GDO file\n");
      sc_file_free (file);
      return gpg_error (GPG_ERR_CARD);
    }

  if (!file->size || file->size >= DIM(buf) )
    { /* FIXME: Use a real parser */
      log_error ("unsupported size of GDO file (%d)\n", file->size);
      sc_file_free (file);
      return gpg_error (GPG_ERR_CARD);
    }
  buflen = file->size;
      
  rc = sc_read_binary (card->scard, 0, buf, buflen, 0);
  sc_file_free (file);
  if (rc < 0) 
    {
      log_error ("error reading GDO file: %s\n", sc_strerror (rc));
      return gpg_error (GPG_ERR_CARD);
    }
  if (rc != buflen)
    {
      log_error ("short read on GDO file\n");
      return gpg_error (GPG_ERR_CARD);
    }

  rc = find_iccsn (buf, buflen, serial);
  if (gpg_err_code (rc) == GPG_ERR_CARD)
    log_error ("invalid structure of GDO file\n");
  if (!rc && card->p15card && !strcmp (*serial, "D27600000000000000000000"))
    { /* This is a German card with a silly serial number.  Try to get
         the serial number from the EF(TokenInfo). We indicate such a
         serial number by the using the prefix: "FF0100". */
      const char *efser = card->p15card->serial_number;
      char *p;

      if (!efser)
        efser = "";
        
      xfree (*serial);
      *serial = NULL;
      p = xtrymalloc (strlen (efser) + 7);
      if (!p)
          rc = gpg_error (gpg_err_code_from_errno (errno));
      else
        {
          strcpy (p, "FF0100");
          strcpy (p+6, efser);
          *serial = p;
        }
    }
  else if (!rc && **serial == 'F' && (*serial)[1] == 'F')
    { /* The serial number starts with our special prefix.  This
         requires that we put our default prefix "FF0000" in front. */
      char *p = xtrymalloc (strlen (*serial) + 7);
      if (!p)
        {
          xfree (*serial);
          *serial = NULL;
          rc = gpg_error (gpg_err_code_from_errno (errno));
        }
      else
        {
          strcpy (p, "FF0000");
          strcpy (p+6, *serial);
          xfree (*serial);
          *serial = p;
        }
    }
  return rc;
#else
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif
}


/* Enumerate all keypairs on the card and return the Keygrip as well
   as the internal identification of the key.  KEYGRIP must be a
   caller provided buffer with a size of 20 bytes which will receive
   the KEYGRIP of the keypair.  If KEYID is not NULL, it returns the
   ID field of the key in allocated memory; this is a string without
   spaces.  The function returns -1 when all keys have been
   enumerated.  Note that the error GPG_ERR_MISSING_CERTIFICATE may be
   returned if there is just the private key but no public key (ie.e a
   certificate) available.  Applications might want to continue
   enumerating after this error.*/
int
card_enum_keypairs (CARD card, int idx,
                    unsigned char *keygrip,
                    char **keyid)
{
  int rc;

  if (keyid)
    *keyid = NULL;

  if (!card || !keygrip)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);
  if (!card->fnc.initialized)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->fnc.enum_keypairs)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  rc = card->fnc.enum_keypairs (card, idx, keygrip, keyid);
  if (opt.verbose)
    log_info ("card operation enum_keypairs result: %s\n",
              gpg_strerror (rc));
  return rc;
}


/* Enumerate all trusted certificates available on the card, return
   their ID in CERT and the type in CERTTYPE.  Types of certificates
   are:
      0   := Unknown
      100 := Regular X.509 cert
      101 := Trusted X.509 cert
      102 := Useful X.509 cert
      110 := Root CA cert (DINSIG)
 */
int
card_enum_certs (CARD card, int idx, char **certid, int *certtype)
{
  int rc;

  if (certid)
    *certid = NULL;

  if (!card)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);
  if (!card->fnc.initialized)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->fnc.enum_certs)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  rc = card->fnc.enum_certs (card, idx, certid, certtype);
  if (opt.verbose)
    log_info ("card operation enum_certs result: %s\n",
              gpg_strerror (rc));
  return rc;
}



/* Read the certificate identified by CERTIDSTR which is the
   hexadecimal encoded ID of the certificate, prefixed with the string
   "3F005015.". The certificate is return in DER encoded form in CERT
   and NCERT. */
int
card_read_cert (CARD card, const char *certidstr,
                unsigned char **cert, size_t *ncert)
{
  int rc;

  if (!card || !certidstr || !cert || !ncert)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!card->fnc.initialized)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->fnc.read_cert)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  rc = card->fnc.read_cert (card, certidstr, cert, ncert);
  if (opt.verbose)
    log_info ("card operation read_cert result: %s\n", gpg_strerror (rc));
  return rc;
}


/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
int 
card_sign (CARD card, const char *keyidstr, int hashalgo,
           int (pincb)(void*, const char *, char **),
           void *pincb_arg,
           const void *indata, size_t indatalen,
           unsigned char **outdata, size_t *outdatalen )
{
  int rc;

  if (!card || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!card->fnc.initialized)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->fnc.sign)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  rc =  card->fnc.sign (card, keyidstr, hashalgo,
                        pincb, pincb_arg,
                        indata, indatalen,
                        outdata, outdatalen);
  if (opt.verbose)
    log_info ("card operation sign result: %s\n", gpg_strerror (rc));
  return rc;
}


/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
int 
card_decipher (CARD card, const char *keyidstr,
               int (pincb)(void*, const char *, char **),
               void *pincb_arg,
               const void *indata, size_t indatalen,
               unsigned char **outdata, size_t *outdatalen )
{
  int rc;

  if (!card || !indata || !indatalen || !outdata || !outdatalen || !pincb)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!card->fnc.initialized)
    return gpg_error (GPG_ERR_CARD_NOT_INITIALIZED);
  if (!card->fnc.decipher)
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
  rc =  card->fnc.decipher (card, keyidstr,
                            pincb, pincb_arg,
                            indata, indatalen,
                            outdata, outdatalen);
  if (opt.verbose)
    log_info ("card operation decipher result: %s\n", gpg_strerror (rc));
  return rc;
}


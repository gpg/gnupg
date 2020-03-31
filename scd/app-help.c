/* app-help.c - Application helper functions
 * Copyright (C) 2004, 2009 Free Software Foundation, Inc.
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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scdaemon.h"
#include "app-common.h"
#include "iso7816.h"
#include "../common/tlv.h"


/* Count the number of bits, assuming the A represents an unsigned big
   integer of length LEN bytes.  If A is NULL a length of 0 is
   returned. */
unsigned int
app_help_count_bits (const unsigned char *a, size_t len)
{
  unsigned int n = len * 8;
  int i;

  if (!a)
    return 0;

  for (; len && !*a; len--, a++, n -=8)
    ;
  if (len)
    {
      for (i=7; i && !(*a & (1<<i)); i--)
        n--;
    }
  return n;
}


/* Return the KEYGRIP for the canonical encoded public key (PK,PKLEN)
 * as an hex encoded string in the user provided buffer HEXKEYGRIP
 * which must be of at least 41 bytes.  If R_PKEY is not NULL and the
 * function succeeded, the S-expression representing the key is
 * stored there.  The caller needs to call gcry_sexp_release on
 * that.  */
gpg_error_t
app_help_get_keygrip_string_pk (const void *pk, size_t pklen, char *hexkeygrip,
                                gcry_sexp_t *r_pkey)
{
  gpg_error_t err;
  gcry_sexp_t s_pkey;
  unsigned char array[KEYGRIP_LEN];

  if (r_pkey)
    *r_pkey = NULL;

  err = gcry_sexp_sscan (&s_pkey, NULL, pk, pklen);
  if (err)
    return err; /* Can't parse that S-expression. */
  if (!gcry_pk_get_keygrip (s_pkey, array))
    {
      gcry_sexp_release (s_pkey);
      return gpg_error (GPG_ERR_GENERAL); /* Failed to calculate the keygrip.*/
    }

  if (r_pkey)
    *r_pkey = s_pkey;
  else
    gcry_sexp_release (s_pkey);

  bin2hex (array, KEYGRIP_LEN, hexkeygrip);

  return 0;
}


/* Return the KEYGRIP for the certificate CERT as an hex encoded
 * string in the user provided buffer HEXKEYGRIP which must be of at
 * least 41 bytes.  If R_PKEY is not NULL and the function succeeded,
 * the S-expression representing the key is stored there.  The caller
 * needs to call gcry_sexp_release on that. */
gpg_error_t
app_help_get_keygrip_string (ksba_cert_t cert, char *hexkeygrip,
                             gcry_sexp_t *r_pkey)
{
  gpg_error_t err;
  ksba_sexp_t p;
  size_t n;

  if (r_pkey)
    *r_pkey = NULL;

  p = ksba_cert_get_public_key (cert);
  if (!p)
    return gpg_error (GPG_ERR_BUG);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  err = app_help_get_keygrip_string_pk ((void*)p, n, hexkeygrip, r_pkey);
  ksba_free (p);
  return err;
}


/* Given the SLOT and the File ID FID, return the length of the
   certificate contained in that file. Returns 0 if the file does not
   exists or does not contain a certificate.  If R_CERTOFF is not
   NULL, the length the header will be stored at this address; thus to
   parse the X.509 certificate a read should start at that offset.

   On success the file is still selected.
*/
size_t
app_help_read_length_of_cert (int slot, int fid, size_t *r_certoff)
{
  gpg_error_t err;
  unsigned char *buffer;
  const unsigned char *p;
  size_t buflen, n;
  int class, tag, constructed, ndef;
  size_t resultlen, objlen, hdrlen;

  err = iso7816_select_file (slot, fid, 0);
  if (err)
    {
      log_info ("error selecting FID 0x%04X: %s\n", fid, gpg_strerror (err));
      return 0;
    }

  err = iso7816_read_binary (slot, 0, 32, &buffer, &buflen);
  if (err)
    {
      log_info ("error reading certificate from FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return 0;
    }

  if (!buflen || *buffer == 0xff)
    {
      log_info ("no certificate contained in FID 0x%04X\n", fid);
      xfree (buffer);
      return 0;
    }

  p = buffer;
  n = buflen;
  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (err)
    {
      log_info ("error parsing certificate in FID 0x%04X: %s\n",
                fid, gpg_strerror (err));
      xfree (buffer);
      return 0;
    }

  /* All certificates should commence with a SEQUENCE except for the
     special ROOT CA which are enclosed in a SET. */
  if ( !(class == CLASS_UNIVERSAL &&  constructed
         && (tag == TAG_SEQUENCE || tag == TAG_SET)))
    {
      log_info ("data at FID 0x%04X does not look like a certificate\n", fid);
      return 0;
    }

  resultlen = objlen + hdrlen;
  if (r_certoff)
    {
      /* The callers want the offset to the actual certificate. */
      *r_certoff = hdrlen;

      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        return 0;

      if (class == CLASS_UNIVERSAL && tag == TAG_OBJECT_ID && !constructed)
        {
          /* The certificate seems to be contained in a
             userCertificate container.  Assume the following sequence
             is the certificate. */
          *r_certoff += hdrlen + objlen;
          if (*r_certoff > resultlen)
            {
              *r_certoff = 0;
              return 0; /* That should never happen. */
            }
        }
      else
        *r_certoff = 0;
    }

  return resultlen;
}

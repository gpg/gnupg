/* openpgp-oids.c - OID helper for OpenPGP
 * Copyright (C) 2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>

#include "util.h"
#include "openpgpdefs.h"

/* A table with all our supported OpenPGP curves.  */
static struct {
  const char *name;   /* Standard name.  */
  const char *oidstr; /* IETF formatted OID.  */
  unsigned int nbits; /* Nominal bit length of the curve.  */
  const char *alias;  /* NULL or alternative name of the curve.  */
  int pubkey_algo;    /* Required OpenPGP algo or 0 for ECDSA/ECDH.  */
} oidtable[] = {

  { "Curve25519", "1.3.6.1.4.1.3029.1.5.1", 255, "cv25519", PUBKEY_ALGO_ECDH },
  { "Ed25519",    "1.3.6.1.4.1.11591.15.1", 255, "ed25519", PUBKEY_ALGO_EDDSA },

  { "NIST P-256",      "1.2.840.10045.3.1.7",    256, "nistp256" },
  { "NIST P-384",      "1.3.132.0.34",           384, "nistp384" },
  { "NIST P-521",      "1.3.132.0.35",           521, "nistp521" },

  { "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7",   256 },
  { "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11",  384 },
  { "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13",  512 },

  { "secp256k1",       "1.3.132.0.10",           256 },

  { NULL, NULL, 0}
};


/* The OID for Curve Ed25519 in OpenPGP format.  */
static const char oid_ed25519[] =
  { 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };

/* The OID for Curve25519 in OpenPGP format.  */
static const char oid_cv25519[] =
  { 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };


/* Helper for openpgp_oid_from_str.  */
static size_t
make_flagged_int (unsigned long value, char *buf, size_t buflen)
{
  int more = 0;
  int shift;

  /* fixme: figure out the number of bits in an ulong and start with
     that value as shift (after making it a multiple of 7) a more
     straigtforward implementation is to do it in reverse order using
     a temporary buffer - saves a lot of compares */
  for (more=0, shift=28; shift > 0; shift -= 7)
    {
      if (more || value >= (1<<shift))
        {
          buf[buflen++] = 0x80 | (value >> shift);
          value -= (value >> shift) << shift;
          more = 1;
        }
    }
  buf[buflen++] = value;
  return buflen;
}


/* Convert the OID given in dotted decimal form in STRING to an DER
 * encoding and store it as an opaque value at R_MPI.  The format of
 * the DER encoded is not a regular ASN.1 object but the modified
 * format as used by OpenPGP for the ECC curve description.  On error
 * the function returns and error code an NULL is stored at R_BUG.
 * Note that scanning STRING stops at the first white space
 * character.  */
gpg_error_t
openpgp_oid_from_str (const char *string, gcry_mpi_t *r_mpi)
{
  unsigned char *buf;
  size_t buflen;
  unsigned long val1, val;
  const char *endp;
  int arcno;

  *r_mpi = NULL;

  if (!string || !*string)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* We can safely assume that the encoded OID is shorter than the string. */
  buf = xtrymalloc (1 + strlen (string) + 2);
  if (!buf)
    return gpg_error_from_syserror ();
  /* Save the first byte for the length.  */
  buflen = 1;

  val1 = 0; /* Avoid compiler warning.  */
  arcno = 0;
  do {
    arcno++;
    val = strtoul (string, (char**)&endp, 10);
    if (!digitp (string) || !(*endp == '.' || !*endp))
      {
        xfree (buf);
        return gpg_error (GPG_ERR_INV_OID_STRING);
      }
    if (*endp == '.')
      string = endp+1;

    if (arcno == 1)
      {
        if (val > 2)
          break; /* Not allowed, error caught below.  */
        val1 = val;
      }
    else if (arcno == 2)
      { /* Need to combine the first two arcs in one octet.  */
        if (val1 < 2)
          {
            if (val > 39)
              {
                xfree (buf);
                return gpg_error (GPG_ERR_INV_OID_STRING);
              }
            buf[buflen++] = val1*40 + val;
          }
        else
          {
            val += 80;
            buflen = make_flagged_int (val, buf, buflen);
          }
      }
    else
      {
        buflen = make_flagged_int (val, buf, buflen);
      }
  } while (*endp == '.');

  if (arcno == 1 || buflen < 2 || buflen > 254 )
    { /* It is not possible to encode only the first arc.  */
      xfree (buf);
      return gpg_error (GPG_ERR_INV_OID_STRING);
    }

  *buf = buflen - 1;
  *r_mpi = gcry_mpi_set_opaque (NULL, buf, buflen * 8);
  if (!*r_mpi)
    {
      xfree (buf);
      return gpg_error_from_syserror ();
    }
  return 0;
}


/* Return a malloced string represenation of the OID in the opaque MPI
   A.  In case of an error NULL is returned and ERRNO is set.  */
char *
openpgp_oid_to_str (gcry_mpi_t a)
{
  const unsigned char *buf;
  size_t length;
  unsigned int lengthi;
  char *string, *p;
  int n = 0;
  unsigned long val, valmask;

  valmask = (unsigned long)0xfe << (8 * (sizeof (valmask) - 1));

  if (!a
      || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE)
      || !(buf = gcry_mpi_get_opaque (a, &lengthi)))
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }

  buf = gcry_mpi_get_opaque (a, &lengthi);
  length = (lengthi+7)/8;

  /* The first bytes gives the length; check consistency.  */
  if (!length || buf[0] != length -1)
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }
  /* Skip length byte.  */
  length--;
  buf++;

  /* To calculate the length of the string we can safely assume an
     upper limit of 3 decimal characters per byte.  Two extra bytes
     account for the special first octect */
  string = p = xtrymalloc (length*(1+3)+2+1);
  if (!string)
    return NULL;
  if (!length)
    {
      *p = 0;
      return string;
    }

  if (buf[0] < 40)
    p += sprintf (p, "0.%d", buf[n]);
  else if (buf[0] < 80)
    p += sprintf (p, "1.%d", buf[n]-40);
  else {
    val = buf[n] & 0x7f;
    while ( (buf[n]&0x80) && ++n < length )
      {
        if ( (val & valmask) )
          goto badoid;  /* Overflow.  */
        val <<= 7;
        val |= buf[n] & 0x7f;
      }
    if (val < 80)
      goto badoid;
    val -= 80;
    sprintf (p, "2.%lu", val);
    p += strlen (p);
  }
  for (n++; n < length; n++)
    {
      val = buf[n] & 0x7f;
      while ( (buf[n]&0x80) && ++n < length )
        {
          if ( (val & valmask) )
            goto badoid;  /* Overflow.  */
          val <<= 7;
          val |= buf[n] & 0x7f;
        }
      sprintf (p, ".%lu", val);
      p += strlen (p);
    }

  *p = 0;
  return string;

 badoid:
  /* Return a special OID (gnu.gnupg.badoid) to indicate the error
     case.  The OID is broken and thus we return one which can't do
     any harm.  Formally this does not need to be a bad OID but an OID
     with an arc that can't be represented in a 32 bit word is more
     than likely corrupt.  */
  xfree (string);
  return xtrystrdup ("1.3.6.1.4.1.11591.2.12242973");
}



/* Return true if A represents the OID for Ed25519.  */
int
openpgp_oid_is_ed25519 (gcry_mpi_t a)
{
  const unsigned char *buf;
  unsigned int nbits;
  size_t n;

  if (!a || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    return 0;

  buf = gcry_mpi_get_opaque (a, &nbits);
  n = (nbits+7)/8;
  return (n == DIM (oid_ed25519)
          && !memcmp (buf, oid_ed25519, DIM (oid_ed25519)));
}


int
openpgp_oid_is_cv25519 (gcry_mpi_t a)
{
  const unsigned char *buf;
  unsigned int nbits;
  size_t n;

  if (!a || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    return 0;

  buf = gcry_mpi_get_opaque (a, &nbits);
  n = (nbits+7)/8;
  return (n == DIM (oid_cv25519)
          && !memcmp (buf, oid_cv25519, DIM (oid_cv25519)));
}


/* Map the Libgcrypt ECC curve NAME to an OID.  If R_NBITS is not NULL
   store the bit size of the curve there.  Returns NULL for unknown
   curve names.  */
const char *
openpgp_curve_to_oid (const char *name, unsigned int *r_nbits)
{
  int i;
  unsigned int nbits = 0;
  const char *oidstr = NULL;

  if (name)
    {
      for (i=0; oidtable[i].name; i++)
        if (!strcmp (oidtable[i].name, name)
            || (oidtable[i].alias && !strcmp (oidtable[i].alias, name)))
          {
            oidstr = oidtable[i].oidstr;
            nbits  = oidtable[i].nbits;
            break;
          }
      if (!oidtable[i].name)
        {
          /* If not found assume the input is already an OID and check
             whether we support it.  */
          for (i=0; oidtable[i].name; i++)
            if (!strcmp (name, oidtable[i].oidstr))
              {
                oidstr = oidtable[i].oidstr;
                nbits  = oidtable[i].nbits;
                break;
              }
        }
    }

  if (r_nbits)
    *r_nbits = nbits;
  return oidstr;
}


/* Map an OpenPGP OID to the Libgcrypt curve NAME.  Returns NULL for
   unknown curve names.  Unless CANON is set we prefer an alias name
   here which is more suitable for printing.  */
const char *
openpgp_oid_to_curve (const char *oidstr, int canon)
{
  int i;

  if (!oidstr)
    return NULL;

  for (i=0; oidtable[i].name; i++)
    if (!strcmp (oidtable[i].oidstr, oidstr))
      return !canon && oidtable[i].alias? oidtable[i].alias : oidtable[i].name;

  return NULL;
}


/* Return true if the curve with NAME is supported.  */
static int
curve_supported_p (const char *name)
{
  int result = 0;
  gcry_sexp_t keyparms;

  if (!gcry_sexp_build (&keyparms, NULL, "(public-key(ecc(curve %s)))", name))
    {
      result = !!gcry_pk_get_curve (keyparms, 0, NULL);
      gcry_sexp_release (keyparms);
    }
  return result;
}


/* Enumerate available and supported OpenPGP curves.  The caller needs
   to set the integer variable at ITERP to zero and keep on calling
   this function until NULL is returned.  */
const char *
openpgp_enum_curves (int *iterp)
{
  int idx = *iterp;

  while (idx >= 0 && idx < DIM (oidtable) && oidtable[idx].name)
    {
      if (curve_supported_p (oidtable[idx].name))
        {
          *iterp = idx + 1;
          return oidtable[idx].alias? oidtable[idx].alias : oidtable[idx].name;
        }
      idx++;
    }
  *iterp = idx;
  return NULL;
}


/* Return the Libgcrypt name for the gpg curve NAME if supported.  If
 * R_ALGO is not NULL the required OpenPGP public key algo or 0 is
 * stored at that address.  If R_NBITS is not NULL the nominal bitsize
 * of the curves is stored there.  NULL is returned if the curve is
 * not supported. */
const char *
openpgp_is_curve_supported (const char *name, int *r_algo,
                            unsigned int *r_nbits)
{
  int idx;

  if (r_algo)
    *r_algo = 0;
  if (r_nbits)
    *r_nbits = 0;
  for (idx = 0; idx < DIM (oidtable) && oidtable[idx].name; idx++)
    {
      if ((!strcmp (name, oidtable[idx].name)
           || (oidtable[idx].alias && !strcmp (name, (oidtable[idx].alias))))
          && curve_supported_p (oidtable[idx].name))
        {
          if (r_algo)
            *r_algo = oidtable[idx].pubkey_algo;
          if (r_nbits)
            *r_nbits = oidtable[idx].nbits;
          return oidtable[idx].name;
        }
    }
  return NULL;
}

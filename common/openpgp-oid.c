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
  { "Curve25519", "1.3.101.110",            255, "cv25519", PUBKEY_ALGO_ECDH },
  { "Ed25519",    "1.3.101.112",            255, "ed25519", PUBKEY_ALGO_EDDSA },
  { "X448",       "1.3.101.111",            448, "cv448",   PUBKEY_ALGO_ECDH },
  { "Ed448",      "1.3.101.113",            456, "ed448",   PUBKEY_ALGO_EDDSA },

  { "NIST P-256",      "1.2.840.10045.3.1.7",    256, "nistp256" },
  { "NIST P-384",      "1.3.132.0.34",           384, "nistp384" },
  { "NIST P-521",      "1.3.132.0.35",           521, "nistp521" },

  { "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7",   256 },
  { "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11",  384 },
  { "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13",  512 },

  { "secp256k1",       "1.3.132.0.10",           256 },

  { NULL, NULL, 0}
};


/* The OID for Curve Ed25519 in OpenPGP format.  The shorter v5
 * variant may only be used with v5 keys.  */
static const char oid_ed25519[] =
  { 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };
static const char oid_ed25519_v5[] = { 0x03, 0x2b, 0x65, 0x70 };

/* The OID for Curve25519 in OpenPGP format.  The shorter v5
 * variant may only be used with v5 keys.  */
static const char oid_cv25519[] =
  { 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
static const char oid_cv25519_v5[] = { 0x03, 0x2b, 0x65, 0x6e };

/* The OID for X448 in OpenPGP format. */
/*
 * Here, we have a little semantic discrepancy.  X448 is the name of
 * the ECDH computation and the OID is assigned to the algorithm in
 * RFC 8410.  Note that this OID is not the one which is assigned to
 * the curve itself (originally in 8410).  Nevertheless, we use "X448"
 * for the curve in libgcrypt.
 */
static const char oid_cv448[] = { 0x03, 0x2b, 0x65, 0x6f };

/* The OID for Ed448 in OpenPGP format. */
static const char oid_ed448[] = { 0x03, 0x2b, 0x65, 0x71 };


/* A table to store keyalgo strings like "rsa2048 or "ed25519" so that
 * we do not need to allocate them.  This is currently a simple array
 * but may eventually be changed to a fast data structure.  Noet that
 * unknown algorithms are stored with (NBITS,CURVE) set to (0,NULL). */
struct keyalgo_string_s
{
  enum gcry_pk_algos algo;   /* Mandatory. */
  unsigned int nbits;        /* Size for classical algos.  */
  char *curve;               /* Curvename (OID) or NULL.   */
  char *name;                /* Allocated name.  */
};
static struct keyalgo_string_s *keyalgo_strings;  /* The table.       */
static size_t keyalgo_strings_size;               /* Allocated size.  */
static size_t keyalgo_strings_used;               /* Used size.       */


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


/* Return a malloced string representation of the OID in the buffer
 * (BUF,LEN).  In case of an error NULL is returned and ERRNO is set.
 * As per OpenPGP spec the first byte of the buffer is the length of
 * the rest; the function performs a consistency check.  */
char *
openpgp_oidbuf_to_str (const unsigned char *buf, size_t len)
{
  char *string, *p;
  int n = 0;
  unsigned long val, valmask;

  valmask = (unsigned long)0xfe << (8 * (sizeof (valmask) - 1));
  /* The first bytes gives the length; check consistency.  */

  if (!len || buf[0] != len -1)
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }
  /* Skip length byte.  */
  len--;
  buf++;

  /* To calculate the length of the string we can safely assume an
     upper limit of 3 decimal characters per byte.  Two extra bytes
     account for the special first octet */
  string = p = xtrymalloc (len*(1+3)+2+1);
  if (!string)
    return NULL;
  if (!len)
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
    while ( (buf[n]&0x80) && ++n < len )
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
  for (n++; n < len; n++)
    {
      val = buf[n] & 0x7f;
      while ( (buf[n]&0x80) && ++n < len )
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


/* Return a malloced string representation of the OID in the opaque
 * MPI A.  In case of an error NULL is returned and ERRNO is set.  */
char *
openpgp_oid_to_str (gcry_mpi_t a)
{
  const unsigned char *buf;
  unsigned int lengthi;

  if (!a
      || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE)
      || !(buf = gcry_mpi_get_opaque (a, &lengthi)))
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }

  return openpgp_oidbuf_to_str (buf, (lengthi+7)/8);
}


/* Return true if (BUF,LEN) represents the OID for Ed25519.  */
int
openpgp_oidbuf_is_ed25519 (const void *buf, size_t len)
{
  if (!buf)
    return 0;
  return ((len == DIM (oid_ed25519)
           && !memcmp (buf, oid_ed25519, DIM (oid_ed25519)))
          || (len == DIM (oid_ed25519_v5)
              && !memcmp (buf, oid_ed25519_v5, DIM (oid_ed25519_v5))));
}


/* Return true if A represents the OID for Ed25519.  */
int
openpgp_oid_is_ed25519 (gcry_mpi_t a)
{
  const unsigned char *buf;
  unsigned int nbits;

  if (!a || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    return 0;

  buf = gcry_mpi_get_opaque (a, &nbits);
  return openpgp_oidbuf_is_ed25519 (buf, (nbits+7)/8);
}


/* Return true if (BUF,LEN) represents the OID for Curve25519.  */
int
openpgp_oidbuf_is_cv25519 (const void *buf, size_t len)
{
  if (!buf)
    return 0;
  return ((len == DIM (oid_cv25519)
           && !memcmp (buf, oid_cv25519, DIM (oid_cv25519)))
          || (len == DIM (oid_cv25519_v5)
              && !memcmp (buf, oid_cv25519_v5, DIM (oid_cv25519_v5))));
}


/* Return true if (BUF,LEN) represents the OID for Ed448.  */
static int
openpgp_oidbuf_is_ed448 (const void *buf, size_t len)
{
  return (buf && len == DIM (oid_ed448)
          && !memcmp (buf, oid_ed448, DIM (oid_ed448)));
}


/* Return true if (BUF,LEN) represents the OID for X448.  */
static int
openpgp_oidbuf_is_cv448 (const void *buf, size_t len)
{
  return (buf && len == DIM (oid_cv448)
          && !memcmp (buf, oid_cv448, DIM (oid_cv448)));
}


/* Return true if the MPI A represents the OID for Curve25519.  */
int
openpgp_oid_is_cv25519 (gcry_mpi_t a)
{
  const unsigned char *buf;
  unsigned int nbits;

  if (!a || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    return 0;

  buf = gcry_mpi_get_opaque (a, &nbits);
  return openpgp_oidbuf_is_cv25519 (buf, (nbits+7)/8);
}


/* Return true if the MPI A represents the OID for Ed448.  */
int
openpgp_oid_is_ed448 (gcry_mpi_t a)
{
  const unsigned char *buf;
  unsigned int nbits;

  if (!a || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    return 0;

  buf = gcry_mpi_get_opaque (a, &nbits);
  return openpgp_oidbuf_is_ed448 (buf, (nbits+7)/8);
}


/* Return true if the MPI A represents the OID for X448.  */
int
openpgp_oid_is_cv448 (gcry_mpi_t a)
{
  const unsigned char *buf;
  unsigned int nbits;

  if (!a || !gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    return 0;

  buf = gcry_mpi_get_opaque (a, &nbits);
  return openpgp_oidbuf_is_cv448 (buf, (nbits+7)/8);
}


/* Map the Libgcrypt ECC curve NAME to an OID.  If R_NBITS is not NULL
   store the bit size of the curve there.  Returns NULL for unknown
   curve names.  If R_ALGO is not NULL and a specific ECC algorithm is
   required for this curve its OpenPGP algorithm number is stored
   there; otherwise 0 is stored which indicates that ECDSA or ECDH can
   be used. */
const char *
openpgp_curve_to_oid (const char *name, unsigned int *r_nbits, int *r_algo)
{
  int i;
  unsigned int nbits = 0;
  const char *oidstr = NULL;
  int algo = 0;

  if (name)
    {
      for (i=0; oidtable[i].name; i++)
        if (!ascii_strcasecmp (oidtable[i].name, name)
            || (oidtable[i].alias
                && !ascii_strcasecmp (oidtable[i].alias, name)))
          {
            oidstr = oidtable[i].oidstr;
            nbits  = oidtable[i].nbits;
            algo   = oidtable[i].pubkey_algo;
            break;
          }
      if (!oidtable[i].name)
        {
          /* If not found assume the input is already an OID and check
             whether we support it.  */
          for (i=0; oidtable[i].name; i++)
            if (!ascii_strcasecmp (name, oidtable[i].oidstr))
              {
                oidstr = oidtable[i].oidstr;
                nbits  = oidtable[i].nbits;
                algo   = oidtable[i].pubkey_algo;
                break;
              }
        }
    }

  if (r_nbits)
    *r_nbits = nbits;
  if (r_algo)
    *r_algo = algo;
  return oidstr;
}


/* Map an OpenPGP OID to the Libgcrypt curve name.  Returns NULL for
 * unknown curve names.  Unless CANON is set we prefer an alias name
 * here which is more suitable for printing.  */
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


/* Map an OpenPGP OID, name or alias to the Libgcrypt curve name.
 * Returns NULL for unknown curve names.  Unless CANON is set we
 * prefer an alias name here which is more suitable for printing.  */
const char *
openpgp_oid_or_name_to_curve (const char *oidname, int canon)
{
  int i;

  if (!oidname)
    return NULL;

  for (i=0; oidtable[i].name; i++)
    if (!ascii_strcasecmp (oidtable[i].oidstr, oidname)
        || !ascii_strcasecmp (oidtable[i].name, oidname)
        || (oidtable[i].alias
            && !ascii_strcasecmp (oidtable[i].alias, oidname)))
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
      if ((!ascii_strcasecmp (name, oidtable[idx].name)
           || (oidtable[idx].alias
               && !ascii_strcasecmp (name, (oidtable[idx].alias))))
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


/* Map a Gcrypt public key algorithm number to the used by OpenPGP.
 * Returns 0 for unknown gcry algorithm.  */
pubkey_algo_t
map_gcry_pk_to_openpgp (enum gcry_pk_algos algo)
{
  switch (algo)
    {
    case GCRY_PK_EDDSA:  return PUBKEY_ALGO_EDDSA;
    case GCRY_PK_ECDSA:  return PUBKEY_ALGO_ECDSA;
    case GCRY_PK_ECDH:   return PUBKEY_ALGO_ECDH;
    default: return algo < 110 ? (pubkey_algo_t)algo : 0;
    }
}


/* Map an OpenPGP public key algorithm number to the one used by
 * Libgcrypt.  Returns 0 for unknown gcry algorithm.  */
enum gcry_pk_algos
map_openpgp_pk_to_gcry (pubkey_algo_t algo)
{
  switch (algo)
    {
    case PUBKEY_ALGO_EDDSA:  return GCRY_PK_EDDSA;
    case PUBKEY_ALGO_ECDSA:  return GCRY_PK_ECDSA;
    case PUBKEY_ALGO_ECDH:   return GCRY_PK_ECDH;
    default: return algo < 110 ? (enum gcry_pk_algos)algo : 0;
    }
}


/* Return a string describing the public key algorithm and the
 * keysize.  For elliptic curves the function prints the name of the
 * curve because the keysize is a property of the curve.  ALGO is the
 * Gcrypt algorithm number, CURVE is either NULL or gives the OID of
 * the curve, NBITS is either 0 or the size for algorithms like RSA.
 * The returned string is taken from permanent table.  Examples
 * for the output are:
 *
 * "rsa3072"    - RSA with 3072 bit
 * "elg1024"    - Elgamal with 1024 bit
 * "ed25519"    - ECC using the curve Ed25519.
 * "E_1.2.3.4"  - ECC using the unsupported curve with OID "1.2.3.4".
 * "E_1.3.6.1.4.1.11591.2.12242973" - ECC with a bogus OID.
 * "unknown_N"  - Unknown OpenPGP algorithm N.
 *                If N is > 110 this is a gcrypt algo.
 */
const char *
get_keyalgo_string (enum gcry_pk_algos algo,
                    unsigned int nbits, const char *curve)
{
  const char *prefix;
  int i;
  char *name, *curvebuf;

  switch (algo)
    {
    case GCRY_PK_RSA:   prefix = "rsa"; break;
    case GCRY_PK_ELG:   prefix = "elg"; break;
    case GCRY_PK_DSA:	prefix = "dsa"; break;
    case GCRY_PK_ECC:
    case GCRY_PK_ECDH:
    case GCRY_PK_ECDSA:
    case GCRY_PK_EDDSA: prefix = "";    break;
    default:            prefix = NULL;  break;
    }

  if (prefix && *prefix && nbits)
    {
      for (i=0; i < keyalgo_strings_used; i++)
        {
          if (keyalgo_strings[i].algo == algo
              && keyalgo_strings[i].nbits
              && keyalgo_strings[i].nbits == nbits)
            return keyalgo_strings[i].name;
        }
      /* Not yet in the table - add it.  */
      name = xasprintf ("%s%u", prefix, nbits);
      nbits = nbits? nbits : 1;  /* No nbits - oops - use 1 instead.  */
      curvebuf = NULL;
    }
  else if (prefix && !*prefix)
    {
      const char *curvename;

      for (i=0; i < keyalgo_strings_used; i++)
        {
          if (keyalgo_strings[i].algo == algo
              && keyalgo_strings[i].curve && curve
              && !ascii_strcasecmp (keyalgo_strings[i].curve, curve))
            return keyalgo_strings[i].name;
        }

      /* Not yet in the table - add it.  */
      curvename = openpgp_oid_or_name_to_curve (curve, 0);
      if (curvename)
        name = xasprintf ("%s", curvename);
      else if (curve)
        name = xasprintf ("E_%s", curve);
      else
        name = xasprintf ("E_error");
      nbits = 0;
      curvebuf = curve? xstrdup (curve) : NULL;
    }
  else
    {
      for (i=0; i < keyalgo_strings_used; i++)
        {
          if (keyalgo_strings[i].algo == algo
              && !keyalgo_strings[i].nbits
              && !keyalgo_strings[i].curve)
            return keyalgo_strings[i].name;
        }
      /* Not yet in the table - add it.  */
      name = xasprintf ("unknown_%u", (unsigned int)algo);
      nbits = 0;
      curvebuf = NULL;
    }

  /* Store a new entry.  This is a loop because of a possible nPth
   * thread switch during xrealloc.  */
  while (keyalgo_strings_used >= keyalgo_strings_size)
    {
      keyalgo_strings_size += 10;
      if (keyalgo_strings_size > 1024*1024)
        log_fatal ("%s: table getting too large - possible DoS\n", __func__);
      keyalgo_strings = xrealloc (keyalgo_strings, (keyalgo_strings_size
                                                    * sizeof *keyalgo_strings));
    }
  keyalgo_strings[keyalgo_strings_used].algo = algo;
  keyalgo_strings[keyalgo_strings_used].nbits = nbits;
  keyalgo_strings[keyalgo_strings_used].curve = curvebuf;
  keyalgo_strings[keyalgo_strings_used].name = name;
  keyalgo_strings_used++;

  return name;  /* Note that this is in the table.  */
}

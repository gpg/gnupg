/* keyid.c - key ID and fingerprint handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004, 2006, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 * Copyright (C) 2016, 2023 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "gpg.h"
#include "../common/util.h"
#include "main.h"
#include "packet.h"
#include "options.h"
#include "keydb.h"
#include "../common/i18n.h"
#include "rmd160.h"
#include "../common/host2net.h"


#define KEYID_STR_SIZE 19

#ifdef HAVE_UNSIGNED_TIME_T
# define IS_INVALID_TIME_T(a) ((a) == (time_t)(-1))
#else
  /* Error or 32 bit time_t and value after 2038-01-19.  */
# define IS_INVALID_TIME_T(a) ((a) < 0)
#endif


/* Return a letter describing the public key algorithms.  */
int
pubkey_letter( int algo )
{
  switch (algo)
    {
    case PUBKEY_ALGO_RSA:	return 'R' ;
    case PUBKEY_ALGO_RSA_E:	return 'r' ;
    case PUBKEY_ALGO_RSA_S:	return 's' ;
    case PUBKEY_ALGO_ELGAMAL_E: return 'g' ;
    case PUBKEY_ALGO_ELGAMAL:   return 'G' ;
    case PUBKEY_ALGO_DSA:	return 'D' ;
    case PUBKEY_ALGO_ECDH:	return 'e' ;	/* ECC DH (encrypt only) */
    case PUBKEY_ALGO_ECDSA:	return 'E' ;	/* ECC DSA (sign only)   */
    case PUBKEY_ALGO_EDDSA:	return 'E' ;	/* ECC EdDSA (sign only) */
    default: return '?';
    }
}

/* Return a string describing the public key algorithm and the
   keysize.  For elliptic curves the function prints the name of the
   curve because the keysize is a property of the curve.  The string
   is copied to the supplied buffer up a length of BUFSIZE-1.
   Examples for the output are:

   "rsa3072"  - RSA with 3072 bit
   "elg1024"  - Elgamal with 1024 bit
   "ed25519"  - ECC using the curve Ed25519.
   "E_1.2.3.4"  - ECC using the unsupported curve with OID "1.2.3.4".
   "E_1.3.6.1.4.1.11591.2.12242973" ECC with a bogus OID.
   "unknown_N"  - Unknown OpenPGP algorithm N.

   If the option --legacy-list-mode is active, the output use the
   legacy format:

   "3072R" - RSA with 3072 bit
   "1024g" - Elgamal with 1024 bit
   "256E"  - ECDSA using a curve with 256 bit

   The macro PUBKEY_STRING_SIZE may be used to allocate a buffer with
   a suitable size.  Note that a more general version of this function
   exists as get_keyalgo_string.  However, that has no special
   treatment for the old and unsupported Elgamal which we here print as
   xxxNNNN.  */
char *
pubkey_string (PKT_public_key *pk, char *buffer, size_t bufsize)
{
  const char *prefix = NULL;

  if (opt.legacy_list_mode)
    {
      snprintf (buffer, bufsize, "%4u%c",
                nbits_from_pk (pk), pubkey_letter (pk->pubkey_algo));
      return buffer;
    }

  switch (pk->pubkey_algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:	prefix = "rsa"; break;
    case PUBKEY_ALGO_ELGAMAL_E: prefix = "elg"; break;
    case PUBKEY_ALGO_DSA:	prefix = "dsa"; break;
    case PUBKEY_ALGO_ELGAMAL:   prefix = "xxx"; break;
    case PUBKEY_ALGO_ECDH:
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_EDDSA:     prefix = "";    break;
    }

  if (prefix && *prefix)
    snprintf (buffer, bufsize, "%s%u", prefix, nbits_from_pk (pk));
  else if (prefix)
    {
      char *curve = openpgp_oid_to_str (pk->pkey[0]);
      const char *name = openpgp_oid_to_curve (curve, 0);

      if (name)
        snprintf (buffer, bufsize, "%s", name);
      else if (curve)
        snprintf (buffer, bufsize, "E_%s", curve);
      else
        snprintf (buffer, bufsize, "E_error");
      xfree (curve);
    }
  else
    snprintf (buffer, bufsize, "unknown_%u", (unsigned int)pk->pubkey_algo);

  return buffer;
}


/* Helper for compare_pubkey_string.  This skips leading spaces,
 * commas and optional condition operators and returns a pointer to
 * the first non-space character or NULL in case of an error.  The
 * length of a prefix consisting of letters is then returned ar PFXLEN
 * and the value of the number (e.g. 384 for "brainpoolP384r1") at
 * NUMBER.  R_LENGTH receives the entire length of the algorithm name
 * which is terminated by a space, nul, or a comma.  If R_CONDITION is
 * not NULL, 0 is stored for a leading "=", 1 for a ">", 2 for a ">=",
 * -1 for a "<", and -2 for a "<=".  If R_CONDITION is NULL no
 * condition prefix is allowed.  */
static const char *
parse_one_algo_string (const char *str, size_t *pfxlen, unsigned int *number,
                       size_t *r_length, int *r_condition)
{
  int condition = 0;
  const char *result;

  while (spacep (str) || *str ==',')
    str++;
  if (!r_condition)
    ;
  else if (*str == '>' && str[1] == '=')
    condition = 2, str += 2;
  else if (*str == '>' )
    condition = 1, str += 1;
  else if (*str == '<' && str[1] == '=')
    condition = -2, str += 2;
  else if (*str == '<')
    condition = -1, str += 1;
  else if (*str == '=')  /* Default.  */
    str += 1;

  if (!alphap (str))
    return NULL;  /* Error.  */

  *pfxlen = 1;
  for (result = str++; alphap (str); str++)
    ++*pfxlen;
  while (*str == '-' || *str == '+')
    str++;
  *number = atoi (str);
  while (*str && !spacep (str) && *str != ',')
    str++;

  *r_length = str - result;
  if (r_condition)
    *r_condition = condition;
  return result;
}

/* Helper for compare_pubkey_string.  If BPARSED is set to 0 on
 * return, an error in ASTR or BSTR was found and further checks are
 * not possible.  */
static int
compare_pubkey_string_part (const char *astr, const char *bstr_arg,
                            size_t *bparsed)
{
  const char *bstr = bstr_arg;
  size_t alen, apfxlen, blen, bpfxlen;
  unsigned int anumber, bnumber;
  int condition;

  *bparsed = 0;
  astr = parse_one_algo_string (astr, &apfxlen, &anumber, &alen, &condition);
  if (!astr)
    return 0;  /* Invalid algorithm name.  */
  bstr = parse_one_algo_string (bstr, &bpfxlen, &bnumber, &blen, &condition);
  if (!bstr)
    return 0;  /* Invalid algorithm name.  */
  *bparsed = blen + (bstr - bstr_arg);
  if (apfxlen != bpfxlen || ascii_strncasecmp (astr, bstr, apfxlen))
    return 0;  /* false.  */
  switch (condition)
    {
    case 2: return anumber >= bnumber;
    case 1: return anumber > bnumber;
    case -1: return anumber < bnumber;
    case -2: return anumber <= bnumber;
    }

  return alen == blen && !ascii_strncasecmp (astr, bstr, alen);
}


/* Check whether ASTR matches the constraints given by BSTR.  ASTR may
 * be any algo string like "rsa2048", "ed25519" and BSTR may be a
 * constraint which is in the simplest case just another algo string.
 * BSTR may have more that one string in which case they are comma
 * separated and any match will return true.  It is possible to prefix
 * BSTR with ">", ">=", "<=", or "<".  That prefix operator is applied
 * to the number part of the algorithm, i.e. the first sequence of
 * digits found before end-of-string or a comma.  Examples:
 *
 * | ASTR     | BSTR                 | result |
 * |----------+----------------------+--------|
 * | rsa2048  | rsa2048              | true   |
 * | rsa2048  | >=rsa2048            | true   |
 * | rsa2048  | >rsa2048             | false  |
 * | ed25519  | >rsa1024             | false  |
 * | ed25519  | ed25519              | true   |
 * | nistp384 | >nistp256            | true   |
 * | nistp521 | >=rsa3072, >nistp384 | true   |
 */
int
compare_pubkey_string (const char *astr, const char *bstr)
{
  size_t bparsed;
  int result;

  while (*bstr)
    {
      result = compare_pubkey_string_part (astr, bstr, &bparsed);
      if (result)
        return 1;
      if (!bparsed)
        return 0; /* Syntax error in ASTR or BSTR.  */
      bstr += bparsed;
    }

  return 0;
}



/* Hash a public key and allow to specify the to be used format.
 * Note that if the v5 format is requested for a v4 key, a 0x04 as
 * version is hashed instead of the 0x05. */
static void
do_hash_public_key (gcry_md_hd_t md, PKT_public_key *pk, int use_v5)
{
  unsigned int n;
  unsigned int nn[PUBKEY_MAX_NPKEY];
  byte *pp[PUBKEY_MAX_NPKEY];
  int i;
  unsigned int nbits;
  size_t nbytes;
  int npkey = pubkey_get_npkey (pk->pubkey_algo);

  n = use_v5? 10 : 6;
  /* FIXME: We can avoid the extra malloc by calling only the first
     mpi_print here which computes the required length and calling the
     real mpi_print only at the end.  The speed advantage would only be
     for ECC (opaque MPIs) or if we could implement an mpi_print
     variant with a callback handler to do the hashing.  */
  if (npkey==0 && pk->pkey[0]
      && gcry_mpi_get_flag (pk->pkey[0], GCRYMPI_FLAG_OPAQUE))
    {
      pp[0] = gcry_mpi_get_opaque (pk->pkey[0], &nbits);
      nn[0] = (nbits+7)/8;
      n+=nn[0];
    }
  else
    {
      for (i=0; i < npkey; i++ )
        {
          if (!pk->pkey[i])
            {
              /* This case may only happen if the parsing of the MPI
                 failed but the key was anyway created.  May happen
                 during "gpg KEYFILE".  */
              pp[i] = NULL;
              nn[i] = 0;
            }
          else if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_OPAQUE))
            {
              const char *p;
              int is_sos = 0;

              if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_USER2))
                is_sos = 2;

              p = gcry_mpi_get_opaque (pk->pkey[i], &nbits);
              pp[i] = xmalloc ((nbits+7)/8 + is_sos);
              if (p)
                memcpy (pp[i] + is_sos, p, (nbits+7)/8);
              else
                pp[i] = NULL;
              if (is_sos)
                {
                  if (*p)
                    {
                      nbits = ((nbits + 7) / 8) * 8;

                      if (nbits >= 8 && !(*p & 0x80))
                        if (--nbits >= 7 && !(*p & 0x40))
                          if (--nbits >= 6 && !(*p & 0x20))
                            if (--nbits >= 5 && !(*p & 0x10))
                              if (--nbits >= 4 && !(*p & 0x08))
                                if (--nbits >= 3 && !(*p & 0x04))
                                  if (--nbits >= 2 && !(*p & 0x02))
                                    if (--nbits >= 1 && !(*p & 0x01))
                                      --nbits;
                    }

                  pp[i][0] = (nbits >> 8);
                  pp[i][1] = nbits;
                }
              nn[i] = (nbits+7)/8 + is_sos;
              n += nn[i];
            }
          else
            {
              if (gcry_mpi_print (GCRYMPI_FMT_PGP, NULL, 0,
                                  &nbytes, pk->pkey[i]))
                BUG ();
              pp[i] = xmalloc (nbytes);
              if (gcry_mpi_print (GCRYMPI_FMT_PGP, pp[i], nbytes,
                                  &nbytes, pk->pkey[i]))
                BUG ();
              nn[i] = nbytes;
              n += nn[i];
            }
        }
    }

  if (use_v5)
    {
      gcry_md_putc ( md, 0x9a );     /* ctb */
      gcry_md_putc ( md, n >> 24 );  /* 4 byte length header (upper bits) */
      gcry_md_putc ( md, n >> 16 );
    }
  else
    {
      gcry_md_putc ( md, 0x99 );     /* ctb */
    }
  gcry_md_putc ( md, n >> 8 );       /* lower bits of the length header.  */
  gcry_md_putc ( md, n );
  gcry_md_putc ( md, pk->version );
  gcry_md_putc ( md, pk->timestamp >> 24 );
  gcry_md_putc ( md, pk->timestamp >> 16 );
  gcry_md_putc ( md, pk->timestamp >>  8 );
  gcry_md_putc ( md, pk->timestamp       );

  gcry_md_putc ( md, pk->pubkey_algo );

  if (use_v5) /* Hash the 32 bit length */
    {
      n -= 10;
      gcry_md_putc ( md, n >> 24 );
      gcry_md_putc ( md, n >> 16 );
      gcry_md_putc ( md, n >>  8 );
      gcry_md_putc ( md, n       );
    }

  if(npkey==0 && pk->pkey[0]
     && gcry_mpi_get_flag (pk->pkey[0], GCRYMPI_FLAG_OPAQUE))
    {
      if (pp[0])
        gcry_md_write (md, pp[0], nn[0]);
    }
  else
    {
      for(i=0; i < npkey; i++ )
        {
          if (pp[i])
            gcry_md_write ( md, pp[i], nn[i] );
          xfree(pp[i]);
        }
    }
}


/* Hash a public key.  This function is useful for v4 and v5
 * fingerprints and for v3 or v4 key signing. */
void
hash_public_key (gcry_md_hd_t md, PKT_public_key *pk)
{
  do_hash_public_key (md, pk, (pk->version == 5));
}


/* fixme: Check whether we can replace this function or if not
   describe why we need it.  */
u32
v3_keyid (gcry_mpi_t a, u32 *ki)
{
  byte *buffer, *p;
  size_t nbytes;

  if (gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &nbytes, a ))
    BUG ();
  /* fixme: allocate it on the stack */
  buffer = xmalloc (nbytes);
  if (gcry_mpi_print( GCRYMPI_FMT_USG, buffer, nbytes, NULL, a ))
    BUG ();
  if (nbytes < 8) /* oops */
    ki[0] = ki[1] = 0;
  else
    {
      p = buffer + nbytes - 8;
      ki[0] = buf32_to_u32 (p);
      p += 4;
      ki[1] = buf32_to_u32 (p);
    }
  xfree (buffer);
  return ki[1];
}


/* Return PK's keyid.  The memory is owned by PK.  */
u32 *
pk_keyid (PKT_public_key *pk)
{
  keyid_from_pk (pk, NULL);

  /* Uncomment this for help tracking down bugs related to keyid or
     main_keyid not being set correctly.  */
#if 0
  if (! (pk->main_keyid[0] || pk->main_keyid[1]))
    log_bug ("pk->main_keyid not set!\n");
  if (keyid_cmp (pk->keyid, pk->main_keyid) == 0
      && ! pk->flags.primary)
    log_bug ("keyid and main_keyid are the same, but primary flag not set!\n");
  if (keyid_cmp (pk->keyid, pk->main_keyid) != 0
      && pk->flags.primary)
    log_bug ("keyid and main_keyid are different, but primary flag set!\n");
#endif

  return pk->keyid;
}

/* Return the keyid of the primary key associated with PK.  The memory
   is owned by PK.  */
u32 *
pk_main_keyid (PKT_public_key *pk)
{
  /* Uncomment this for help tracking down bugs related to keyid or
     main_keyid not being set correctly.  */
#if 0
  if (! (pk->main_keyid[0] || pk->main_keyid[1]))
    log_bug ("pk->main_keyid not set!\n");
#endif

  return pk->main_keyid;
}

/* Copy the keyid in SRC to DEST and return DEST.  */
u32 *
keyid_copy (u32 *dest, const u32 *src)
{
  dest[0] = src[0];
  dest[1] = src[1];
  return dest;
}

char *
format_keyid (u32 *keyid, int format, char *buffer, int len)
{
  if (! buffer)
    {
      len = KEYID_STR_SIZE;
      buffer = xtrymalloc (len);
      if (!buffer)
        return NULL;
    }

  if (format == KF_DEFAULT)
    format = opt.keyid_format;
  if (format == KF_DEFAULT)
    format = KF_NONE;

  switch (format)
    {
    case KF_NONE:
      if (len)
        *buffer = 0;
      break;

    case KF_SHORT:
      snprintf (buffer, len, "%08lX", (ulong)keyid[1]);
      break;

    case KF_LONG:
      snprintf (buffer, len, "%08lX%08lX", (ulong)keyid[0], (ulong)keyid[1]);
      break;

    case KF_0xSHORT:
      snprintf (buffer, len, "0x%08lX", (ulong)keyid[1]);
      break;

    case KF_0xLONG:
      snprintf (buffer, len, "0x%08lX%08lX", (ulong)keyid[0],(ulong)keyid[1]);
      break;

    default:
      BUG();
    }

  return buffer;
}

size_t
keystrlen(void)
{
  int format = opt.keyid_format;
  if (format == KF_DEFAULT)
    format = KF_NONE;

  switch(format)
    {
    case KF_NONE:
      return 0;

    case KF_SHORT:
      return 8;

    case KF_LONG:
      return 16;

    case KF_0xSHORT:
      return 10;

    case KF_0xLONG:
      return 18;

    default:
      BUG();
    }
}


const char *
keystr (u32 *keyid)
{
  static char keyid_str[KEYID_STR_SIZE];
  int format = opt.keyid_format;

  if (format == KF_DEFAULT)
    format = KF_NONE;
  if (format == KF_NONE)
    format = KF_LONG;

  return format_keyid (keyid, format, keyid_str, sizeof (keyid_str));
}

/* This function returns the key id of the main and possible the
 * subkey as one string.  It is used by error messages.  */
const char *
keystr_with_sub (u32 *main_kid, u32 *sub_kid)
{
  static char buffer[KEYID_STR_SIZE+1+KEYID_STR_SIZE];
  char *p;
  int format = opt.keyid_format;

  if (format == KF_NONE)
    format = KF_LONG;

  format_keyid (main_kid, format, buffer, KEYID_STR_SIZE);
  if (sub_kid)
    {
      p = buffer + strlen (buffer);
      *p++ = '/';
      format_keyid (sub_kid, format, p, KEYID_STR_SIZE);
    }
  return buffer;
}


const char *
keystr_from_pk(PKT_public_key *pk)
{
  keyid_from_pk(pk,NULL);

  return keystr(pk->keyid);
}


const char *
keystr_from_pk_with_sub (PKT_public_key *main_pk, PKT_public_key *sub_pk)
{
  keyid_from_pk (main_pk, NULL);
  if (sub_pk)
    keyid_from_pk (sub_pk, NULL);

  return keystr_with_sub (main_pk->keyid, sub_pk? sub_pk->keyid:NULL);
}


/* Return PK's key id as a string using the default format.  PK owns
   the storage.  */
const char *
pk_keyid_str (PKT_public_key *pk)
{
  return keystr (pk_keyid (pk));
}


const char *
keystr_from_desc(KEYDB_SEARCH_DESC *desc)
{
  switch(desc->mode)
    {
    case KEYDB_SEARCH_MODE_LONG_KID:
    case KEYDB_SEARCH_MODE_SHORT_KID:
      return keystr(desc->u.kid);

    case KEYDB_SEARCH_MODE_FPR:
      {
	u32 keyid[2];

        if (desc->fprlen == 32)
          {
            keyid[0] = buf32_to_u32 (desc->u.fpr);
            keyid[1] = buf32_to_u32 (desc->u.fpr+4);
          }
        else if (desc->fprlen == 20)
          {
            keyid[0] = buf32_to_u32 (desc->u.fpr+12);
            keyid[1] = buf32_to_u32 (desc->u.fpr+16);
          }
        else if (desc->fprlen == 16)
          return "?v3 fpr?";
        else /* oops */
          return "?vx fpr?";
	return keystr(keyid);
      }

    default:
      BUG();
    }
}


/* Compute the fingerprint and keyid and store it in PK.  */
static void
compute_fingerprint (PKT_public_key *pk)
{
  const byte *dp;
  gcry_md_hd_t md;
  size_t len;

  if (gcry_md_open (&md, pk->version == 5 ? GCRY_MD_SHA256 : GCRY_MD_SHA1, 0))
    BUG ();
  hash_public_key (md, pk);
  gcry_md_final (md);
  dp = gcry_md_read (md, 0);
  len = gcry_md_get_algo_dlen (gcry_md_get_algo (md));
  log_assert (len <= MAX_FINGERPRINT_LEN);
  memcpy (pk->fpr, dp, len);
  pk->fprlen = len;
  if (pk->version == 5)
    {
      pk->keyid[0] = buf32_to_u32 (dp);
      pk->keyid[1] = buf32_to_u32 (dp+4);
    }
  else
    {
      pk->keyid[0] = buf32_to_u32 (dp+12);
      pk->keyid[1] = buf32_to_u32 (dp+16);
    }
  gcry_md_close( md);
}


/*
 * Get the keyid from the public key PK and store it at KEYID unless
 * this is NULL.  Returns the 32 bit short keyid.
 */
u32
keyid_from_pk (PKT_public_key *pk, u32 *keyid)
{
  u32 dummy_keyid[2];

  if (!keyid)
    keyid = dummy_keyid;

  if (!pk->fprlen)
    compute_fingerprint (pk);

  keyid[0] = pk->keyid[0];
  keyid[1] = pk->keyid[1];

  if (pk->fprlen == 32)
    return keyid[0];
  else
    return keyid[1];
}


/*
 * Get the keyid from the fingerprint.  This function is simple for
 * most keys, but has to do a key lookup for old v3 keys where the
 * keyid is not part of the fingerprint.
 */
u32
keyid_from_fingerprint (ctrl_t ctrl, const byte *fprint,
                        size_t fprint_len, u32 *keyid)
{
  u32 dummy_keyid[2];

  if( !keyid )
    keyid = dummy_keyid;

  if (fprint_len != 20 && fprint_len != 32)
    {
      /* This is special as we have to lookup the key first.  */
      PKT_public_key pk;
      int rc;

      memset (&pk, 0, sizeof pk);
      rc = get_pubkey_byfprint (ctrl, &pk, NULL, fprint, fprint_len);
      if( rc )
        {
          log_printhex (fprint, fprint_len,
                        "Oops: keyid_from_fingerprint: no pubkey; fpr:");
          keyid[0] = 0;
          keyid[1] = 0;
        }
      else
        keyid_from_pk (&pk, keyid);
    }
  else
    {
      const byte *dp = fprint;
      if (fprint_len == 20)  /* v4 key */
        {
          keyid[0] = buf32_to_u32 (dp+12);
          keyid[1] = buf32_to_u32 (dp+16);
        }
      else  /* v5 key */
        {
          keyid[0] = buf32_to_u32 (dp);
          keyid[1] = buf32_to_u32 (dp+4);
        }
    }

  return keyid[1];
}


u32
keyid_from_sig (PKT_signature *sig, u32 *keyid)
{
  if( keyid )
    {
      keyid[0] = sig->keyid[0];
      keyid[1] = sig->keyid[1];
    }
  return sig->keyid[1];  /*FIXME:shortkeyid*/
}


byte *
namehash_from_uid (PKT_user_id *uid)
{
  if (!uid->namehash)
    {
      uid->namehash = xmalloc (20);

      if (uid->attrib_data)
	rmd160_hash_buffer (uid->namehash, uid->attrib_data, uid->attrib_len);
      else
	rmd160_hash_buffer (uid->namehash, uid->name, uid->len);
    }

  return uid->namehash;
}


/*
 * Return the number of bits used in PK.
 */
unsigned int
nbits_from_pk (PKT_public_key *pk)
{
    return pubkey_nbits (pk->pubkey_algo, pk->pkey);
}


/* Convert an UTC TIMESTAMP into an UTC yyyy-mm-dd string.  Return
 * that string.  The caller should pass a buffer with at least a size
 * of MK_DATESTR_SIZE.  */
char *
mk_datestr (char *buffer, size_t bufsize, u32 timestamp)
{
  time_t atime = timestamp;
  struct tm *tp;

  if (IS_INVALID_TIME_T (atime))
    strcpy (buffer, "????" "-??" "-??"); /* Mark this as invalid. */
  else
    {
      tp = gmtime (&atime);
      snprintf (buffer, bufsize, "%04d-%02d-%02d",
                1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    }
  return buffer;
}


/*
 * return a string with the creation date of the pk
 * Note: this is alloced in a static buffer.
 *    Format is: yyyy-mm-dd
 */
const char *
dateonlystr_from_pk (PKT_public_key *pk)
{
  static char buffer[MK_DATESTR_SIZE];

  return mk_datestr (buffer, sizeof buffer, pk->timestamp);
}


/* Same as dateonlystr_from_pk but with a global option a full iso
 * timestamp is returned.  In this case it shares a static buffer with
 * isotimestamp(). */
const char *
datestr_from_pk (PKT_public_key *pk)
{
  if (opt.flags.full_timestrings)
    return isotimestamp (pk->timestamp);
  else
    return dateonlystr_from_pk (pk);
}


const char *
dateonlystr_from_sig (PKT_signature *sig )
{
  static char buffer[MK_DATESTR_SIZE];

  return mk_datestr (buffer, sizeof buffer, sig->timestamp);
}

const char *
datestr_from_sig (PKT_signature *sig )
{
  if (opt.flags.full_timestrings)
    return isotimestamp (sig->timestamp);
  else
    return dateonlystr_from_sig (sig);
}


const char *
expirestr_from_pk (PKT_public_key *pk)
{
  static char buffer[MK_DATESTR_SIZE];

  if (!pk->expiredate)
    return _("never     ");

  if (opt.flags.full_timestrings)
    return isotimestamp (pk->expiredate);

  return mk_datestr (buffer, sizeof buffer, pk->expiredate);
}


const char *
expirestr_from_sig (PKT_signature *sig)
{
  static char buffer[MK_DATESTR_SIZE];

  if (!sig->expiredate)
    return _("never     ");

  if (opt.flags.full_timestrings)
    return isotimestamp (sig->expiredate);

  return mk_datestr (buffer, sizeof buffer, sig->expiredate);
}


const char *
revokestr_from_pk( PKT_public_key *pk )
{
  static char buffer[MK_DATESTR_SIZE];

  if(!pk->revoked.date)
    return _("never     ");

  if (opt.flags.full_timestrings)
    return isotimestamp (pk->revoked.date);

  return mk_datestr (buffer, sizeof buffer, pk->revoked.date);
}


const char *
usagestr_from_pk (PKT_public_key *pk, int fill)
{
  static char buffer[10];
  int i = 0;
  unsigned int use = pk->pubkey_usage;

  if ( use & PUBKEY_USAGE_SIG )
    buffer[i++] = 'S';

  if ( use & PUBKEY_USAGE_CERT )
    buffer[i++] = 'C';

  if ( use & PUBKEY_USAGE_ENC )
    buffer[i++] = 'E';

  if ( (use & PUBKEY_USAGE_AUTH) )
    buffer[i++] = 'A';

  if ( (use & PUBKEY_USAGE_RENC) )
    buffer[i++] = 'R';
  if ( (use & PUBKEY_USAGE_TIME) )
    buffer[i++] = 'T';
  if ( (use & PUBKEY_USAGE_GROUP) )
    buffer[i++] = 'G';

  while (fill && i < 4)
    buffer[i++] = ' ';

  buffer[i] = 0;
  return buffer;
}


const char *
colon_strtime (u32 t)
{
  static char buf[20];

  if (!t)
    return "";
  snprintf (buf, sizeof buf, "%lu", (ulong)t);
  return buf;
}

const char *
colon_datestr_from_pk (PKT_public_key *pk)
{
  static char buf[20];

  snprintf (buf, sizeof buf, "%lu", (ulong)pk->timestamp);
  return buf;
}


const char *
colon_datestr_from_sig (PKT_signature *sig)
{
  static char buf[20];

  snprintf (buf, sizeof buf, "%lu", (ulong)sig->timestamp);
  return buf;
}

const char *
colon_expirestr_from_sig (PKT_signature *sig)
{
  static char buf[20];

  if (!sig->expiredate)
    return "";

  snprintf (buf, sizeof buf,"%lu", (ulong)sig->expiredate);
  return buf;
}



/*
 * Return a byte array with the fingerprint for the given PK/SK
 * The length of the array is returned in ret_len. Caller must free
 * the array or provide an array of length MAX_FINGERPRINT_LEN.
 */
byte *
fingerprint_from_pk (PKT_public_key *pk, byte *array, size_t *ret_len)
{
  if (!pk->fprlen)
    compute_fingerprint (pk);

  if (!array)
    array = xmalloc (pk->fprlen);
  memcpy (array, pk->fpr, pk->fprlen);

  if (ret_len)
    *ret_len = pk->fprlen;
  return array;
}


/*
 * Return a byte array with the fingerprint for the given PK/SK The
 * length of the array is returned in ret_len. Caller must free the
 * array or provide an array of length MAX_FINGERPRINT_LEN.  This
 * version creates a v5 fingerprint even vor v4 keys.
 */
byte *
v5_fingerprint_from_pk (PKT_public_key *pk, byte *array, size_t *ret_len)
{
  const byte *dp;
  gcry_md_hd_t md;

  if (pk->version == 5)
    return fingerprint_from_pk (pk, array, ret_len);

  if (gcry_md_open (&md, GCRY_MD_SHA256, 0))
    BUG ();
  do_hash_public_key (md, pk, 1);
  gcry_md_final (md);
  dp = gcry_md_read (md, 0);
  if (!array)
    array = xmalloc (32);
  memcpy (array, dp, 32);
  gcry_md_close (md);

  if (ret_len)
    *ret_len = 32;
  return array;
}


/*
 * This is the core of fpr20_from_pk which directly takes a
 * fingerprint and its length instead of the public key.  See below
 * for details.
 */
void
fpr20_from_fpr (const byte *fpr, unsigned int fprlen, byte array[20])
{
  if (fprlen >= 32)            /* v5 fingerprint (or larger) */
    {
      memcpy (array +  0, fpr + 20, 4);
      memcpy (array +  4, fpr + 24, 4);
      memcpy (array +  8, fpr + 28, 4);
      memcpy (array + 12, fpr +  0, 4); /* kid[0] */
      memcpy (array + 16, fpr +  4, 4); /* kid[1] */
    }
  else if (fprlen == 20)       /* v4 fingerprint */
    memcpy (array, fpr, 20);
  else                         /* v3 or too short: fill up with zeroes.  */
    {
      memset (array, 0, 20);
      memcpy (array, fpr, fprlen);
    }
}


/*
 * Get FPR20 for the given PK/SK into ARRAY.
 *
 * FPR20 is special form of fingerprint of length 20 for the record of
 * trustdb.  For v4key, having fingerprint with SHA-1, FPR20 is the
 * same one.  For v5key, FPR20 is constructed from its fingerprint
 * with SHA-2, so that its kid of last 8-byte can be as same as
 * kid of v5key fingerprint.
 *
 */
void
fpr20_from_pk (PKT_public_key *pk, byte array[20])
{
  if (!pk->fprlen)
    compute_fingerprint (pk);

  fpr20_from_fpr (pk->fpr, pk->fprlen, array);
}


/* Return an allocated buffer with the fingerprint of PK formatted as
 * a plain hexstring.  If BUFFER is NULL the result is a malloc'd
 * string.  If BUFFER is not NULL the result will be copied into this
 * buffer.  In the latter case BUFLEN describes the length of the
 * buffer; if this is too short the function terminates the process.
 * Returns a malloc'ed string or BUFFER.  A suitable length for BUFFER
 * is (2*MAX_FINGERPRINT_LEN + 1). */
char *
hexfingerprint (PKT_public_key *pk, char *buffer, size_t buflen)
{
  if (!pk->fprlen)
    compute_fingerprint (pk);

  if (!buffer)
    {
      buffer = xtrymalloc (2 * pk->fprlen + 1);
      if (!buffer)
        return NULL;
    }
  else if (buflen < 2 * pk->fprlen + 1)
    log_fatal ("%s: buffer too short (%zu)\n", __func__, buflen);

  bin2hex (pk->fpr, pk->fprlen, buffer);
  return buffer;
}


/* Same as hexfingerprint but returns a v5 fingerprint also for a v4
 * key.  */
char *
v5hexfingerprint (PKT_public_key *pk, char *buffer, size_t buflen)
{
  char fprbuf[32];

  if (pk->version == 5)
    return hexfingerprint (pk, buffer, buflen);

  if (!buffer)
    {
      buffer = xtrymalloc (2 * 32 + 1);
      if (!buffer)
        return NULL;
    }
  else if (buflen < 2 * 32 + 1)
    log_fatal ("%s: buffer too short (%zu)\n", __func__, buflen);

  v5_fingerprint_from_pk (pk, fprbuf, NULL);
  return bin2hex (fprbuf, 32, buffer);
}


/* Pretty print a hex fingerprint.  If BUFFER is NULL the result is a
   malloc'd string.  If BUFFER is not NULL the result will be copied
   into this buffer.  In the latter case BUFLEN describes the length
   of the buffer; if this is too short the function terminates the
   process.  Returns a malloc'ed string or BUFFER.  A suitable length
   for BUFFER is (MAX_FORMATTED_FINGERPRINT_LEN + 1).  */
char *
format_hexfingerprint (const char *fingerprint, char *buffer, size_t buflen)
{
  int hexlen = strlen (fingerprint);
  int space;
  int i, j;

  if (hexlen == 40)  /* v4 fingerprint */
    {
      space = (/* The characters and the NUL.  */
	       40 + 1
	       /* After every fourth character, we add a space (except
		  the last).  */
	       + 40 / 4 - 1
	       /* Half way through we add a second space.  */
	       + 1);
    }
  else if (hexlen == 64 || hexlen == 50)  /* v5 fingerprint */
    {
      /* The v5 fingerprint is commonly printed truncated to 25
       * octets.  We accept the truncated as well as the full hex
       * version here and format it like this:
       * 19347 BC987 24640 25F99 DF3EC 2E000 0ED98 84892 E1F7B 3EA4C
       */
      hexlen = 50;
      space = 10 * 5 + 9 + 1;
    }
  else  /* Other fingerprint versions - print as is.  */
    {
      /* We truncated here so that we do not need to provide a buffer
       * of a length which is in reality never used.  */
      if (hexlen > MAX_FORMATTED_FINGERPRINT_LEN - 1)
        hexlen = MAX_FORMATTED_FINGERPRINT_LEN - 1;
      space = hexlen + 1;
    }

  if (!buffer)
    buffer = xmalloc (space);
  else if (buflen < space)
    log_fatal ("%s: buffer too short (%zu)\n", __func__, buflen);

  if (hexlen == 40)  /* v4 fingerprint */
    {
      for (i = 0, j = 0; i < 40; i ++)
        {
          if (i && !(i % 4))
            buffer[j ++] = ' ';
          if (i == 40 / 2)
            buffer[j ++] = ' ';

          buffer[j ++] = fingerprint[i];
        }
      buffer[j ++] = 0;
      log_assert (j == space);
    }
  else if (hexlen == 50)  /* v5 fingerprint */
    {
      for (i=j=0; i < 50; i++)
        {
          if (i && !(i % 5))
            buffer[j++] = ' ';
          buffer[j++] = fingerprint[i];
        }
      buffer[j++] = 0;
      log_assert (j == space);
    }
  else
    {
      mem2str (buffer, fingerprint, space);
    }

  return buffer;
}



/* Return the so called KEYGRIP which is the SHA-1 hash of the public
   key parameters expressed as an canonical encoded S-Exp.  ARRAY must
   be 20 bytes long.  Returns 0 on success or an error code.  */
gpg_error_t
keygrip_from_pk (PKT_public_key *pk, unsigned char *array)
{
  gpg_error_t err;
  gcry_sexp_t s_pkey;

  if (DBG_PACKET)
    log_debug ("get_keygrip for public key\n");

  switch (pk->pubkey_algo)
    {
    case GCRY_PK_DSA:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                             pk->pkey[0], pk->pkey[1],
                             pk->pkey[2], pk->pkey[3]);
      break;

    case GCRY_PK_ELG:
    case GCRY_PK_ELG_E:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(elg(p%m)(g%m)(y%m)))",
                             pk->pkey[0], pk->pkey[1], pk->pkey[2]);
      break;

    case GCRY_PK_RSA:
    case GCRY_PK_RSA_S:
    case GCRY_PK_RSA_E:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(rsa(n%m)(e%m)))",
                             pk->pkey[0], pk->pkey[1]);
      break;

    case PUBKEY_ALGO_EDDSA:
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_ECDH:
      {
        char *curve = openpgp_oid_to_str (pk->pkey[0]);
        if (!curve)
          err = gpg_error_from_syserror ();
        else
          {
            err = gcry_sexp_build (&s_pkey, NULL,
                                   pk->pubkey_algo == PUBKEY_ALGO_EDDSA?
                                   "(public-key(ecc(curve%s)(flags eddsa)(q%m)))":
                                   (pk->pubkey_algo == PUBKEY_ALGO_ECDH
                                    && openpgp_oid_is_cv25519 (pk->pkey[0]))?
                                   "(public-key(ecc(curve%s)(flags djb-tweak)(q%m)))":
                                   "(public-key(ecc(curve%s)(q%m)))",
                                   curve, pk->pkey[1]);
            xfree (curve);
          }
      }
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      break;
    }

  if (err)
    return err;

  if (!gcry_pk_get_keygrip (s_pkey, array))
    {
      char *hexfpr;

      hexfpr = hexfingerprint (pk, NULL, 0);
      log_info ("error computing keygrip (fpr=%s)\n", hexfpr);
      xfree (hexfpr);

      memset (array, 0, 20);
      err = gpg_error (GPG_ERR_GENERAL);
    }
  else
    {
      if (DBG_PACKET)
        log_printhex (array, 20, "keygrip=");
      /* FIXME: Save the keygrip in PK.  */
    }
  gcry_sexp_release (s_pkey);

  return err;
}


/* Store an allocated buffer with the keygrip of PK encoded as a
   hexstring at r_GRIP.  Returns 0 on success.  */
gpg_error_t
hexkeygrip_from_pk (PKT_public_key *pk, char **r_grip)
{
  gpg_error_t err;
  unsigned char grip[KEYGRIP_LEN];

  *r_grip = NULL;
  err = keygrip_from_pk (pk, grip);
  if (!err)
    {
      char * buf = xtrymalloc (KEYGRIP_LEN * 2 + 1);
      if (!buf)
        err = gpg_error_from_syserror ();
      else
        {
          bin2hex (grip, KEYGRIP_LEN, buf);
          *r_grip = buf;
        }
    }
  return err;
}


/* Return a hexfied malloced string of the ECDH parameters for an ECDH
 * key from the public key PK.  Returns NULL on error.  */
char *
ecdh_param_str_from_pk (PKT_public_key *pk)
{
  const unsigned char *s;
  unsigned int n;

  if (!pk
      || pk->pubkey_algo != PUBKEY_ALGO_ECDH
      || !gcry_mpi_get_flag (pk->pkey[2], GCRYMPI_FLAG_OPAQUE)
      || !(s = gcry_mpi_get_opaque (pk->pkey[2], &n)) || !n)
    {
      gpg_err_set_errno (EINVAL);
      return NULL;  /* Invalid parameter */
    }

  n = (n+7)/8;
  return bin2hex (s, n, NULL);
}

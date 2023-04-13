/* protect.c - Un/Protect a secret key
 * Copyright (C) 1998-2003, 2007, 2009, 2011 Free Software Foundation, Inc.
 * Copyright (C) 1998-2003, 2007, 2009, 2011, 2013-2015 Werner Koch
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
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else
# include <sys/times.h>
#endif

#include "agent.h"

#include "cvt-openpgp.h"
#include "../common/sexp-parse.h"
#include "../common/openpgpdefs.h"  /* For s2k functions.  */


/* The protection mode for encryption.  The supported modes for
   decryption are listed in agent_unprotect().  */
#define PROT_CIPHER        GCRY_CIPHER_AES128
#define PROT_CIPHER_STRING "aes"
#define PROT_CIPHER_KEYLEN (128/8)


/* A table containing the information needed to create a protected
   private key.  */
static const struct {
  const char *algo;
  const char *parmlist;
  int prot_from, prot_to;
  int ecc_hack;
} protect_info[] = {
  { "rsa",  "nedpqu", 2, 5 },
  { "dsa",  "pqgyx", 4, 4 },
  { "elg",  "pgyx", 3, 3 },
  { "ecdsa","pabgnqd", 6, 6, 1 },
  { "ecdh", "pabgnqd", 6, 6, 1 },
  { "ecc",  "pabgnqd", 6, 6, 1 },
  { NULL }
};


/* The number of milliseconds we use in the S2K function and the
 * calibrated count value.  A count value of zero indicates that the
 * calibration has not yet been done or needs to be done again.  */
static unsigned int s2k_calibration_time = AGENT_S2K_CALIBRATION;
static unsigned long s2k_calibrated_count;


/* A helper object for time measurement.  */
struct calibrate_time_s
{
#ifdef HAVE_W32_SYSTEM
  FILETIME creation_time, exit_time, kernel_time, user_time;
#else
  clock_t ticks;
#endif
};


static int
hash_passphrase (const char *passphrase, int hashalgo,
                 int s2kmode,
                 const unsigned char *s2ksalt, unsigned long s2kcount,
                 unsigned char *key, size_t keylen);




/*
 * Determine if we can use clock_gettime with CLOCK_THREAD_CPUTIME_ID,
 * at compile time.
 */
#if defined (CLOCK_THREAD_CPUTIME_ID)
# if _POSIX_THREAD_CPUTIME > 0
# define USE_CLOCK_GETTIME 1
# elif _POSIX_THREAD_CPUTIME == 0
/*
 * In this case, we should check sysconf with _POSIX_THREAD_CPUTIME at
 * run time.  As heuristics, for system with newer GNU C library, we
 * can assume it is available.
 */
#  if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 17
#  define USE_CLOCK_GETTIME 1
#  endif
# endif
#else
#undef USE_CLOCK_GETTIME
#endif

/* Get the process time and store it in DATA.  */
static void
calibrate_get_time (struct calibrate_time_s *data)
{
#ifdef HAVE_W32_SYSTEM
  GetProcessTimes (GetCurrentProcess (),
                   &data->creation_time, &data->exit_time,
                   &data->kernel_time, &data->user_time);
#elif defined (USE_CLOCK_GETTIME)
  struct timespec tmp;

  clock_gettime (CLOCK_THREAD_CPUTIME_ID, &tmp);
  data->ticks = (clock_t)(((unsigned long long)tmp.tv_sec * 1000000000 +
                           tmp.tv_nsec) * CLOCKS_PER_SEC / 1000000000);
#else
  data->ticks = clock ();
#endif
}


static unsigned long
calibrate_elapsed_time (struct calibrate_time_s *starttime)
{
  struct calibrate_time_s stoptime;

  calibrate_get_time (&stoptime);
#ifdef HAVE_W32_SYSTEM
  {
    unsigned long long t1, t2;

    t1 = (((unsigned long long)starttime->kernel_time.dwHighDateTime << 32)
          + starttime->kernel_time.dwLowDateTime);
    t1 += (((unsigned long long)starttime->user_time.dwHighDateTime << 32)
           + starttime->user_time.dwLowDateTime);
    t2 = (((unsigned long long)stoptime.kernel_time.dwHighDateTime << 32)
          + stoptime.kernel_time.dwLowDateTime);
    t2 += (((unsigned long long)stoptime.user_time.dwHighDateTime << 32)
           + stoptime.user_time.dwLowDateTime);
    return (unsigned long)((t2 - t1)/10000);
  }
#else
  return (unsigned long)((((double) (stoptime.ticks - starttime->ticks))
                          /CLOCKS_PER_SEC)*1000);
#endif
}


/* Run a test hashing for COUNT and return the time required in
   milliseconds.  */
static unsigned long
calibrate_s2k_count_one (unsigned long count)
{
  int rc;
  char keybuf[PROT_CIPHER_KEYLEN];
  struct calibrate_time_s starttime;

  calibrate_get_time (&starttime);
  rc = hash_passphrase ("123456789abcdef0", GCRY_MD_SHA1,
                        3, "saltsalt", count, keybuf, sizeof keybuf);
  if (rc)
    BUG ();
  return calibrate_elapsed_time (&starttime);
}


/* Measure the time we need to do the hash operations and deduce an
   S2K count which requires roughly some targeted amount of time.  */
static unsigned long
calibrate_s2k_count (void)
{
  unsigned long count;
  unsigned long ms;

  for (count = 65536; count; count *= 2)
    {
      ms = calibrate_s2k_count_one (count);
      if (opt.verbose > 1)
        log_info ("S2K calibration: %lu -> %lums\n", count, ms);
      if (ms > s2k_calibration_time)
        break;
    }

  count = (unsigned long)(((double)count / ms) * s2k_calibration_time);
  count /= 1024;
  count *= 1024;
  if (count < 65536)
    count = 65536;

  if (opt.verbose)
    {
      ms = calibrate_s2k_count_one (count);
      log_info ("S2K calibration: %lu -> %lums\n", count, ms);
    }

  return count;
}


/* Set the calibration time.  This may be called early at startup or
 * at any time.  Thus it should one set variables.  */
void
set_s2k_calibration_time (unsigned int milliseconds)
{
  if (!milliseconds)
    milliseconds = AGENT_S2K_CALIBRATION;
  else if (milliseconds > 60 * 1000)
    milliseconds = 60 * 1000;  /* Cap at 60 seconds.  */
  s2k_calibration_time = milliseconds;
  s2k_calibrated_count = 0;  /* Force re-calibration.  */
}


/* Return the calibrated S2K count.  This is only public for the use
 * of the Assuan getinfo s2k_count_cal command.  */
unsigned long
get_calibrated_s2k_count (void)
{
  if (!s2k_calibrated_count)
    s2k_calibrated_count = calibrate_s2k_count ();

  /* Enforce a lower limit.  */
  return s2k_calibrated_count < 65536 ? 65536 : s2k_calibrated_count;
}


/* Return the standard S2K count.  */
unsigned long
get_standard_s2k_count (void)
{
  if (opt.s2k_count)
    return opt.s2k_count < 65536 ? 65536 : opt.s2k_count;

  return get_calibrated_s2k_count ();
}


/* Return the milliseconds required for the standard S2K
 * operation.  */
unsigned long
get_standard_s2k_time (void)
{
  return calibrate_s2k_count_one (get_standard_s2k_count ());
}


/* Same as get_standard_s2k_count but return the count in the encoding
   as described by rfc4880.  */
unsigned char
get_standard_s2k_count_rfc4880 (void)
{
  unsigned long iterations;
  unsigned int count;
  unsigned char result;
  unsigned char c=0;

  iterations = get_standard_s2k_count ();
  if (iterations >= 65011712)
    return 255;

  /* Need count to be in the range 16-31 */
  for (count=iterations>>6; count>=32; count>>=1)
    c++;

  result = (c<<4)|(count-16);

  if (S2K_DECODE_COUNT(result) < iterations)
    result++;

  return result;

}



/* Calculate the MIC for a private key or shared secret S-expression.
   SHA1HASH should point to a 20 byte buffer.  This function is
   suitable for all algorithms. */
static gpg_error_t
calculate_mic (const unsigned char *plainkey, unsigned char *sha1hash)
{
  const unsigned char *hash_begin, *hash_end;
  const unsigned char *s;
  size_t n;
  int is_shared_secret;

  s = plainkey;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (smatch (&s, n, "private-key"))
    is_shared_secret = 0;
  else if (smatch (&s, n, "shared-secret"))
    is_shared_secret = 1;
  else
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  hash_begin = s;
  if (!is_shared_secret)
    {
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      s += n; /* Skip the algorithm name.  */
    }

  while (*s == '(')
    {
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      s += n;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      s += n;
      if ( *s != ')' )
        return gpg_error (GPG_ERR_INV_SEXP);
      s++;
    }
  if (*s != ')')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  hash_end = s;

  gcry_md_hash_buffer (GCRY_MD_SHA1, sha1hash,
                       hash_begin, hash_end - hash_begin);

  return 0;
}



/* Encrypt the parameter block starting at PROTBEGIN with length
   PROTLEN using the utf8 encoded key PASSPHRASE and return the entire
   encrypted block in RESULT or return with an error code.  SHA1HASH
   is the 20 byte SHA-1 hash required for the integrity code.

   The parameter block is expected to be an incomplete canonical
   encoded S-Expression of the form (example in advanced format):

     (d #046129F..[some bytes not shown]..81#)
     (p #00e861b..[some bytes not shown]..f1#)
     (q #00f7a7c..[some bytes not shown]..61#)
     (u #304559a..[some bytes not shown]..9b#)

     the returned block is the S-Expression:

     (protected mode (parms) encrypted_octet_string)

*/
static int
do_encryption (const unsigned char *hashbegin, size_t hashlen,
               const unsigned char *protbegin, size_t protlen,
               const char *passphrase,
               const char *timestamp_exp, size_t timestamp_exp_len,
               unsigned char **result, size_t *resultlen,
	       unsigned long s2k_count)
{
  gcry_cipher_hd_t hd;
  const char *modestr;
  int enclen, outlen;
  unsigned char *iv = NULL;
  unsigned int ivsize;  /* Size of the buffer allocated for IV.  */
  const unsigned char *s2ksalt; /* Points into IV.  */
  int rc;
  char *outbuf = NULL;
  char *p;
  int saltpos, ivpos, encpos;

  s2ksalt = iv;  /* Silence compiler warning.  */

  *resultlen = 0;
  *result = NULL;

  modestr = "openpgp-s2k3-ocb-aes";

  rc = gcry_cipher_open (&hd, PROT_CIPHER,
                         GCRY_CIPHER_MODE_OCB,
                         GCRY_CIPHER_SECURE);
  if (rc)
    return rc;

  /* We need to work on a copy of the data because this makes it
   * easier to add the trailer and the padding and more important we
   * have to prefix the text with 2 parenthesis.  Due to OCB mode we
   * have to allocate enough space for just:
   *
   *   ((<parameter_list>))
   */

  /*       ((            )) */
  outlen = 2 + protlen + 2 ;
  enclen = outlen + 16 /* taglen */;
  outbuf = gcry_malloc_secure (enclen);
  if (!outbuf)
    {
      rc = out_of_core ();
      goto leave;
    }

  /* Allocate a buffer for the nonce and the salt.  */
  if (!rc)
    {
      /* Allocate random bytes to be used as nonce and s2k salt.  The
       * nonce is set later because for OCB we need to set the key
       * first.  */
      ivsize = 12 + 8;
      iv = xtrymalloc (ivsize);
      if (!iv)
        rc = gpg_error_from_syserror ();
      else
        {
          gcry_create_nonce (iv, ivsize);
          s2ksalt = iv + ivsize - 8;
        }
    }

  /* Hash the passphrase and set the key.  */
  if (!rc)
    {
      unsigned char *key;
      size_t keylen = PROT_CIPHER_KEYLEN;

      key = gcry_malloc_secure (keylen);
      if (!key)
        rc = out_of_core ();
      else
        {
          rc = hash_passphrase (passphrase, GCRY_MD_SHA1,
                                3, s2ksalt,
				s2k_count? s2k_count:get_standard_s2k_count(),
				key, keylen);
          if (!rc)
            rc = gcry_cipher_setkey (hd, key, keylen);
          xfree (key);
        }
    }

  if (rc)
    goto leave;

  /* Set the IV/nonce.  */
  rc = gcry_cipher_setiv (hd, iv, 12);
  if (rc)
    goto leave;

  /* In OCB Mode we use only the public key parameters as AAD.  */
  rc = gcry_cipher_authenticate (hd, hashbegin, protbegin - hashbegin);
  if (!rc)
    rc = gcry_cipher_authenticate (hd, timestamp_exp, timestamp_exp_len);
  if (!rc)
    rc = gcry_cipher_authenticate
      (hd, protbegin+protlen, hashlen - (protbegin+protlen - hashbegin));

  /* Encrypt.  */
  if (!rc)
    {
      p = outbuf;
      *p++ = '(';
      *p++ = '(';
      memcpy (p, protbegin, protlen);
      p += protlen;
      *p++ = ')';
      *p++ = ')';
      log_assert ( p - outbuf == outlen);
      gcry_cipher_final (hd);
      rc = gcry_cipher_encrypt (hd, outbuf, outlen, NULL, 0);
      if (!rc)
        {
          log_assert (outlen + 16 == enclen);
          rc = gcry_cipher_gettag (hd, outbuf + outlen, 16);
        }
    }

  if (rc)
    goto leave;

  /* Release cipher handle and check for errors.  */
  gcry_cipher_close (hd);

  /* Now allocate the buffer we want to return.  This is

     (protected openpgp-s2k3-sha1-aes-cbc
       ((sha1 salt no_of_iterations) 16byte_iv)
       encrypted_octet_string)

     in canoncical format of course.  We use asprintf and %n modifier
     and dummy values as placeholders.  */
  {
    char countbuf[35];

    snprintf (countbuf, sizeof countbuf, "%lu",
	    s2k_count ? s2k_count : get_standard_s2k_count ());
    p = xtryasprintf
      ("(9:protected%d:%s((4:sha18:%n_8bytes_%u:%s)%d:%n%*s)%d:%n%*s)",
       (int)strlen (modestr), modestr,
       &saltpos,
       (unsigned int)strlen (countbuf), countbuf,
       12, &ivpos, 12, "",
       enclen, &encpos, enclen, "");
    if (!p)
      {
        gpg_error_t tmperr = out_of_core ();
        xfree (iv);
        xfree (outbuf);
        return tmperr;
      }

  }
  *resultlen = strlen (p);
  *result = (unsigned char*)p;
  memcpy (p+saltpos, s2ksalt, 8);
  memcpy (p+ivpos, iv, 12);
  memcpy (p+encpos, outbuf, enclen);
  xfree (iv);
  xfree (outbuf);
  return 0;

 leave:
  gcry_cipher_close (hd);
  xfree (iv);
  xfree (outbuf);
  return rc;
}



/* Protect the key encoded in canonical format in PLAINKEY.  We assume
 * a valid S-Exp here.  */
int
agent_protect (const unsigned char *plainkey, const char *passphrase,
               unsigned char **result, size_t *resultlen,
	       unsigned long s2k_count)
{
  int rc;
  const char *parmlist;
  int prot_from_idx, prot_to_idx;
  const unsigned char *s;
  const unsigned char *hash_begin, *hash_end;
  const unsigned char *prot_begin, *prot_end, *real_end;
  size_t n;
  int c, infidx, i;
  char timestamp_exp[35];
  unsigned char *protected;
  size_t protectedlen;
  int depth = 0;
  unsigned char *p;
  int have_curve = 0;

  /* Create an S-expression with the protected-at timestamp.  */
  memcpy (timestamp_exp, "(12:protected-at15:", 19);
  gnupg_get_isotime (timestamp_exp+19);
  timestamp_exp[19+15] = ')';

  /* Parse original key.  */
  s = plainkey;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  depth++;
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, n, "private-key"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  depth++;
  hash_begin = s;
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  for (infidx=0; protect_info[infidx].algo
              && !smatch (&s, n, protect_info[infidx].algo); infidx++)
    ;
  if (!protect_info[infidx].algo)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  /* The parser below is a complete mess: To make it robust for ECC
     use we should reorder the s-expression to include only what we
     really need and thus guarantee the right order for saving stuff.
     This should be done before calling this function and maybe with
     the help of the new gcry_sexp_extract_param.  */
  parmlist      = protect_info[infidx].parmlist;
  prot_from_idx = protect_info[infidx].prot_from;
  prot_to_idx   = protect_info[infidx].prot_to;
  prot_begin = prot_end = NULL;
  for (i=0; (c=parmlist[i]); i++)
    {
      if (i == prot_from_idx)
        prot_begin = s;
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      depth++;
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (n != 1 || c != *s)
        {
          if (n == 5 && !memcmp (s, "curve", 5)
              && !i && protect_info[infidx].ecc_hack)
            {
              /* This is a private ECC key but the first parameter is
                 the name of the curve.  We change the parameter list
                 here to the one we expect in this case.  */
              have_curve = 1;
              parmlist = "?qd";
              prot_from_idx = 2;
              prot_to_idx = 2;
            }
          else if (n == 5 && !memcmp (s, "flags", 5)
                   && i == 1 && have_curve)
            {
              /* "curve" followed by "flags": Change again.  */
              parmlist = "??qd";
              prot_from_idx = 3;
              prot_to_idx = 3;
            }
          else
            return gpg_error (GPG_ERR_INV_SEXP);
        }
      s += n;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      s +=n; /* skip value */
      if (*s != ')')
        return gpg_error (GPG_ERR_INV_SEXP);
      depth--;
      if (i == prot_to_idx)
        prot_end = s;
      s++;
    }
  if (*s != ')' || !prot_begin || !prot_end )
    return gpg_error (GPG_ERR_INV_SEXP);
  depth--;
  hash_end = s;
  s++;
  /* Skip to the end of the S-expression.  */
  log_assert (depth == 1);
  rc = sskip (&s, &depth);
  if (rc)
    return rc;
  log_assert (!depth);
  real_end = s-1;

  rc = do_encryption (hash_begin, hash_end - hash_begin + 1,
                      prot_begin, prot_end - prot_begin + 1,
                      passphrase, timestamp_exp, sizeof (timestamp_exp),
                      &protected, &protectedlen, s2k_count);
  if (rc)
    return rc;

  /* Now create the protected version of the key.  Note that the 10
     extra bytes are for the inserted "protected-" string (the
     beginning of the plaintext reads: "((11:private-key(" ).  The 35
     term is the space for (12:protected-at15:<timestamp>).  */
  *resultlen = (10
                + (prot_begin-plainkey)
                + protectedlen
                + 35
                + (real_end-prot_end));
  *result = p = xtrymalloc (*resultlen);
  if (!p)
    {
      gpg_error_t tmperr = out_of_core ();
      xfree (protected);
      return tmperr;
    }
  memcpy (p, "(21:protected-", 14);
  p += 14;
  memcpy (p, plainkey+4, prot_begin - plainkey - 4);
  p += prot_begin - plainkey - 4;
  memcpy (p, protected, protectedlen);
  p += protectedlen;

  memcpy (p, timestamp_exp, 35);
  p += 35;

  memcpy (p, prot_end+1, real_end - prot_end);
  p += real_end - prot_end;
  log_assert ( p - *result == *resultlen);
  xfree (protected);

  return 0;
}



/* Do the actual decryption and check the return list for consistency.  */
static gpg_error_t
do_decryption (const unsigned char *aad_begin, size_t aad_len,
               const unsigned char *aadhole_begin, size_t aadhole_len,
               const unsigned char *protected, size_t protectedlen,
               const char *passphrase,
               const unsigned char *s2ksalt, unsigned long s2kcount,
               const unsigned char *iv, size_t ivlen,
               int prot_cipher, int prot_cipher_keylen, int is_ocb,
               unsigned char **result)
{
  int rc;
  int blklen;
  gcry_cipher_hd_t hd;
  unsigned char *outbuf;
  size_t reallen;

  blklen = gcry_cipher_get_algo_blklen (prot_cipher);
  if (is_ocb)
    {
      /* OCB does not require a multiple of the block length but we
       * check that it is long enough for the 128 bit tag and that we
       * have the 96 bit nonce.  */
      if (protectedlen < (4 + 16) || ivlen != 12)
        return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
    }
  else
    {
      if (protectedlen < 4 || (protectedlen%blklen))
        return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
    }

  rc = gcry_cipher_open (&hd, prot_cipher,
                         is_ocb? GCRY_CIPHER_MODE_OCB :
                         GCRY_CIPHER_MODE_CBC,
                         GCRY_CIPHER_SECURE);
  if (rc)
    return rc;

  outbuf = gcry_malloc_secure (protectedlen);
  if (!outbuf)
    rc = out_of_core ();

  /* Hash the passphrase and set the key.  */
  if (!rc)
    {
      unsigned char *key;

      key = gcry_malloc_secure (prot_cipher_keylen);
      if (!key)
        rc = out_of_core ();
      else
        {
          rc = hash_passphrase (passphrase, GCRY_MD_SHA1,
                                3, s2ksalt, s2kcount, key, prot_cipher_keylen);
          if (!rc)
            rc = gcry_cipher_setkey (hd, key, prot_cipher_keylen);
          xfree (key);
        }
    }

  /* Set the IV/nonce.  */
  if (!rc)
    {
      rc = gcry_cipher_setiv (hd, iv, ivlen);
    }

  /* Decrypt.  */
  if (!rc)
    {
      if (is_ocb)
        {
          rc = gcry_cipher_authenticate (hd, aad_begin,
                                         aadhole_begin - aad_begin);
          if (!rc)
            rc = gcry_cipher_authenticate
              (hd, aadhole_begin + aadhole_len,
               aad_len - (aadhole_begin+aadhole_len - aad_begin));

          if (!rc)
            {
              gcry_cipher_final (hd);
              rc = gcry_cipher_decrypt (hd, outbuf, protectedlen - 16,
                                        protected, protectedlen - 16);
            }
          if (!rc)
            {
              rc = gcry_cipher_checktag (hd, protected + protectedlen - 16, 16);
              if (gpg_err_code (rc) == GPG_ERR_CHECKSUM)
                {
                  /* Return Bad Passphrase instead of checksum error */
                  rc = gpg_error (GPG_ERR_BAD_PASSPHRASE);
                }
            }
        }
      else
        {
          rc = gcry_cipher_decrypt (hd, outbuf, protectedlen,
                                    protected, protectedlen);
        }
    }

  /* Release cipher handle and check for errors.  */
  gcry_cipher_close (hd);
  if (rc)
    {
      xfree (outbuf);
      return rc;
    }

  /* Do a quick check on the data structure. */
  if (*outbuf != '(' && outbuf[1] != '(')
    {
      xfree (outbuf);
      return gpg_error (GPG_ERR_BAD_PASSPHRASE);
    }

  /* Check that we have a consistent S-Exp. */
  reallen = gcry_sexp_canon_len (outbuf, protectedlen, NULL, NULL);
  if (!reallen || (reallen + blklen < protectedlen) )
    {
      xfree (outbuf);
      return gpg_error (GPG_ERR_BAD_PASSPHRASE);
    }
  *result = outbuf;
  return 0;
}


/* Merge the parameter list contained in CLEARTEXT with the original
 * protect lists PROTECTEDKEY by replacing the list at REPLACEPOS.
 * Return the new list in RESULT and the MIC value in the 20 byte
 * buffer SHA1HASH; if SHA1HASH is NULL no MIC will be computed.
 * CUTOFF and CUTLEN will receive the offset and the length of the
 * resulting list which should go into the MIC calculation but then be
 * removed.  */
static gpg_error_t
merge_lists (const unsigned char *protectedkey,
             size_t replacepos,
             const unsigned char *cleartext,
             unsigned char *sha1hash,
             unsigned char **result, size_t *resultlen,
             size_t *cutoff, size_t *cutlen)
{
  size_t n, newlistlen;
  unsigned char *newlist, *p;
  const unsigned char *s;
  const unsigned char *startpos, *endpos;
  int i, rc;

  *result = NULL;
  *resultlen = 0;
  *cutoff = 0;
  *cutlen = 0;

  if (replacepos < 26)
    return gpg_error (GPG_ERR_BUG);

  /* Estimate the required size of the resulting list.  We have a large
     safety margin of >20 bytes (FIXME: MIC hash from CLEARTEXT and the
     removed "protected-" */
  newlistlen = gcry_sexp_canon_len (protectedkey, 0, NULL, NULL);
  if (!newlistlen)
    return gpg_error (GPG_ERR_BUG);
  n = gcry_sexp_canon_len (cleartext, 0, NULL, NULL);
  if (!n)
    return gpg_error (GPG_ERR_BUG);
  newlistlen += n;
  newlist = gcry_malloc_secure (newlistlen);
  if (!newlist)
    return out_of_core ();

  /* Copy the initial segment */
  strcpy ((char*)newlist, "(11:private-key");
  p = newlist + 15;
  memcpy (p, protectedkey+15+10, replacepos-15-10);
  p += replacepos-15-10;

  /* Copy the cleartext.  */
  s = cleartext;
  if (*s != '(' && s[1] != '(')
    {
      xfree (newlist);
      return gpg_error (GPG_ERR_BUG);  /*we already checked this */
    }
  s += 2;
  startpos = s;
  while ( *s == '(' )
    {
      s++;
      n = snext (&s);
      if (!n)
        goto invalid_sexp;
      s += n;
      n = snext (&s);
      if (!n)
        goto invalid_sexp;
      s += n;
      if ( *s != ')' )
        goto invalid_sexp;
      s++;
    }
  if ( *s != ')' )
    goto invalid_sexp;
  endpos = s;
  s++;

  /* Intermezzo: Get the MIC if requested.  */
  if (sha1hash)
    {
      if (*s != '(')
        goto invalid_sexp;
      s++;
      n = snext (&s);
      if (!smatch (&s, n, "hash"))
        goto invalid_sexp;
      n = snext (&s);
      if (!smatch (&s, n, "sha1"))
        goto invalid_sexp;
      n = snext (&s);
      if (n != 20)
        goto invalid_sexp;
      memcpy (sha1hash, s, 20);
      s += n;
      if (*s != ')')
        goto invalid_sexp;
    }

  /* Append the parameter list.  */
  memcpy (p, startpos, endpos - startpos);
  p += endpos - startpos;

  /* Skip over the protected list element in the original list.  */
  s = protectedkey + replacepos;
  log_assert (*s == '(');
  s++;
  i = 1;
  rc = sskip (&s, &i);
  if (rc)
    goto failure;
  /* Record the position of the optional protected-at expression.  */
  if (*s == '(')
    {
      const unsigned char *save_s = s;
      s++;
      n = snext (&s);
      if (smatch (&s, n, "protected-at"))
        {
          i = 1;
          rc = sskip (&s, &i);
          if (rc)
            goto failure;
          *cutlen = s - save_s;
        }
      s = save_s;
    }
  startpos = s;
  i = 2; /* we are inside this level */
  rc = sskip (&s, &i);
  if (rc)
    goto failure;
  log_assert (s[-1] == ')');
  endpos = s; /* one behind the end of the list */

  /* Append the rest. */
  if (*cutlen)
    *cutoff = p - newlist;
  memcpy (p, startpos, endpos - startpos);
  p += endpos - startpos;


  /* ready */
  *result = newlist;
  *resultlen = newlistlen;
  return 0;

 failure:
  wipememory (newlist, newlistlen);
  xfree (newlist);
  return rc;

 invalid_sexp:
  wipememory (newlist, newlistlen);
  xfree (newlist);
  return gpg_error (GPG_ERR_INV_SEXP);
}



/* Unprotect the key encoded in canonical format.  We assume a valid
   S-Exp here.  If a protected-at item is available, its value will
   be stored at protected_at unless this is NULL.  */
gpg_error_t
agent_unprotect (ctrl_t ctrl,
                 const unsigned char *protectedkey, const char *passphrase,
                 gnupg_isotime_t protected_at,
                 unsigned char **result, size_t *resultlen)
{
  static const struct {
    const char *name; /* Name of the protection method. */
    int algo;         /* (A zero indicates the "openpgp-native" hack.)  */
    int keylen;       /* Used key length in bytes.  */
    unsigned int is_ocb:1;
  } algotable[] = {
    { "openpgp-s2k3-sha1-aes-cbc",    GCRY_CIPHER_AES128, (128/8)},
    { "openpgp-s2k3-sha1-aes256-cbc", GCRY_CIPHER_AES256, (256/8)},
    { "openpgp-s2k3-ocb-aes",         GCRY_CIPHER_AES128, (128/8), 1},
    { "openpgp-native", 0, 0 }
  };
  int rc;
  const unsigned char *s;
  const unsigned char *protect_list;
  size_t n;
  int infidx, i;
  unsigned char sha1hash[20], sha1hash2[20];
  const unsigned char *s2ksalt;
  unsigned long s2kcount;
  const unsigned char *iv;
  int prot_cipher, prot_cipher_keylen;
  int is_ocb;
  const unsigned char *aad_begin, *aad_end, *aadhole_begin, *aadhole_end;
  const unsigned char *prot_begin;
  unsigned char *cleartext;
  unsigned char *final;
  size_t finallen;
  size_t cutoff, cutlen;

  if (protected_at)
    *protected_at = 0;

  s = protectedkey;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, n, "protected-private-key"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  {
    aad_begin = aad_end = s;
    aad_end++;
    i = 1;
    rc = sskip (&aad_end, &i);
    if (rc)
      return rc;
  }

  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  for (infidx=0; protect_info[infidx].algo
              && !smatch (&s, n, protect_info[infidx].algo); infidx++)
    ;
  if (!protect_info[infidx].algo)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  /* See whether we have a protected-at timestamp.  */
  protect_list = s;  /* Save for later.  */
  if (protected_at)
    {
      while (*s == '(')
        {
          prot_begin = s;
          s++;
          n = snext (&s);
          if (!n)
            return gpg_error (GPG_ERR_INV_SEXP);
          if (smatch (&s, n, "protected-at"))
            {
              n = snext (&s);
              if (!n)
                return gpg_error (GPG_ERR_INV_SEXP);
              if (n != 15)
                return gpg_error (GPG_ERR_UNKNOWN_SEXP);
              memcpy (protected_at, s, 15);
              protected_at[15] = 0;
              break;
            }
          s += n;
          i = 1;
          rc = sskip (&s, &i);
          if (rc)
            return rc;
        }
    }

  /* Now find the list with the protected information.  Here is an
     example for such a list:
     (protected openpgp-s2k3-sha1-aes-cbc
        ((sha1 <salt> <count>) <Initialization_Vector>)
        <encrypted_data>)
   */
  s = protect_list;
  for (;;)
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      prot_begin = s;
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (smatch (&s, n, "protected"))
        break;
      s += n;
      i = 1;
      rc = sskip (&s, &i);
      if (rc)
        return rc;
    }
  /* found */
  {
    aadhole_begin = aadhole_end = prot_begin;
    aadhole_end++;
    i = 1;
    rc = sskip (&aadhole_end, &i);
    if (rc)
      return rc;
  }
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  /* Lookup the protection algo.  */
  prot_cipher = 0;        /* (avoid gcc warning) */
  prot_cipher_keylen = 0; /* (avoid gcc warning) */
  is_ocb = 0;
  for (i=0; i < DIM (algotable); i++)
    if (smatch (&s, n, algotable[i].name))
      {
        prot_cipher = algotable[i].algo;
        prot_cipher_keylen = algotable[i].keylen;
        is_ocb = algotable[i].is_ocb;
        break;
      }
  if (i == DIM (algotable))
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTECTION);

  if (!prot_cipher)  /* This is "openpgp-native".  */
    {
      gcry_sexp_t s_prot_begin;

      rc = gcry_sexp_sscan (&s_prot_begin, NULL,
                            prot_begin,
                            gcry_sexp_canon_len (prot_begin, 0,NULL,NULL));
      if (rc)
        return rc;

      rc = convert_from_openpgp_native (ctrl, s_prot_begin, passphrase, &final);
      gcry_sexp_release (s_prot_begin);
      if (!rc)
        {
          *result = final;
          *resultlen = gcry_sexp_canon_len (final, 0, NULL, NULL);
        }
      return rc;
    }

  if (*s != '(' || s[1] != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s += 2;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, n, "sha1"))
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTECTION);
  n = snext (&s);
  if (n != 8)
    return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
  s2ksalt = s;
  s += n;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
  /* We expect a list close as next, so we can simply use strtoul()
     here.  We might want to check that we only have digits - but this
     is nothing we should worry about */
  if (s[n] != ')' )
    return gpg_error (GPG_ERR_INV_SEXP);

  /* Old versions of gpg-agent used the funny floating point number in
     a byte encoding as specified by OpenPGP.  However this is not
     needed and thus we now store it as a plain unsigned integer.  We
     can easily distinguish the old format by looking at its value:
     Less than 256 is an old-style encoded number; other values are
     plain integers.  In any case we check that they are at least
     65536 because we never used a lower value in the past and we
     should have a lower limit.  */
  s2kcount = strtoul ((const char*)s, NULL, 10);
  if (!s2kcount)
    return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
  if (s2kcount < 256)
    s2kcount = (16ul + (s2kcount & 15)) << ((s2kcount >> 4) + 6);
  if (s2kcount < 65536)
    return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);

  s += n;
  s++; /* skip list end */

  n = snext (&s);
  if (is_ocb)
    {
      if (n != 12) /* Wrong size of the nonce. */
        return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
    }
  else
    {
      if (n != 16) /* Wrong blocksize for IV (we support only 128 bit). */
        return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
    }
  iv = s;
  s += n;
  if (*s != ')' )
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  cleartext = NULL; /* Avoid cc warning. */
  rc = do_decryption (aad_begin, aad_end - aad_begin,
                      aadhole_begin, aadhole_end - aadhole_begin,
                      s, n,
                      passphrase, s2ksalt, s2kcount,
                      iv, is_ocb? 12:16,
                      prot_cipher, prot_cipher_keylen, is_ocb,
                      &cleartext);
  if (rc)
    return rc;

  rc = merge_lists (protectedkey, prot_begin-protectedkey, cleartext,
                    is_ocb? NULL : sha1hash,
                    &final, &finallen, &cutoff, &cutlen);
  /* Albeit cleartext has been allocated in secure memory and thus
     xfree will wipe it out, we do an extra wipe just in case
     somethings goes badly wrong. */
  wipememory (cleartext, n);
  xfree (cleartext);
  if (rc)
    return rc;

  if (!is_ocb)
    {
      rc = calculate_mic (final, sha1hash2);
      if (!rc && memcmp (sha1hash, sha1hash2, 20))
        rc = gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
      if (rc)
        {
          wipememory (final, finallen);
          xfree (final);
          return rc;
        }
    }

  /* Now remove the part which is included in the MIC but should not
     go into the final thing.  */
  if (cutlen)
    {
      memmove (final+cutoff, final+cutoff+cutlen, finallen-cutoff-cutlen);
      finallen -= cutlen;
    }

  *result = final;
  *resultlen = gcry_sexp_canon_len (final, 0, NULL, NULL);
  return 0;
}


/* Check the type of the private key, this is one of the constants:
   PRIVATE_KEY_UNKNOWN if we can't figure out the type (this is the
   value 0), PRIVATE_KEY_CLEAR for an unprotected private key.
   PRIVATE_KEY_PROTECTED for an protected private key or
   PRIVATE_KEY_SHADOWED for a sub key where the secret parts are
   stored elsewhere.  Finally PRIVATE_KEY_OPENPGP_NONE may be returned
   is the key is still in the openpgp-native format but without
   protection.  */
int
agent_private_key_type (const unsigned char *privatekey)
{
  const unsigned char *s;
  size_t n;
  int i;

  s = privatekey;
  if (*s != '(')
    return PRIVATE_KEY_UNKNOWN;
  s++;
  n = snext (&s);
  if (!n)
    return PRIVATE_KEY_UNKNOWN;
  if (smatch (&s, n, "protected-private-key"))
    {
      /* We need to check whether this is openpgp-native protected
         with the protection method "none".  In that case we return a
         different key type so that the caller knows that there is no
         need to ask for a passphrase. */
      if (*s != '(')
        return PRIVATE_KEY_PROTECTED; /* Unknown sexp - assume protected. */
      s++;
      n = snext (&s);
      if (!n)
        return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
      s += n; /* Skip over the algo */

      /* Find the (protected ...) list.  */
      for (;;)
        {
          if (*s != '(')
            return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
          s++;
          n = snext (&s);
          if (!n)
            return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
          if (smatch (&s, n, "protected"))
            break;
          s += n;
          i = 1;
          if (sskip (&s, &i))
            return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
        }
      /* Found - Is this openpgp-native? */
      n = snext (&s);
      if (!n)
        return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
      if (smatch (&s, n, "openpgp-native")) /* Yes.  */
        {
          if (*s != '(')
            return PRIVATE_KEY_UNKNOWN; /* Unknown sexp. */
          s++;
          n = snext (&s);
          if (!n)
            return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
          s += n; /* Skip over "openpgp-private-key".  */
          /* Find the (protection ...) list.  */
          for (;;)
            {
              if (*s != '(')
                return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
              s++;
              n = snext (&s);
              if (!n)
                return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
              if (smatch (&s, n, "protection"))
                break;
              s += n;
              i = 1;
              if (sskip (&s, &i))
                return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
            }
          /* Found - Is the mode "none"? */
          n = snext (&s);
          if (!n)
            return PRIVATE_KEY_UNKNOWN; /* Invalid sexp.  */
          if (smatch (&s, n, "none"))
            return PRIVATE_KEY_OPENPGP_NONE;  /* Yes.  */
        }

      return PRIVATE_KEY_PROTECTED;
    }
  if (smatch (&s, n, "shadowed-private-key"))
    return PRIVATE_KEY_SHADOWED;
  if (smatch (&s, n, "private-key"))
    return PRIVATE_KEY_CLEAR;
  return PRIVATE_KEY_UNKNOWN;
}



/* Transform a passphrase into a suitable key of length KEYLEN and
   store this key in the caller provided buffer KEY.  The caller must
   provide an HASHALGO, a valid S2KMODE (see rfc-2440) and depending on
   that mode an S2KSALT of 8 random bytes and an S2KCOUNT.

   Returns an error code on failure.  */
static int
hash_passphrase (const char *passphrase, int hashalgo,
                 int s2kmode,
                 const unsigned char *s2ksalt,
                 unsigned long s2kcount,
                 unsigned char *key, size_t keylen)
{
  /* The key derive function does not support a zero length string for
     the passphrase in the S2K modes.  Return a better suited error
     code than GPG_ERR_INV_DATA.  */
  if (!passphrase || !*passphrase)
    return gpg_error (GPG_ERR_NO_PASSPHRASE);
  return gcry_kdf_derive (passphrase, strlen (passphrase),
                          s2kmode == 3? GCRY_KDF_ITERSALTED_S2K :
                          s2kmode == 1? GCRY_KDF_SALTED_S2K :
                          s2kmode == 0? GCRY_KDF_SIMPLE_S2K : GCRY_KDF_NONE,
                          hashalgo, s2ksalt, 8, s2kcount,
                          keylen, key);
}


gpg_error_t
s2k_hash_passphrase (const char *passphrase, int hashalgo,
                     int s2kmode,
                     const unsigned char *s2ksalt,
                     unsigned int s2kcount,
                     unsigned char *key, size_t keylen)
{
  return hash_passphrase (passphrase, hashalgo, s2kmode, s2ksalt,
                          S2K_DECODE_COUNT (s2kcount),
                          key, keylen);
}




/* Create an canonical encoded S-expression with the shadow info from
   a card's SERIALNO and the IDSTRING.  */
unsigned char *
make_shadow_info (const char *serialno, const char *idstring)
{
  const char *s;
  char *info, *p;
  char numbuf[20];
  size_t n;

  for (s=serialno, n=0; *s && s[1]; s += 2)
    n++;

  info = p = xtrymalloc (1 + sizeof numbuf + n
                           + sizeof numbuf + strlen (idstring) + 1 + 1);
  if (!info)
    return NULL;
  *p++ = '(';
  p = stpcpy (p, smklen (numbuf, sizeof numbuf, n, NULL));
  for (s=serialno; *s && s[1]; s += 2)
    *(unsigned char *)p++ = xtoi_2 (s);
  p = stpcpy (p, smklen (numbuf, sizeof numbuf, strlen (idstring), NULL));
  p = stpcpy (p, idstring);
  *p++ = ')';
  *p = 0;
  return (unsigned char *)info;
}



/* Create a shadow key from a public key.  We use the shadow protocol
  "t1-v1" and insert the S-expressionn SHADOW_INFO.  The resulting
  S-expression is returned in an allocated buffer RESULT will point
  to. The input parameters are expected to be valid canonicalized
  S-expressions */
int
agent_shadow_key_type (const unsigned char *pubkey,
                       const unsigned char *shadow_info,
                       const unsigned char *type,
                       unsigned char **result)
{
  const unsigned char *s;
  const unsigned char *point;
  size_t n;
  int depth = 0;
  char *p;
  size_t pubkey_len = gcry_sexp_canon_len (pubkey, 0, NULL,NULL);
  size_t shadow_info_len = gcry_sexp_canon_len (shadow_info, 0, NULL,NULL);

  if (!pubkey_len || !shadow_info_len)
    return gpg_error (GPG_ERR_INV_VALUE);
  s = pubkey;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  depth++;
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, n, "public-key"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  depth++;
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  s += n; /* skip over the algorithm name */

  while (*s != ')')
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      depth++;
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      s += n;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      s +=n; /* skip value */
      if (*s != ')')
        return gpg_error (GPG_ERR_INV_SEXP);
      depth--;
      s++;
    }
  point = s; /* insert right before the point */
  depth--;
  s++;
  log_assert (depth == 1);

  /* Calculate required length by taking in account: the "shadowed-"
     prefix, the "shadowed", shadow type as well as some parenthesis */
  n = 12 + pubkey_len + 1 + 3+8 + 2+5 + shadow_info_len + 1;
  *result = xtrymalloc (n);
  p = (char*)*result;
  if (!p)
      return out_of_core ();
  p = stpcpy (p, "(20:shadowed-private-key");
  /* (10:public-key ...)*/
  memcpy (p, pubkey+14, point - (pubkey+14));
  p += point - (pubkey+14);
  p += sprintf (p, "(8:shadowed%d:%s", (int)strlen(type), type);
  memcpy (p, shadow_info, shadow_info_len);
  p += shadow_info_len;
  *p++ = ')';
  memcpy (p, point, pubkey_len - (point - pubkey));
  p += pubkey_len - (point - pubkey);

  return 0;
}

int
agent_shadow_key (const unsigned char *pubkey,
                  const unsigned char *shadow_info,
                  unsigned char **result)
{
  return agent_shadow_key_type (pubkey, shadow_info, "t1-v1", result);
}

/* Parse a canonical encoded shadowed key and return a pointer to the
   inner list with the shadow_info and the shadow type */
gpg_error_t
agent_get_shadow_info_type (const unsigned char *shadowkey,
                            unsigned char const **shadow_info,
                            unsigned char **shadow_type)
{
  const unsigned char *s, *saved_s;
  size_t n, saved_n;
  int depth = 0;

  (void)depth;
  s = shadowkey;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  depth++;
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, n, "shadowed-private-key"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  depth++;
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  s += n; /* skip over the algorithm name */

  for (;;)
    {
      if (*s == ')')
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      depth++;
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (smatch (&s, n, "shadowed"))
        break;
      s += n;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      s +=n; /* skip value */
      if (*s != ')')
        return gpg_error (GPG_ERR_INV_SEXP);
      depth--;
      s++;
    }
  /* Found the shadowed list, S points to the protocol */
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  saved_s = s;
  saved_n = n;
  if (smatch (&s, n, "t1-v1") || smatch(&s, n, "tpm2-v1"))
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      if (shadow_info)
        *shadow_info = s;
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);
  s = saved_s;
  n = saved_n;

  if (shadow_type)
    {
      char *buf = xtrymalloc(n+1);
      if (!buf)
        return gpg_error_from_syserror ();
      memcpy (buf, s, n);
      buf[n] = '\0';
      *shadow_type = buf;
    }

  return 0;
}


gpg_error_t
agent_get_shadow_info (const unsigned char *shadowkey,
                       unsigned char const **shadow_info)
{
  return agent_get_shadow_info_type (shadowkey, shadow_info, NULL);
}


int
agent_is_tpm2_key (gcry_sexp_t s_skey)
{
  unsigned char *buf;
  unsigned char *type;
  size_t len;
  gpg_error_t err;

  err = make_canon_sexp (s_skey, &buf, &len);
  if (err)
    return 0;

  err = agent_get_shadow_info_type (buf, NULL, &type);
  xfree (buf);
  if (err)
    return 0;

  err = strcmp (type, "tpm2-v1") == 0;
  xfree (type);
  return err;
}


gpg_error_t
agent_get_shadow_type (const unsigned char *shadowkey,
                       unsigned char **shadow_type)
{
  return agent_get_shadow_info_type (shadowkey, NULL, shadow_type);
}


/* Parse the canonical encoded SHADOW_INFO S-expression.  On success
   the hex encoded serial number is returned as a malloced strings at
   R_HEXSN and the Id string as a malloced string at R_IDSTR.  On
   error an error code is returned and NULL is stored at the result
   parameters addresses.  If the serial number or the ID string is not
   required, NULL may be passed for them.  Note that R_PINLEN is
   currently not used by any caller.  */
gpg_error_t
parse_shadow_info (const unsigned char *shadow_info,
                   char **r_hexsn, char **r_idstr, int *r_pinlen)
{
  const unsigned char *s;
  size_t n;

  if (r_hexsn)
    *r_hexsn = NULL;
  if (r_idstr)
    *r_idstr = NULL;
  if (r_pinlen)
    *r_pinlen = 0;

  s = shadow_info;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  if (r_hexsn)
    {
      *r_hexsn = bin2hex (s, n, NULL);
      if (!*r_hexsn)
        return gpg_error_from_syserror ();
    }
  s += n;

  n = snext (&s);
  if (!n)
    {
      if (r_hexsn)
        {
          xfree (*r_hexsn);
          *r_hexsn = NULL;
        }
      return gpg_error (GPG_ERR_INV_SEXP);
    }

  if (r_idstr)
    {
      *r_idstr = xtrymalloc (n+1);
      if (!*r_idstr)
        {
          if (r_hexsn)
            {
              xfree (*r_hexsn);
              *r_hexsn = NULL;
            }
          return gpg_error_from_syserror ();
        }
      memcpy (*r_idstr, s, n);
      (*r_idstr)[n] = 0;
    }

  /* Parse the optional PINLEN.  */
  n = snext (&s);
  if (!n)
    return 0;

  if (r_pinlen)
    {
      char *tmpstr = xtrymalloc (n+1);
      if (!tmpstr)
        {
          if (r_hexsn)
            {
              xfree (*r_hexsn);
              *r_hexsn = NULL;
            }
          if (r_idstr)
            {
              xfree (*r_idstr);
              *r_idstr = NULL;
            }
          return gpg_error_from_syserror ();
        }
      memcpy (tmpstr, s, n);
      tmpstr[n] = 0;

      *r_pinlen = (int)strtol (tmpstr, NULL, 10);
      xfree (tmpstr);
    }

  return 0;
}

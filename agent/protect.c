/* protect.c - Un/Protect a secret key
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2003, 2007, 2009 Free Software Foundation, Inc.
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
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
#else
# include <sys/times.h>
#endif

#include "agent.h"

#include "sexp-parse.h"

#define PROT_CIPHER        GCRY_CIPHER_AES
#define PROT_CIPHER_STRING "aes"
#define PROT_CIPHER_KEYLEN (128/8)


/* A table containing the information needed to create a protected
   private key */
static struct {
  const char *algo;
  const char *parmlist;
  int prot_from, prot_to;
} protect_info[] = {
  { "rsa",  "nedpqu", 2, 5 },
  { "dsa",  "pqgyx", 4, 4 },
  { "elg",  "pgyx", 3, 3 },
  { NULL }
};


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

/* Get the process time and store it in DATA.  */
static void
calibrate_get_time (struct calibrate_time_s *data)
{
#ifdef HAVE_W32_SYSTEM
  GetProcessTimes (GetCurrentProcess (),
                   &data->creation_time, &data->exit_time,
                   &data->kernel_time, &data->user_time);
#else
  struct tms tmp;
  
  times (&tmp);
  data->ticks = tmp.tms_utime;
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
                          /CLOCKS_PER_SEC)*10000000);
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
   S2K count which requires about 100ms of time.  */ 
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
      if (ms > 100)
        break;
    }

  count = (unsigned long)(((double)count / ms) * 100);
  count /= 1024;
  count *= 1024;
  if (count < 65536)
    count = 65536;

  if (opt.verbose)
    {
      ms = calibrate_s2k_count_one (count);
      log_info ("S2K calibration: %lu iterations for %lums\n", count, ms);
    }

  return count;
}



/* Return the standard S2K count.  */
unsigned long
get_standard_s2k_count (void)
{
  static unsigned long count;

  if (!count)
    count = calibrate_s2k_count ();

  /* Enforce a lower limit.  */
  return count < 65536 ? 65536 : count;
}




/* Calculate the MIC for a private key S-Exp. SHA1HASH should point to
   a 20 byte buffer.  This function is suitable for any algorithms. */
static int 
calculate_mic (const unsigned char *plainkey, unsigned char *sha1hash)
{
  const unsigned char *hash_begin, *hash_end;
  const unsigned char *s;
  size_t n;

  s = plainkey;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 
  if (!smatch (&s, n, "private-key"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP); 
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  hash_begin = s;
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 
  s += n; /* skip over the algorithm name */

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

   The parameter block is expected to be an incomplete S-Expression of
   the form (example in advanced format):

     (d #046129F..[some bytes not shown]..81#)
     (p #00e861b..[some bytes not shown]..f1#)
     (q #00f7a7c..[some bytes not shown]..61#)
     (u #304559a..[some bytes not shown]..9b#) 

   the returned block is the S-Expression:

    (protected mode (parms) encrypted_octet_string)

*/
static int
do_encryption (const unsigned char *protbegin, size_t protlen, 
               const char *passphrase,  const unsigned char *sha1hash,
               unsigned char **result, size_t *resultlen)
{
  gcry_cipher_hd_t hd;
  const char *modestr = "openpgp-s2k3-sha1-" PROT_CIPHER_STRING "-cbc";
  int blklen, enclen, outlen;
  unsigned char *iv = NULL;
  int rc;
  char *outbuf = NULL;
  char *p;
  int saltpos, ivpos, encpos;

  *resultlen = 0;
  *result = NULL;

  rc = gcry_cipher_open (&hd, PROT_CIPHER, GCRY_CIPHER_MODE_CBC,
                         GCRY_CIPHER_SECURE);
  if (rc)
    return rc;


  /* We need to work on a copy of the data because this makes it
     easier to add the trailer and the padding and more important we
     have to prefix the text with 2 parenthesis, so we have to
     allocate enough space for:

     ((<parameter_list>)(4:hash4:sha120:<hashvalue>)) + padding

     We always append a full block of random bytes as padding but
     encrypt only what is needed for a full blocksize.  */
  blklen = gcry_cipher_get_algo_blklen (PROT_CIPHER);
  outlen = 2 + protlen + 2 + 6 + 6 + 23 + 2 + blklen;
  enclen = outlen/blklen * blklen;
  outbuf = gcry_malloc_secure (outlen);
  if (!outbuf)
    rc = out_of_core ();
  if (!rc)
    {
      /* Allocate random bytes to be used as IV, padding and s2k salt. */
      iv = xtrymalloc (blklen*2+8);
      if (!iv)
        rc = gpg_error (GPG_ERR_ENOMEM);
      else
        {
          gcry_create_nonce (iv, blklen*2+8);
          rc = gcry_cipher_setiv (hd, iv, blklen);
        }
    }
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
                                3, iv+2*blklen, 
                                get_standard_s2k_count (), key, keylen);
          if (!rc)
            rc = gcry_cipher_setkey (hd, key, keylen);
          xfree (key);
        }
    }
  if (!rc)
    {
      p = outbuf;
      *p++ = '(';
      *p++ = '(';
      memcpy (p, protbegin, protlen);
      p += protlen;
      memcpy (p, ")(4:hash4:sha120:", 17);
      p += 17;
      memcpy (p, sha1hash, 20);
      p += 20;
      *p++ = ')';
      *p++ = ')';
      memcpy (p, iv+blklen, blklen); 
      p += blklen;
      assert ( p - outbuf == outlen);
      rc = gcry_cipher_encrypt (hd, outbuf, enclen, NULL, 0);
    }
  gcry_cipher_close (hd);
  if (rc)
    {
      xfree (iv);
      xfree (outbuf);
      return rc;
    }

  /* Now allocate the buffer we want to return.  This is

     (protected openpgp-s2k3-sha1-aes-cbc
       ((sha1 salt no_of_iterations) 16byte_iv)
       encrypted_octet_string)
       
     in canoncical format of course.  We use asprintf and %n modifier
     and dummy values as placeholders.  */
  {
    char countbuf[35];

    snprintf (countbuf, sizeof countbuf, "%lu", get_standard_s2k_count ());
    p = xtryasprintf
      ("(9:protected%d:%s((4:sha18:%n_8bytes_%u:%s)%d:%n%*s)%d:%n%*s)",
       (int)strlen (modestr), modestr,
       &saltpos, 
       (unsigned int)strlen (countbuf), countbuf,
       blklen, &ivpos, blklen, "",
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
  memcpy (p+saltpos, iv+2*blklen, 8);
  memcpy (p+ivpos, iv, blklen);
  memcpy (p+encpos, outbuf, enclen);
  xfree (iv);
  xfree (outbuf);
  return 0;
}



/* Protect the key encoded in canonical format in PLAINKEY.  We assume
   a valid S-Exp here. */
int 
agent_protect (const unsigned char *plainkey, const char *passphrase,
               unsigned char **result, size_t *resultlen)
{
  int rc;
  const unsigned char *s;
  const unsigned char *hash_begin, *hash_end;
  const unsigned char *prot_begin, *prot_end, *real_end;
  size_t n;
  int c, infidx, i;
  unsigned char hashvalue[20];
  char timestamp_exp[35];
  unsigned char *protected;
  size_t protectedlen;
  int depth = 0;
  unsigned char *p;
  gcry_md_hd_t md;

  /* Create an S-expression with the procted-at timestamp.  */
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

  prot_begin = prot_end = NULL;
  for (i=0; (c=protect_info[infidx].parmlist[i]); i++)
    {
      if (i == protect_info[infidx].prot_from)
        prot_begin = s;
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      depth++;
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP); 
      if (n != 1 || c != *s)
        return gpg_error (GPG_ERR_INV_SEXP); 
      s += n;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP); 
      s +=n; /* skip value */
      if (*s != ')')
        return gpg_error (GPG_ERR_INV_SEXP); 
      depth--;
      if (i == protect_info[infidx].prot_to)
        prot_end = s;
      s++;
    }
  if (*s != ')' || !prot_begin || !prot_end )
    return gpg_error (GPG_ERR_INV_SEXP); 
  depth--;
  hash_end = s;
  s++;
  /* skip to the end of the S-exp */
  assert (depth == 1);
  rc = sskip (&s, &depth);
  if (rc)
    return rc;
  assert (!depth);
  real_end = s-1;

  
  /* Hash the stuff.  Because the timestamp_exp won't get protected,
     we can't simply hash a continuous buffer but need to use several
     md_writes.  */ 
  rc = gcry_md_open (&md, GCRY_MD_SHA1, 0 );
  if (rc)
    return rc;
  gcry_md_write (md, hash_begin, hash_end - hash_begin);
  gcry_md_write (md, timestamp_exp, 35);
  gcry_md_write (md, ")", 1);
  memcpy (hashvalue, gcry_md_read (md, GCRY_MD_SHA1), 20);
  gcry_md_close (md);

  rc = do_encryption (prot_begin, prot_end - prot_begin + 1,
                      passphrase,  hashvalue,
                      &protected, &protectedlen);
  if (rc)
    return rc;

  /* Now create the protected version of the key.  Note that the 10
     extra bytes are for for the inserted "protected-" string (the
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
  assert ( p - *result == *resultlen);
  xfree (protected);

  return 0;
}


/* Do the actual decryption and check the return list for consistency.  */
static int
do_decryption (const unsigned char *protected, size_t protectedlen, 
               const char *passphrase, 
               const unsigned char *s2ksalt, unsigned long s2kcount,
               const unsigned char *iv, size_t ivlen,
               unsigned char **result)
{
  int rc = 0;
  int blklen;
  gcry_cipher_hd_t hd;
  unsigned char *outbuf;
  size_t reallen;

  blklen = gcry_cipher_get_algo_blklen (PROT_CIPHER);
  if (protectedlen < 4 || (protectedlen%blklen))
    return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);

  rc = gcry_cipher_open (&hd, PROT_CIPHER, GCRY_CIPHER_MODE_CBC,
                         GCRY_CIPHER_SECURE);
  if (rc)
    return rc;

  outbuf = gcry_malloc_secure (protectedlen);
  if (!outbuf)
    rc = out_of_core ();
  if (!rc)
    rc = gcry_cipher_setiv (hd, iv, ivlen);
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
                                3, s2ksalt, s2kcount, key, keylen);
          if (!rc)
            rc = gcry_cipher_setkey (hd, key, keylen);
          xfree (key);
        }
    }
  if (!rc)
    rc = gcry_cipher_decrypt (hd, outbuf, protectedlen,
                              protected, protectedlen);
  gcry_cipher_close (hd);
  if (rc)
    {
      xfree (outbuf);
      return rc;
    }
  /* Do a quick check first. */
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
   protect lists PROTECTEDKEY by replacing the list at REPLACEPOS.
   Return the new list in RESULT and the MIC value in the 20 byte
   buffer SHA1HASH.  CUTOFF and CUTLEN will receive the offset and the
   length of the resulting list which should go into the MIC
   calculation but then be removed.  */
static int
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
     safety margin of >20 bytes (MIC hash from CLEARTEXT and the
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

  /* copy the cleartext */
  s = cleartext;
  if (*s != '(' && s[1] != '(')
    return gpg_error (GPG_ERR_BUG);  /*we already checked this */
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
  /* Intermezzo: Get the MIC */
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
  /* End intermezzo */

  /* append the parameter list */
  memcpy (p, startpos, endpos - startpos);
  p += endpos - startpos;
  
  /* Skip over the protected list element in the original list.  */
  s = protectedkey + replacepos;
  assert (*s == '(');
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
  assert (s[-1] == ')');
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
   be stored at protocted_at unless this is NULL.  */
int 
agent_unprotect (const unsigned char *protectedkey, const char *passphrase,
                 gnupg_isotime_t protected_at, 
                 unsigned char **result, size_t *resultlen)
{
  int rc;
  const unsigned char *s;
  const unsigned char *protect_list; 
  size_t n;
  int infidx, i;
  unsigned char sha1hash[20], sha1hash2[20];
  const unsigned char *s2ksalt;
  unsigned long s2kcount;
  const unsigned char *iv;
  const unsigned char *prot_begin;
  unsigned char *cleartext = NULL; /* Just to avoid gcc warning.  */
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
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 

  for (infidx=0; protect_info[infidx].algo
              && !smatch (&s, n, protect_info[infidx].algo); infidx++)
    ;
  if (!protect_info[infidx].algo)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM); 


  /* See wether we have a protected-at timestamp.  */
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
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 
  if (!smatch (&s, n, "openpgp-s2k3-sha1-" PROT_CIPHER_STRING "-cbc"))
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTECTION);
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
  if (n != 16) /* Wrong blocksize for IV (we support only aes-128). */
    return gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
  iv = s;
  s += n;
  if (*s != ')' )
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP); 
  
  rc = do_decryption (s, n,
                      passphrase, s2ksalt, s2kcount,
                      iv, 16,
                      &cleartext);
  if (rc)
    return rc;

  rc = merge_lists (protectedkey, prot_begin-protectedkey, cleartext,
                    sha1hash, &final, &finallen, &cutoff, &cutlen);
  /* Albeit cleartext has been allocated in secure memory and thus
     xfree will wipe it out, we do an extra wipe just in case
     somethings goes badly wrong. */
  wipememory (cleartext, n);
  xfree (cleartext);
  if (rc)
    return rc;

  rc = calculate_mic (final, sha1hash2);
  if (!rc && memcmp (sha1hash, sha1hash2, 20))
    rc = gpg_error (GPG_ERR_CORRUPTED_PROTECTION);
  if (rc)
    {
      wipememory (final, finallen);
      xfree (final);
      return rc;
    }
  /* Now remove tha part which is included in the MIC but should not
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
   PRIVATE_KEY_SHADOWED for a sub key where the secret parts are stored
   elsewhere. */
int
agent_private_key_type (const unsigned char *privatekey)
{
  const unsigned char *s;
  size_t n;

  s = privatekey;
  if (*s != '(')
    return PRIVATE_KEY_UNKNOWN;
  s++;
  n = snext (&s);
  if (!n)
    return PRIVATE_KEY_UNKNOWN;
  if (smatch (&s, n, "protected-private-key"))
    return PRIVATE_KEY_PROTECTED;
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
  int rc;
  gcry_md_hd_t md;
  int pass, i;
  int used = 0;
  int pwlen = strlen (passphrase);

  if ( (s2kmode != 0 && s2kmode != 1 && s2kmode != 3)
      || !hashalgo || !keylen || !key || !passphrase)
    return gpg_error (GPG_ERR_INV_VALUE);
  if ((s2kmode == 1 ||s2kmode == 3) && !s2ksalt)
    return gpg_error (GPG_ERR_INV_VALUE);
  
  rc = gcry_md_open (&md, hashalgo, GCRY_MD_FLAG_SECURE);
  if (rc)
    return rc;

  for (pass=0; used < keylen; pass++)
    {
      if (pass)
        {
          gcry_md_reset (md);
          for (i=0; i < pass; i++) /* preset the hash context */
            gcry_md_putc (md, 0);
	}

      if (s2kmode == 1 || s2kmode == 3)
        {
          int len2 = pwlen + 8;
          unsigned long count = len2;

          if (s2kmode == 3)
            {
              count = s2kcount;
              if (count < len2)
                count = len2;
            }

          while (count > len2)
            {
              gcry_md_write (md, s2ksalt, 8);
              gcry_md_write (md, passphrase, pwlen);
              count -= len2;
            }
          if (count < 8)
            gcry_md_write (md, s2ksalt, count);
          else 
            {
              gcry_md_write (md, s2ksalt, 8);
              count -= 8;
              gcry_md_write (md, passphrase, count);
            }
        }
      else
        gcry_md_write (md, passphrase, pwlen);
      
      gcry_md_final (md);
      i = gcry_md_get_algo_dlen (hashalgo);
      if (i > keylen - used)
        i = keylen - used;
      memcpy  (key+used, gcry_md_read (md, hashalgo), i);
      used += i;
    }
  gcry_md_close(md);
  return 0;
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
  "ti-v1" and insert the S-expressionn SHADOW_INFO.  The resulting
  S-expression is returned in an allocated buffer RESULT will point
  to. The input parameters are expected to be valid canonicalized
  S-expressions */
int 
agent_shadow_key (const unsigned char *pubkey,
                  const unsigned char *shadow_info,
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
  assert (depth == 1);

  /* Calculate required length by taking in account: the "shadowed-"
     prefix, the "shadowed", "t1-v1" as well as some parenthesis */
  n = 12 + pubkey_len + 1 + 3+8 + 2+5 + shadow_info_len + 1;
  *result = xtrymalloc (n);
  p = (char*)*result;
  if (!p)
      return out_of_core ();
  p = stpcpy (p, "(20:shadowed-private-key");
  /* (10:public-key ...)*/
  memcpy (p, pubkey+14, point - (pubkey+14));
  p += point - (pubkey+14);
  p = stpcpy (p, "(8:shadowed5:t1-v1");
  memcpy (p, shadow_info, shadow_info_len);
  p += shadow_info_len;
  *p++ = ')';
  memcpy (p, point, pubkey_len - (point - pubkey));
  p += pubkey_len - (point - pubkey);

  return 0;
}

/* Parse a canonical encoded shadowed key and return a pointer to the
   inner list with the shadow_info */
int 
agent_get_shadow_info (const unsigned char *shadowkey,
                       unsigned char const **shadow_info)
{
  const unsigned char *s;
  size_t n;
  int depth = 0;

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
  if (smatch (&s, n, "t1-v1"))
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      *shadow_info = s;
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);
  return 0;
}


/* Parse the canonical encoded SHADOW_INFO S-expression.  On success
   the hex encoded serial number is returned as a malloced strings at
   R_HEXSN and the Id string as a malloced string at R_IDSTR.  On
   error an error code is returned and NULL is stored at the result
   parameters addresses.  If the serial number or the ID string is not
   required, NULL may be passed for them.  */
gpg_error_t
parse_shadow_info (const unsigned char *shadow_info, 
                   char **r_hexsn, char **r_idstr)
{
  const unsigned char *s;
  size_t n;

  if (r_hexsn)
    *r_hexsn = NULL;
  if (r_idstr)
    *r_idstr = NULL;

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

  return 0;
}


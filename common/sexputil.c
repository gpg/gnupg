/* sexputil.c - Utility functions for S-expressions.
 * Copyright (C) 2005, 2007, 2009 Free Software Foundation, Inc.
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

/* This file implements a few utility functions useful when working
   with canonical encrypted S-expressions (i.e. not the S-exprssion
   objects from libgcrypt).  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "util.h"
#include "tlv.h"
#include "sexp-parse.h"
#include "openpgpdefs.h"  /* for pubkey_algo_t */


/* Return a malloced string with the S-expression CANON in advanced
   format.  Returns NULL on error.  */
static char *
sexp_to_string (gcry_sexp_t sexp)
{
  size_t n;
  char *result;

  if (!sexp)
    return NULL;
  n = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  if (!n)
    return NULL;
  result = xtrymalloc (n);
  if (!result)
    return NULL;
  n = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, result, n);
  if (!n)
    BUG ();

  return result;
}


/* Return a malloced string with the S-expression CANON in advanced
   format.  Returns NULL on error.  */
char *
canon_sexp_to_string (const unsigned char *canon, size_t canonlen)
{
  size_t n;
  gcry_sexp_t sexp;
  char *result;

  n = gcry_sexp_canon_len (canon, canonlen, NULL, NULL);
  if (!n)
    return NULL;
  if (gcry_sexp_sscan (&sexp, NULL, canon, n))
    return NULL;
  result = sexp_to_string (sexp);
  gcry_sexp_release (sexp);
  return result;
}


/* Print the canonical encoded S-expression in SEXP in advanced
   format.  SEXPLEN may be passed as 0 is SEXP is known to be valid.
   With TEXT of NULL print just the raw S-expression, with TEXT just
   an empty string, print a trailing linefeed, otherwise print an
   entire debug line. */
void
log_printcanon (const char *text, const unsigned char *sexp, size_t sexplen)
{
  if (text && *text)
    log_debug ("%s ", text);
  if (sexp)
    {
      char *buf = canon_sexp_to_string (sexp, sexplen);
      log_printf ("%s", buf? buf : "[invalid S-expression]");
      xfree (buf);
    }
  if (text)
    log_printf ("\n");
}


/* Print the gcrypt S-expression SEXP in advanced format.  With TEXT
   of NULL print just the raw S-expression, with TEXT just an empty
   string, print a trailing linefeed, otherwise print an entire debug
   line. */
void
log_printsexp (const char *text, gcry_sexp_t sexp)
{
  if (text && *text)
    log_debug ("%s ", text);
  if (sexp)
    {
      char *buf = sexp_to_string (sexp);
      log_printf ("%s", buf? buf : "[invalid S-expression]");
      xfree (buf);
    }
  if (text)
    log_printf ("\n");
}


/* Helper function to create a canonical encoded S-expression from a
   Libgcrypt S-expression object.  The function returns 0 on success
   and the malloced canonical S-expression is stored at R_BUFFER and
   the allocated length at R_BUFLEN.  On error an error code is
   returned and (NULL, 0) stored at R_BUFFER and R_BUFLEN.  If the
   allocated buffer length is not required, NULL by be used for
   R_BUFLEN.  */
gpg_error_t
make_canon_sexp (gcry_sexp_t sexp, unsigned char **r_buffer, size_t *r_buflen)
{
  size_t len;
  unsigned char *buf;

  *r_buffer = NULL;
  if (r_buflen)
    *r_buflen = 0;;

  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  if (!len)
    return gpg_error (GPG_ERR_BUG);
  buf = xtrymalloc (len);
  if (!buf)
    return gpg_error_from_syserror ();
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, buf, len);
  if (!len)
    return gpg_error (GPG_ERR_BUG);

  *r_buffer = buf;
  if (r_buflen)
    *r_buflen = len;

  return 0;
}


/* Same as make_canon_sexp but pad the buffer to multiple of 64
   bits.  If SECURE is set, secure memory will be allocated.  */
gpg_error_t
make_canon_sexp_pad (gcry_sexp_t sexp, int secure,
                     unsigned char **r_buffer, size_t *r_buflen)
{
  size_t len;
  unsigned char *buf;

  *r_buffer = NULL;
  if (r_buflen)
    *r_buflen = 0;;

  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  if (!len)
    return gpg_error (GPG_ERR_BUG);
  len += (8 - len % 8) % 8;
  buf = secure? xtrycalloc_secure (1, len) : xtrycalloc (1, len);
  if (!buf)
    return gpg_error_from_syserror ();
  if (!gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, buf, len))
    return gpg_error (GPG_ERR_BUG);

  *r_buffer = buf;
  if (r_buflen)
    *r_buflen = len;

  return 0;
}

/* Return the so called "keygrip" which is the SHA-1 hash of the
   public key parameters expressed in a way dependend on the algorithm.

   KEY is expected to be an canonical encoded S-expression with a
   public or private key. KEYLEN is the length of that buffer.

   GRIP must be at least 20 bytes long.  On success 0 is returned, on
   error an error code. */
gpg_error_t
keygrip_from_canon_sexp (const unsigned char *key, size_t keylen,
                         unsigned char *grip)
{
  gpg_error_t err;
  gcry_sexp_t sexp;

  if (!grip)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = gcry_sexp_sscan (&sexp, NULL, (const char *)key, keylen);
  if (err)
    return err;
  if (!gcry_pk_get_keygrip (sexp, grip))
    err = gpg_error (GPG_ERR_INTERNAL);
  gcry_sexp_release (sexp);
  return err;
}


/* Compare two simple S-expressions like "(3:foo)".  Returns 0 if they
   are identical or !0 if they are not.  Note that this function can't
   be used for sorting. */
int
cmp_simple_canon_sexp (const unsigned char *a_orig,
                       const unsigned char *b_orig)
{
  const char *a = (const char *)a_orig;
  const char *b = (const char *)b_orig;
  unsigned long n1, n2;
  char *endp;

  if (!a && !b)
    return 0; /* Both are NULL, they are identical. */
  if (!a || !b)
    return 1; /* One is NULL, they are not identical. */
  if (*a != '(' || *b != '(')
    log_bug ("invalid S-exp in cmp_simple_canon_sexp\n");

  a++;
  n1 = strtoul (a, &endp, 10);
  a = endp;
  b++;
  n2 = strtoul (b, &endp, 10);
  b = endp;

  if (*a != ':' || *b != ':' )
    log_bug ("invalid S-exp in cmp_simple_canon_sexp\n");
  if (n1 != n2)
    return 1; /* Not the same. */

  for (a++, b++; n1; n1--, a++, b++)
    if (*a != *b)
      return 1; /* Not the same. */
  return 0;
}



/* Helper for cmp_canon_sexp.  */
static int
cmp_canon_sexp_def_tcmp (void *ctx, int depth,
                         const unsigned char *aval, size_t alen,
                         const unsigned char *bval, size_t blen)
{
  (void)ctx;
  (void)depth;

  if (alen > blen)
    return 1;
  else if (alen < blen)
    return -1;
  else
    return memcmp (aval, bval, alen);
}


/* Compare the two canonical encoded s-expressions A with maximum
 * length ALEN and B with maximum length BLEN.
 *
 * Returns 0 if they match.
 *
 * If TCMP is NULL, this is not different really different from a
 * memcmp but does not consider any garbage after the last closing
 * parentheses.
 *
 * If TCMP is not NULL, it is expected to be a function to compare the
 * values of each token.  TCMP is called for each token while parsing
 * the s-expressions until TCMP return a non-zero value.  Here the CTX
 * receives the provided value TCMPCTX, DEPTH is the number of
 * currently open parentheses and (AVAL,ALEN) and (BVAL,BLEN) the
 * values of the current token.  TCMP needs to return zero to indicate
 * that the tokens match.  */
int
cmp_canon_sexp (const unsigned char *a, size_t alen,
                const unsigned char *b, size_t blen,
                int (*tcmp)(void *ctx, int depth,
                            const unsigned char *aval, size_t avallen,
                            const unsigned char *bval, size_t bvallen),
                void *tcmpctx)
{
  const unsigned char *a_buf, *a_tok;
  const unsigned char *b_buf, *b_tok;
  size_t a_buflen, a_toklen;
  size_t b_buflen, b_toklen;
  int a_depth, b_depth, ret;

  if ((!a && !b) || (!alen && !blen))
    return 0; /* Both are NULL, they are identical. */
  if (!a || !b)
    return !!a - !!b; /* One is NULL, they are not identical. */
  if (*a != '(' || *b != '(')
    log_bug ("invalid S-exp in %s\n", __func__);

  if (!tcmp)
    tcmp = cmp_canon_sexp_def_tcmp;

  a_depth = 0;
  a_buf = a;
  a_buflen = alen;
  b_depth = 0;
  b_buf = b;
  b_buflen = blen;

  for (;;)
    {
      if (parse_sexp (&a_buf, &a_buflen, &a_depth, &a_tok, &a_toklen))
        return -1;  /* A is invalid.  */
      if (parse_sexp (&b_buf, &b_buflen, &b_depth, &b_tok, &b_toklen))
        return -1;  /* B is invalid.  */
      if (!a_depth && !b_depth)
        return 0; /* End of both expressions - they match.  */
      if (a_depth != b_depth)
        return a_depth - b_depth; /* Not the same structure   */
      if (!a_tok && !b_tok)
        ; /* parens */
      else if (a_tok && b_tok)
        {
          ret = tcmp (tcmpctx, a_depth, a_tok, a_toklen, b_tok, b_toklen);
          if (ret)
            return ret;  /* Mismatch */
        }
      else /* One has a paren other has not.  */
        return !!a_tok - !!b_tok;
    }
}


/* Create a simple S-expression from the hex string at LINE.  Returns
   a newly allocated buffer with that canonical encoded S-expression
   or NULL in case of an error.  On return the number of characters
   scanned in LINE will be stored at NSCANNED.  This functions stops
   converting at the first character not representing a hexdigit. Odd
   numbers of hex digits are allowed; a leading zero is then
   assumed. If no characters have been found, NULL is returned.*/
unsigned char *
make_simple_sexp_from_hexstr (const char *line, size_t *nscanned)
{
  size_t n, len;
  const char *s;
  unsigned char *buf;
  unsigned char *p;
  char numbuf[50], *numbufp;
  size_t numbuflen;

  for (n=0, s=line; hexdigitp (s); s++, n++)
    ;
  if (nscanned)
    *nscanned = n;
  if (!n)
    return NULL;
  len = ((n+1) & ~0x01)/2;
  numbufp = smklen (numbuf, sizeof numbuf, len, &numbuflen);
  buf = xtrymalloc (1 + numbuflen + len + 1 + 1);
  if (!buf)
    return NULL;
  buf[0] = '(';
  p = (unsigned char *)stpcpy ((char *)buf+1, numbufp);
  s = line;
  if ((n&1))
    {
      *p++ = xtoi_1 (s);
      s++;
      n--;
    }
  for (; n > 1; n -=2, s += 2)
    *p++ = xtoi_2 (s);
  *p++ = ')';
  *p = 0; /* (Not really needed.) */

  return buf;
}


/* Return the hash algorithm from a KSBA sig-val. SIGVAL is a
   canonical encoded S-expression.  Return 0 if the hash algorithm is
   not encoded in SIG-VAL or it is not supported by libgcrypt.  */
int
hash_algo_from_sigval (const unsigned char *sigval)
{
  const unsigned char *s = sigval;
  size_t n;
  int depth;
  char buffer[50];

  if (!s || *s != '(')
    return 0; /* Invalid S-expression.  */
  s++;
  n = snext (&s);
  if (!n)
    return 0; /* Invalid S-expression.  */
  if (!smatch (&s, n, "sig-val"))
    return 0; /* Not a sig-val.  */
  if (*s != '(')
    return 0; /* Invalid S-expression.  */
  s++;
  /* Skip over the algo+parameter list.  */
  depth = 1;
  if (sskip (&s, &depth) || depth)
    return 0; /* Invalid S-expression.  */
  if (*s != '(')
    return 0; /* No further list.  */
  /* Check whether this is (hash ALGO).  */
  s++;
  n = snext (&s);
  if (!n)
    return 0; /* Invalid S-expression.  */
  if (!smatch (&s, n, "hash"))
    return 0; /* Not a "hash" keyword.  */
  n = snext (&s);
  if (!n || n+1 >= sizeof (buffer))
    return 0; /* Algorithm string is missing or too long.  */
  memcpy (buffer, s, n);
  buffer[n] = 0;

  return gcry_md_map_name (buffer);
}


/* Create a public key S-expression for an RSA public key from the
   modulus M with length MLEN and the public exponent E with length
   ELEN.  Returns a newly allocated buffer of NULL in case of a memory
   allocation problem.  If R_LEN is not NULL, the length of the
   canonical S-expression is stored there. */
unsigned char *
make_canon_sexp_from_rsa_pk (const void *m_arg, size_t mlen,
                             const void *e_arg, size_t elen,
                             size_t *r_len)
{
  const unsigned char *m = m_arg;
  const unsigned char *e = e_arg;
  int m_extra = 0;
  int e_extra = 0;
  char mlen_str[35];
  char elen_str[35];
  unsigned char *keybuf, *p;
  const char part1[] = "(10:public-key(3:rsa(1:n";
  const char part2[] = ")(1:e";
  const char part3[] = ")))";

  /* Remove leading zeroes.  */
  for (; mlen && !*m; mlen--, m++)
    ;
  for (; elen && !*e; elen--, e++)
    ;

  /* Insert a leading zero if the number would be zero or interpreted
     as negative.  */
  if (!mlen || (m[0] & 0x80))
    m_extra = 1;
  if (!elen || (e[0] & 0x80))
    e_extra = 1;

  /* Build the S-expression.  */
  snprintf (mlen_str, sizeof mlen_str, "%u:", (unsigned int)mlen+m_extra);
  snprintf (elen_str, sizeof elen_str, "%u:", (unsigned int)elen+e_extra);

  keybuf = xtrymalloc (strlen (part1) + strlen (mlen_str) + mlen + m_extra
                       + strlen (part2) + strlen (elen_str) + elen + e_extra
                       + strlen (part3) + 1);
  if (!keybuf)
    return NULL;

  p = stpcpy (keybuf, part1);
  p = stpcpy (p, mlen_str);
  if (m_extra)
    *p++ = 0;
  memcpy (p, m, mlen);
  p += mlen;
  p = stpcpy (p, part2);
  p = stpcpy (p, elen_str);
  if (e_extra)
    *p++ = 0;
  memcpy (p, e, elen);
  p += elen;
  p = stpcpy (p, part3);

  if (r_len)
    *r_len = p - keybuf;

  return keybuf;
}


/* Return the parameters of a public RSA key expressed as an
   canonical encoded S-expression.  */
gpg_error_t
get_rsa_pk_from_canon_sexp (const unsigned char *keydata, size_t keydatalen,
                            unsigned char const **r_n, size_t *r_nlen,
                            unsigned char const **r_e, size_t *r_elen)
{
  gpg_error_t err;
  const unsigned char *buf, *tok;
  size_t buflen, toklen;
  int depth, last_depth1, last_depth2;
  const unsigned char *rsa_n = NULL;
  const unsigned char *rsa_e = NULL;
  size_t rsa_n_len, rsa_e_len;

  *r_n = NULL;
  *r_nlen = 0;
  *r_e = NULL;
  *r_elen = 0;

  buf = keydata;
  buflen = keydatalen;
  depth = 0;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (!tok || !((toklen == 10 && !memcmp ("public-key", tok, toklen))
                || (toklen == 11 && !memcmp ("private-key", tok, toklen))))
    return gpg_error (GPG_ERR_BAD_PUBKEY);
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (!tok || toklen != 3 || memcmp ("rsa", tok, toklen))
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  last_depth1 = depth;
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        return err;
      if (tok && toklen == 1)
        {
          const unsigned char **mpi;
          size_t *mpi_len;

          switch (*tok)
            {
            case 'n': mpi = &rsa_n; mpi_len = &rsa_n_len; break;
            case 'e': mpi = &rsa_e; mpi_len = &rsa_e_len; break;
            default:  mpi = NULL;   mpi_len = NULL; break;
            }
          if (mpi && *mpi)
            return gpg_error (GPG_ERR_DUP_VALUE);

          if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
            return err;
          if (tok && mpi)
            {
              /* Strip off leading zero bytes and save. */
              for (;toklen && !*tok; toklen--, tok++)
                ;
              *mpi = tok;
              *mpi_len = toklen;
            }
        }

      /* Skip to the end of the list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        return err;
    }

  if (err)
    return err;

  if (!rsa_n || !rsa_n_len || !rsa_e || !rsa_e_len)
    return gpg_error (GPG_ERR_BAD_PUBKEY);

  *r_n = rsa_n;
  *r_nlen = rsa_n_len;
  *r_e = rsa_e;
  *r_elen = rsa_e_len;
  return 0;
}


/* Return the public key parameter Q of a public RSA or ECC key
 * expressed as an canonical encoded S-expression.  */
gpg_error_t
get_ecc_q_from_canon_sexp (const unsigned char *keydata, size_t keydatalen,
                           unsigned char const **r_q, size_t *r_qlen)
{
  gpg_error_t err;
  const unsigned char *buf, *tok;
  size_t buflen, toklen;
  int depth, last_depth1, last_depth2;
  const unsigned char *ecc_q = NULL;
  size_t ecc_q_len = 0;

  *r_q = NULL;
  *r_qlen = 0;

  buf = keydata;
  buflen = keydatalen;
  depth = 0;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (!tok || toklen != 10 || memcmp ("public-key", tok, toklen))
    return gpg_error (GPG_ERR_BAD_PUBKEY);
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (tok && toklen == 3 && !memcmp ("ecc", tok, toklen))
    ;
  else if (tok && toklen == 5 && (!memcmp ("ecdsa", tok, toklen)
                                  || !memcmp ("eddsa", tok, toklen)))
    ;
  else
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  last_depth1 = depth;
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        return err;
      if (tok && toklen == 1)
        {
          const unsigned char **mpi;
          size_t *mpi_len;

          switch (*tok)
            {
            case 'q': mpi = &ecc_q; mpi_len = &ecc_q_len; break;
            default:  mpi = NULL;   mpi_len = NULL; break;
            }
          if (mpi && *mpi)
            return gpg_error (GPG_ERR_DUP_VALUE);

          if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
            return err;
          if (tok && mpi)
            {
              *mpi = tok;
              *mpi_len = toklen;
            }
        }

      /* Skip to the end of the list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        return err;
    }

  if (err)
    return err;

  if (!ecc_q || !ecc_q_len)
    return gpg_error (GPG_ERR_BAD_PUBKEY);

  *r_q = ecc_q;
  *r_qlen = ecc_q_len;
  return 0;
}


/* Return an uncompressed point (X,Y) in P at R_BUF as a malloced
 * buffer with its byte length stored at R_BUFLEN.  May not be used
 * for sensitive data. */
static gpg_error_t
ec2os (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t p,
       unsigned char **r_buf, unsigned int *r_buflen)
{
  gpg_error_t err;
  int pbytes = (mpi_get_nbits (p)+7)/8;
  size_t n;
  unsigned char *buf, *ptr;

  *r_buf = NULL;
  *r_buflen = 0;

  buf = xtrymalloc (1 + 2*pbytes);
  if (!buf)
    return gpg_error_from_syserror ();
  *buf = 04; /* Uncompressed point.  */
  ptr = buf+1;
  err = gcry_mpi_print (GCRYMPI_FMT_USG, ptr, pbytes, &n, x);
  if (err)
    {
      xfree (buf);
      return err;
    }
  if (n < pbytes)
    {
      memmove (ptr+(pbytes-n), ptr, n);
      memset (ptr, 0, (pbytes-n));
    }
  ptr += pbytes;
  err = gcry_mpi_print (GCRYMPI_FMT_USG, ptr, pbytes, &n, y);
  if (err)
    {
      xfree (buf);
      return err;
    }
  if (n < pbytes)
    {
      memmove (ptr+(pbytes-n), ptr, n);
      memset (ptr, 0, (pbytes-n));
    }

  *r_buf = buf;
  *r_buflen = 1 + 2*pbytes;
  return 0;
}


/* Convert the ECC parameter Q in the canonical s-expression
 * (KEYDATA,KEYDATALEN) to uncompressed form.  On success and if a
 * conversion was done, the new canonical encoded s-expression is
 * returned at (R_NEWKEYDAT,R_NEWKEYDATALEN); if a conversion was not
 * required (NULL,0) is stored there.  On error an error code is
 * returned.  The function may take any kind of key but will only do
 * the conversion for ECC curves where compression is supported.  */
gpg_error_t
uncompress_ecc_q_in_canon_sexp (const unsigned char *keydata,
                                size_t keydatalen,
                                unsigned char **r_newkeydata,
                                size_t *r_newkeydatalen)
{
  gpg_error_t err;
  const unsigned char *buf, *tok;
  size_t buflen, toklen, n;
  int depth, last_depth1, last_depth2;
  const unsigned char *q_ptr;     /* Points to the value of "q".      */
  size_t q_ptrlen;                /* Remaining length in KEYDATA.     */
  size_t q_toklen;                /* Q's length including prefix.     */
  const unsigned char *curve_ptr; /* Points to the value of "curve".  */
  size_t curve_ptrlen;            /* Remaining length in KEYDATA.     */
  gcry_mpi_t x, y;                /* Point Q            */
  gcry_mpi_t p, a, b;             /* Curve parameters.  */
  gcry_mpi_t x3, t, p1_4;         /* Helper             */
  int y_bit;
  unsigned char *qvalue;          /* Q in uncompressed form.  */
  unsigned int   qvaluelen;
  unsigned char *dst;             /* Helper */
  char lenstr[35];                /* Helper for a length prefix.  */

  *r_newkeydata = NULL;
  *r_newkeydatalen = 0;

  buf = keydata;
  buflen = keydatalen;
  depth = 0;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (!tok)
    return gpg_error (GPG_ERR_BAD_PUBKEY);
  else if (toklen == 10 || !memcmp ("public-key", tok, toklen))
    ;
  else if (toklen == 11 || !memcmp ("private-key", tok, toklen))
    ;
  else if (toklen == 20 || !memcmp ("shadowed-private-key", tok, toklen))
    ;
  else
    return gpg_error (GPG_ERR_BAD_PUBKEY);

  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;

  if (tok && toklen == 3 && !memcmp ("ecc", tok, toklen))
    ;
  else if (tok && toklen == 5 && !memcmp ("ecdsa", tok, toklen))
    ;
  else
    return 0; /* Other algo - no need for conversion.  */

  last_depth1 = depth;
  q_ptr = curve_ptr = NULL;
  q_ptrlen = 0; /*(silence cc warning)*/
  while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
         && depth && depth >= last_depth1)
    {
      if (tok)
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
        return err;
      if (tok && toklen == 1 && *tok == 'q' && !q_ptr)
        {
          q_ptr = buf;
          q_ptrlen = buflen;
        }
      else if (tok && toklen == 5 && !memcmp (tok, "curve", 5) && !curve_ptr)
        {
          curve_ptr = buf;
          curve_ptrlen = buflen;
        }

      if (q_ptr && curve_ptr)
        break;  /* We got all what we need.  */

      /* Skip to the end of the list. */
      last_depth2 = depth;
      while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
             && depth && depth >= last_depth2)
        ;
      if (err)
        return err;
    }
  if (err)
    return err;

  if (!q_ptr)
    return 0;  /* No Q - nothing to do.  */

  /* Get Q's value and check whether uncompressing is at all required.  */
  buf = q_ptr;
  buflen = q_ptrlen;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    return err;
  if (toklen < 2 || !(*tok == 0x02 || *tok == 0x03))
    return 0;  /* Invalid length or not compressed.  */
  q_toklen = buf - q_ptr;  /* We want the length with the prefix.  */

  /* Put the x-coordinate of q into X and remember the y bit */
  y_bit = (*tok == 0x03);
  err = gcry_mpi_scan (&x, GCRYMPI_FMT_USG, tok+1, toklen-1, NULL);
  if (err)
    return err;

  /* For uncompressing we need to know the curve.  */
  if (!curve_ptr)
    {
      gcry_mpi_release (x);
      return gpg_error (GPG_ERR_INV_CURVE);
    }
  buf = curve_ptr;
  buflen = curve_ptrlen;
  if ((err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen)))
    {
      gcry_mpi_release (x);
      return err;
    }

  {
    char name[50];
    gcry_sexp_t curveparam;

    if (toklen + 1 > sizeof name)
      {
        gcry_mpi_release (x);
        return gpg_error (GPG_ERR_TOO_LARGE);
      }
    mem2str (name, tok, toklen+1);
    curveparam = gcry_pk_get_param (GCRY_PK_ECC, name);
    if (!curveparam)
      {
        gcry_mpi_release (x);
        return gpg_error (GPG_ERR_UNKNOWN_CURVE);
      }

    err = gcry_sexp_extract_param (curveparam, NULL, "pab", &p, &a, &b, NULL);
    gcry_sexp_release (curveparam);
    if (err)
      {
        gcry_mpi_release (x);
        return gpg_error (GPG_ERR_INTERNAL);
      }
  }

  if (!mpi_test_bit (p, 1))
    {
      /* No support for point compression for this curve.  */
      gcry_mpi_release (x);
      gcry_mpi_release (p);
      gcry_mpi_release (a);
      gcry_mpi_release (b);
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

  /*
   * Recover Y.  The Weierstrass curve: y^2 = x^3 + a*x + b
   */

  x3 = mpi_new (0);
  t = mpi_new (0);
  p1_4 = mpi_new (0);
  y = mpi_new (0);

  /* Compute right hand side.  */
  mpi_powm (x3, x, GCRYMPI_CONST_THREE, p);
  mpi_mul (t, a, x);
  mpi_mod (t, t, p);
  mpi_add (t, t, b);
  mpi_mod (t, t, p);
  mpi_add (t, t, x3);
  mpi_mod (t, t, p);

  /*
   * When p mod 4 = 3, modular square root of A can be computed by
   * A^((p+1)/4) mod p
   */

  /* Compute (p+1)/4 into p1_4 */
  mpi_rshift (p1_4, p, 2);
  mpi_add_ui (p1_4, p1_4, 1);

  mpi_powm (y, t, p1_4, p);

  if (y_bit != mpi_test_bit (y, 0))
    mpi_sub (y, p, y);

  gcry_mpi_release (p1_4);
  gcry_mpi_release (t);
  gcry_mpi_release (x3);
  gcry_mpi_release (a);
  gcry_mpi_release (b);

  err = ec2os (x, y, p, &qvalue, &qvaluelen);
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (p);
  if (err)
    return err;

  snprintf (lenstr, sizeof lenstr, "%u:", (unsigned int)qvaluelen);
  /* Note that for simplicity we do not subtract the old length of Q
   * for the new buffer.  */
  *r_newkeydata = xtrymalloc (qvaluelen + strlen(lenstr) + qvaluelen);
  if (!*r_newkeydata)
    return gpg_error_from_syserror ();
  dst = *r_newkeydata;

  n = q_ptr - keydata;
  memcpy (dst, keydata, n);         /* Copy first part of original data.  */
  dst += n;

  n = strlen (lenstr);
  memcpy (dst, lenstr, n);          /* Copy new prefix of Q's value.  */
  dst += n;

  memcpy (dst, qvalue, qvaluelen);  /* Copy new value of Q.    */
  dst += qvaluelen;

  log_assert (q_toklen < q_ptrlen);
  n = q_ptrlen - q_toklen;
  memcpy (dst, q_ptr + q_toklen, n);/* Copy rest of original data.  */
  dst += n;

  *r_newkeydatalen = dst - *r_newkeydata;

  xfree (qvalue);

  return 0;
}


/* Return the algo of a public KEY of SEXP. */
int
get_pk_algo_from_key (gcry_sexp_t key)
{
  gcry_sexp_t list;
  const char *s;
  size_t n;
  char algoname[6];
  int algo = 0;

  list = gcry_sexp_nth (key, 1);
  if (!list)
    goto out;
  s = gcry_sexp_nth_data (list, 0, &n);
  if (!s)
    goto out;
  if (n >= sizeof (algoname))
    goto out;
  memcpy (algoname, s, n);
  algoname[n] = 0;

  algo = gcry_pk_map_name (algoname);
  if (algo == GCRY_PK_ECC)
    {
      gcry_sexp_t l1;
      int i;

      l1 = gcry_sexp_find_token (list, "flags", 0);
      for (i = l1 ? gcry_sexp_length (l1)-1 : 0; i > 0; i--)
	{
	  s = gcry_sexp_nth_data (l1, i, &n);
	  if (!s)
	    continue; /* Not a data element. */

	  if (n == 5 && !memcmp (s, "eddsa", 5))
	    {
	      algo = GCRY_PK_EDDSA;
	      break;
	    }
	}
      gcry_sexp_release (l1);

      l1 = gcry_sexp_find_token (list, "curve", 0);
      s = gcry_sexp_nth_data (l1, 1, &n);
      if (n == 5 && !memcmp (s, "Ed448", 5))
        algo = GCRY_PK_EDDSA;
      gcry_sexp_release (l1);
    }

 out:
  gcry_sexp_release (list);

  return algo;
}


/* This is a variant of get_pk_algo_from_key but takes an canonical
 * encoded S-expression as input.  Returns a GCRYPT public key
 * identiier or 0 on error.  */
int
get_pk_algo_from_canon_sexp (const unsigned char *keydata, size_t keydatalen)
{
  gcry_sexp_t sexp;
  int algo;

  if (gcry_sexp_sscan (&sexp, NULL, keydata, keydatalen))
    return 0;

  algo = get_pk_algo_from_key (sexp);
  gcry_sexp_release (sexp);
  return algo;
}


/* Given the public key S_PKEY, return a new buffer with a descriptive
 * string for its algorithm.  This function may return NULL on memory
 * error.  If R_ALGOID is not NULL the gcrypt algo id is stored there. */
char *
pubkey_algo_string (gcry_sexp_t s_pkey, enum gcry_pk_algos *r_algoid)
{
  const char *prefix;
  gcry_sexp_t l1;
  char *algoname;
  int algo;
  char *result;

  if (r_algoid)
    *r_algoid = 0;

  l1 = gcry_sexp_find_token (s_pkey, "public-key", 0);
  if (!l1)
    l1 = gcry_sexp_find_token (s_pkey, "private-key", 0);
  if (!l1)
    return xtrystrdup ("E_no_key");
  {
    gcry_sexp_t l_tmp = gcry_sexp_cadr (l1);
    gcry_sexp_release (l1);
    l1 = l_tmp;
  }
  algoname = gcry_sexp_nth_string (l1, 0);
  gcry_sexp_release (l1);
  if (!algoname)
    return xtrystrdup ("E_no_algo");

  algo = gcry_pk_map_name (algoname);
  switch (algo)
    {
    case GCRY_PK_RSA: prefix = "rsa"; break;
    case GCRY_PK_ELG: prefix = "elg"; break;
    case GCRY_PK_DSA: prefix = "dsa"; break;
    case GCRY_PK_ECC: prefix = "";  break;
    default:          prefix = NULL; break;
    }

  if (prefix && *prefix)
    result = xtryasprintf ("%s%u", prefix, gcry_pk_get_nbits (s_pkey));
  else if (prefix)
    {
      const char *curve = gcry_pk_get_curve (s_pkey, 0, NULL);
      const char *name = openpgp_oid_to_curve
        (openpgp_curve_to_oid (curve, NULL, NULL), 0);

      if (name)
        result = xtrystrdup (name);
      else if (curve)
        result = xtryasprintf ("X_%s", curve);
      else
        result = xtrystrdup ("E_unknown");
    }
  else
    result = xtryasprintf ("X_algo_%d", algo);

  if (r_algoid)
    *r_algoid = algo;
  xfree (algoname);
  return result;
}


/* Map a pubkey algo id from gcrypt to a string.  This is the same as
 * gcry_pk_algo_name but makes sure that the ECC algo identifiers are
 * not all mapped to "ECC".  */
const char *
pubkey_algo_to_string (int algo)
{
  if (algo == GCRY_PK_ECDSA)
    return "ECDSA";
  else if (algo == GCRY_PK_ECDH)
    return "ECDH";
  else if (algo == GCRY_PK_EDDSA)
    return "EdDSA";
  else
    return gcry_pk_algo_name (algo);
}


/* Map a hash algo id from gcrypt to a string.  This is the same as
 * gcry_md_algo_name but the returned string is lower case, as
 * expected by libksba and it avoids some overhead.  */
const char *
hash_algo_to_string (int algo)
{
  static const struct
  {
    const char *name;
    int algo;
  } hashnames[] =
      {
       { "sha256",    GCRY_MD_SHA256 },
       { "sha512",    GCRY_MD_SHA512 },
       { "sha1",      GCRY_MD_SHA1 },
       { "sha384",    GCRY_MD_SHA384 },
       { "sha224",    GCRY_MD_SHA224 },
       { "sha3-224",  GCRY_MD_SHA3_224 },
       { "sha3-256",  GCRY_MD_SHA3_256 },
       { "sha3-384",  GCRY_MD_SHA3_384 },
       { "sha3-512",  GCRY_MD_SHA3_512 },
       { "ripemd160", GCRY_MD_RMD160 },
       { "rmd160",    GCRY_MD_RMD160 },
       { "md2",       GCRY_MD_MD2 },
       { "md4",       GCRY_MD_MD4 },
       { "tiger",     GCRY_MD_TIGER },
       { "haval",     GCRY_MD_HAVAL },
       { "sm3",       GCRY_MD_SM3 },
       { "md5",       GCRY_MD_MD5 }
      };
  int i;

  for (i=0; i < DIM (hashnames); i++)
    if (algo == hashnames[i].algo)
      return hashnames[i].name;
  return "?";
}


/* Map cipher modes to a string.  */
const char *
cipher_mode_to_string (int mode)
{
  switch (mode)
    {
    case GCRY_CIPHER_MODE_CFB: return "CFB";
    case GCRY_CIPHER_MODE_CBC: return "CBC";
    case GCRY_CIPHER_MODE_GCM: return "GCM";
    case GCRY_CIPHER_MODE_OCB: return "OCB";
    case 14:                   return "EAX";  /* Only in gcrypt 1.9 */
    default: return "[?]";
    }
}

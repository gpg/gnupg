/* sexputil.c - Utility functions for S-expressions.
 * Copyright (C) 2005, 2007, 2009 Free Software Foundation, Inc.
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

/* This file implements a few utility functions useful when working
   with canonical encrypted S-expresions (i.e. not the S-exprssion
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
#include "sexp-parse.h"


/* Helper function to create a a canonical encoded S-expression from a
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


/* Return the so called "keygrip" which is the SHA-1 hash of the
   public key parameters expressed in a way depended on the algorithm.

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
   are identical or !0 if they are not.  Not that this function can't
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


/* Create a simple S-expression from the hex string at LIBNE.  Returns
   a newly allocated buffer with that canonical encoded S-expression
   or NULL in case of an error.  On return the number of characters
   scanned in LINE will be stored at NSCANNED.  This fucntions stops
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
  *p = 0; /* (Not really neaded.) */

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
    return 0; /* No futher list.  */
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


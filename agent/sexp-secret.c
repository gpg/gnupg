/* sexp-secret.c - SEXP handling of the secret key
 * Copyright (C) 2020 g10 Code GmbH.
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
#include "agent.h"
#include "../common/sexp-parse.h"

/*
 * Fixup private key part in the cannonical SEXP.
 */
size_t
fixup_when_ecc_private_key (unsigned char *buf, size_t buflen)
{
  const unsigned char *s;
  size_t n;

  s = buf;
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
  s++;
  n = snext (&s);
  if (!smatch (&s, n, "ecc"))
    return buflen;

  /* It's ECC */
  while (*s == '(')
    {
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (n == 1 && *s == 'd')
        {
          unsigned char *s0;
          size_t n0;

          s += n;
          s0 = (unsigned char *)s;
          n = snext (&s);
	  n0 = s - s0;

          if (!n)
            return gpg_error (GPG_ERR_INV_SEXP);
          else if ((n & 1) && !*s)
            /* Detect wrongly added 0x00.  */
            /* For all existing curves in libgcrypt-1.9 (so far), the
               size of private part should be even.  */
            {
              size_t numsize;

              n--;
              buflen--;
              numsize = snprintf (s0, s-s0+1, "%u:", (unsigned int)n);
              memmove (s0+numsize, s+1, buflen - (s - buf));
	      memset (s0+numsize+buflen - (s - buf), 0, (n0 - numsize) + 1);
              buflen -= (n0 - numsize);
              s = s0+numsize+n;
            }
          else
            s += n;
        }
      else
        {
          s += n;
          n = snext (&s);
          if (!n)
            return gpg_error (GPG_ERR_INV_SEXP);
          s += n;
        }
      if ( *s != ')' )
        return gpg_error (GPG_ERR_INV_SEXP);
      s++;
    }
  if (*s != ')')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;

  return buflen;
}

gpg_error_t
sexp_sscan_private_key (gcry_sexp_t *result, size_t *r_erroff,
                        unsigned char *buf)
{
  gpg_error_t err;
  size_t buflen, buflen1;

  buflen = gcry_sexp_canon_len (buf, 0, NULL, NULL);
  buflen1 = fixup_when_ecc_private_key (buf, buflen);
  err = gcry_sexp_sscan (result, r_erroff, (char*)buf, buflen1);
  wipememory (buf, buflen);

  return err;
}

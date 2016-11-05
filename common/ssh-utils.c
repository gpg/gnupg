/* ssh-utils.c - Secure Shell helper functions
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include "ssh-utils.h"


/* Return true if KEYPARMS holds an EdDSA key.  */
static int
is_eddsa (gcry_sexp_t keyparms)
{
  int result = 0;
  gcry_sexp_t list;
  const char *s;
  size_t n;
  int i;

  list = gcry_sexp_find_token (keyparms, "flags", 0);
  for (i = list ? gcry_sexp_length (list)-1 : 0; i > 0; i--)
    {
      s = gcry_sexp_nth_data (list, i, &n);
      if (!s)
        continue; /* Not a data element. */

      if (n == 5 && !memcmp (s, "eddsa", 5))
        {
          result = 1;
          break;
        }
    }
  gcry_sexp_release (list);
  return result;
}


/* Return the Secure Shell type fingerprint for KEY.  The length of
   the fingerprint is returned at R_LEN and the fingerprint itself at
   R_FPR.  In case of a error code is returned and NULL stored at
   R_FPR.  */
static gpg_error_t
get_fingerprint (gcry_sexp_t key, void **r_fpr, size_t *r_len, int as_string)
{
  gpg_error_t err;
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2 = NULL;
  const char *s;
  char *name = NULL;
  int idx;
  const char *elems;
  gcry_md_hd_t md = NULL;
  int blobmode = 0;

  *r_fpr = NULL;
  *r_len = 0;

  /* Check that the first element is valid. */
  list = gcry_sexp_find_token (key, "public-key", 0);
  if (!list)
    list = gcry_sexp_find_token (key, "private-key", 0);
  if (!list)
    list = gcry_sexp_find_token (key, "protected-private-key", 0);
  if (!list)
    list = gcry_sexp_find_token (key, "shadowed-private-key", 0);
  if (!list)
    {
      err = gpg_err_make (default_errsource, GPG_ERR_UNKNOWN_SEXP);
      goto leave;
    }

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  l2 = NULL;

  name = gcry_sexp_nth_string (list, 0);
  if (!name)
    {
      err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
      goto leave;
    }

  err = gcry_md_open (&md, GCRY_MD_MD5, 0);
  if (err)
    goto leave;

  switch (gcry_pk_map_name (name))
    {
    case GCRY_PK_RSA:
      elems = "en";
      gcry_md_write (md, "\0\0\0\x07ssh-rsa", 11);
      break;

    case GCRY_PK_DSA:
      elems = "pqgy";
      gcry_md_write (md, "\0\0\0\x07ssh-dss", 11);
      break;

    case GCRY_PK_ECC:
      if (is_eddsa (list))
        {
          elems = "q";
          blobmode = 1;
          /* For now there is just one curve, thus no need to switch
             on it.  */
          gcry_md_write (md, "\0\0\0\x0b" "ssh-ed25519", 15);
        }
      else
        {
          /* We only support the 3 standard curves for now.  It is
             just a quick hack.  */
          elems = "q";
          gcry_md_write (md, "\0\0\0\x13" "ecdsa-sha2-nistp", 20);
          l2 = gcry_sexp_find_token (list, "curve", 0);
          if (!l2)
            elems = "";
          else
            {
              gcry_free (name);
              name = gcry_sexp_nth_string (l2, 1);
              gcry_sexp_release (l2);
              l2 = NULL;
              if (!name)
                elems = "";
              else if (!strcmp (name, "NIST P-256")||!strcmp (name, "nistp256"))
                gcry_md_write (md, "256\0\0\0\x08nistp256", 15);
              else if (!strcmp (name, "NIST P-384")||!strcmp (name, "nistp384"))
                gcry_md_write (md, "384\0\0\0\x08nistp384", 15);
              else if (!strcmp (name, "NIST P-521")||!strcmp (name, "nistp521"))
                gcry_md_write (md, "521\0\0\0\x08nistp521", 15);
              else
                elems = "";
            }
          if (!*elems)
            err = gpg_err_make (default_errsource, GPG_ERR_UNKNOWN_CURVE);
        }
      break;

    default:
      elems = "";
      err = gpg_err_make (default_errsource, GPG_ERR_PUBKEY_ALGO);
      break;
    }
  if (err)
    goto leave;


  for (idx = 0, s = elems; *s; s++, idx++)
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
          goto leave;
        }
      if (blobmode)
        {
          const char *blob;
          size_t bloblen;
          unsigned char lenbuf[4];

          blob = gcry_sexp_nth_data (l2, 1, &bloblen);
          if (!blob)
            {
              err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
              goto leave;
            }
          blob++;
          bloblen--;
          lenbuf[0] = bloblen >> 24;
          lenbuf[1] = bloblen >> 16;
          lenbuf[2] = bloblen >>  8;
          lenbuf[3] = bloblen;
          gcry_md_write (md, lenbuf, 4);
          gcry_md_write (md, blob, bloblen);
        }
      else
        {
          gcry_mpi_t a;
          unsigned char *buf;
          size_t buflen;

          a = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
          gcry_sexp_release (l2);
          l2 = NULL;
          if (!a)
            {
              err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
              goto leave;
            }

          err = gcry_mpi_aprint (GCRYMPI_FMT_SSH, &buf, &buflen, a);
          gcry_mpi_release (a);
          if (err)
            goto leave;
          gcry_md_write (md, buf, buflen);
          gcry_free (buf);
        }
    }

  *r_fpr = gcry_malloc (as_string? 61:20);
  if (!*r_fpr)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      goto leave;
    }

  if (as_string)
    {
      bin2hexcolon (gcry_md_read (md, GCRY_MD_MD5), 16, *r_fpr);
      *r_len = 3*16+1;
      strlwr (*r_fpr);
    }
  else
    {
      memcpy (*r_fpr, gcry_md_read (md, GCRY_MD_MD5), 16);
      *r_len = 16;
    }
  err = 0;

 leave:
  gcry_free (name);
  gcry_sexp_release (l2);
  gcry_md_close (md);
  gcry_sexp_release (list);
  return err;
}

/* Return the Secure Shell type fingerprint for KEY.  The length of
   the fingerprint is returned at R_LEN and the fingerprint itself at
   R_FPR.  In case of an error an error code is returned and NULL
   stored at R_FPR.  */
gpg_error_t
ssh_get_fingerprint (gcry_sexp_t key, void **r_fpr, size_t *r_len)
{
  return get_fingerprint (key, r_fpr, r_len, 0);
}


/* Return the Secure Shell type fingerprint for KEY as a string.  The
   fingerprint is mallcoed and stored at R_FPRSTR.  In case of an
   error an error code is returned and NULL stored at R_FPRSTR.  */
gpg_error_t
ssh_get_fingerprint_string (gcry_sexp_t key, char **r_fprstr)
{
  gpg_error_t err;
  size_t dummy;
  void *string;

  err = get_fingerprint (key, &string, &dummy, 1);
  *r_fprstr = string;
  return err;
}
